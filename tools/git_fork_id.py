#!/usr/bin/env python3
"""Recompute the cargo git-checkout directory suffix for candidate fork URLs.

The captured binary keeps the checkout path of its git dependency in rodata:
`/home/ubuntu/.cargo/git/checkouts/reth-<16 hex>/3212af2/...`. That suffix is
cargo's `short_hash` of the source's canonical URL, so a candidate URL can be
confirmed or rejected without running a build.

Three pieces are reproduced from cargo and from the hasher it links:

- `CanonicalUrl::new` (src/util/canonical_url.rs): strip a trailing slash,
  force `https` and lower-case the path on github.com, drop a `.git` suffix.
  The query and fragment are already gone by then, because `SourceId::from_url`
  clears them before canonicalizing a git URL.
- `Hash for str`: the UTF-8 bytes followed by `0xFF`.
- `short_hash` (src/util/hex.rs) on top of `StableSipHasher128`
  (rust-lang/rustc-stable-hash, SipHash-1-3 with a 128-bit state, keys 0/0),
  finishing as `low * 3 + high` and hex-encoding the result little-endian.

`--selftest` checks the hasher against the upstream 1-3 test vector.
"""

import argparse
import json
import sys
from urllib.parse import urlsplit

MASK64 = (1 << 64) - 1

# Upstream vector: hash of bytes 0..i under these keys, i in 0..64.
VECTOR_KEYS = (0x0706050403020100, 0x0F0E0D0C0B0A0908)
VECTOR = [
    'e77ebcb22788a5befd62db6add303001', 'fc6f370460d3eda85e0573cc2b2ff063', '75787f090569839b855bc9548c6aea95', '6bc5ccfa1edcf79f4823187712ebd743',
    '0c784e71ac2b285a9f8e92e78fbf2c25', 'f328db89345b620c795229a42695843e', 'dcd03d29f743e7100951b0e83985a6f8', '1084b923f2aae0c3a62f2ec80848ab77',
    'aa12fee1d5e3dab4724f16ab35f9c799', '81ddb8042cf33994f4720e0094137c42', '4faa541d5d498e89ba0ea4c387b22fb4', '723b9af3554491dbb1d6633dfc6e0c4e',
    'e53f92859e4819a8dc0695739fea8c65', 'b2f858c7c9ea801d53d603596d657844', '87e76268dbc9227226b0ca665f64e378', 'c17e5505b2bd526c2921cdec1e7e0109',
    'd0a8d95715518eebb513b0f83d9e1793', '234126f93fbb668d975112e8febdf7ec', 'ef42f03db78f704d023c449f16b7092b', 'abf76238c20af161b2314b4d5526bce9',
    '3c2c2f11bb90cf0be335ca9b2e91e9b7', '2a7a680f22a02a92f45149d20fece0ef', 'c9a8d130231dd43e42e6456957f83779', '1d127b84405ceab99fd8775a9be6c559',
    '9e4bf837bcfd92cace09d2061a84d04a', '39031a965d73b4af5a274d18f973b1d2', '7f4d0a1209d67e4ed06f7538e1cfad64', 'e61ee240fbdcce38969f4cd24927dd93',
    '4c3ba2b37b0fdd8cfa5e95c189b29414', 'e06fd4ca066fecdd54068a5ad8896f86', '5ca84c34139c6580a88af24990720706', '42ea961c5b3c858b17c3e550dfa79010',
    '406c44dee67857b2943160f30c7417d3', 'c5f57bae1320fcf4b4e868e71d56c66b', '04bf737a5b676be7c3de05017df4bff9', '5163c9c03f1907ea1044ed5c30727b4f',
    '37a110f002718edad24b3f9ee453f140', 'b9877e381aedd3da08c33e75ff23ac10', '7c5004005ec5da4c5ac9440e5c723193', '81b8243783dbc646ca9d0cd82abdb46c',
    '505720543eb9b413d50b3cfad9eef938', '945f594de72411e4d335be874456d8f3', '37923b3e371777b21170bf9d7e62f602', '3ad4e7c85764964611eb0a6c4d62de56',
    'cd91396c44af4f5185578d9dd9803f0a', 'fe28158e727b868f3903c9acda64a258', '40cc10b8288ce5f0bc3ac0b68a0eebc8', '6f1490f540699a3cd4974420ecc92737',
    'd505f1b75e1a84a603c43583b2ed0308', '491573cfd72bb4682b7ca5880e1c8d6f', '3ed69cfe45ab403f2fd2ad959ba27666', '8be839ef1b20b57c83ba7eb6a8c22b6a',
    '1409186ab42231fedee18162cf1cb4ca', '2bf3ccc24ab672cf151fb8d2f3f3069b', 'b9b93a2882d6025cdb8c56fa13f7537b', 'd97cca3694fb206db8bd1f3650c33322',
    '94ec2e19a40be41af3940d6b30c49384', '4b41603f209a045be140a341a3dffe10', '23fbcb309f1cf094890755ab1b426569', 'e7d9b65690918a2b232f2f5c12c8300e',
    'ade83cf7e7f3847b36fa4b54b00dce61', '0610c5f2ee571c8ac80cbfe538bdf1c7', '271d5d00fbdb5d155d9dcea97cb40218', '4c5800e34efe426f079f6b0aa75260ad',
]


def _rotl(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def _round(state):
    v0, v1, v2, v3 = state
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = _rotl(v1, 13) ^ v0
    v3 = _rotl(v3, 16) ^ v2
    v0 = _rotl(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = _rotl(v1, 17) ^ v2
    v3 = _rotl(v3, 21) ^ v0
    v2 = _rotl(v2, 32)
    return [v0, v1, v2, v3]


def siphash13_128(data, key0=0, key1=0):
    """Return the (low, high) pair of the 128-bit SipHash-1-3 state."""
    state = [
        key0 ^ 0x736F6D6570736575,
        key1 ^ (0x646F72616E646F6D ^ 0xEE),
        key0 ^ 0x6C7967656E657261,
        key1 ^ 0x7465646279746573,
    ]
    total = len(data)
    offset = 0
    while total - offset >= 8:
        word = int.from_bytes(data[offset:offset + 8], 'little')
        state[3] ^= word
        state = _round(state)
        state[0] ^= word
        offset += 8
    tail = data[offset:]
    block = ((total & 0xFF) << 56) | int.from_bytes(tail.ljust(8, b'\0'), 'little')
    state[3] ^= block
    state = _round(state)
    state[0] ^= block
    state[2] ^= 0xEE
    for _ in range(3):
        state = _round(state)
    low = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[1] ^= 0xDD
    for _ in range(3):
        state = _round(state)
    high = state[0] ^ state[1] ^ state[2] ^ state[3]
    return low, high


def hash_u64(text, key0=0, key1=0):
    """`Hash for str` then `Hasher::finish`."""
    low, high = siphash13_128(text.encode('utf-8') + b'\xff', key0, key1)
    return (low * 3 + high) & MASK64


def short_hash(text):
    return hash_u64(text).to_bytes(8, 'little').hex()


def canonicalize(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.netloc:
        raise ValueError('not an absolute http(s) URL: %s' % url)
    path = parts.path
    if path.endswith('/'):
        path = path[:-1]
    scheme = parts.scheme
    if parts.hostname == 'github.com':
        scheme = 'https'
        path = path.lower()
    if path.endswith('.git'):
        path = path[:-4]
    return '%s://%s%s' % (scheme, parts.netloc, path)


def evaluate(urls, expect):
    rows = []
    for url in urls:
        canonical = canonicalize(url)
        digest = short_hash(canonical)
        rows.append({
            'url': url,
            'canonical': canonical,
            'short_hash': digest,
            'match': None if expect is None else digest == expect,
        })
    return rows


def selftest():
    failures = []
    for length, expected in enumerate(VECTOR):
        low, high = siphash13_128(bytes(range(length)), *VECTOR_KEYS)
        got = (low.to_bytes(8, 'little') + high.to_bytes(8, 'little')).hex()
        if got != expected:
            failures.append('length %d: %s != %s' % (length, got, expected))
    if short_hash(canonicalize('https://github.com/rust-lang/cargo.git')) != short_hash(
            'https://github.com/rust-lang/cargo'):
        failures.append('.git suffix changed the digest')
    if short_hash(canonicalize('https://github.com/Rust-Lang/Cargo/')) != short_hash(
            'https://github.com/rust-lang/cargo'):
        failures.append('github case and trailing slash were not canonicalized')
    if canonicalize('https://gitlab.com/x/y.git') != 'https://gitlab.com/x/y':
        failures.append('non-github .git suffix survived')
    for failure in failures:
        print('FAIL %s' % failure)
    return not failures


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--url', action='append', default=[], help='candidate URL, repeatable')
    parser.add_argument('--from-file', help='file with one candidate URL per line')
    parser.add_argument('--expect', help='16 hex characters to compare against')
    parser.add_argument('--selftest', action='store_true')
    parser.add_argument('--output', help='write the JSON result here instead of stdout')
    args = parser.parse_args()

    if args.selftest:
        ok = selftest()
        print('selftest %s' % ('ok' if ok else 'failed'))
        return 0 if ok else 1

    urls = list(args.url)
    if args.from_file:
        with open(args.from_file, encoding='utf-8') as handle:
            urls.extend(line.strip() for line in handle if line.strip())
    if not urls:
        parser.error('no candidate URL')
    if args.expect and (len(args.expect) != 16 or args.expect.strip('0123456789abcdef')):
        parser.error('--expect takes 16 lower-case hex characters')

    rows = evaluate(urls, args.expect)
    result = {'expect': args.expect, 'count': len(rows), 'rows': rows}
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
