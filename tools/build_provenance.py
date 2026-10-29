#!/usr/bin/env python3
"""Extract build provenance fingerprints from a captured ELF without executing it.

Everything here is a byte-level observation of strings the compiler, linker and C
build scripts left in the image. The extractor never claims that a fingerprint is
the flag that produced it; it records what is present and what a matched rebuild
would therefore have to explain.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'provenance' / 'artifacts.json'

RUSTC_PATH = re.compile(rb'/rustc/([0-9a-f]{40})/library/[^\x00\s"]{0,120}')
CHECKOUT = re.compile(rb'/checkout/[^\x00\s"]{0,120}')
CARGO_HOME = re.compile(rb'(/[A-Za-z0-9_./-]*\.cargo)/([a-z]+)/')
REGISTRY = re.compile(rb'/([A-Za-z0-9_./-]*\.cargo/registry/src/)(index\.crates\.io-[0-9a-f]+)/([A-Za-z0-9_.+-]+)-([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*)/')
GIT_CHECKOUT = re.compile(rb'/([A-Za-z0-9_./-]*\.cargo/git/checkouts)/([A-Za-z0-9_.-]+)/([0-9a-f]{7,40})/')
VENDOR = re.compile(rb'/(z_vendor)/([A-Za-z0-9_.+-]+)/')
HOME = re.compile(rb'/home/([A-Za-z0-9_.-]+)/')
SOURCE = re.compile(rb'(?<![\w./+-])(?:/home/[A-Za-z0-9_./+-]{3,140}\.rs|(?:\.\./)?[A-Za-z_][A-Za-z0-9_.+-]*(?:/[A-Za-z0-9_.+-]+)+\.rs)')
COMMENT_MAX = 4096


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def expected_digest(release):
    for row in json.loads(ARTIFACTS.read_text())['files']:
        if row['path'] == f'artifacts/node/{release}/hl-node':
            return row['sha256']
    raise ValueError(f'No manifest entry for release {release}')


def comment(data, secs):
    rows = [s for s in secs if s['name'] == '.comment']
    if not rows:
        return []
    if len(rows) != 1:
        raise ValueError('More than one .comment section')
    row = rows[0]
    if row['size'] > COMMENT_MAX:
        raise ValueError('.comment larger than the accepted bound')
    body = data[row['offset']:row['offset'] + row['size']]
    if body.count(0) < 2 or not body.endswith(b'\0'):
        raise ValueError('.comment is not a NUL-terminated list')
    entries = [chunk.decode('utf-8') for chunk in body.split(b'\0') if chunk]
    if not entries:
        raise ValueError('Empty .comment section')
    return entries


def unique(matches):
    return sorted({match.decode('utf-8') for match in matches})


def _group(matches, limit=200):
    """Group a regex's captured fields into sorted (value, reference count) rows."""
    counts = {}
    for match in matches:
        fields = match if isinstance(match, tuple) else (match,)
        key = tuple(part.decode('utf-8') for part in fields)
        counts[key] = counts.get(key, 0) + 1
    if len(counts) > limit:
        raise ValueError(f'More than {limit} distinct rows; narrow the pattern')
    return [{'fields': list(key), 'refs': value} for key, value in sorted(counts.items())]


def source_paths(data):
    """Split panic-location paths into absolute and relative, dropping std-only ones."""
    absolute, relative = [], []
    for raw in unique(SOURCE.findall(data)):
        if '/home/' in raw and not raw.startswith('/home/'):
            raw = raw[raw.index('/home/'):]
        if raw.startswith('/'):
            absolute.append(raw)
        elif not raw.startswith(('src/', '../')):
            relative.append(raw)
    return absolute, relative


def layout(absolute, root, depth=3):
    """Count the first segments of every absolute source path below the build root."""
    counts = {}
    prefix = root.rstrip('/') + '/'
    for path in absolute:
        if not path.startswith(prefix):
            continue
        parts = path[len(prefix):].split('/')[:-1][:depth]
        for size in range(1, len(parts) + 1):
            key = '/'.join(parts[:size])
            counts[key] = counts.get(key, 0) + 1
    return [{'prefix': k, 'refs': v} for k, v in sorted(counts.items())]


def analyze(data, release, digest):
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise ValueError('Expected ELF64 little-endian input')
    secs = sections(data)
    names = {row['name'] for row in secs}
    roots = [root for root in unique(re.findall(rb'(/home/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/[A-Za-z0-9_]+/', data))
             if not root.endswith('/.cargo')]
    if len(roots) > 1:
        raise ValueError(f'More than one build root: {roots}')
    build_root = roots[0] if roots else None
    absolute, relative = source_paths(data)
    tree = layout(absolute, build_root) if build_root else []
    return {
        'layout': tree,
        'release': release,
        'artifact': f'artifacts/node/{release}/hl-node',
        'sha256': digest,
        'elf_class': 'ELF64-LE',
        'sections': {
            'count': len(secs),
            'has_debug': sorted(n for n in names if n.startswith('.debug') or n in {'.symtab', '.strtab'}),
            'has_comment': '.comment' in names,
        },
        'comment': comment(data, secs),
        'build_root': build_root,
        'home_users': unique(HOME.findall(data)),
        'cargo_homes': unique(match[0] for match in CARGO_HOME.findall(data)),
        'registry': _group(REGISTRY.findall(data)),
        'vendor': _group(VENDOR.findall(data)),
        'git_checkouts': _group(GIT_CHECKOUT.findall(data)),
        'rustc_commits': _group(RUSTC_PATH.findall(data)),
        'rustc_library_paths': len(RUSTC_PATH.findall(data)),
        'checkout_paths': unique(CHECKOUT.findall(data)),
        'sources': {
            'absolute_count': len(absolute),
            'relative_count': len(relative),
            'relative_sample': relative[:40],
        },
        'unresolved': [
            'compiler flags: no .debug_info, so no DW_AT_producer and no recorded rustc -C options',
            'cargo profile: panic=abort vs unwind, lto, codegen-units, opt-level are not recorded in the image',
            'git fork URLs: checkout directories carry only a URL-derived hash and a revision',
            'registry completeness: only crates whose paths survive as strings are visible',
            'build date: no SOURCE_DATE_EPOCH or reproducible timestamp in the retained metadata',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, choices=['94', '115'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    path = ROOT / f'artifacts/node/{args.release}/hl-node'
    data = path.read_bytes()
    digest = sha256(path)
    expected = expected_digest(args.release)
    if digest != expected:
        raise ValueError(f'SHA-256 {digest} differs from the manifest {expected}')
    result = analyze(data, args.release, digest)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
        print(f'{args.output}: {len(result["registry"])} registry rows, '
              f'{len(result["git_checkouts"])} git checkouts, {result["sources"]["absolute_count"]} absolute sources')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
