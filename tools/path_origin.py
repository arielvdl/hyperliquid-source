#!/usr/bin/env python3
"""Attribute each embedded source path to its origin and find crates built twice.

A path in rodata names where its source came from: a registry extract, a git
checkout, a path override, a vendored directory, or the workspace itself. That
makes dependency sourcing observable without a manifest, and it shows which
crates the recorded paths cannot be reproduced without.

Two things matter for a rebuild. An override or vendored directory that shadows
a registry crate changes both the code and the recorded path, so it cannot be
dropped; a crate that appears in two origins was compiled twice. This tool
counts both and fails closed on an origin directory the name map does not know,
because an unmapped directory would silently be reported as its own crate.

Override and vendor directories carry only directory names, never package
names. `DIR_PACKAGES` is that mapping; every row built from a directory name is
marked so that an assumption is never read as an observation.
"""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import check
from build_provenance import TARGETS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'research/work-items/RE-002-build-provenance'

# Override directory -> package it replaces. A directory name is not a package
# name, so the mapping is recorded rather than guessed per row.
DIR_PACKAGES = {
    'bincode-fork': 'bincode',
    'hyper-fork': 'hyper',
    'hyper-tls-fork': 'hyper-tls',
    'hyper-alloy-core-fork': None,  # per-crate, see ALLOY_CORE_CRATES
    # Forks whose directory name is already the package name (#115 only).
    'reth-chainspec': 'reth-chainspec',
    'reth-ethereum-forks': 'reth-ethereum-forks',
    'reth-rpc-eth-types': 'reth-rpc-eth-types',
    'reth-rpc-server-types': 'reth-rpc-server-types',
    'revm-precompile': 'revm-precompile',
}
# Crate directory -> package inside the alloy-core fork.
ALLOY_CORE_CRATES = {'primitives': 'alloy-primitives', 'sol-types': 'alloy-sol-types'}
WORKSPACE = 'code_Mainnet'
SOURCE = re.compile(rb'(?<![\w./+-])(?:/home/[A-Za-z0-9_./+-]{3,140}\.rs|(?:\.\./)?[A-Za-z_][A-Za-z0-9_.+-]*(?:/[A-Za-z0-9_.+-]+)+\.rs)')


class Unmapped(Exception):
    pass


def classify(path, root):
    """Return (origin, package) for one source path."""
    if not path.startswith('/'):
        parts = path.split('/')
        if parts[0] == 'z_forks' and len(parts) > 2:
            return _override(f'z_forks/{parts[1]}', parts[1:])
        if parts[0] == 'z_vendor' and len(parts) > 1:
            return 'vendor', _strip_version(parts[1])
        return 'relative', parts[0]
    cargo = path.split('/.cargo/', 1)
    if len(cargo) == 2:
        parts = cargo[1].split('/')
        if len(parts) > 3 and parts[0] == 'registry' and parts[1] == 'src':
            return 'registry', _strip_version(parts[3])
        if len(parts) > 4 and parts[0] == 'git' and parts[1] == 'checkouts':
            return f'git:{parts[2].rsplit("-", 1)[0]}@{parts[3]}', _git_crate(parts[4:])
        return 'cargo', None
    if not root or not path.startswith(root.rstrip('/') + '/'):
        return 'outside', None
    parts = path[len(root.rstrip('/')) + 1:].split('/')
    head = parts[0]
    if head == WORKSPACE:
        if len(parts) > 2 and parts[1] == 'z_vendor':
            return 'vendor', _strip_version(parts[2])
        if len(parts) > 2 and parts[1] == 'z_forks':
            return _override(f'z_forks/{parts[2]}', parts[2:])
        if len(parts) > 1:
            return 'workspace', parts[1]
        return 'workspace', None
    if head.endswith('-fork'):
        return _override(head, parts)
    return 'workspace', head


def _override(origin, parts):
    directory = origin.rsplit('/', 1)[-1]
    if directory not in DIR_PACKAGES:
        raise Unmapped(f'Unknown override directory: {origin}')
    mapped = DIR_PACKAGES[directory]
    if mapped is None:
        crates = [p for p in parts if p != 'crates']
        if len(crates) < 2:
            raise Unmapped(f'{origin} path without a crate directory: {"".join(parts)}')
        if crates[1] not in ALLOY_CORE_CRATES:
            raise Unmapped(f'Unknown crate in {origin}: {crates[1]}')
        return f'override:{origin}', ALLOY_CORE_CRATES[crates[1]]
    return f'override:{origin}', mapped


def _strip_version(name):
    match = re.match(r'^(.*?)-(\d+\.\d+\.\d+.*)$', name)
    return match.group(1) if match else name


def _git_crate(rest):
    """Crate directory inside a checkout: everything before `src`."""
    if 'src' in rest:
        return '/'.join(rest[:rest.index('src')])
    return '/'.join(rest[:2]) if len(rest) >= 2 else None


def matrix(paths, root):
    origins, rows = {}, {}
    for path in paths:
        origin, package = classify(path, root)
        origins[origin] = origins.get(origin, 0) + 1
        if package:
            rows.setdefault(package, {}).setdefault(origin, 0)
            rows[package][origin] += 1
    collisions = []
    for package, by_origin in sorted(rows.items()):
        if len(by_origin) > 1:
            collisions.append({
                'package': package,
                'origins': dict(sorted(by_origin.items())),
                'shadowed': any(o.startswith('override:') for o in by_origin),
                'from_directory_name': any('override:' in o or o == 'vendor' for o in by_origin),
            })
    return {
        'sources': len(paths),
        'origins': dict(sorted(origins.items())),
        'crates': {p: dict(sorted(o.items())) for p, o in sorted(rows.items())},
        'collisions': collisions,
    }


def sources(data):
    """Distinct source paths; std-only `src/` and `../` prefixes are dropped."""
    paths = set()
    for raw in (m.decode() for m in SOURCE.findall(data)):
        if '/home/' in raw and not raw.startswith('/home/'):
            raw = raw[raw.index('/home/'):]
        if raw.startswith('/') or not raw.startswith(('src/', '../')):
            paths.add(raw)
    return sorted(paths)


def record(release):
    manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
    item = next(x for x in manifest['files'] if x['path'] == TARGETS[release])
    check(ROOT / TARGETS[release], item)
    data = (ROOT / TARGETS[release]).read_bytes()
    paths = sources(data)
    absolute = [p for p in paths if p.startswith('/')]
    rooted = [p for p in absolute if '/code_' in p]
    root = rooted[0][:rooted[0].index('/code_')] if rooted else None
    result = {'target': TARGETS[release], 'sha256': item['sha256'],
              'tool': 'tools/path_origin.py', 'build_root': root}
    result.update(matrix(paths, root))
    result['absolute_paths'] = len(absolute)
    result['relative_paths'] = len(paths) - len(absolute)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, choices=sorted(TARGETS))
    args = parser.parse_args()
    result = record(args.release)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    path = OUT / f'sourcing-{args.release}.json'
    path.write_text(text)
    print(f'{path}: {len(result["crates"])} crates, {len(result["collisions"])} collisions')


if __name__ == '__main__':
    main()
