#!/usr/bin/env python3
"""Classify where each embedded source path came from, and find shadowed crates.

A path in rodata names its origin: a registry extract, a git checkout, a path
override under the build root, a vendored crate, or the workspace itself. That
makes dependency sourcing observable without a manifest.

Two things matter for a rebuild. An override that shadows a registry crate
changes both the code and the recorded path, so it cannot be dropped; a crate
that appears in two origins was compiled twice. This tool counts both and fails
closed on an override directory that the name map does not know, because an
unmapped directory would silently be reported as its own crate.

The package names of the four overrides are a mapping, not an observation: the
path only carries directory names. `OVERRIDE_PACKAGES` records the mapping and
every collision row says which side came from a directory name.
"""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_provenance import analyze, expected_digest, sha256

ROOT = Path(__file__).resolve().parents[1]

# Directory name -> package it replaces. Cargo's checkout and registry layout
# embed the package name; a path override only embeds the directory name.
OVERRIDE_PACKAGES = {
    'bincode-fork': 'bincode',
    'hyper-fork': 'hyper',
    'hyper-alloy-core-fork': None,  # per-crate, see ALLOY_CORE_CRATES
    'hyper-tls-fork': 'hyper-tls',
}
# Crate directory -> package inside the alloy-core fork.
ALLOY_CORE_CRATES = {'primitives': 'alloy-primitives', 'sol-types': 'alloy-sol-types'}

WORKSPACE_MARKER = 'code_Mainnet'


class Unmapped(Exception):
    pass


def classify(path, root):
    """Return (origin, package) for one absolute source path."""
    cargo = path.split('/.cargo/', 1)
    if len(cargo) == 2:
        parts = cargo[1].split('/')
        if len(parts) > 3 and parts[0] == 'registry' and parts[1] == 'src':
            return 'registry', _strip_version(parts[3])
        if len(parts) > 4 and parts[0] == 'git' and parts[1] == 'checkouts':
            repo = parts[2].rsplit('-', 1)[0]
            return f'git:{repo}@{parts[3]}', _git_crate(parts[4:])
        return 'cargo', None
    if not root or not path.startswith(root.rstrip('/') + '/'):
        return 'outside', None
    parts = path[len(root.rstrip('/')) + 1:].split('/')
    head = parts[0]
    if head == WORKSPACE_MARKER:
        if len(parts) > 2 and parts[1] == 'z_vendor':
            return 'vendor', _strip_version(parts[2])
        if len(parts) > 1:
            return 'workspace', parts[1]
        return 'workspace', None
    if head.endswith('-fork'):
        if head not in OVERRIDE_PACKAGES:
            raise Unmapped(f'Unknown override directory: {head}')
        mapped = OVERRIDE_PACKAGES[head]
        if mapped is None:
            if len(parts) < 3 or parts[1] != 'crates':
                raise Unmapped(f'{head} path without a crate directory: {path}')
            if parts[2] not in ALLOY_CORE_CRATES:
                raise Unmapped(f'Unknown crate in {head}: {parts[2]}')
            return f'override:{head}', ALLOY_CORE_CRATES[parts[2]]
        return f'override:{head}', mapped
    return 'workspace', head


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
            })
    return {
        'origins': dict(sorted(origins.items())),
        'packages': len(rows),
        'collisions': collisions,
        'crates': {p: dict(sorted(o.items())) for p, o in sorted(rows.items())},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, choices=['94', '115'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    path = ROOT / f'artifacts/node/{args.release}/hl-node'
    digest = sha256(path)
    expected = expected_digest(args.release)
    if digest != expected:
        raise ValueError(f'SHA-256 {digest} differs from the manifest {expected}')
    data = path.read_bytes()
    packet = analyze(data, args.release, digest)
    sources = _sources(data, packet)
    result = {'release': args.release, 'artifact': packet['artifact'], 'sha256': digest,
              'sources': len(sources), 'build_root': packet['build_root']}
    result.update(matrix(sources, packet['build_root']))
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
        print(f'{args.output}: {len(result["crates"])} crates, '
              f'{len(result["collisions"])} collisions')
    else:
        sys.stdout.write(text)


def _sources(data, packet):
    """All source paths, absolute and relative, without the std-only ones."""
    from build_provenance import source_paths
    absolute, _ = source_paths(data)
    return absolute


if __name__ == '__main__':
    main()
