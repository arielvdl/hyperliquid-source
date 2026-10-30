#!/usr/bin/env python3
"""Pin the version behind each path override by matching its embedded file set.

A path override under the build root carries a directory name and nothing else: no
URL, no revision, no version. But the compiler records the file that panicked, so the
image still holds a partial file list of the override. That list is a fingerprint of
the tree it was built from.

This tool takes that list, walks the crates.io versions of the crate the override is
mapped to, and keeps the versions whose published tree contains every recorded path.
A fork that only edits files inside a tree still matches the tree it forked, so the
output is a set of candidates and a set of exclusions with the path that excludes
each one, never a single asserted version.

Downloads are cached under `work/prov/crates` and every tarball used is recorded with
its SHA-256, so a later run can be checked against the same bytes.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import check
from build_provenance import TARGETS
from path_origin import ALLOY_CORE_CRATES

ROOT = Path(__file__).resolve().parents[1]
SOURCE = re.compile(rb'(?<![\w./+-])(?:/home/[A-Za-z0-9_./+-]{3,140}\.rs|(?:\.\./)?[A-Za-z_][A-Za-z0-9_.+-]*(?:/[A-Za-z0-9_.+-]+)+\.rs)')
BUILD_ROOT = re.compile(rb'(/home/[\w.-]+/hl/code_\w+)/')
REGISTRY = re.compile(rb'\.cargo/registry/src/[^/\0]+/([A-Za-z0-9_][A-Za-z0-9_.-]*?)-(\d+\.\d+\.\d+[A-Za-z0-9.+-]*)/')
CACHE = ROOT / 'work' / 'prov' / 'crates'
INDEX = 'https://index.crates.io'
STATIC = 'https://static.crates.io/crates'
MAX_VERSIONS = 320
# Crates whose requirement is checked against the versions the image itself resolved.
# A candidate that needs a hyper major the image does not contain cannot be the tree.
GUARDS = {
    'hyper-tls': {'hyper': 'hyper'},
    'hyper-fork': {'tokio': 'tokio', 'h2': 'h2', 'bytes': 'bytes'},
}
WORKERS = 8
TIMEOUT = 30

# Override directory -> crate whose published tree the file list is compared against.
# The alloy override holds a workspace copy, so each `crates/<name>` directory is
# matched against the separately published package, not against the `alloy-core`
# facade, which ships no workspace layout.
UPSTREAM = {
    'bincode-fork': 'bincode',
    'hyper-fork': 'hyper',
    'hyper-tls-fork': 'hyper-tls',
    'hyper-alloy-core-fork': {
        'primitives': 'alloy-primitives',
        'sol-types': 'alloy-sol-types',
    },
}


def load(release):
    """Verified bytes of one target plus the facts this tool needs from it."""
    manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
    rel = TARGETS[release]
    item = next(x for x in manifest['files'] if x['path'] == rel)
    path = ROOT / rel
    check(path, item)
    data = path.read_bytes()
    root = sorted({m.decode() for m in BUILD_ROOT.findall(data)})
    if len(root) != 1:
        raise ValueError(f'{len(root)} build roots in {rel}')
    paths = {m.decode() for m in SOURCE.findall(data)}
    paths = {p[p.index('/home/'):] if '/home/' in p and not p.startswith('/home/') else p for p in paths}
    versions = {}
    for name, version in REGISTRY.findall(data):
        versions.setdefault(name.decode(), []).append(version.decode())
    return rel, item['sha256'], data, root[0].rsplit('/code_', 1)[0], paths, versions


def index_path(name):
    if len(name) == 1:
        return f'1/{name}'
    if len(name) == 2:
        return f'2/{name}'
    if len(name) == 3:
        return f'3/{name[0]}/{name}'
    return f'{name[:2]}/{name[2:4]}/{name}'


def versions(name):
    """Published versions of a crate, oldest first, without prereleases."""
    with urllib.request.urlopen(f'{INDEX}/{index_path(name)}', timeout=TIMEOUT) as response:
        rows = [json.loads(line) for line in response if line.strip()]
    picked = [(row['vers'], bool(row.get('yanked'))) for row in rows if '-' not in row['vers']]
    if len(picked) > MAX_VERSIONS:
        raise ValueError(f'{name} has {len(picked)} versions, above the accepted bound')
    return picked


def fetch(name, version):
    """Download a crate file once and return its bytes plus the digest."""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f'{name}-{version}.crate'
    if not path.exists():
        url = f'{STATIC}/{name}/{name}-{version}.crate'
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as response:
                body = response.read()
        except urllib.error.HTTPError as error:
            raise ValueError(f'{name}-{version}: HTTP {error.code}') from error
        path.write_bytes(body)
    body = path.read_bytes()
    return body, hashlib.sha256(body).hexdigest()


def tree(body, wanted=()):
    """Files in a crate tarball, plus the line count of the paths we care about."""
    files, lines = set(), {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = member.name.split('/', 1)[1]
            files.add(path)
            if path in wanted:
                handle = archive.extractfile(member)
                lines[path] = handle.read().count(b'\n') if handle else 0
    return files, lines


def match(paths, files):
    """Versions containing every path, as (kept, missing) over an iterable of (version, tree)."""
    kept, missing = [], []
    for version, files_ in files:
        absent = sorted(set(paths) - files_)
        if absent:
            missing.append({'version': version, 'missing': absent[:5]})
        else:
            kept.append(version)
    return kept, missing


def line_floors(data, directory, root):
    """Highest panic line recorded for each path under one override directory.

    A panic location is `path:line`, so the built file had at least that many lines.
    An upstream version with a shorter file cannot be the tree that was compiled
    unless the fork itself added the lines.
    """
    prefix = f'{root.rstrip("/")}/{directory}/'.encode()
    floors = {}
    for raw in re.findall(re.escape(prefix) + rb'([A-Za-z0-9_./+-]*):([0-9]{1,6})', data):
        path, line = raw[0].decode(), int(raw[1])
        if line > floors.get(path, 0):
            floors[path] = line
    return floors


def floor_filter(kept, floors, trees):
    """Split versions by whether their files are long enough for the recorded lines."""
    by_version = dict(trees)
    passing, short = [], []
    for version in kept:
        files_ = by_version[version]
        short_paths = []
        for path, line in sorted(floors.items()):
            if path not in files_ or files_[path] < line:
                short_paths.append(f'{path}:{line}>{files_.get(path, 0)}')
        if short_paths:
            short.append({'version': version, 'too_short': short_paths[:5]})
        else:
            passing.append(version)
    return passing, short


def relative(paths, directory, root):
    """Paths inside one override directory, relative to the crate it shadows."""
    prefix = f'{root.rstrip("/")}/{directory}/'
    rows = sorted({path[len(prefix):] for path in paths if path.startswith(prefix)})
    if not rows:
        raise ValueError(f'No recorded path under {directory}')
    return rows


def strip_alloy(directory, rows):
    """Drop the `crates/<crate>` prefix the alloy workspace adds, keeping one crate."""
    out = {}
    for row in rows:
        parts = row.split('/')
        if len(parts) < 4 or parts[0] != 'crates' or parts[1] not in ALLOY_CORE_CRATES:
            raise ValueError(f'Unexpected path in {directory}: {row}')
        out.setdefault(parts[1], []).append('/'.join(parts[2:]))
    return {crate: sorted(paths) for crate, paths in out.items()}


def split_floors(floors, directory, upstream):
    """Floors keyed by the published crate the path belongs to."""
    if not isinstance(upstream, dict):
        return {upstream: floors}
    out = {}
    for path, line in floors.items():
        parts = path.split('/')
        if len(parts) < 4 or parts[0] != 'crates':
            raise ValueError(f'Unexpected panic path in {directory}: {path}')
        out.setdefault(upstream[parts[1]], {})['/'.join(parts[2:])] = line
    return out


def requirement(body, name):
    """Version requirement a crate file declares for one dependency, or None."""
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        names = [n for n in archive.getnames() if n.endswith('/Cargo.toml') and n.count('/') == 1]
        if not names:
            return None
        handle = archive.extractfile(names[0])
        text = handle.read().decode('utf-8', 'replace') if handle else ''
    patterns = (rf'^{name}\s*=\s*(?:\{{[^}}]*version\s*=\s*)?"([^"]+)"',
                rf'^\[dependencies\.{name}\]\s*\n(?:[^[].*\n)*?version\s*=\s*"([^"]+)"')
    for pattern in patterns:
        match = re.search(pattern, text, re.M)
        if match:
            return match.group(1)
    return None


def compatible(requirement, versions):
    """Whether any version in the image satisfies a caret requirement.

    Cargo's caret keeps the leftmost non-zero field: `0.14.2` allows only 0.14.x,
    `1.44` allows any 1.x.
    """
    match = re.match(r'^\^?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?$', requirement.strip())
    if not match:
        return None
    major, minor = int(match.group(1)), match.group(2)
    for version in versions:
        parts = version.split('.')
        if int(parts[0]) != major:
            continue
        if major == 0 and minor is not None and int(parts[1]) != int(minor):
            continue
        return True
    return False


def dependency_filter(passing, bodies, published, guards):
    """Drop versions whose declared requirement the image cannot satisfy."""
    kept, dropped = [], []
    for version in passing:
        index = [v for v, _ in published].index(version)
        body = bodies[index][0]
        verdicts = {}
        for name, versions in guards.items():
            wanted = requirement(body, name)
            if wanted is None:
                verdicts[name] = None
                continue
            verdicts[name] = compatible(wanted, versions)
        if any(value is False for value in verdicts.values()):
            dropped.append({'version': version, 'requirements': verdicts})
        else:
            kept.append(version)
    return kept, dropped


def pin(paths, root, data, versions_by_crate):
    """Resolve every override directory to its candidate versions."""
    result = {}
    for directory, upstream in sorted(UPSTREAM.items()):
        rows = relative(paths, directory, root)
        floors = split_floors(line_floors(data, directory, root), directory, upstream)
        if isinstance(upstream, dict):
            groups = {upstream[crate]: group for crate, group in strip_alloy(directory, rows).items()}
        else:
            groups = {upstream: rows}
        for crate, group in sorted(groups.items()):
            wanted = set(floors.get(crate, {}))
            published = versions(crate)
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                bodies = list(pool.map(lambda row: fetch(crate, row[0]), published))
            trees, digests = [], {}
            for (version, _), (body, digest) in zip(published, bodies):
                digests[version] = digest
                trees.append((version, tree(body, wanted)))
            kept, missing = match(group, [(v, files) for v, (files, _) in trees])
            if not kept:
                raise ValueError(f'{directory}: no {crate} version contains the recorded paths')
            passing, short = floor_filter(kept, floors.get(crate, {}),
                                          [(v, lines) for v, (_, lines) in trees if v in kept])
            if not passing:
                raise ValueError(f'{directory}: no {crate} version is long enough for the recorded lines')
            guards = GUARDS.get(crate, {})
            passing, dropped = dependency_filter(passing, bodies, published,
                                                 {name: versions_by_crate.get(crate_name, [])
                                                  for name, crate_name in guards.items()})
            if not passing:
                raise ValueError(f'{directory}: no {crate} version agrees with the versions in the image')
            key = f'{directory}:{crate}' if isinstance(upstream, dict) else directory
            result[key] = {
                'upstream': crate,
                'paths': len(group),
                'panic_lines': len(floors.get(crate, {})),
                'candidates': passing,
                'excluded_missing_path': missing,
                'excluded_short_file': short,
                'excluded_requirement': dropped,
                'crate_sha256': digests,
            }
    return pair_alloy(result)


def pair_alloy(result):
    """Both alloy crates come from one workspace, so only shared versions can hold."""
    left, right = 'hyper-alloy-core-fork:alloy-primitives', 'hyper-alloy-core-fork:alloy-sol-types'
    if left not in result or right not in result:
        return result
    shared = sorted(set(result[left]['candidates']) & set(result[right]['candidates']))
    if not shared:
        raise ValueError('The two alloy crates share no candidate version')
    for key in (left, right):
        result[key]['candidates'] = shared
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True, choices=['94', '115'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    artifact, digest, data, root, paths, versions_by_crate = load(args.release)
    present = sorted(d for d in UPSTREAM if any(f'/{d}/' in p for p in paths))
    if not present:
        raise ValueError('No path override in this release')
    result = {
        'release': args.release,
        'artifact': artifact,
        'sha256': digest,
        'index': INDEX,
        'overrides': pin(paths, root, data, versions_by_crate),
    }
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
        for name, row in sorted(result['overrides'].items()):
            print(f'{name}: {row["paths"]} paths, {row["panic_lines"]} line floors, candidates {row["candidates"]}')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
