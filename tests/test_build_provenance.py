import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import OUT, TARGETS, derive, diff, interpret, record
from path_origin import Unmapped, classify, matrix, record as record_sourcing


def elf(comment, rodata):
    names = b'\0.shstrtab\0.comment\0.rodata\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    blobs = [names, comment, rodata]
    offsets = []
    for blob in blobs:
        offsets.append(len(body))
        body += blob
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, 4, 1)
    rows = [(0, 0, 0, 0, 0, 0)]
    for name, blob, off in zip((b'.shstrtab', b'.comment', b'.rodata'), blobs, offsets):
        rows.append((names.index(name + b'\0'), 3 if name == b'.shstrtab' else 1, 0, 0, off, len(blob)))
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row, 0, 0, 1, 0)
    return bytes(body), offsets


def dynamic_elf(tags):
    names = b'\0.shstrtab\0.dynstr\0.dynamic\0'
    dynstr = b'\0libfixture.so\0'
    blob = b''.join(struct.pack('<qQ', *tag) for tag in tags)
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, kind, data, link, entsize in ((b'.shstrtab', 3, names, 0, 0), (b'.dynstr', 3, dynstr, 0, 0),
                                             (b'.dynamic', 6, blob, 2, 16)):
        body += b'\0' * (-len(body) % 8)
        rows.append((names.index(name + b'\0'), kind, 0, 0, len(body), len(data), link, 0, 8, entsize))
        body += data
    body += b'\0' * (-len(body) % 8)
    struct.pack_into('<Q', body, 40, len(body))
    struct.pack_into('<HHH', body, 58, 64, len(rows), 1)
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body)


def dynamic_facts(tags):
    return {i['key']: i['value'] for i in derive(dynamic_elf(tags))}


def by_key(items, key):
    return [i for i in items if i['key'] == key]


class DeriveTests(unittest.TestCase):
    def setUp(self):
        comment = b'rustc version 1.94.1 (e408947bf 2026-03-25)\0Linker: LLD 21.1.8 (/checkout/src/llvm-project/llvm x)\0'
        rodata = (b'\0/rustc/' + b'a' * 40 + b'/library/core/src/x.rs\0'
                  b'/home/u/.cargo/registry/src/index.crates.io-0123/tokio-1.44.2/src/lib.rs\0'
                  b'/home/u/.cargo/git/checkouts/reth-e231042ee7db3fb7/3212af2/crates/a.rs\0'
                  b'/home/u/hl/code_Mainnet/z_vendor/axum/src/lib.rs\0'
                  b'/home/u/hl/code_Mainnet/z_vendor/ark-ff-0.5.0/src/lib.rs\0')
        self.data, self.offsets = elf(comment, rodata)
        self.items = derive(self.data)

    def test_comment_stamps_are_exact_with_their_offsets(self):
        stamps = by_key(self.items, 'comment')
        self.assertEqual([s['value'] for s in stamps][0], 'rustc version 1.94.1 (e408947bf 2026-03-25)')
        self.assertEqual(stamps[0]['evidence'], {'file_offset': hex(self.offsets[1]), 'section': '.comment'})

    def test_dependency_paths_keep_versions_only_where_present(self):
        self.assertEqual(by_key(self.items, 'crate.registry')[0]['value'], {'name': 'tokio', 'version': '1.44.2'})
        self.assertEqual(by_key(self.items, 'crate.git_checkout')[0]['value'],
                         {'checkout': 'reth-e231042ee7db3fb7', 'short_rev': '3212af2'})
        vendored = {v['value']['dir']: v['value']['version_in_path'] for v in by_key(self.items, 'crate.z_vendor_dir')}
        self.assertEqual(vendored, {'axum': None, 'ark-ff-0.5.0': '0.5.0'})

    def test_unrecorded_settings_stay_unknown(self):
        facts = interpret(self.items)
        for key in ('opt_level', 'lto', 'codegen_units', 'cargo_lock', 'panic_strategy'):
            self.assertEqual([(i['label'], i['value']) for i in by_key(facts, key)], [('unknown', None)], key)
        self.assertEqual(by_key(facts, 'linker')[0]['label'], 'inferred')

    def test_diff_ignores_offsets_and_reports_changed_values(self):
        old = {'facts': [{'key': 'k', 'label': 'exact', 'value': 1, 'evidence': {'file_offset': '0x1'}},
                         {'key': 'same', 'label': 'exact', 'value': 2, 'evidence': {'file_offset': '0x2'}}]}
        new = {'facts': [{'key': 'k', 'label': 'exact', 'value': 3, 'evidence': {}},
                         {'key': 'same', 'label': 'exact', 'value': 2, 'evidence': {'file_offset': '0x9'}}]}
        self.assertEqual(diff(old, new), ([('k', 'exact', '1')], [('k', 'exact', '3')]))

    def test_dynamic_entries_after_dt_null_are_ignored(self):
        facts = dynamic_facts([(1, 1), (0, 0), (30, 8), (1, 1), (15, 1)])
        self.assertEqual(facts['dynamic.needed'], ['libfixture.so'])
        self.assertIs(facts['dynamic.bind_now'], False)
        self.assertEqual(facts['dynamic.runpath'], [])

    def test_bind_now_accepts_every_abi_encoding(self):
        self.assertIs(dynamic_facts([(0, 0)])['dynamic.bind_now'], False)
        for tags in ([(30, 8), (0, 0)], [(0x6FFFFFFB, 1), (0, 0)], [(24, 0), (0, 0)]):
            self.assertIs(dynamic_facts(tags)['dynamic.bind_now'], True, tags)

    def test_non_elf_input_is_rejected(self):
        with self.assertRaises(ValueError):
            derive(b'not an elf' * 10)


def captured(release):
    path = ROOT / TARGETS[release]
    return path.is_file() and path.stat().st_size > 1_000_000


@unittest.skipUnless(all(captured(r) for r in TARGETS), 'captured binaries not materialized (git lfs pull)')
class CapturedTargetTests(unittest.TestCase):
    def test_committed_records_reproduce_from_verified_targets(self):
        for release in TARGETS:
            committed = json.loads((OUT / f'provenance-{release}.json').read_text())
            self.assertEqual(committed, json.loads(json.dumps(record(release))), release)

    def test_node_94_and_115_toolchains_differ(self):
        def commits(release):
            return {i['value'] for i in record(release)['facts'] if i['key'] == 'rustc.commit_path'}
        self.assertEqual(commits('94'), {'e408947bfd200af42db322daf0fadfe7e26d3bd1'})
        self.assertEqual(commits('115'), {'59807616e1fa2540724bfbac14d7976d7e4a3860'})


class PathOriginTests(unittest.TestCase):
    root = '/home/ubuntu/hl'

    def test_registry_row_keeps_the_package_and_drops_the_version(self):
        path = '/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.120/src/value/ser.rs'
        self.assertEqual(classify(path, self.root), ('registry', 'serde_json'))

    def test_build_metadata_version_is_stripped_whole(self):
        path = '/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/bzip2-sys-0.1.11+1.0.8/src/lib.rs'
        self.assertEqual(classify(path, self.root), ('registry', 'bzip2-sys'))

    def test_git_checkout_reports_the_repo_and_revision(self):
        path = '/home/ubuntu/.cargo/git/checkouts/reth-e231042ee7db3fb7/3212af2/crates/primitives/src/receipt.rs'
        self.assertEqual(classify(path, self.root), ('git:reth@3212af2', 'crates/primitives'))

    def test_absolute_and_vendored_override_paths(self):
        self.assertEqual(classify('/home/ubuntu/hl/bincode-fork/src/lib.rs', self.root),
                         ('override:bincode-fork', 'bincode'))
        self.assertEqual(classify('z_forks/reth-rpc-eth-types/src/lib.rs', self.root),
                         ('override:z_forks/reth-rpc-eth-types', 'reth-rpc-eth-types'))
        self.assertEqual(classify('/home/ubuntu/hl/hyper-alloy-core-fork/crates/sol-types/src/utils.rs', self.root),
                         ('override:hyper-alloy-core-fork', 'alloy-sol-types'))

    def test_unmapped_override_directory_fails_closed(self):
        with self.assertRaises(Unmapped):
            classify('/home/ubuntu/hl/tokio-fork/src/lib.rs', self.root)
        with self.assertRaises(Unmapped):
            classify('z_forks/tokio-fork/src/lib.rs', self.root)

    def test_vendor_workspace_and_outside_paths(self):
        self.assertEqual(classify('/home/ubuntu/hl/code_Mainnet/z_vendor/hashbrown-0.15.2/src/lib.rs', self.root),
                         ('vendor', 'hashbrown'))
        self.assertEqual(classify('/home/ubuntu/hl/code_Mainnet/base/src/a.rs', self.root),
                         ('workspace', 'base'))
        self.assertEqual(classify('base/src/api_secrets.rs', self.root), ('relative', 'base'))
        self.assertEqual(classify('/checkout/src/llvm-project/llvm/x.rs', self.root), ('outside', None))

    def test_collision_marks_a_crate_built_from_two_origins(self):
        paths = ['/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-0.14.29/src/lib.rs',
                 '/home/ubuntu/hl/hyper-fork/src/lib.rs']
        rows = matrix(paths, self.root)
        self.assertEqual(len(rows['collisions']), 1)
        self.assertEqual(rows['collisions'][0]['package'], 'hyper')
        self.assertTrue(rows['collisions'][0]['shadowed'])

    def test_single_origin_is_not_a_collision(self):
        rows = matrix(['/home/ubuntu/hl/bincode-fork/src/lib.rs'], self.root)
        self.assertEqual(rows['collisions'], [])
        self.assertEqual(rows['crates']['bincode'], {'override:bincode-fork': 1})

    def test_committed_sourcing_matches_a_rerun(self):
        for release in ('94', '115'):
            committed = json.loads((OUT / f'sourcing-{release}.json').read_text())
            self.assertEqual(committed, json.loads(json.dumps(record_sourcing(release))), release)

    def test_hyper_is_the_only_crate_built_twice(self):
        for release in ('94', '115'):
            self.assertEqual([c['package'] for c in record_sourcing(release)['collisions']], ['hyper'], release)


if __name__ == '__main__':
    unittest.main()
