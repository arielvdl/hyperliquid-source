import copy
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from build_provenance import analyze as analyze_provenance
from catalogue import owner, validate_progress
from elf_index import entry_file_offset, sections, unwind_index
from git_fork_id import canonicalize, short_hash, siphash13_128
from path_origin import Unmapped, classify, matrix


def fixture():
    data = bytearray(832)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 512)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
    data[64:64+len(names)] = names
    entries = [(0,0,0,0,0,0), (1,3,0,0,64,len(names)), (11,1,6,0x100,256,32),
               (17,1,2,0x200,320,20), (31,1,2,0x300,384,16)]
    # Use the actual string offsets so fixtures remain readable.
    entries[2] = (names.index(b'.text'),1,6,0x100,256,32)
    entries[3] = (names.index(b'.eh_frame_hdr'),1,2,0x200,320,20)
    entries[4] = (names.index(b'.eh_frame\0'),1,2,0x300,384,16)
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512+i*64, *e, 0,0,1,0)
    data[320:324] = bytes([1,0x1b,3,0x3b])
    struct.pack_into('<Iii', data, 328, 1, -0x100, 0x100)
    return data


class UnwindTests(unittest.TestCase):
    def test_entry_uses_source_offset_not_linked_or_rebased_address(self):
        data = fixture()
        struct.pack_into('<Q', data, 24, 0x108)
        self.assertEqual(entry_file_offset(data), 264)


    def test_data_relative_negative_start(self):
        secs, rows = unwind_index(fixture())
        self.assertEqual(rows, [{'index':0, 'start':0x100, 'fde':0x300, 'section':'.text', 'next_index_upper_bound':0x120}])

    def test_rejects_truncated_table(self):
        data = fixture()
        struct.pack_into('<I', data, 328, 100)
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_unknown_encoding(self):
        data = fixture(); data[323] = 0
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_non_executable_start(self):
        data = fixture(); struct.pack_into('<i', data, 332, 0x100)
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_truncated_sections(self):
        with self.assertRaises(ValueError): sections(fixture()[:600])


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.parts = json.loads((self.root / 'research/components.json').read_text())['components']
        self.progress = json.loads((self.root / 'research/progress.json').read_text())

    def test_specific_handler_before_exchange_fallback(self):
        self.assertEqual(owner('l1/exchange/handlers/14_order.rs', self.parts), 'action-dispatch')
        self.assertEqual(owner('l1/exchange/impl_trading.rs', self.parts), 'exchange')
        self.assertEqual(owner('l1/clearinghouse/oracle/reference_oracle.rs', self.parts), 'risk')

    def test_unknown_tree_rejected(self):
        with self.assertRaises(ValueError): owner('unrecognized/private.rs', self.parts)

    def test_complete_gate_without_evidence_rejected(self):
        d = copy.deepcopy(self.progress)
        d['components']['orderbook']['gates']['built'] = True
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_fabricated_denominator_rejected(self):
        d = copy.deepcopy(self.progress)
        row = d['components']['orderbook']
        row['raw_equal_bodies'] = 2; row['total_function_windows'] = 1
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_missing_component_rejected(self):
        d = copy.deepcopy(self.progress); del d['components']['visor']
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)


def provenance_fixture(comment=b'\0rustc version 1.94.1 (e408947bf 2026-03-25)\0',
                       rodata=b''):
    data = bytearray(4096)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 512)
    struct.pack_into('<HHH', data, 58, 64, 4, 1)
    names = b'\0.shstrtab\0.rodata\0.comment\0'
    data[64:64+len(names)] = names
    entries = [(0,0,0,0,0,0), (1,3,0,0,64,len(names)),
               (names.index(b'.rodata'),1,2,0x400,1024,len(rodata)),
               (names.index(b'.comment'),1,0x30,0x300,768,len(comment))]
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512+i*64, *e, 0,0,1,0)
    data[768:768+len(comment)] = comment
    data[1024:1024+len(rodata)] = rodata
    return data


class ProvenanceTests(unittest.TestCase):
    def test_extracts_comment_and_paths(self):
        rodata = (b'/home/ubuntu/hl/code_Mainnet/base/src/time.rs\0'
                  b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.217/src/lib.rs\0'
                  b'/home/ubuntu/.cargo/git/checkouts/reth-e231042ee7db3fb7/3212af2/crates/primitives/src/lib.rs\0'
                  b'/home/ubuntu/hl/code_Mainnet/z_vendor/h2/src/codec.rs\0'
                  b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/alloc/src/fmt.rs\0')
        result = analyze_provenance(bytes(provenance_fixture(rodata=rodata)), '94', 'f' * 64)
        self.assertEqual(result['build_root'], '/home/ubuntu/hl')
        self.assertEqual(result['comment'], ['rustc version 1.94.1 (e408947bf 2026-03-25)'])
        self.assertEqual([row['fields'] for row in result['registry']],
                         [['home/ubuntu/.cargo/registry/src/', 'index.crates.io-1949cf8c6b5b557f', 'serde', '1.0.217']])
        self.assertEqual([row['fields'][1:] for row in result['git_checkouts']],
                         [['reth-e231042ee7db3fb7', '3212af2']])
        self.assertEqual([row['fields'][1] for row in result['vendor']], ['h2'])
        self.assertEqual([row['fields'][0] for row in result['rustc_commits']],
                         ['e408947bfd200af42db322daf0fadfe7e26d3bd1'])
        self.assertIn({'prefix': 'code_Mainnet/base', 'refs': 1}, result['layout'])

    def test_absolute_path_with_preceding_junk_is_trimmed(self):
        rodata = b'ERRORstatus/home/ubuntu/hl/code_Mainnet/base/src/ren.rs\0'
        result = analyze_provenance(bytes(provenance_fixture(rodata=rodata)), '94', 'f' * 64)
        self.assertEqual(result['sources']['absolute_count'], 1)
        self.assertEqual([row['prefix'] for row in result['layout']],
                         ['code_Mainnet', 'code_Mainnet/base', 'code_Mainnet/base/src'])

    def test_relative_paths_stay_relative(self):
        rodata = b'base/src/api_secrets.rs\0z_forks/hyper-fork/src/client.rs\0'
        result = analyze_provenance(bytes(provenance_fixture(rodata=rodata)), '115', 'f' * 64)
        self.assertEqual(result['sources']['relative_count'], 2)
        self.assertEqual(result['sources']['absolute_count'], 0)
        self.assertEqual(result['layout'], [])

    def test_rejects_unterminated_comment(self):
        with self.assertRaises(ValueError):
            analyze_provenance(bytes(provenance_fixture(comment=b'\0rustc version 1.94.1')), '94', 'f' * 64)

    def test_rejects_missing_comment(self):
        data = provenance_fixture()
        struct.pack_into('<Q', data, 512 + 3*64 + 32, 0)
        with self.assertRaises(ValueError):
            analyze_provenance(bytes(data), '94', 'f' * 64)

    def test_rejects_two_build_roots(self):
        rodata = (b'/home/ubuntu/hl/code_Mainnet/base/src/a.rs\0'
                  b'/home/ubuntu/other/code_Mainnet/base/src/b.rs\0')
        with self.assertRaises(ValueError):
            analyze_provenance(bytes(provenance_fixture(rodata=rodata)), '94', 'f' * 64)


class GitForkIdTests(unittest.TestCase):
    def test_matches_upstream_siphash_vector(self):
        keys = (0x0706050403020100, 0x0F0E0D0C0B0A0908)
        for length, expected in enumerate([
                'e77ebcb22788a5befd62db6add303001',
                'fc6f370460d3eda85e0573cc2b2ff063',
                '75787f090569839b855bc9548c6aea95',
                '6bc5ccfa1edcf79f4823187712ebd743',
                '0c784e71ac2b285a9f8e92e78fbf2c25']):
            low, high = siphash13_128(bytes(range(length)), *keys)
            self.assertEqual((low.to_bytes(8, 'little') + high.to_bytes(8, 'little')).hex(), expected)

    def test_reproduces_observed_checkout_suffix(self):
        self.assertEqual(short_hash(canonicalize('https://github.com/paradigmxyz/reth')), 'e231042ee7db3fb7')

    def test_canonicalizes_github_case_slash_and_suffix(self):
        self.assertEqual(canonicalize('https://github.com/ParadigmXYZ/Reth.git/'),
                         'https://github.com/paradigmxyz/reth')

    def test_keeps_non_github_case(self):
        self.assertEqual(canonicalize('https://gitlab.com/Owner/Repo'), 'https://gitlab.com/Owner/Repo')

    def test_rejects_scp_style_source(self):
        with self.assertRaises(ValueError):
            canonicalize('git@github.com:paradigmxyz/reth.git')

    def test_hash_depends_on_the_whole_path(self):
        self.assertNotEqual(short_hash(canonicalize('https://github.com/paradigmxyz/reth')),
                            short_hash(canonicalize('https://github.com/paradigmxyz/reth-fork')))


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

    def test_override_directory_maps_to_the_replaced_package(self):
        self.assertEqual(classify('/home/ubuntu/hl/bincode-fork/src/lib.rs', self.root),
                         ('override:bincode-fork', 'bincode'))
        self.assertEqual(classify('/home/ubuntu/hl/hyper-alloy-core-fork/crates/sol-types/src/utils.rs', self.root),
                         ('override:hyper-alloy-core-fork', 'alloy-sol-types'))

    def test_unmapped_override_directory_fails_closed(self):
        with self.assertRaises(Unmapped):
            classify('/home/ubuntu/hl/tokio-fork/src/lib.rs', self.root)
        with self.assertRaises(Unmapped):
            classify('/home/ubuntu/hl/hyper-alloy-core-fork/other/src/lib.rs', self.root)

    def test_vendor_workspace_and_outside_paths(self):
        self.assertEqual(classify('/home/ubuntu/hl/code_Mainnet/z_vendor/hashbrown-0.15.2/src/lib.rs', self.root),
                         ('vendor', 'hashbrown'))
        self.assertEqual(classify('/home/ubuntu/hl/code_Mainnet/base/src/a.rs', self.root),
                         ('workspace', 'base'))
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
