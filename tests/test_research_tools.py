import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import owner, validate_progress
from elf_index import entry_file_offset, sections, unwind_index
from fde_extents import analyze, generate


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


TEXT, HDR = 0x1000, 0x2000


def extent_fixture():
    """Two functions, one padding gap, one code gap, a relocated init_array."""
    data = bytearray(2048)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 1024)
    struct.pack_into('<HHH', data, 58, 64, 8, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0.rela.dyn\0.dynamic\0.init_array\0'
    data[64:64 + len(names)] = names
    text, hdr, frame, rela, dynamic, array = TEXT, HDR, 0x3000, 0x4000, 0x5000, 0x6000
    rows = [(0, 0, 0, 0, 0, 0), (1, 3, 0, 0, 64, len(names)),
            (names.index(b'.text'), 1, 6, text, 256, 40),
            (names.index(b'.eh_frame_hdr'), 1, 2, hdr, 384, 28),
            (names.index(b'.eh_frame\0'), 1, 2, frame, 512, 96),
            (names.index(b'.rela.dyn'), 1, 2, rela, 768, 24),
            (names.index(b'.dynamic'), 1, 3, dynamic, 832, 48),
            (names.index(b'.init_array'), 1, 3, array, 896, 8)]
    for index, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, 1024 + index * 64, *row, 0, 0, 1, 0)
    data[256:264] = bytes([0x90] * 8)
    data[264:272] = bytes([0xcc] * 8)
    data[272:283] = b'\xe8\x00\x00\x00\x00\xe8\x06\x00\x00\x00\x90'
    data[283:288] = bytes([0x90] * 5)
    data[288:296] = b'\x0f\x1f\x44\x00\x00\x90\x90\x90'
    struct.pack_into('<i', data, 273, text - (text + 16 + 5))
    # CIE with zR and pcrel|sdata4, then two FDEs pointing at it.
    cie = b'\x10\0\0\0\0\0\0\0\x01zR\0\x01\x78\x10\x01\x1b\0\0\0'
    data[512:512 + len(cie)] = cie
    for slot, start, span in ((20, text, 8), (40, text + 16, 16)):
        field = frame + slot + 8
        struct.pack_into('<IIiiI', data, 512 + slot, 16, slot + 4, start - field, span, 0)
    data[384:388] = bytes([1, 0x1b, 3, 0x3b])
    struct.pack_into('<Iii', data, 392, 2, text - hdr, (frame + 20) - hdr)
    struct.pack_into('<ii', data, 404, (text + 16) - hdr, (frame + 40) - hdr)
    struct.pack_into('<QQq', data, 768, array, 8, text + 16)
    struct.pack_into('<qQqQqQ', data, 832, 25, array, 27, 8, 0, 0)
    return data


class FdeExtentTests(unittest.TestCase):
    def test_decodes_ranges_and_classifies_gaps(self):
        summary = generate(extent_fixture(), Path(tempfile.mkdtemp()) / 'fixture')
        self.assertEqual(summary['unwind_entries'], 2)
        self.assertEqual(summary['duplicate_starts'], 0)
        self.assertEqual(summary['sections']['.text']['gap_count'], 2)
        self.assertEqual(summary['sections']['.text']['padding_gap_bytes'], 8)
        self.assertEqual(summary['sections']['.text']['non_padding_gap_bytes'], 8)
        self.assertEqual(summary['direct_e8_call_targets']['by_section']['.text']['fde_start'], 1)
        self.assertEqual(summary['gaps_reached_by_direct_calls']['.text']['non_padding_gaps_reached'], 1)
        self.assertEqual(summary['duplicate_fde_references'], 0)
        self.assertEqual(summary['sections']['.text']['fde_entries'], 2)
        self.assertEqual(len(summary['range_tsv_sha256']), 64)
        self.assertTrue(summary['analysis_state'].startswith('complete'))

    def test_start_disagreeing_with_fde_rejected(self):
        data = extent_fixture()
        struct.pack_into('<i', data, 392, TEXT - HDR + 1)
        with self.assertRaises(ValueError): analyze(bytes(data))

    def test_duplicate_start_counted(self):
        data = extent_fixture()
        struct.pack_into('<i', data, 404, TEXT - HDR)
        struct.pack_into('<i', data, 512 + 40 + 8, TEXT - (0x3000 + 40 + 8))
        struct.pack_into('<i', data, 512 + 40 + 12, 8)
        summary = generate(data, Path(tempfile.mkdtemp()) / 'fixture')
        self.assertEqual(summary['duplicate_starts'], 1)

    def test_relocated_init_array_entry_resolved(self):
        summary = generate(extent_fixture(), Path(tempfile.mkdtemp()) / 'fixture')
        array = summary['entrypoints']['DT_INIT_ARRAY']
        self.assertEqual(array['relocated_entries'], 1)
        self.assertEqual(array['entries_on_fde_start'], 1)

    def test_rejects_unsupported_header_encoding(self):
        data = extent_fixture(); data[385] = 0
        with self.assertRaises(ValueError): analyze(bytes(data))

    def test_rejects_truncated_table(self):
        data = extent_fixture(); struct.pack_into('<I', data, 392, 9)
        with self.assertRaises(ValueError): analyze(bytes(data))
