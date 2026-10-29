#!/usr/bin/env python3
"""Decode .eh_frame FDE extents and cross-check them against .eh_frame_hdr.

Static only: reads the verified artifact, decodes CIEs/FDEs, and refuses to
publish ranges that disagree with the unwind index. It does not execute,
disassemble or import the target.
"""
import argparse
import bisect
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]

# DW_EH_PE value formats and applications.
FORMATS = {0x00: 8, 0x01: None, 0x02: 2, 0x03: 4, 0x04: 8,
           0x09: None, 0x0a: 2, 0x0b: 4, 0x0c: 8}
APPLICATIONS = {0x00: 'absptr', 0x10: 'pcrel', 0x20: 'textrel', 0x30: 'datarel',
                0x40: 'funcrel', 0x50: 'aligned'}


def uleb(buf, pos):
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def sleb(buf, pos):
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos


def section_for(secs, address):
    return next((s for s in secs if s['type'] != 8 and s['address'] <= address < s['address'] + s['size']), None)


def va_to_offset(secs, address):
    section = section_for(secs, address)
    if section is None:
        raise ValueError(f'Address outside file mapping: {address:#x}')
    return section['offset'] + address - section['address']


def decode_pointer(data, secs, pos, encoding, field_va, datarel):
    """Decode one DW_EH_PE pointer at absolute file offset pos."""
    if encoding == 0xff:
        return None, pos
    fmt, app, indirect = encoding & 0x0f, encoding & 0x70, encoding & 0x80
    if fmt not in FORMATS or app not in APPLICATIONS:
        raise ValueError(f'Unsupported pointer encoding: {encoding:#x}')
    if fmt in (0x00, 0x04, 0x0c):
        value, = struct.unpack_from('<q' if fmt else '<Q', data, pos)
        pos += 8
    elif fmt == 0x01:
        value, pos = uleb(data, pos)
    elif fmt == 0x02:
        value, = struct.unpack_from('<H', data, pos)
        pos += 2
    elif fmt == 0x03:
        value, = struct.unpack_from('<I', data, pos)
        pos += 4
    elif fmt == 0x09:
        value, pos = sleb(data, pos)
    elif fmt == 0x0a:
        value, = struct.unpack_from('<h', data, pos)
        pos += 2
    elif fmt == 0x0b:
        value, = struct.unpack_from('<i', data, pos)
        pos += 4
    if app == 0x10:
        value += field_va
    elif app == 0x30:
        value += datarel
    elif app == 0x40:
        value += field_va
    elif app == 0x50:
        value = (value + 0x7) & ~0x7
    if indirect:
        value, = struct.unpack_from('<Q', data, va_to_offset(secs, value))
    return value, pos


def parse_cies(data, blob, base_va, limit):
    """Parse CIE records from an .eh_frame blob; returns offset -> CIE info."""
    cies = {}
    pos = 0
    while pos + 4 <= limit:
        start = pos
        length, = struct.unpack_from('<I', blob, pos)
        pos += 4
        if length == 0:
            continue
        if length == 0xffffffff:
            length, = struct.unpack_from('<Q', blob, pos)
            pos += 8
        end = pos + length
        if end > limit:
            raise ValueError(f'Truncated .eh_frame record at {base_va + start:#x}')
        cie_id, = struct.unpack_from('<I', blob, pos)
        pos += 4
        if cie_id == 0:
            version = blob[pos]
            pos += 1
            if version != 1:
                raise ValueError(f'Unsupported CIE version {version}')
            name_end = blob.index(b'\0', pos)
            augmentation = blob[pos:name_end].decode('latin-1')
            pos = name_end + 1
            code_align, pos = uleb(blob, pos)
            data_align, pos = sleb(blob, pos)
            ra_register, pos = uleb(blob, pos)
            info = {'code_align': code_align, 'data_align': data_align,
                    'ra_register': ra_register, 'fde_encoding': 0x00, 'lsda_encoding': 0xff}
            if 'z' in augmentation:
                aug_len, pos = uleb(blob, pos)
                aug_end = pos + aug_len
                for char in augmentation:
                    if char == 'R':
                        info['fde_encoding'] = blob[pos]
                        pos += 1
                    elif char == 'L':
                        info['lsda_encoding'] = blob[pos]
                        pos += 1
                    elif char == 'P':
                        personality_encoding = blob[pos]
                        pos = _skip_encoded(blob, pos + 1, personality_encoding, base_va + pos, base_va)
                    elif char == 'B':
                        pass
                pos = aug_end
            cies[start] = info
        pos = end
    return cies


def _skip_encoded(buf, pos, encoding, field_va, datarel):
    if encoding == 0xff:
        return pos
    fmt = encoding & 0x0f
    if fmt == 0x01:
        return uleb(buf, pos)[1]
    if fmt == 0x09:
        return sleb(buf, pos)[1]
    size = FORMATS.get(fmt)
    if size is None:
        raise ValueError(f'Unsupported pointer encoding: {encoding:#x}')
    return pos + size


def fde_table(data):
    secs = sections(data)
    header = next((s for s in secs if s['name'] == '.eh_frame_hdr'), None)
    frame = next((s for s in secs if s['name'] == '.eh_frame'), None)
    if header is None or frame is None:
        raise ValueError('Missing .eh_frame_hdr or .eh_frame')
    off, base = header['offset'], header['address']
    if header['size'] < 12 or data[off:off + 4] != bytes([1, 0x1b, 0x03, 0x3b]):
        raise ValueError('Unsupported .eh_frame_hdr encodings; do not guess')
    count = struct.unpack_from('<I', data, off + 8)[0]
    if 12 + count * 8 > header['size']:
        raise ValueError('Unwind table is truncated')
    blob = data[frame['offset']:frame['offset'] + frame['size']]
    cies = parse_cies(data, blob, frame['address'], frame['size'])
    fdes = {}
    pos = 0
    while pos + 4 <= frame['size']:
        start = pos
        length, = struct.unpack_from('<I', blob, pos)
        pos += 4
        if length == 0:
            continue
        if length == 0xffffffff:
            length, = struct.unpack_from('<Q', blob, pos)
            pos += 8
        end = pos + length
        if end > frame['size']:
            raise ValueError(f'Truncated .eh_frame record at {frame["address"] + start:#x}')
        cie_delta, = struct.unpack_from('<I', blob, pos)
        pos += 4
        if cie_delta:
            cie = cies.get(start + 4 - cie_delta)
            if cie is None:
                raise ValueError(f'FDE at {frame["address"] + start:#x} points at an unknown CIE')
            field_va = frame['address'] + pos
            location, pos = decode_pointer(data, secs, frame['offset'] + pos, cie['fde_encoding'], field_va, base)
            span, pos = decode_pointer(data, secs, pos, cie['fde_encoding'] & 0x0f, frame['address'] + pos, base)
            fdes[start] = {'location': location, 'span': span, 'encoding': cie['fde_encoding'],
                           'fde_va': frame['address'] + start}
        pos = end
    return secs, header, frame, count, fdes


def analyze(data):
    secs, header, frame, count, fdes = fde_table(data)
    executable = [s for s in secs if s['flags'] & 4 and s['size']]
    base, off = header['address'], header['offset']
    rows = []
    mismatched = outside = zero = duplicate_start = duplicate_fde = 0
    starts_seen = set()
    fdes_seen = set()
    for index in range(count):
        start_delta, fde_delta = struct.unpack_from('<ii', data, off + 12 + index * 8)
        start, fde_va = base + start_delta, base + fde_delta
        fde = fdes.get(fde_va - frame['address'])
        if fde is None:
            raise ValueError(f'Table entry {index} points outside a decoded FDE: {fde_va:#x}')
        if fde['location'] != start:
            mismatched += 1
        if fde['span'] == 0:
            zero += 1
        if start in starts_seen:
            duplicate_start += 1
        if fde_va in fdes_seen:
            duplicate_fde += 1
        starts_seen.add(start)
        fdes_seen.add(fde_va)
        section = section_for(executable, start)
        if section is None:
            outside += 1
            section = section_for(secs, start)
        if section is None:
            raise ValueError(f'Start outside file mapping: {start:#x}')
        end = start + fde['span']
        if end > section['address'] + section['size']:
            outside += 1
        rows.append({'index': index, 'start': start, 'end': end, 'span': fde['span'],
                     'fde': fde_va, 'section': section['name'], 'encoding': fde['encoding']})
    if mismatched:
        raise ValueError(f'{mismatched} unwind-index starts disagree with their FDE initial_location')
    if outside:
        raise ValueError(f'{outside} ranges leave their executable section')
    starts = [r['start'] for r in rows]
    if starts != sorted(starts):
        raise ValueError('Unwind index is not ordered')
    return secs, rows, {'duplicate_fde_references': duplicate_fde}


def padding(data, secs, start, end):
    blob = data[va_to_offset(secs, start):va_to_offset(secs, start) + (end - start)]
    return all(byte in (0x00, 0x90, 0xcc) for byte in blob)


def coverage(secs, rows, data):
    report = {}
    by_section = collections.defaultdict(list)
    for row in rows:
        by_section[row['section']].append(row)
    for section in (s for s in secs if s['flags'] & 4 and s['size']):
        found = by_section.get(section['name'], [])
        low, high = section['address'], section['address'] + section['size']
        gaps, cursor, covered, overlap = [], low, 0, 0
        for row in found:
            if row['start'] < cursor:
                overlap += min(cursor, row['end']) - row['start']
            if row['start'] > cursor:
                gaps.append({'start': cursor, 'end': row['start'], 'size': row['start'] - cursor})
            covered += max(0, min(row['end'], high) - max(row['start'], low))
            cursor = max(cursor, row['end'])
        if cursor < high:
            gaps.append({'start': cursor, 'end': high, 'size': high - cursor})
        for gap in gaps:
            gap['padding'] = padding(data, secs, gap['start'], gap['end'])
        padding_gaps = [g for g in gaps if g['padding']]
        report[section['name']] = {'address': low, 'size': section['size'], 'fde_entries': len(found),
                                   'covered_bytes': covered, 'overlap_bytes': overlap,
                                   'gap_count': len(gaps), 'gap_bytes': sum(g['size'] for g in gaps),
                                   'padding_gap_count': len(padding_gaps),
                                   'padding_gap_bytes': sum(g['size'] for g in padding_gaps),
                                   'non_padding_gap_count': len(gaps) - len(padding_gaps),
                                   'non_padding_gap_bytes': sum(g['size'] for g in gaps if not g['padding']),
                                   'largest_gaps': sorted(gaps, key=lambda g: -g['size'])[:8]}
    return report


def direct_targets(data, secs, rows):
    """Classify rel32 E8 call targets per executable section.

    Scanning is byte-based, so immediate data that happens to be 0xe8 also
    produces candidates. Sections without unwind ranges (PLT/init/fini stubs)
    are reported separately from gaps inside a section that has FDEs.
    """
    ranges = [(r['start'], r['end']) for r in rows]
    starts = [r['start'] for r in rows]
    counts = collections.defaultdict(collections.Counter)
    gap_hits = collections.defaultdict(set)
    gaps = []
    for section in (s for s in secs if s['flags'] & 4 and s['size']):
        low, high = section['address'], section['address'] + section['size']
        cursor = low
        for row in (r for r in rows if r['section'] == section['name']):
            if row['start'] > cursor:
                gaps.append((cursor, row['start']))
            cursor = max(cursor, row['end'])
        if cursor < high:
            gaps.append((cursor, high))
    gaps.sort()
    gap_starts = [g[0] for g in gaps]
    padding_flags = [padding(data, secs, start, end) for start, end in gaps]
    for section in (s for s in secs if s['flags'] & 4 and s['size']):
        blob = data[section['offset']:section['offset'] + section['size']]
        low, name = section['address'], section['name']
        for index in range(len(blob) - 5):
            if blob[index] != 0xe8:
                continue
            target = low + index + 5 + struct.unpack_from('<i', blob, index + 1)[0]
            holder = section_for(secs, target)
            if holder is None or not holder['flags'] & 4:
                counts['outside_executable']['outside_executable'] += 1
                continue
            position = bisect.bisect_right(starts, target)
            if position and ranges[position - 1][0] <= target < ranges[position - 1][1]:
                counts[holder['name']]['fde_start' if ranges[position - 1][0] == target else 'fde_interior'] += 1
                continue
            gap_index = bisect.bisect_right(gap_starts, target) - 1
            if gap_index >= 0 and target < gaps[gap_index][1]:
                counts[holder['name']]['gap_start' if target == gaps[gap_index][0] else 'gap_interior'] += 1
                gap_hits[holder['name']].add(gap_index)
                continue
            counts[holder['name']]['unclassified'] += 1
    report = {name: dict(row) for name, row in sorted(counts.items())}
    reached = {}
    for name, hits in gap_hits.items():
        code_hits = [i for i in hits if not padding_flags[i]]
        reached[name] = {'gaps_reached': len(hits),
                         'gap_bytes_reached': sum(gaps[i][1] - gaps[i][0] for i in hits),
                         'non_padding_gaps_reached': len(code_hits),
                         'non_padding_gap_bytes_reached': sum(gaps[i][1] - gaps[i][0] for i in code_hits)}
    totals = collections.Counter()
    for row in report.values():
        totals.update(row)
    return {'by_section': report, 'totals': dict(totals)}, reached


def relative_relocations(data, secs):
    """R_X86_64_RELATIVE addends keyed by target address (PIE array slots)."""
    table = next((s for s in secs if s['name'] == '.rela.dyn'), None)
    values = {}
    if table is None:
        return values
    blob = data[table['offset']:table['offset'] + table['size']]
    for index in range(0, len(blob) - 24 + 1, 24):
        offset, info, addend = struct.unpack_from('<QQq', blob, index)
        if info & 0xffffffff == 8:
            values[offset] = addend
    return values


def entrypoints(data, secs, rows):
    starts = {r['start'] for r in rows}
    relocated = relative_relocations(data, secs)
    entry = struct.unpack_from('<Q', data, 24)[0]
    found = {'elf_entry': entry}
    dynamic = next((s for s in secs if s['name'] == '.dynamic'), None)
    arrays = {'DT_INIT_ARRAY': (25, 27), 'DT_FINI_ARRAY': (26, 28)}
    if dynamic is not None:
        blob = data[dynamic['offset']:dynamic['offset'] + dynamic['size']]
        tags = {}
        for index in range(0, len(blob), 16):
            tag, value = struct.unpack_from('<qQ', blob, index)
            if tag == 12:
                found['DT_INIT'] = value
            for name, (tag_id, size_id) in arrays.items():
                if tag == tag_id:
                    tags[name] = (value, size_id)
                elif tag == size_id:
                    tags.setdefault(name, (None, size_id))
                    tags[name] = (tags[name][0], value)
        for name, (address, size) in tags.items():
            if address is None:
                continue
            section = section_for(secs, address)
            limit = size if isinstance(size, int) and size else (section['size'] if section else 0)
            count = min(limit // 8, 4096)
            base_offset = va_to_offset(secs, address)
            values = [relocated.get(address + i * 8,
                                    struct.unpack_from('<Q', data, base_offset + i * 8)[0]) for i in range(count)]
            found[name] = {'address': address, 'entries': len(values),
                           'relocated_entries': sum(address + i * 8 in relocated for i in range(count)),
                           'entries_on_fde_start': sum(v in starts for v in values),
                           'entries_in_executable_section': sum(
                               (section_for(secs, v) or {}).get('flags', 0) & 4 != 0 for v in values)}
    report = {}
    for name, value in found.items():
        if isinstance(value, dict):
            report[name] = {**value, 'address_on_fde_start': value['address'] in starts}
            continue
        section = section_for(secs, value)
        report[name] = {'address': value, 'section': section['name'] if section else None,
                        'on_fde_start': value in starts}
    return report


def generate(binary, prefix):
    data = binary.read_bytes() if hasattr(binary, 'read_bytes') else bytes(binary)
    secs, rows, extra = analyze(data)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    tsv = prefix.with_suffix('.tsv')
    with tsv.open('w', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(['index', 'start_va', 'end_va', 'size', 'fde_va', 'section', 'fde_encoding'])
        for row in rows:
            writer.writerow([row['index'], hex(row['start']), hex(row['end']), hex(row['span']),
                             hex(row['fde']), row['section'], hex(row['encoding'])])
    counts, reached = direct_targets(data, secs, rows)
    sections_report = coverage(secs, rows, data)
    summary = {
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'range_tsv_sha256': hashlib.sha256(tsv.read_bytes()).hexdigest(),
        'analysis_state': 'complete: every unwind entry decoded over the full executable sections; no range limit, no timeout',
        'unwind_entries': len(rows),
        'unique_starts': len({r['start'] for r in rows}),
        'duplicate_starts': len(rows) - len({r['start'] for r in rows}),
        'zero_length_ranges': sum(r['span'] == 0 for r in rows),
        'duplicate_fde_references': extra['duplicate_fde_references'],
        'range_size_total': sum(r['span'] for r in rows),
        'range_size_max': max(r['span'] for r in rows),
        'starts_match_fde_initial_location': True,
        'sections': sections_report,
        'entrypoints': entrypoints(data, secs, rows),
        'direct_e8_call_targets': counts,
        'gaps_reached_by_direct_calls': reached,
        'observations': [
            'FDE initial_location equals the matching .eh_frame_hdr start for every entry.',
            'Range ends are decoded address_range values, not next-index bounds.',
            'Duplicate starts and duplicate FDE references are counted, not merged.',
            'Gap regions have no unwind range; padding means every byte is 0x00, 0x90 or 0xcc.',
            'gaps_reached counts every gap; non_padding_gaps_reached is the code-like subset.',
            'E8 scanning is byte-based, so operand data inside code can produce false positives.',
        ],
        'limitations': 'Unwind ranges are not a complete function census. Assembly, PLT/init stubs and any code without FDEs are absent. Component ownership, symbol identity and reconstructed-source equivalence are not established.',
    }
    prefix.with_suffix('.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=['94', '115'], required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'work/fde')
    args = parser.parse_args()
    from artifacts import check
    relative = f'artifacts/node/{args.release}/hl-node'
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                if i['path'] == relative)
    check(ROOT / relative, item)
    summary = generate(ROOT / relative, args.output_dir / f'node-{args.release}-fde')
    print(json.dumps({k: summary[k] for k in ('binary_sha256', 'unwind_entries', 'unique_starts',
                                              'duplicate_starts', 'zero_length_ranges',
                                              'range_size_total', 'direct_e8_call_targets')}, indent=2))


if __name__ == '__main__':
    main()
