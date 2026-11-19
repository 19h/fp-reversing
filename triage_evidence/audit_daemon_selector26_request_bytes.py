#!/usr/bin/env python3
"""Compare pre-call selector 26 images with archived Avp method-100 records."""

import argparse
import hashlib
import json
import re
import struct
import subprocess
from collections import Counter
from pathlib import Path

from audit_daemon_selector26_pidpath_paths import AGGREGATE, DESCRIPTOR, DIRECT, check_positive
from audit_daemon_selector26_pidpath_returns import FIXTURE_PATH
from audit_daemon_selector26_record_consumer import FRONTIER, REPLAY, SOURCE, number, sections
from audit_daemon_selector26_self_pidpath import check_pidpath
from daemon_receive_tools import ROOT, verify_original_fixups

DAEMON_SHA = '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
ADID_SHA = 'ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf'
TRACE_SHA = '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
KEYS = (0x5c241ab2, 0x7976211a, 0xfd2821c7)
HEADER = struct.Struct('>IHI')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(name):
    raw = subprocess.check_output(['zstd', '-dc', str(ROOT / (name + '.json.zst'))])
    return json.loads(raw), sha(raw)


def offsets(blob, pattern):
    matches = []
    start = blob.find(pattern)
    while start >= 0:
        matches.append(start)
        start = blob.find(pattern, start + 1)
    return matches


def key_offsets(blob):
    return {f'{key:08x}': offsets(blob, key.to_bytes(4, 'big')) for key in KEYS}


def records(blob, start=0, size=None):
    cursor = start
    limit = len(blob) if size is None else start + size
    entries = []
    assert limit <= len(blob)
    while cursor < limit:
        if limit - cursor < HEADER.size:
            return entries, {'offset': cursor, 'remaining': limit - cursor}
        key, field_type, length = HEADER.unpack_from(blob, cursor)
        end = cursor + HEADER.size + length
        row = {'offset': cursor, 'key': f'{key:08x}', 'type': f'{field_type:04x}',
               'body_size': length, 'end': end}
        if end > limit:
            return entries, row | {'remaining': limit - cursor}
        entries.append(row)
        cursor = end
    return entries, None


def span_records(blob, span):
    assert span['type'] == '50db'
    start = span['offset'] + HEADER.size
    return records(blob, start, span['body_size'])


def compare_shared_records(blob, rows, packet, packet_rows):
    matches = []
    for row in rows:
        for other in packet_rows:
            if row['key'] != other['key'] or int(row['key'], 16) not in KEYS:
                continue
            start, end = row['offset'], row['end']
            other_start, other_end = other['offset'], other['end']
            matches.append({
                'key': row['key'],
                'selector_offset': start,
                'avp_offset': other_start,
                'type_equal': row['type'] == other['type'],
                'length_equal': row['body_size'] == other['body_size'],
                'record_equal': blob[start:end] == packet[other_start:other_end],
            })
    return matches


def archived_avp():
    contracts, contracts_sha = archive('adid_avp_packet_contracts')
    checks, checks_sha = archive('adid_avp_packet_checks')
    assert contracts['thin_sha256'] == ADID_SHA
    baseline = contracts['baseline_method100_request']['bytes144']
    packets = [('baseline', bytes.fromhex(baseline))]
    packets.extend((row['label'], bytes.fromhex(row['bytes320']))
                   for row in checks['source_built_followup_packets'])
    rows = []
    for label, blob in packets:
        outer, error = records(blob)
        assert error is None and len(blob) in (144, 320)
        option, span = outer[1:3]
        assert (option['offset'], option['key'], option['type'], option['body_size']) == (
            18, '7976211a', '9777', 4)
        assert (span['offset'], span['key'], span['type'], span['body_size']) == (
            32, 'fd2821c7', '50db', 80 if len(blob) == 144 else 256)
        rows.append({'label': label, 'size': len(blob), 'sha256': sha(blob), 'outer': outer,
                     'raw_key_offsets': key_offsets(blob)})
    return packets, rows, {'contracts_sha256': contracts_sha, 'checks_sha256': checks_sha}


def defined_buffer(frame, base, extent):
    assert all(base + offset in frame.ram for offset in range(extent))
    return bytes(number(frame.get(base + offset, 1)) for offset in range(extent))


def write_coverage(frame, base, blob):
    last_writer = [None] * len(blob)
    counts = Counter()
    for pc, address, width, value in frame.stores:
        lo, hi = max(base, address), min(base + len(blob), address + width)
        if lo >= hi:
            continue
        store_bytes = (number(value) % (1 << (8 * width))).to_bytes(width, 'little')
        counts[pc] += 1
        for at in range(lo, hi):
            last_writer[at - base] = pc, store_bytes[at - address]
    assert all(cell is not None for cell in last_writer)
    assert bytes(byte for _, byte in last_writer) == blob
    runs = []
    for offset, (pc, _) in enumerate(last_writer):
        if runs and runs[-1]['pc'] == hex(pc):
            runs[-1]['end'] += 1
        else:
            runs.append({'start': offset, 'end': offset + 1, 'pc': hex(pc)})
    return {'covered_bytes': len(blob), 'store_counts': {hex(pc): counts[pc] for pc in sorted(counts)},
            'last_writer_runs': runs}


def selector_requests(packets, packet_rows):
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE.read_bytes()) == DAEMON_SHA == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    original_sections = sections()
    data = [row for row in original_sections if row['segment'] == '__DATA']
    constant, = [row for row in original_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    cases, slots = [], set()
    for equal in (False, True):
        for fixture, seed, pid, abi in ((0x98, 0, 11747, DIRECT), (0x99, 17, 501, DESCRIPTOR)):
            _, routes, state = check_pidpath(fixture, data, profiles, equal, seed, pid, constant)
            edges, extent = check_positive(state, routes[0], FIXTURE_PATH, abi)
            slots.update(slot for _, slot, _ in edges)
            frame = state[0]
            assert extent == (272 if equal else 288)
            blob = defined_buffer(frame, AGGREGATE, extent)
            coverage = write_coverage(frame, AGGREGATE, blob)
            outer_address = number(frame.read('x2'))
            outer = defined_buffer(frame, outer_address, number(frame.read('x3')))
            if abi == DIRECT:
                assert outer == blob
                descriptor = None
            else:
                address, nested_extent, word = struct.unpack('<QII', outer)
                assert (address, nested_extent) == (AGGREGATE, extent)
                descriptor = {'pointer_matches_aggregate': True, 'extent': nested_extent,
                              'final_word': f'{word:08x}'}
            headers, terminal = records(blob)
            assert terminal is None and len(headers) == 4
            span = headers[1]
            assert (span['offset'], span['key'], span['type']) == (14, '812b9aed', '50db')
            nested, nested_terminal = span_records(blob, span)
            packet_comparison = [
                {'label': label, 'avp_packet_in_aggregate': offsets(blob, packet),
                 'aggregate_in_avp_packet': offsets(packet, blob),
                 'avp_prefix18_in_aggregate': offsets(blob, packet[:18]),
                 'shared_records_against_avp_outer': compare_shared_records(blob, nested, packet, archived['outer'])}
                for (label, packet), archived in zip(packets, packet_rows, strict=True)
            ]
            cases.append({
                'class': hex(fixture), 'equal_predecessor': equal, 'method_call_pc': hex(abi[-1]),
                'aggregate_size': extent, 'aggregate_sha256': sha(blob), 'first_header': blob[:10].hex(),
                'records': headers, 'terminal': terminal, 'aggregate_key_offsets': key_offsets(blob),
                'span_at_14_records': nested, 'span_at_14_terminal': nested_terminal,
                'coverage': coverage, 'inline_size': len(outer), 'inline_sha256': sha(outer),
                'inline_key_offsets': key_offsets(outer), 'descriptor': descriptor,
                'predicted_request_user_bytes': 84 + (len(outer) + 3) // 4 * 4,
                'packet_comparison': packet_comparison,
            })
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    return cases, len(slots)


def trace_boundary(path):
    raw = path.read_bytes()
    assert sha(raw) == TRACE_SHA
    lines = raw.decode().splitlines()
    header = re.compile(r'\b(send|received) bits=.*\blocal=(0x[0-9a-f]+).*\bid=(\d+)')
    events = [(line, match[1], int(match[2], 16), int(match[3]))
              for line, content in enumerate(lines, 1) if (match := header.search(content))]
    assert len(events) == 44 and all(ident not in (2865, 2965) for _, _, _, ident in events)
    assert events[-2:] == [(1726, 'send', 0x507, 2862), (1736, 'received', 0x507, 2962)]
    dump = re.compile(r'\]\s+[0-9a-f]{4}\s+([0-9a-f ]+)\|')
    reply = b''.join(bytes.fromhex(match[1]) for line in lines[1736:1740]
                     if (match := dump.search(line)))
    assert len(reply) == 60
    assert struct.unpack_from('<I', reply, 4)[0] == 52
    assert struct.unpack_from('<II', reply, 24) == (1, 0)
    status, = struct.unpack_from('<I', reply, 48)
    assert status == 0xe00002c2
    return {'sha256': sha(raw), 'message_events': len(events), 'final_pair': events[-2:],
            'open_result': hex(status), 'returned_connection': 0, 'observed_2865_or_2965': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    packets, packet_rows, packet_sources = archived_avp()
    trace = trace_boundary(args.trace)
    cases, slots = selector_requests(packets, packet_rows)
    receipt = {'daemon_sha256': DAEMON_SHA, 'avp_archives': packet_sources,
               'avp_packets': packet_rows, 'cases': cases, 'verified_fixups': slots,
               'trace': trace, 'native_method_executed': False}
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
