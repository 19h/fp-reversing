#!/usr/bin/env python3
"""Decode the supplied textual capture; never execute fairplayd or change IDA.

Linear time and space in the trace and Mach-O input sizes. Header/descriptor
values come from hex bytes; annotations are retained separately.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def image_info(path):
    b = path.read_bytes()
    assert b[:4] == bytes.fromhex('cffaedfe'), 'expected thin Mach-O 64 LE'
    result = {'path': str(path), 'sha256': digest(b), 'size_bytes': len(b),
              'text_sections': []}
    off = 32
    for _ in range(struct.unpack_from('<I', b, 16)[0]):
        cmd, size = struct.unpack_from('<II', b, off)
        if cmd == 0x1b:
            result['uuid'] = str(uuid.UUID(bytes=b[off+8:off+24]))
        if cmd == 0x19:
            for j in range(struct.unpack_from('<I', b, off+64)[0]):
                q = off + 72 + j * 80
                name = b[q:q+16].split(b'\0')[0].decode()
                seg = b[q+16:q+32].split(b'\0')[0].decode()
                va, length, fileoff = struct.unpack_from('<QQI', b, q+32)
                if seg == '__TEXT':
                    result['text_sections'].append({
                        'section': name, 'address': hex(va), 'size': length,
                        'file_offset': fileoff,
                        'sha256': digest(b[fileoff:fileoff+length])})
        off += size
    return result


def decode_descriptors(raw, bits):
    result = []
    if not bits & 0x80000000:
        return result
    count = struct.unpack_from('<I', raw, 24)[0]
    off = 28
    for _ in range(count):
        kind = raw[off+11]
        if kind == 0:
            name = struct.unpack_from('<I', raw, off)[0]
            result.append({'kind': 'port', 'offset': off, 'name': hex(name),
                           'disposition': raw[off+10]})
            off += 12
        elif kind in (1, 3):
            addr = struct.unpack_from('<Q', raw, off)[0]
            length = struct.unpack_from('<I', raw, off+12)[0]
            result.append({'kind': 'ool', 'offset': off, 'address': hex(addr),
                           'size': length, 'deallocate': raw[off+8],
                           'copy': raw[off+9], 'type': kind})
            off += 16
        else:
            raise ValueError(f'unhandled descriptor type {kind}')
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory', type=Path,
                    default=Path('/Users/___/Downloads/zut'))
    ap.add_argument('--idb', type=Path,
                    default=Path(__file__).with_name('zut_idb_identity.json'))
    ap.add_argument('--output', type=Path,
                    default=Path(__file__).with_name('zut_trace_decoded.json'))
    args = ap.parse_args()
    trace = args.directory / 'annotated-strace-rax-user.txt'
    original = trace.read_bytes()
    lines = original.decode().splitlines()
    start = re.compile(r'\s+(send|received) bits=(0x[0-9a-f]+) size=(\d+) '
                       r'remote=(0x[0-9a-f]+) local=(0x[0-9a-f]+) '
                       r'voucher=(0x[0-9a-f]+) id=(\d+)')
    hexdump = re.compile(r'\]\s+([0-9a-f]{4,})\s+((?:[0-9a-f]{2}\s+)+)\|')
    events = []
    for i, line in enumerate(lines):
        m = start.search(line)
        if not m:
            continue
        raw = bytearray()
        j = i + 1
        while j < len(lines):
            h = hexdump.search(lines[j])
            if not h:
                break
            assert int(h[1], 16) == len(raw), (j+1, len(raw), h[1])
            raw.extend(bytes.fromhex(h[2]))
            j += 1
        bits, size, remote, local, voucher, mid = struct.unpack_from('<6I', raw)
        annotated = [int(m[k], 0 if k in (2, 4, 5, 6) else 10)
                     for k in range(2, 8)]
        assert [bits, size, remote, local, voucher, mid] == annotated, i+1
        assert len(raw) >= size, (i+1, len(raw), size)
        body = bytes(raw[:size])
        e = {'line': i+1, 'hex_end_line': j, 'direction': m[1],
             'bits': hex(bits), 'size_bytes': size, 'remote': hex(remote),
             'local': hex(local), 'voucher': hex(voucher), 'id': mid,
             'message_hex': body.hex(), 'trailer_hex': raw[size:].hex(),
             'descriptors': decode_descriptors(body, bits),
             'annotation': line,
             'strings': [s.decode('ascii') for s in
                         re.findall(rb'[\x20-\x7e]{5,}', body)]}
        if m[1] == 'send' and mid in (3409, 3410):
            e['special_port_selector'] = struct.unpack_from('<I', body, size-4)[0]
        if m[1] == 'send' and mid == 412:
            e['host_node'], e['special_port_selector'] = struct.unpack_from('<iI', body, 32)
        if m[1] == 'send' and mid == 2862:
            e.update(connect_type=struct.unpack_from('<I', body, 64)[0],
                     explicit_ndr_hex=body[68:76].hex(),
                     properties_count=struct.unpack_from('<I', body, 76)[0])
        if m[1] == 'received' and mid == 2962 and size == 52:
            e['open_result'] = hex(struct.unpack_from('<I', body, 48)[0])
        if m[1] == 'received' and mid == 2977:
            e['return_code'] = struct.unpack_from('<I', body, 32)[0]
            e['io_server_version'] = hex(struct.unpack_from('<Q', body, 36)[0])
        events.append(e)
    sends = [e for e in events if e['direction'] == 'send']
    counts = collections.Counter(e['id'] for e in sends)
    pairs = []
    for i, e in enumerate(events):
        if e['direction'] != 'send':
            continue
        assert i+1 < len(events) and events[i+1]['direction'] == 'received'
        reply = events[i+1]
        expected = 536870912 if e['id'] == 1073742030 else e['id'] + 100
        assert reply['id'] == expected, (e['line'], reply['line'])
        pairs.append({'send_line': e['line'], 'reply_line': reply['line'],
                      'send_id': e['id'], 'reply_id': reply['id']})
    image = image_info(args.directory / 'fairplayd.arm64e')
    idb = json.loads(args.idb.read_text())
    comparisons = []
    assert image['uuid'] == idb['uuid']
    assert len(image['text_sections']) == len(idb['text_sections'])
    for section, peer in zip(image['text_sections'], idb['text_sections']):
        comparisons.append({'section': section['section'], 'equal': section == peer})
        assert section == peer, section['section']
    legacy_audit = []
    old = json.loads((args.directory / 'evidence.json').read_text())
    binary = (args.directory / 'fairplayd.arm64e').read_bytes()
    text_section = image['text_sections'][0]
    conditions = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
                  'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv']
    for block in old['blocks']:
        for insn in block['insns']:
            word = int(insn['raw'], 0)
            if word & 0xff000010 != 0x54000000:
                continue
            pc = int(insn['pc'], 0)
            off = pc-int(text_section['address'], 0)+text_section['file_offset']
            assert struct.unpack_from('<I', binary, off)[0] == word
            legacy_audit.append({'pc': insn['pc'], 'raw': insn['raw'],
                                 'legacy_disassembly': insn['disasm'],
                                 'decoded_condition': conditions[word & 15],
                                 'bytes_match_file': True})
    result = {'trace_path': str(trace), 'trace_sha256': digest(original),
              'trace_lines': len(lines), 'image': image, 'idb_identity': idb,
              'text_section_comparison': comparisons,
              'send_count': len(sends), 'send_ids': dict(sorted(counts.items())),
              'pairs': pairs, 'events': events,
              'legacy_conditional_branch_audit': legacy_audit,
              'bridge_log': [{'line': i+1, 'text': s} for i, s in enumerate(lines)
                             if s.startswith('rax-user: bridge:')]}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'sends': len(sends),
                      'replies': len(events)-len(sends),
                      'matching_text_sections': len(comparisons),
                      'send_ids': dict(sorted(counts.items()))}, indent=2))


if __name__ == '__main__':
    main()
