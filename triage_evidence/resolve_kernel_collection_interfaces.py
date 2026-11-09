#!/usr/bin/env python3
"""Resolve extracted-kext external values against a matching kernel collection.

Read-only inputs; output is an analysis snapshot. Exact symbols and segment
membership are separate evidence. No inferred function start is substituted
for an exact symbol match. O(B + N + F log F + P*G) time and
O(B + N + F + P) space: B input bytes, N processed nlist/string data,
F fixups, P candidate pointers, and G fileset segments.
"""
import collections
import bisect
import hashlib
import json
from pathlib import Path
import struct
import uuid

ROOT = Path(__file__).resolve().parent
CACHE = Path('/Users/___/Downloads/fpx/img4_dump/kernelcache.macho')
KEXT = ROOT.parent / 'com.apple.driver.FairPlayIOKit'
SPECIAL = {'_host_get_special_port', '_host_priv_self', '_ipc_port_release_send',
           '_mach_msg_rpc_from_kernel_proper', '_mig_get_reply_port',
           '_IOMallocAligned', '_IOMallocAligned_external', '_IOMallocTypeImpl'}


def commands(data, offset):
    assert data[offset:offset+4].hex() == 'cffaedfe'
    q = offset + 32
    for _ in range(struct.unpack_from('<I', data, offset+16)[0]):
        cmd, size = struct.unpack_from('<II', data, q)
        assert size >= 8 and q+size <= len(data)
        yield q, cmd, size
        q += size


def string(data, off):
    return data[off:data.index(0, off)].decode(errors='replace')


def macho(data, offset, name):
    r = {'name': name, 'header_offset': offset, 'segments': [], 'sections': []}
    for o, cmd, size in commands(data, offset):
        if cmd == 0x1b:
            r['uuid'] = str(uuid.UUID(bytes=data[o+8:o+24]))
        if cmd == 2:
            r['symtab'] = struct.unpack_from('<4I', data, o+8)
        if cmd != 0x19:
            continue
        seg = data[o+8:o+24].split(b'\0')[0].decode()
        va, vm_size, fileoff, file_size = struct.unpack_from('<4Q', data, o+24)
        r['segments'].append({'name': seg, 'address': va, 'vm_size': vm_size,
                              'file_offset': fileoff, 'file_size': file_size})
        for j in range(struct.unpack_from('<I', data, o+64)[0]):
            q = o+72+j*80
            sec = data[q:q+16].split(b'\0')[0].decode()
            a, n, f = struct.unpack_from('<QQI', data, q+32)
            flags = struct.unpack_from('<I', data, q+64)[0]
            r['sections'].append({'segment': seg, 'section': sec,
                                  'address': a, 'size': n, 'file_offset': f,
                                  'flags': flags})
    return r


def chained_rebases(data):
    root = macho(data, 0, 'collection')
    base = next(s['address'] for s in root['segments'] if s['file_offset'] == 0)
    decoded = {}
    metadata = {}
    for o, cmd, size in commands(data, 0):
        if cmd != 0x80000034:
            continue
        fixoff, fixsize = struct.unpack_from('<II', data, o+8)
        version, starts, _, _, imports, _, _ = struct.unpack_from('<7I', data, fixoff)
        assert version == 0 and imports == 0
        starts += fixoff
        count = struct.unpack_from('<I', data, starts)[0]
        assert count == len(root['segments'])
        for i in range(count):
            delta = struct.unpack_from('<I', data, starts+4+4*i)[0]
            if not delta:
                continue
            info = starts+delta
            size, page_size, fmt, vmoff, _, pages = struct.unpack_from('<IHHQIH', data, info)
            assert fmt == 8, 'this corpus uses kernel-cache pointer format 8'
            seg = root['segments'][i]
            assert seg['address'] == base+vmoff
            for page in range(pages):
                start = struct.unpack_from('<H', data, info+22+2*page)[0]
                if start == 0xffff:
                    continue
                chain_starts = []
                if start & 0x8000:
                    index = start & 0x7fff
                    while True:
                        value = struct.unpack_from('<H', data, info+22+2*index)[0]
                        chain_starts.append(value & 0x7fff)
                        index += 1
                        if value & 0x8000:
                            break
                else:
                    chain_starts = [start]
                for start in chain_starts:
                    at = seg['file_offset']+page*page_size+start
                    page_end = seg['file_offset']+(page+1)*page_size
                    while True:
                        # Format 8 permits a pointer starting in the final
                        # four bytes of a page; its full width fits the segment.
                        assert at < page_end
                        assert at+8 <= seg['file_offset']+seg['file_size']
                        word = struct.unpack_from('<Q', data, at)[0]
                        assert (word >> 30) & 3 == 0, 'other cache levels unproved'
                        target = base+(word & 0x3fffffff)
                        if at in decoded:
                            assert decoded[at] == target
                        decoded[at] = target
                        metadata[at] = {'raw': hex(word), 'target': hex(target),
                                        'format': fmt, 'auth': word >> 63,
                                        'diversity': hex((word >> 32) & 0xffff),
                                        'address_diversity': (word >> 48) & 1,
                                        'key': (word >> 49) & 3}
                        step = ((word >> 51) & 0xfff)*4
                        if not step:
                            break
                        at += step
    return base, decoded, metadata


def main():
    data = CACHE.read_bytes()
    entries = []
    for o, cmd, size in commands(data, 0):
        if cmd == 0x80000035:
            va, fileoff, ident, reserved = struct.unpack_from('<QQII', data, o+8)
            entries.append(macho(data, fileoff, string(data, o+ident)))
    extracted = KEXT.read_bytes()
    own = macho(extracted, 0, 'extracted')
    origin = next(x for x in entries if x['name'] == 'com.apple.driver.FairPlayIOKit')
    assert own['uuid'] == origin['uuid'] == '227f9df7-645d-39b8-b74a-685303d16b4b'
    cache_base, rebases, fixup_metadata = chained_rebases(data)
    rebase_offsets = sorted(rebases)
    checks = []
    for sec in own['sections']:
        # Zero-fill sections have no backing bytes. 1,12,18 are zerofill kinds.
        if sec['flags'] & 0xff in (1, 12, 18) or not sec['size']:
            continue
        matches = [x for x in origin['sections'] if
                   (x['segment'], x['section'], x['address'], x['size']) ==
                   (sec['segment'], sec['section'], sec['address'], sec['size'])]
        if not matches:
            checks.append({'segment': sec['segment'], 'section': sec['section'],
                           'match': False, 'reason': 'no identical section layout'})
            continue
        src = matches[0]
        a = extracted[sec['file_offset']:sec['file_offset']+sec['size']]
        b = data[src['file_offset']:src['file_offset']+src['size']]
        normalized = bytearray(b)
        lo = bisect.bisect_left(rebase_offsets, src['file_offset'])
        hi = bisect.bisect_left(rebase_offsets, src['file_offset']+src['size'])
        for offset in rebase_offsets[lo:hi]:
            struct.pack_into('<Q', normalized, offset-src['file_offset'], rebases[offset])
        checks.append({'segment': sec['segment'], 'section': sec['section'],
                       'address': hex(sec['address']), 'size': sec['size'],
                       'extracted_sha256': hashlib.sha256(a).hexdigest(),
                       'collection_sha256': hashlib.sha256(b).hexdigest(),
                       'match': a == b,
                       'normalized_collection_sha256': hashlib.sha256(normalized).hexdigest(),
                       'normalized_match': a == normalized,
                       'decoded_fixups_in_section': hi-lo})
    pointers = json.loads((ROOT/'external_pointer_values.json').read_text())
    wanted = {int(x, 16) for x in pointers}
    symbols = collections.defaultdict(list)
    special = []
    total = 0
    for entry in entries:
        if 'symtab' not in entry:
            continue
        so, ns, st, ss = entry['symtab']
        assert so+ns*16 <= len(data) and st+ss <= len(data)
        for j in range(ns):
            sx, ty, se, desc, value = struct.unpack_from('<IBBHQ', data, so+j*16)
            total += 1
            if not sx or sx >= ss or not value:
                continue
            name = string(data, st+sx)
            record = {'entry': entry['name'], 'address': hex(value),
                      'name': name, 'n_type': ty, 'n_section': se}
            if value in wanted:
                symbols[value].append(record)
            if name in SPECIAL:
                special.append(record)
    records = []
    for value in sorted(wanted):
        owners = []
        for entry in entries:
            for seg in entry['segments']:
                a = seg['address']
                if a <= value < a+seg['vm_size']:
                    fo = seg['file_offset']+value-a
                    owners.append({'entry': entry['name'], 'uuid': entry.get('uuid'),
                                   'segment': seg['name'], 'file_offset': fo,
                                   'file_backed': value < a+seg['file_size'],
                                   'prefix_hex': data[fo:fo+16].hex() if value < a+seg['file_size'] else None})
        provenance = []
        for slot in pointers[hex(value)]:
            address = int(slot, 16)
            seg = next(s for s in origin['segments'] if
                       s['address'] <= address < s['address']+s['file_size'])
            at = seg['file_offset']+address-seg['address']
            original = struct.unpack_from('<Q', data, at)[0]
            expected = rebases.get(at, original)
            provenance.append({'slot': slot, 'collection_file_offset': at,
                               'raw': hex(original), 'normalized_value': hex(expected),
                               'matches_extracted': expected == value,
                               'chain': fixup_metadata.get(at)})
        records.append({'address': hex(value), 'pointer_slots': pointers[hex(value)],
                        'exact_symbols': symbols[value], 'owners': owners,
                        'slot_provenance': provenance})
    result = {'collection': str(CACHE),
              'collection_sha256': hashlib.sha256(data).hexdigest(),
              'kernel_uuid': next(x['uuid'] for x in entries if x['name'] == 'com.apple.kernel'),
              'kext_sha256': hashlib.sha256(extracted).hexdigest(),
              'kext_uuid': own['uuid'], 'kext_section_comparisons': checks,
              'fileset_entries': len(entries), 'nlist_records_scanned': total,
              'collection_base': hex(cache_base), 'decoded_collection_fixups': len(rebases),
              'external_values': len(records),
              'values_with_exact_symbols': sum(bool(x['exact_symbols']) for x in records),
              'values_with_segment_owners': sum(bool(x['owners']) for x in records),
              'special_symbols': special, 'resolved_external_values': records}
    (ROOT/'kernel_collection_interfaces.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: v for k, v in result.items() if k not in
                      ['resolved_external_values', 'kext_section_comparisons']}, indent=2))
    print('Normalized section mismatches:', [x for x in checks if not x.get('normalized_match')])
    print('Pointer mismatches:', [p for x in records for p in x['slot_provenance'] if not p['matches_extracted']])


if __name__ == '__main__':
    main()
