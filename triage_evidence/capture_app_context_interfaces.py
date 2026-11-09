#!/usr/bin/env python3
"""Capture original-byte evidence for app-context and text-pager interfaces.

Read-only binaries. Run with the supplied zut virtualenv (Capstone installed).
Bounded disassembly is not a claim about execution or indirect-call reachability.
O(B + S + F + D) time/space for binary bytes, symbols, fixups, disassembly.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from resolve_kernel_collection_interfaces import (
    CACHE, commands, macho, string, chained_rebases)
from verify_interface_contracts import Image

ROOT = Path(__file__).resolve().parent
KEXT = ROOT.parent/'com.apple.driver.FairPlayIOKit'
CS = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def main():
    data = CACHE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == 'd5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
    root = macho(data, 0, 'root')
    entries = []
    for at, cmd, size in commands(data, 0):
        if cmd == 0x80000035:
            va, off, ident, reserved = struct.unpack_from('<QQII', data, at+8)
            entries.append(macho(data, off, string(data, at+ident)))
    all_symbols = []
    by_value = {}
    patterns = ('TextCrypter', 'text_crypter', 'DCkic', 'xhU6d1',
                'ycJai39mD8', 'FPAppDecryptOrigin', 'rp6S0jzg')
    matches = []
    for entry in entries:
        if 'symtab' not in entry:
            continue
        so, ns, st, ss = entry['symtab']
        for j in range(ns):
            sx, ty, se, desc, value = struct.unpack_from('<IBBHQ', data, so+j*16)
            if not sx or sx >= ss or not value:
                continue
            name = string(data, st+sx)
            rec = {'entry': entry['name'], 'name': name, 'address': hex(value),
                   'type': ty, 'section': se}
            all_symbols.append(rec)
            by_value.setdefault(value, []).append(rec)
            if any(p in name for p in patterns):
                matches.append(rec)
    symbol_path = ROOT/'app_context_collection_symbols.json'
    symbol_path.write_text(json.dumps({'input': str(CACHE), 'sha256': digest,
        'patterns': patterns, 'entry_count': len(entries), 'symbols': matches}, indent=2)+'\n')

    def offset(va, n):
        seg = next(s for s in root['segments'] if s['address'] <= va and
                   va+n <= s['address']+s['file_size'])
        return seg['file_offset']+va-seg['address']

    def capture(a, z, label):
        off = offset(a, z-a)
        raw = data[off:off+z-a]
        ins = [{'ea': hex(i.address), 'mnemonic': i.mnemonic,
                'operands': i.op_str} for i in CS.disasm(raw, a)]
        assert sum(i.size for i in CS.disasm(raw, a)) == len(raw)
        return {'start': hex(a), 'end': hex(z), 'label': label,
                'file_offset': off, 'sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': raw.hex(), 'instructions': ins}

    spans = [
        (0xfffffe000b12c718, 0xfffffe000b12c8e4, 'IOTextCrypter start, hook and pager callback construction'),
        (0xfffffe000b12c970, 0xfffffe000b12cb70, 'generic session, page and close adapters'),
        (0xfffffe000b12d120, 0xfffffe000b12d710, 'AppleFairplayTextCrypter start, session create/cache/end and page adapter'),
        (0xfffffe000b12d9d8, 0xfffffe000b12dc44, 'AppleFairplayTextCrypterSession open, close and free'),
        (0xfffffe000b12df2c, 0xfffffe000b12e08c, 'IOTextEncryptionFamily authenticated import stubs'),
        (0xfffffe000bd14690, 0xfffffe000bd146a0, 'kernel text-crypter hook setter'),
        (0xfffffe0008d1b50c, 0xfffffe0008d1b800, 'AppleAVD crypt reference and provider adapters'),
        (0xfffffe000a60ad28, 0xfffffe000a60b820, 'conditional host-success scalar state and RPC mode preparation'),
        (0xfffffe000a504dbc, 0xfffffe000a504fa0, 'FairPlay provider app-context and text/AVD adapters'),
    ]
    captures = [capture(a,z,label) for a,z,label in spans]
    # Bound otherwise unnamed kernel consumers using LC_FUNCTION_STARTS, not
    # the nearest exported symbol (kernel local names are mostly stripped).
    kernel = next(e for e in entries if e['name'] == 'com.apple.kernel')
    text_base = next(s['address'] for s in kernel['segments'] if s['name']=='__TEXT')
    starts = []
    for at, cmd, size in commands(data, kernel['header_offset']):
        if cmd != 0x26:
            continue
        fo, size = struct.unpack_from('<II',data,at+8)
        value = shift = 0
        address = text_base
        for byte in data[fo:fo+size]:
            value |= (byte & 127) << shift
            if byte & 128:
                shift += 7
                continue
            if not value:
                break
            address += value
            starts.append(address)
            value = shift = 0
    for site in [0xfffffe000c2b66a4,0xfffffe000c35a6a8,0xfffffe000becad88]:
        ix = bisect.bisect_right(starts,site)
        a,z = starts[ix-1:ix+1]
        rec = capture(a,z,'kernel hook reference; LC_FUNCTION_STARTS bounds')
        rec['boundary_evidence'] = 'com.apple.kernel LC_FUNCTION_STARTS'
        rec['exact_start_symbols'] = by_value.get(a,[])
        captures.append(rec)
    # Verify that previously captured live IDA bytes equal the original image.
    image = Image(KEXT)
    live_checks = []
    for name in ['app_context_wrappers_native.json', 'app_context_providers_native.json']:
        for rec in json.loads((ROOT/name).read_text()):
            raw = bytes.fromhex(rec['bytes'])
            assert image.read(int(rec['start'],16),len(raw)) == raw
            live_checks.append({'source':name,'start':rec['start'],
                                'bytes':len(raw),'original_matches':True})
    base, rebases, fixup_meta = chained_rebases(data)
    pointer_records = []
    def pointer(va, label):
        off = offset(va,8)
        assert off in rebases
        target = rebases[off]
        rec = {'slot':hex(va),'label':label,'target':hex(target),
               'exact_symbols':by_value.get(target,[]), **fixup_meta[off]}
        pointer_records.append(rec)
        return target

    # The vptr points 16 bytes beyond the Mach-O vtable symbol.
    for off in range(0x880,0x8e8,8):
        va = 0xfffffe000846b8c0+16+off
        target = pointer(va, f'FairPlayIOKit vptr+{hex(off)}')
        assert struct.unpack('<Q',image.read(va,8))[0] == target
    for off in [0x880,0x888,0x890,0x898]:
        pointer(0xfffffe0008938010+16+off,
                f'AppleFairplayTextCrypter vptr+{hex(off)}')
    for va in range(0xfffffe0008938d38,0xfffffe0008938de8,8):
        pointer(va,'IOTextEncryptionFamily authenticated import')
    for name, offsets in [
        ('__ZTV8OSString',[0x168,0x178]),
        ('__ZTV7OSArray',[0x1e8,0x208,0x228]),
        ('__ZTV20OSCollectionIterator',[0x148]),
        ('__ZTV8OSObject',[0x18,0x20,0x28]),
    ]:
        symbols = [r for r in all_symbols if r['name']==name]
        addresses = {int(r['address'],16) for r in symbols}
        assert len(addresses)==1, (name,addresses)
        symbol = addresses.pop()
        for off in offsets:
            pointer(symbol+16+off,f'{name} vptr+{hex(off)}')
    strings = []
    for va in [0xfffffe0007bae378,0xfffffe0007bae397,
               0xfffffe0007bae470,0xfffffe0007bae4b3]:
        off = offset(va,1)
        strings.append({'address':hex(va),'text':string(data,off)})
    constants = []
    for va in [0xfffffe000700dc38,0xfffffe000700dd68]:
        raw = data[offset(va,8):offset(va,8)+8]
        constants.append({'address':hex(va),'bytes':raw.hex(),
                          'u64_le':struct.unpack('<Q',raw)[0]})
    out = {'kernel_collection': str(CACHE),'sha256':digest,'entry_count':len(entries),
           'source_kind':'original file bytes, not target execution',
           'ranges':captures,'live_ida_original_checks':live_checks,
           'pointers':pointer_records,'strings':strings,'origin_constants':constants,
           'kernel_function_starts_count':len(starts)}
    (ROOT/'app_context_collection_native.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'ranges':len(captures),'symbols':len(matches),
        'pointer_bindings':len(pointer_records),'live_byte_checks':len(live_checks)}))


if __name__ == '__main__':
    main()
