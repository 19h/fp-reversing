#!/usr/bin/env python3
"""Verify the daemon's registry-parent call and installed Mach transport."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from audit_archived_iokit_open_retirement import GUEST_MESSAGE, THIN_SHA, TRACE_SHA, decode_guest
from audit_daemon_iokit_retirement import Image, fixups
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_iokit_mach_transport import (
    CACHE_UUID, IOKIT, LIBKERNEL, Cache, Dylib, CS, clean_pointer, dyld_uuid, record_windows,
)
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map
from audit_live_kext_selector26_transfer import words


def daemon_evidence(path):
    image = Image(path)
    assert sha256(image.data).hexdigest() == THIN_SHA
    imports = fixups(path)
    parent_calls = [(slot, entry) for slot, entry in imports.items()
                    if entry['target'] == 'IOKit/_IORegistryEntryGetParentEntry']
    (slot, binding), = parent_calls
    assert (slot, binding['kind'], binding['modifier'], binding['address_diversity'], binding['key']) == (
        0x1010b1bc0, 'auth-bind', 0, 1, 'IA')
    assert image.read(0x100e2a960, 16).hex() == '311400f031022f91300240f9110a1fd7'
    text = 0x100001058
    raw = image.read(text, 14849960)
    destinations = {0x100e2a950: 'property', 0x100e2a960: 'parent'}
    matches = {role: [] for role in destinations.values()}
    for index, (word,) in enumerate(struct.iter_unpack('<I', raw)):
        if word >> 26 not in (5, 37):
            continue
        pc = text + 4 * index
        target = pc + 4 * ((word & 0x1ffffff) - (word & 0x2000000))
        if target in destinations:
            matches[destinations[target]].append(hex(pc))
    assert matches == {'parent': ['0x100004338'], 'property': ['0x1000042bc', '0x100004310', '0x100004358']}
    assert image.read(0x101033c83, 10) == b'IOService\0'
    expected = (
        (0x100004328, 'adrp', 'x1, #0x101033000'),
        (0x10000432c, 'add', 'x1, x1, #0xc83'),
        (0x100004330, 'add', 'x2, sp, #0xc'),
        (0x100004334, 'mov', 'x0, x19'),
        (0x100004340, 'cbnz', 'w0, #0x100004384'),
        (0x100004344, 'ldr', 'w0, [sp, #0xc]'),
        (0x100004358, 'bl', '#0x100e2a950'),
    )
    check(image.read, expected)
    return {'sha256': THIN_SHA, 'text_bytes': len(raw), 'text_sha256': sha256(raw).hexdigest(),
            'direct_references': matches, 'parent_import': {'slot': hex(slot), **binding},
            'windows': record_windows(image.read, ((0x100004328, 0x34), (0x100e2a960, 16)))}


def check(read, anchors):
    for pc, mnemonic, operands in anchors:
        insn, = CS.disasm(read(pc, 4), pc)
        assert (insn.mnemonic, insn.op_str) == (mnemonic, operands), hex(pc)


def framework():
    cache = Cache()
    io = Dylib(cache, IOKIT)
    libkernel = Dylib(cache, LIBKERNEL)
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    assert io.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert io.exports['_IORegistryEntryGetParentEntry']['address'] == 0x184ebedf4
    veneers = {}
    for pc, name in ((0x18806c480, '_mach_port_deallocate'), (0x188080db0, '_mig_strncpy_zerofill'),
                     (0x188080da0, '_mig_strncpy'), (0x188076d50, '_mig_get_reply_port'),
                     (0x188088af0, '_mach_msg2_internal')):
        code = list(CS.disasm(cache.read(pc, 16), pc))
        assert [item.mnemonic for item in code] == ['adrp', 'add', 'ldr', 'braa']
        slot = sum(int(item.op_str.split('#')[-1], 16) for item in code[:2])
        pointer = cache.pointer(slot)
        assert pointer['authenticated'] and name in {s['name'] for s in libkernel.symbols_at(int(pointer['target'], 16))}
        veneers[name] = clean_pointer(pointer)
    for address, expected in ((0x184f989a8, (0, 2814)), (0x184f98948, (0, 2802)), (0x184f98930, (0x1513, 24))):
        assert struct.unpack('<II', cache.read(address, 8)) == expected
    anchors = (
        (0x184ebee14, 'bl', '#0x184ebee70'),
        (0x184ebee18, 'cbnz', 'w0, #0x184ebee60'),
        (0x184ebee1c, 'ldr', 'w0, [sp, #8]'),
        (0x184ebee28, 'bl', '#0x184ebd530'),
        (0x184ebee34, 'csel', 'w8, w8, wzr, eq'),
        (0x184ebee38, 'str', 'w8, [x19]'),
        (0x184ebee48, 'bl', '#0x18806c480'),
        (0x184ebee50, 'mov', 'w9, #0x2c0'),
        (0x184ebee54, 'movk', 'w9, #0xe000, lsl #16'),
        (0x184ebee5c, 'csel', 'w0, w9, wzr, eq'),
        (0x184ebeed8, 'add', 'x0, x8, #0x28'),
        (0x184ebeedc, 'mov', 'w2, #0x80'),
        (0x184ebeef0, 'stp', 'wzr, w0, [sp, #0x20]'),
        (0x184ebeef8, 'and', 'w8, w8, #0xfffffffc'),
        (0x184ebeefc, 'add', 'w21, w8, #0x28'),
        (0x184ebef00, 'bl', '#0x188076d50'),
        (0x184ebef04, 'mov', 'w2, #0x1513'),
        (0x184ebef0c, 'stp', 'w20, w0, [sp, #8]'),
        (0x184ebef14, 'ldr', 'd0, [x8, #0x9a8]'),
        (0x184ebef44, 'bl', '#0x188088af0'),
        (0x184ebef90, 'cmp', 'w8, #0xb62'),
        (0x184ebf014, 'ldr', 'w8, [sp, #0x1c]'),
        (0x184ebf018, 'str', 'w8, [x19]'),
        (0x184ebd564, 'stp', 'w19, w0, [sp, #8]'),
        (0x184ebd56c, 'ldr', 'd0, [x8, #0x948]'),
        (0x184ebd59c, 'bl', '#0x188088af0'),
        (0x184ebd5e8, 'cmp', 'w8, #0xb56'),
        (0x184ebd66c, 'ldr', 'w8, [sp, #0x1c]'),
        (0x184ebd670, 'str', 'w8, [x20]'),
    )
    check(cache.read, anchors)
    return {'cache_uuid': cache.uuid, 'iokit_uuid': io.uuid, 'veneers': veneers,
            'instruction_assertions': len(anchors), 'plane_count_bytes': len(b'IOService\0'),
            'plane_request_size_bytes': 40 + ((len(b'IOService\0') + 3) & ~3),
            'windows': record_windows(cache.read, ((0x184ebedf4, 0x7c), (0x184ebee70, 0x1f0),
                                                   (0x184ebd530, 0x168)))}


def kernel(image):
    table = int(mig_map(image)['subsystem'], 16)
    stubs = {}
    for ident, target in ((2802, 0xfffffe000be8651c), (2814, 0xfffffe000be857f8)):
        slot = table + 40 + 32 * (ident - 2800)
        pointer = image.pointer(slot)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (hex(target), 1, '0x3a83')
        assert struct.unpack('<4I', image.read(slot + 8, 16)) == (2 if ident == 2802 else 3, 0, 1, 52)
        stubs[ident] = pointer
    calls = {0xfffffe000be858b8: 0xfffffe000be7e18c, 0xfffffe000be86564: 0xfffffe000be7e18c,
             0xfffffe000be858c8: 0xfffffe000c5bd6c0, 0xfffffe000be86570: 0xfffffe000c5b9200,
             0xfffffe000be8591c: 0xfffffe000c5b07cc, 0xfffffe000be865dc: 0xfffffe000c5b07cc,
             0xfffffe000bd0f208: 0xfffffe000bd0fbf0}
    for pc, target in calls.items():
        assert image.branch(pc, 'bl') == target
    anchors = (
        (0xfffffe000be7e1c4, 'cmp', 'w8, #0x28'),
        (0xfffffe000be85874, 'add', 'x19, x1, #0x10'),
        (0xfffffe000be858c4, 'mov', 'x1, x19'),
        (0xfffffe000be85918, 'mov', 'w1, #0x28'),
        (0xfffffe000be85960, 'stur', 'x17, [x21, #0x24]'),
        (0xfffffe000be865d8, 'mov', 'w1, #0x28'),
        (0xfffffe000be86620, 'stur', 'x17, [x21, #0x24]'),
        (0xfffffe000c5bd790, 'ldr', 'x9, [x16, #0x328]'),
        (0xfffffe000c5bd7a0, 'blraa', 'x9, x17'),
        (0xfffffe000c5bd86c, 'b', '#0xfffffe000c5bd8ac'),
        (0xfffffe000c5bd8b0, 'str', 'x21, [x19]'),
        (0xfffffe000c5b92ac, 'mov', 'x17, #0x170'),
        (0xfffffe000c5b92c0, 'blraa', 'x8, x16'),
        (0xfffffe000c5b9318, 'str', 'x0, [x19]'),
        (0xfffffe000bd3c678, 'add', 'w8, w8, #0x64'),
    )
    for pc, mnemonic, operands in anchors:
        image.instruction(pc, mnemonic, operands)
    slots = {}
    for name, offset, target, discriminator in (
        ('15IORegistryEntry', 0x328, 0xfffffe000c51632c, '0x8a26'),
        ('14IOUserIterator', 0x170, 0xfffffe000c5af550, '0xedb1'),
    ):
        pointer = image.pointer(image.named(f'__ZTV{name}') + 16 + offset)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (hex(target), 1, discriminator)
        slots[name] = pointer
    assert image.named('__ZNK15IORegistryEntry17getParentIteratorEPK15IORegistryPlane') == 0xfffffe000c51632c
    assert image.named('__ZTV14IOUserIterator') == 0xfffffe0007f5cd18
    bounds = compiler_ranges(image)
    starts = [int(s['target'], 16) for s in stubs.values()] + [0xfffffe000c5bd6c0, 0xfffffe000c5b9200]
    return {'identity': IDENTITIES[1], 'stubs': stubs, 'vtable_slots': slots,
            'instruction_assertions': len(anchors), 'direct_calls': {hex(pc): hex(dst) for pc, dst in calls.items()},
            'windows': {hex(pc): words(image, pc, bounds[pc][1] - pc) for pc in starts}}


def archived(path):
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    lines = raw.decode().splitlines()
    ids = [int(m[8]) for line in lines if (m := GUEST_MESSAGE.fullmatch(line))]
    assert len(ids) == 44 and not {2814, 2914}.intersection(ids)
    assert ids.count(2802) == ids.count(2902) == 1
    match, body = decode_guest(lines, 1699, 'send', (0x1513, 100, 0x1703, 0x507, 0, 2881))
    assert b'com_apple_driver_FairPlayIOKit\0' in body
    matched, _ = decode_guest(lines, 1709, 'received', (0x80001200, 40, 0, 0x507, 0, 2981))
    step, _ = decode_guest(lines, 1715, 'send', (0x1513, 24, 0x1803, 0x507, 0, 2802))
    service, _ = decode_guest(lines, 1720, 'received', (0x80001200, 40, 0, 0x507, 0, 2902))
    assert matched['descriptors'][0]['name'] == step['remote'] == '0x1803'
    assert service['descriptors'][0]['name'] == '0x1903'
    return {'sha256': TRACE_SHA, 'headers': len(ids), 'parent_messages': 0,
            'matching_iterator_exchange': [match, matched, step, service]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps({'daemon': daemon_evidence(args.daemon), 'framework': framework(),
                      'kernel': kernel(Collection(args.collection, IDENTITIES[1])),
                      'archive': archived(args.trace), 'native_network_exchange_observed': False}, indent=2))
