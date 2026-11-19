#!/usr/bin/env python3
"""Verify current FairPlayIOKit open status channels against the archived trace."""

import argparse
import json
import re
import struct
from pathlib import Path

from analyze_zut_trace import decode_descriptors, digest
from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_iokit_mach_transport import CACHE_UUID, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import CLIENT, PROVIDER, Collection, IDENTITIES, mig_map

TRACE_SHA = '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
ENTITLEMENTS = (
    (0xfffffe0007915201, 'com.apple.private.FairPlayIOKitUserClient.access'),
    (0xfffffe0007915232, 'com.apple.private.ProvInfoIOKitUserClient.access'),
    (0xfffffe0007915263, 'com.apple.private.FairPlayIOKitUserClient.Virtual.access'),
)
KERNEL = (
    (0xfffffe000be81ac4, 'bti', 'c'),
    (0xfffffe000be81ad4, 'cmp', 'w8, #2'),
    (0xfffffe000be81ae0, 'cmp', 'w8, #0x5c'),
    (0xfffffe000be81b58, 'bl', '#0xfffffe000be7e18c'),
    (0xfffffe000be81b78, 'autda', 'x16, x17'),
    (0xfffffe000be81bb4, 'bl', '#0xfffffe000bd41ef4'),
    (0xfffffe000be81be0, 'str', 'xzr, [sp, #8]'),
    (0xfffffe000be81be4, 'add', 'x6, x23, #8'),
    (0xfffffe000be81be8, 'add', 'x7, sp, #8'),
    (0xfffffe000be81bf4, 'bl', '#0xfffffe000c5bdc84'),
    (0xfffffe000be81c28, 'cbz', 'w22, #0xfffffe000be81c40'),
    (0xfffffe000be81c2c, 'str', 'w22, [x24, #0x28]'),
    (0xfffffe000be81c64, 'bl', '#0xfffffe000be7e814'),
    (0xfffffe000be81c84, 'stur', 'x17, [x24, #0x24]'),
    (0xfffffe000be81c98, 'orr', 'w8, w8, #0x80000000'),
    (0xfffffe000be81c9c, 'mov', 'w9, #0x40'),
    (0xfffffe000be81ca0, 'stp', 'w8, w9, [x24]'),
    (0xfffffe000be81ca8, 'str', 'w8, [x24, #0x20]'),
    (0xfffffe000c5bdca8, 'str', 'xzr, [sp, #0x38]'),
    (0xfffffe000c5bdcac, 'mov', 'w25, #0x2bc'),
    (0xfffffe000c5bdcb0, 'movk', 'w25, #0xe000, lsl #16'),
    (0xfffffe000c5bdd0c, 'add', 'w8, w25, #6'),
    (0xfffffe000c5bdd10, 'mov', 'x0, x8'),
    (0xfffffe000c5bdd38, 'cbz', 'x20, #0xfffffe000c5bdd10'),
    (0xfffffe000c5bdd40, 'mrs', 'x0, tpidr_el1'),
    (0xfffffe000c5bdd48, 'cmp', 'x20, x0'),
    (0xfffffe000c5bdd54, 'b', '#0xfffffe000c5bdd10'),
    (0xfffffe000c5bdd94, 'mov', 'x17, #0x7a0'),
    (0xfffffe000c5bdda8, 'mov', 'x1, x20'),
    (0xfffffe000c5bddac, 'mov', 'x2, x20'),
    (0xfffffe000c5bddb0, 'mov', 'x3, x22'),
    (0xfffffe000c5bddb4, 'mov', 'x4, #0'),
    (0xfffffe000c5bddbc, 'blraa', 'x8, x16'),
    (0xfffffe000c5bddc4, 'ldr', 'x0, [sp, #0x38]'),
    (0xfffffe000c5bddc8, 'cbz', 'w8, #0xfffffe000c5bdde8'),
    (0xfffffe000c5bddcc, 'mov', 'x25, x8'),
    (0xfffffe000c5bddd8, 'mov', 'w8, #0'),
    (0xfffffe000c5bdddc, 'str', 'x0, [x10]'),
    (0xfffffe000c5bdde0, 'str', 'w25, [x9]'),
    (0xfffffe000c51b624, 'mov', 'w0, #0x2c7'),
    (0xfffffe000c51b628, 'movk', 'w0, #0xe000, lsl #16'),
    (0xfffffe000c51b6fc, 'mov', 'w19, #0x2c7'),
    (0xfffffe000c51b700, 'movk', 'w19, #0xe000, lsl #16'),
    (0xfffffe000c51b8c4, 'mov', 'x17, #0x910'),
    (0xfffffe000c51b8e8, 'blraa', 'x8, x16'),
    (0xfffffe000c51b8f8, 'tbz', 'w0, #0, #0xfffffe000c51b954'),
    (0xfffffe000c51b94c, 'str', 'x26, [x20]'),
    (0xfffffe000c51b960, 'blraa', 'x8, x16'),
    (0xfffffe000c51b964, 'sub', 'w19, w19, #5'),
    (0xfffffe000c5b21c0, 'bl', '#0xfffffe000c52ee60'),
    (0xfffffe000c5b21d8, 'mov', 'x17, #0x918'),
    (0xfffffe000c5b21f8, 'blraa', 'x8, x16'),
    (0xfffffe000c5b21fc, 'and', 'w0, w23, w0'),
    (0xfffffe000a5452a4, 'bl', '#0xfffffe000a6e0324'),
    (0xfffffe000a5452b8, 'bl', '#0xfffffe000a6e0324'),
    (0xfffffe000a5452cc, 'bl', '#0xfffffe000a6e0324'),
    (0xfffffe000a545304, 'cmp', 'x25, x9'),
    (0xfffffe000a545318, 'cmp', 'x24, x9'),
    (0xfffffe000a54532c, 'cmp', 'x21, x8'),
    (0xfffffe000a5453ac, 'mov', 'w0, #0'),
    (0xfffffe000a5453d0, 'str', 'wzr, [x27, #0xf0]!'),
    (0xfffffe000a545400, 'ldr', 'x8, [x26]'),
    (0xfffffe000a545404, 'cmp', 'x21, x8'),
    (0xfffffe000a545408, 'b.ne', '#0xfffffe000a545414'),
    (0xfffffe000a54540c, 'mov', 'w8, #1'),
    (0xfffffe000a545410, 'str', 'w8, [x27]'),
    (0xfffffe000a54545c, 'blraa', 'x8, x17'),
    (0xfffffe000a545468, 'cbz', 'x20, #0xfffffe000a5453b0'),
    (0xfffffe000a54546c, 'cbz', 'w8, #0xfffffe000a5453b0'),
    (0xfffffe000a545470, 'stp', 'xzr, x20, [x19, #0xd8]'),
    (0xfffffe000a545474, 'mov', 'w0, #1'),
    (0xfffffe000a545478, 'strb', 'wzr, [x19, #0xf4]'),
    (0xfffffe000a545484, 'str', 'wzr, [x27, #0xf0]!'),
)
FRAMEWORK = (
    (0x184ebdba4, 'bl', '#0x184ebdbc0'),
    (0x184ebdbb0, 'csel', 'w0, w8, w0, eq'),
    (0x184ebdc20, 'bl', '#0x188076d50'),
    (0x184ebdc30, 'stp', 'w21, w0, [sp, #8]'),
    (0x184ebdc6c, 'bl', '#0x188088af0'),
    (0x184ebdcc4, 'tbnz', 'w9, #0x1f, #0x184ebdd08'),
    (0x184ebdcc8, 'cmp', 'w8, #0x24'),
    (0x184ebdcd0, 'ldr', 'w8, [sp, #0x20]'),
    (0x184ebdd10, 'cmp', 'w9, #1'),
    (0x184ebdd18, 'cmp', 'w8, #0x34'),
    (0x184ebdd3c, 'ldr', 'w8, [sp, #0x30]'),
    (0x184ebdd40, 'ldr', 'w9, [sp, #0x1c]'),
    (0x184ebdd44, 'str', 'w8, [x20]'),
    (0x184ebdd48, 'str', 'w9, [x19]'),
)


def historical(path):
    raw = path.read_bytes()
    assert digest(raw) == TRACE_SHA
    lines = raw.decode().splitlines()
    assert len(lines) == 1748
    hex_line = re.compile(r'\]\s+([0-9a-f]{4,})\s+((?:[0-9a-f]{2}\s+)+)\|')
    result = {}
    for line_number, expected in ((1726, (0x80001513, 80, 0x1903, 0x507, 0, 2862)),
                                  (1736, (0x80001200, 52, 0, 0x507, 0, 2962))):
        body = bytearray()
        for line in lines[line_number:]:
            match = hex_line.search(line)
            if match is None:
                break
            assert int(match[1], 16) == len(body)
            body.extend(bytes.fromhex(match[2]))
        assert struct.unpack_from('<6I', body) == expected
        bits, size, _, _, _, message_id = expected
        message = bytes(body[:size])
        desc = decode_descriptors(message, bits)
        result[message_id] = dict(line=line_number, raw_message=message.hex(), descriptors=desc)
        if message_id == 2862:
            assert len(desc) == 2 and desc[0]['name'] == '0x203' and desc[0]['disposition'] == 19
            assert desc[1]['address'] == '0x0' and desc[1]['size'] == 0
            assert struct.unpack_from('<I', message, 64) == struct.unpack_from('<I', message, 76) == (0,)
        else:
            assert len(desc) == 1 and desc[0]['name'] == '0x0' and desc[0]['disposition'] == 17
            assert struct.unpack_from('<I', message, 48) == (0xe00002c2,)
    assert 'mach_msg2_trap' in lines[1741] and lines[1741].endswith(' = 0x0')
    assert 'sent id 2862 (80 bytes, 2 descriptors' in lines[1733]
    assert 'to host 0x1503 reply 0x1603: 0x0' in lines[1733]
    assert 'received id 2962 (52 bytes, 1 descriptors) on host 0x1603' in lines[1734]
    return dict(sha256=TRACE_SHA, messages=result, transport_result=0, historical_build_known=False)


def audit(collection, trace):
    assert command('sw_vers', '-buildVersion').strip() == b'26C5035r'
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(collection, IDENTITIES[1])
    rpc = mig_map(image)['routines'][2862]
    assert rpc['stub']['target'] == hex(KERNEL[0][0])
    slots = {}
    for table, offset, spelling, diversity in (
        (PROVIDER, 0x7a0, '__ZN9IOService13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient', '0x82cd'),
        (PROVIDER, 0x7a8, '__ZN9IOService13newUserClientEP4taskPvjPP12IOUserClient', '0x808e'),
        (CLIENT, 0x910, '__ZN12IOUserClient12initWithTaskEP4taskPvjP12OSDictionary', '0xbde5'),
        (CLIENT, 0x918, f'__ZN{CLIENT}12initWithTaskEP4taskPvj', '0x5cf5'),
        ('12IOUserClient', 0x918, '__ZN12IOUserClient12initWithTaskEP4taskPvj', '0x5cf5'),
    ):
        slot = image.pointer(image.named('__ZTV' + table) + 16 + offset)
        assert int(slot['target'], 16) == image.named(spelling)
        assert (slot['diversity'], slot['auth'], slot['address_diversity'], slot['key']) == (diversity, 1, 1, 0)
        slots[slot['slot']] = dict(symbol=spelling, **slot)
    for address, symbol in ((0xfffffe0008493080, '__ZTV12IOUserClient'),
                            (0xfffffe00084930a0, '_kOSBooleanTrue')):
        slot = image.pointer(address)
        assert int(slot['target'], 16) == image.named(symbol)
        slots[slot['slot']] = dict(symbol=symbol, **slot)
    for index, (address, name) in enumerate(ENTITLEMENTS):
        assert image.read(address, len(name) + 1) == name.encode() + b'\0'
        pc = 0xfffffe000a545298 + index * 0x14
        image.instruction(pc, 'adrp', 'x1, #0xfffffe0007915000')
        image.instruction(pc + 4, 'add', f'x1, x1, #{address & 0xfff:#x}')
    assert image.named('__ZN9IOService4initEP12OSDictionary') == 0xfffffe000c52ee60

    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    iokit = Dylib(cache, '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit')
    assert iokit.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert iokit.exports['_IOServiceOpen']['address'] == 0x184ebdb74
    return dict(build='26C5035r', kernel_identity=IDENTITIES[1], cache_uuid=cache.uuid,
                framework_uuid=iokit.uuid, open_record=rpc, source_slots=slots,
                entitlement_strings={hex(address): name for address, name in ENTITLEMENTS},
                current_kernel_checks=assert_instructions(image.read, KERNEL),
                framework_checks=assert_instructions(cache.read, FRAMEWORK),
                trace=historical(trace), native_open_observed=False,
                historical_failure_gate_established=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection, args.trace), indent=2))
