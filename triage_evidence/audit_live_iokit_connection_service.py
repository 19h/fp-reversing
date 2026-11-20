#!/usr/bin/env python3
"""Audit IOConnectGetService and the installed FairPlay getter binding."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from audit_archived_iokit_open_retirement import GUEST_MESSAGE, THIN_SHA, TRACE_SHA
from audit_daemon_iokit_retirement import fixups
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, Cache, Dylib, CS, dyld_uuid, record_windows
from audit_live_kext_selector26 import CLIENT, Collection, IDENTITIES, mig_map
from audit_live_kext_selector26_transfer import words

REQUEST = 2817
REPLY = REQUEST + 100
STUB = 0xfffffe000be853ec
GET_SERVICE = 0xfffffe000c5be90c


def framework():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    io = Dylib(cache, IOKIT)
    assert io.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    start = 0x184ec182c
    assert io.exports['_IOConnectGetService']['address'] == start
    assert struct.unpack('<II', cache.read(0x184f98930, 8)) == (0x1513, 24)
    assert struct.unpack('<II', cache.read(0x184f989c0, 8)) == (0, REQUEST)
    anchors = (
        (start, 'b', '#0x184ec1830'),
        (0x184ec1844, 'mov', 'x20, x1'),
        (0x184ec1854, 'bl', '#0x188076d50'),
        (0x184ec185c, 'ldr', 'd0, [x8, #0x930]'),
        (0x184ec1864, 'stp', 'w19, w0, [sp, #8]'),
        (0x184ec186c, 'ldr', 'd0, [x8, #0x9c0]'),
        (0x184ec1894, 'mov', 'w6, #0x30'),
        (0x184ec189c, 'bl', '#0x188088af0'),
        (0x184ec18e8, 'cmp', 'w8, #0xb65'),
        (0x184ec18f4, 'tbnz', 'w9, #0x1f, #0x184ec1938'),
        (0x184ec18f8, 'cmp', 'w8, #0x24'),
        (0x184ec1900, 'ldr', 'w8, [sp, #0x20]'),
        (0x184ec1914, 'csel', 'w19, w8, w19, eq'),
        (0x184ec1940, 'cmp', 'w9, #1'),
        (0x184ec1948, 'cmp', 'w8, #0x28'),
        (0x184ec1954, 'cbnz', 'w8, #0x184ec197c'),
        (0x184ec1958, 'ldrh', 'w8, [sp, #0x26]'),
        (0x184ec1960, 'cmp', 'w8, #0x110, lsl #12'),
        (0x184ec196c, 'ldr', 'w8, [sp, #0x1c]'),
        (0x184ec1970, 'str', 'w8, [x20]'),
    )
    for pc, mnemonic, operands in anchors:
        insn, = CS.disasm(cache.read(pc, 4), pc)
        assert (insn.mnemonic, insn.op_str) == (mnemonic, operands), hex(pc)
    return {'cache_uuid': cache.uuid, 'iokit_uuid': io.uuid, 'instruction_assertions': len(anchors),
            'windows': record_windows(cache.read, ((start, 0x16c), (0x184f98930, 8), (0x184f989c0, 8)))}


def kernel(image):
    subsystem = int(mig_map(image)['subsystem'], 16)
    routine = subsystem + 40 + 32 * (REQUEST - 2800)
    stub = image.pointer(routine)
    assert (stub['target'], stub['auth'], stub['diversity']) == (hex(STUB), 1, '0x3a83')
    routine_fields = struct.unpack('<4I', image.read(routine + 8, 16))
    assert routine_fields == (2, 0, 1, 52)
    inherited = image.named('__ZN12IOUserClient10getServiceEv')
    slots = {}
    for class_name in (CLIENT, '12IOUserClient'):
        slot = image.named(f'__ZTV{class_name}') + 16 + 0x930
        pointer = image.pointer(slot)
        assert (pointer['target'], pointer['auth'], pointer['address_diversity'],
                pointer['key'], pointer['diversity']) == (hex(inherited), 1, 1, 0, '0x3e51')
        slots[class_name] = pointer
    assert inherited == 0xfffffe000c5b202c
    anchors = (
        (0xfffffe000bd3c654, 'mov', 'w9, #0x2c'),
        (0xfffffe000bd3c66c, 'stp', 'x9, xzr, [x16, #8]'),
        (0xfffffe000bd3c678, 'add', 'w8, w8, #0x64'),
        (0xfffffe000bd3c724, 'blraa', 'x8, x17'),
        (0xfffffe000be853f4, 'tbnz', 'w8, #0x1f, #0xfffffe000be85484'),
        (0xfffffe000be853fc, 'cmp', 'w8, #0x20'),
        (0xfffffe000be85430, 'ldr', 'x0, [x0, #8]'),
        (0xfffffe000be8546c, 'cbz', 'w19, #0xfffffe000be8549c'),
        (0xfffffe000be85470, 'str', 'w19, [x21, #0x28]'),
        (0xfffffe000be854a8, 'mov', 'w1, #0x28'),
        (0xfffffe000be854f0, 'stur', 'x17, [x21, #0x24]'),
        (0xfffffe000be854f8, 'orr', 'w8, w8, #0x80000000'),
        (0xfffffe000be854fc, 'mov', 'w9, #0x34'),
        (0xfffffe000be85508, 'str', 'w8, [x21, #0x20]'),
        (0xfffffe000be7e2f8, 'cmp', 'w8, #0x27'),
        (0xfffffe000c5be920, 'mov', 'w20, #0x2c2'),
        (0xfffffe000c5be924, 'movk', 'w20, #0xe000, lsl #16'),
        (0xfffffe000c5be988, 'mov', 'x17, #0x930'),
        (0xfffffe000c5be998, 'movk', 'x16, #0x3e51, lsl #48'),
        (0xfffffe000c5be99c, 'blraa', 'x8, x16'),
        (0xfffffe000c5be9a4, 'cbz', 'x0, #0xfffffe000c5be9d0'),
        (0xfffffe000c5be9c4, 'blraa', 'x8, x16'),
        (0xfffffe000c5be9c8, 'mov', 'w20, #0'),
        (0xfffffe000c5be9d0, 'add', 'w20, w20, #5'),
        (0xfffffe000c5be9e0, 'str', 'x22, [x19]'),
        (0xfffffe000c5be9e4, 'mov', 'x0, x20'),
        (inherited + 4, 'mov', 'x0, #0'),
        (inherited + 8, 'ret', ''),
    )
    for pc, mnemonic, operands in anchors:
        image.instruction(pc, mnemonic, operands)
    calls = {0xfffffe000be85434: 0xfffffe000be7e2c0, 0xfffffe000be85440: GET_SERVICE,
             0xfffffe000be854ac: 0xfffffe000c5b07cc, 0xfffffe000bd0f208: 0xfffffe000bd0fbf0}
    for pc, target in calls.items():
        assert image.branch(pc, 'bl') == target
    assert image.read(0xfffffe000700de30, 8) == bytes.fromhex('0000110000000000')
    bounds = compiler_ranges(image)
    ranges = {hex(pc): (pc, bounds[pc][1] - pc) for pc in (STUB, GET_SERVICE, inherited)}
    ranges.update({'header_template': (0xfffffe000bd3c654, 0x34),
                   'stub_invocation': (0xfffffe000bd3c708, 0x20),
                   'port_type_check': (0xfffffe000be7e2e8, 0x18),
                   'queue_submission': (0xfffffe000bd0f1f8, 0x14)})
    return {'identity': IDENTITIES[1], 'stub': stub, 'mig_record_fields': routine_fields,
            'get_service_vtable_slots': slots, 'instruction_assertions': len(anchors),
            'direct_calls': {hex(pc): hex(target) for pc, target in calls.items()},
            'windows': {role: words(image, pc, length) for role, (pc, length) in ranges.items()}}


def daemon_and_trace(daemon, trace):
    assert sha256(daemon.read_bytes()).hexdigest() == THIN_SHA
    bindings = fixups(daemon)
    assert len(bindings) == 61737
    assert not any(binding['target'].endswith(('/_IOConnectGetService', '/_io_connect_get_service'))
                   for binding in bindings.values())
    iokit = sorted({binding['target'] for binding in bindings.values() if binding['target'].startswith('IOKit/')})
    assert {'IOKit/_IOServiceOpen', 'IOKit/_IOConnectCallStructMethod'} <= set(iokit)
    raw = trace.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    ids = [int(match[8]) for line in raw.decode().splitlines() if (match := GUEST_MESSAGE.fullmatch(line))]
    assert len(ids) == 44
    counts = {identifier: ids.count(identifier) for identifier in (REQUEST, REPLY, 2862, 2962)}
    assert counts == {REQUEST: 0, REPLY: 0, 2862: 1, 2962: 1}
    return {'daemon_sha256': THIN_SHA, 'parsed_fixups': len(bindings), 'unique_iokit_targets': iokit,
            'trace_sha256': TRACE_SHA, 'trace_headers': len(ids), 'counts': counts}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps({'request_id': REQUEST, 'reply_id': REPLY, 'framework': framework(),
                      'kernel': kernel(Collection(args.collection, IDENTITIES[1])),
                      'daemon_and_trace': daemon_and_trace(args.daemon, args.trace),
                      'native_query_observed': False}, indent=2))
