#!/usr/bin/env python3
"""Verify the current synchronous IOKit transport against installed image bytes."""

import argparse
import ctypes
import hashlib
import json
import struct
import subprocess
import uuid
from pathlib import Path

from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map
from bootpolicy_cache_reader import Cache, Dylib, CS

IOKIT = '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
LIBKERNEL = '/usr/lib/system/libsystem_kernel.dylib'
CACHE_UUID = '8b1e17c6-72d6-3017-91a4-916022e3612e'
REQUEST_ID, REPLY_ID = 2865, 2965


def record_windows(read, intervals):
    spans = []
    for pc, size in intervals:
        raw = read(pc, size)
        spans.append({'start': hex(pc), 'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()})
    return spans


def dyld_uuid():
    actual = (ctypes.c_ubyte * 16)()
    call = ctypes.CDLL(None)._dyld_get_shared_cache_uuid
    call.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    call.restype = ctypes.c_bool
    assert call(actual)
    return str(uuid.UUID(bytes=bytes(actual)))


def clean_pointer(row):
    return {key: value for key, value in row.items() if key != 'path'}


def framework_transport():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    io = Dylib(cache, IOKIT)
    libkernel = Dylib(cache, LIBKERNEL)
    assert io.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert libkernel.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'

    def check(pc, mnemonic, args):
        i, = CS.disasm(cache.read(pc, 4), pc)
        assert (i.mnemonic, i.op_str) == (mnemonic, args)

    def veneer(pc, name, address):
        words = list(CS.disasm(cache.read(pc, 16), pc))
        assert [i.mnemonic for i in words] == ['adrp', 'add', 'ldr', 'braa']
        assert [i.op_str for i in words[2:]] == ['x16, [x17]', 'x16, x17']
        slot = sum(int(i.op_str.split('#')[-1], 16) for i in words[:2])
        pointer = cache.pointer(slot)
        assert pointer['authenticated'] and int(pointer['target'], 16) == address
        assert name in [i['name'] for i in libkernel.symbols_at(address)]
        return clean_pointer(pointer)

    for obj, name, address in (
        (io, '_IOConnectCallStructMethod', 0x184ebedb0),
        (io, '_IOConnectCallMethod', 0x184ebdd74),
        (io, '_IOServiceOpen', 0x184ebdb74),
        (io, '_IOServiceClose', 0x184ec199c),
        (libkernel, '_mach_port_construct', 0x180549e9c),
        (libkernel, '_mach_msg2_internal', 0x18055b918),
        (libkernel, '_mach_msg2_trap', 0x180548c18),
    ):
        assert obj.exports[name]['address'] == address
    for pc, mnemonic, args in (
        (0x184ebede4, 'bl', '#0x184ebdd74'),
        (0x184ebdba4, 'bl', '#0x184ebdbc0'),
        (0x184ec19b0, 'bl', '#0x184ec19dc'),
        (0x184ebdbe8, 'stp', 'w22, w1, [sp, #0x18]'),
        (0x184ebdc30, 'stp', 'w21, w0, [sp, #8]'),
        (0x184ebdc6c, 'bl', '#0x188088af0'),
        (0x184ec1a0c, 'stp', 'w19, w0, [sp, #8]'),
        (0x184ec1a44, 'bl', '#0x188088af0'),
        (0x184ebdd98, 'cmp', 'x5, #1, lsl #12'),
        (0x184ebde28, 'cmp', 'x11, #1, lsl #12'),
        (0x184ebde5c, 'bl', '#0x184ebde8c'),
        (0x184ebdfc8, 'str', 'w19, [sp, #0xc]'),
        (0x184ebdfd0, 'add', 'w8, w22, #3'),
        (0x184ebdfd4, 'and', 'w8, w8, #0x3ffc'),
        (0x184ebdffc, 'add', 'w22, w25, #0x54'),
        (0x184ebe04c, 'bl', '#0x188076d50'),
        (0x184ebe050, 'mov', 'w8, #0x1513'),
        (0x184ebe054, 'stp', 'w8, w22, [sp, #0x10]'),
        (0x184ebe05c, 'stp', 'w9, w0, [sp, #0x18]'),
        (0x184ebe064, 'ldr', 'd0, [x9, #0xaf8]'),
        (0x184ebe068, 'str', 'd0, [sp, #0x20]'),
        (0x184ebe06c, 'ldr', 'x3, [sp, #0x18]'),
        (0x184ebe074, 'lsl', 'x5, x0, #0x20'),
        (0x184ebe090, 'bl', '#0x188088af0'),
        (0x184ebe0dc, 'cmp', 'w8, #0xb95'),
        (0x184ebe0e8, 'tbnz', 'w8, #0x1f, #0x184ebe14c'),
        (0x184ebe104, 'ldr', 'w9, [sp, #0x30]'),
        (0x184ebe108, 'ldr', 'w10, [sp, #0x18]'),
        (0x184ebe110, 'ccmp', 'w10, #0, #0, ne'),
        (0x184ebe114, 'mov', 'w10, #0x24'),
        (0x184ebe118, 'ccmp', 'w8, w10, #0, eq'),
        (0x184ebe120, 'csel', 'w19, w9, w8, eq'),
        (0x184ebdf94, 'mov', 'x0, x19'),
        (0x180548f14, 'mrs', 'x19, tpidrro_el0'),
        (0x180548f18, 'ldr', 'w0, [x19, #0x10]'),
        (0x180548f20, 'cbnz', 'w0, #0x180548f5c'),
        (0x180548f4c, 'bl', '#0x180549e9c'),
        (0x180548f58, 'str', 'x0, [x19, #0x10]'),
        (0x18055b960, 'bl', '#0x180548c18'),
        (0x180548c18, 'mov', 'x16, #-0x2f'),
        (0x180548c1c, 'svc', '#0x80'),
    ):
        check(pc, mnemonic, args)
    for pc, expectation in (
        (0x184f98af8, (0, REQUEST_ID)),
        (0x184f98ad0, (0x80001513, 80, 0, 2862)),
        (0x184f98930, (0x1513, 24)),
        (0x184f989b8, (0, 2816)),
    ):
        assert struct.unpack('<' + 'I' * len(expectation), cache.read(pc, 4 * len(expectation))) == expectation
    assert cache.read(0x184f894d8, 8) == bytes.fromhex('0000000000001300')
    return {
        'cache_uuid': cache.uuid, 'iokit_uuid': io.uuid, 'libkernel_uuid': libkernel.uuid,
        'transport_pointer': veneer(0x188088af0, '_mach_msg2_internal', 0x18055b918),
        'reply_port_pointer': veneer(0x188076d50, '_mig_get_reply_port', 0x180548f00),
        'windows': record_windows(cache.read, (
            (0x184ebedb0, 0x44), (0x184ebdd74, 0x34), (0x184ebde28, 0x54),
            (0x184ebdf70, 0x88), (0x184ebdffc, 0x9c), (0x184ebe0d0, 0x5c),
            (0x184f98af8, 8), (0x188088af0, 16), (0x188076d50, 16),
            (0x184ebdb74, 0x4c), (0x184ebdbe0, 0x90),
            (0x184ec199c, 0x40), (0x184ec19f0, 0x58), (0x184f894d8, 8),
            (0x184f98ad0, 16), (0x184f98930, 8), (0x184f989b8, 8),
            (0x180548f14, 0x48), (0x18055b918, 0x100), (0x180548c18, 12),
        )),
        'request_header_bits': '0x1513', 'user_request_bytes_at_16_B': 100,
        'request_emission_sites': {'2816': '0x184ec1a44', '2862': '0x184ebdc6c', '2865': '0x184ebe090'},
        'reply_name_getter': '0x180548f00', 'reply_port_construction_call': '0x180548f4c',
        'short_reply_size_bytes': 36, 'short_reply_status_offset_bytes': 32,
        'current_fairplayd_mapped_cache_uuid_observed': False,
    }


def kernel_transport(path):
    image = Collection(path, IDENTITIES[1])
    runtime = subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower()
    assert runtime == image.entries['com.apple.kernel']['uuid']
    mig = mig_map(image)
    assert mig['routines'][REQUEST_ID]['stub']['target'] == '0xfffffe000be8152c'
    dispatch = 0xfffffe000bd3c048
    queue = 0xfffffe000bd0fbf0
    insert = 0xfffffe000bd0ab5c
    for pc, mnemonic, target in (
        (0xfffffe000bd0f2fc, 'bl', dispatch),
        (0xfffffe000bd0f364, 'bl', dispatch),
        (0xfffffe000bd3c794, 'b.ne', 0xfffffe000bd3c7a8),
        (0xfffffe000bd0f208, 'bl', queue),
        (0xfffffe000bd0fe8c, 'bl', insert),
    ):
        assert image.branch(pc, mnemonic) == target
    for frame in (0xfffffe000bd3c45c, 0xfffffe000bd3c654):
        for offset, mnemonic, operands in (
            (0, 'mov', 'w9, #0x2c'), (4, 'str', 'w9, [x16, #4]'),
            (12, 'ubfx', 'w9, w9, #8, #5'), (16, 'str', 'w9, [x16]'),
            (20, 'ldr', 'x9, [x8, #0x10]'), (24, 'stp', 'x9, xzr, [x16, #8]'),
            (28, 'str', 'wzr, [x16, #0x18]'), (32, 'ldr', 'w8, [x8, #0x1c]'),
            (36, 'add', 'w8, w8, #0x64'), (40, 'str', 'w8, [x16, #0x1c]'),
            (48, 'str', 'x8, [x16, #0x20]'),
        ):
            image.instruction(frame + offset, mnemonic, operands)
    for pc, mnemonic, args in (
        (0xfffffe000bd3c708, 'ldr', 'x8, [x24, #8]'),
        (0xfffffe000bd3c720, 'mov', 'x17, #0x3a83'),
        (0xfffffe000bd3c724, 'blraa', 'x8, x17'),
        (0xfffffe000be816e8, 'str', 'w0, [x21, #0x28]'),
        (0xfffffe000bd3c78c, 'ldr', 'w23, [x16, #0x28]'),
        (0xfffffe000bd3c790, 'cmn', 'w23, #0x131'),
        (0xfffffe000bd0f304, 'mov', 'x19, x0'),
        (0xfffffe000bd0f3b8, 'ldr', 'x20, [x20, #8]'),
        (0xfffffe000bd0f1f8, 'add', 'x0, x20, #0x28'),
        (0xfffffe000bd0f1fc, 'mov', 'x1, x19'),
        (0xfffffe000bd0ab7c, 'stp', 'x10, x8, [x1]'),
        (0xfffffe000bd0ab80, 'str', 'x1, [x8]'),
        (0xfffffe000bd0ab84, 'str', 'x1, [x10, #8]'),
        (0xfffffe000bd0abc4, 'str', 'x1, [x8]'),
        (0xfffffe000bd0e5ec, 'ldr', 'd0, [x8, #0x18]'),
        (0xfffffe000bd0e5f0, 'ldur', 'q1, [x8, #8]'),
        (0xfffffe000bd0e5f4, 'sub', 'w26, w10, #8'),
        (0xfffffe000bd0e5f8, 'xtn', 'v1.2s, v1.2d'),
        (0xfffffe000bd0e604, 'stp', 'w12, w8, [x0, #8]!'),
        (0xfffffe000bd0e608, 'stp', 'd1, d0, [x0, #8]'),
    ):
        image.instruction(pc, mnemonic, args)

    assert REQUEST_ID + 100 == REPLY_ID
    assert 44 - 8 == 36 and 40 - 8 == 32
    return {
        'kernel_uuid': image.entries['com.apple.kernel']['uuid'],
        'collection_sha256': image.digest,
        'routine_record': mig['routines'][REQUEST_ID],
        'reply_dispatch_entry': hex(dispatch), 'queue_call': '0xfffffe000bd0f208',
        'queue_target': hex(queue), 'insertion_call': '0xfffffe000bd0fe8c',
        'insertion_target': hex(insert), 'copyout_header': '0xfffffe000bd0e5ec',
        'short_reply_size_bytes': 44, 'short_reply_status_offset_bytes': 40,
        'windows': record_windows(image.read, (
            (0xfffffe000bd0f2f4, 20), (0xfffffe000bd0f35c, 20),
            (0xfffffe000bd3c45c, 52), (0xfffffe000bd3c654, 52),
            (0xfffffe000bd3c708, 32), (0xfffffe000be816b4, 0x48),
            (0xfffffe000bd3c78c, 28), (0xfffffe000bd0f3ac, 24),
            (0xfffffe000bd0f1f8, 20), (0xfffffe000bd0fe7c, 24),
            (0xfffffe000bd0ab5c, 48), (0xfffffe000bd0abb8, 20),
            (0xfffffe000bd0e5ec, 40),
        )),
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current_collection', type=Path)
    args = parser.parse_args()
    print(json.dumps({
        'user': framework_transport(), 'kernel': kernel_transport(args.current_collection),
        'method_request_id': REQUEST_ID, 'method_reply_id': REPLY_ID,
        'native_selector_exchange_observed': False,
    }, indent=2, sort_keys=True))
