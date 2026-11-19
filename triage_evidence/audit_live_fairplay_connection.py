#!/usr/bin/env python3
"""Verify current connection export, reply copyout, method import and close sites."""

import argparse
import json
import struct
import subprocess
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_iokit_mach_transport import (
    CACHE_UUID, IOKIT, LIBKERNEL, Cache, Dylib, clean_pointer, dyld_uuid,
)
from audit_live_kext_selector26 import CLIENT, Collection, IDENTITIES, mig_map

KERNEL = {
    'export_and_reply_descriptor': (
        (0xfffffe000be81b40, 'ldr', 'd0, [x8, #0xe30]'),
        (0xfffffe000be81b48, 'stur', 'd0, [x3, #0x2c]'),
        (0xfffffe000be81c60, 'ldr', 'x0, [sp, #8]'),
        (0xfffffe000be81c64, 'bl', '#0xfffffe000be7e814'),
        (0xfffffe000be81c70, 'movk', 'x16, #0x1ab, lsl #48'),
        (0xfffffe000be81c78, 'pacda', 'x17, x16'),
        (0xfffffe000be81c84, 'stur', 'x17, [x24, #0x24]'),
        (0xfffffe000be7e818, 'cbz', 'x0, #0xfffffe000be7e86c'),
        (0xfffffe000be7e830, 'mov', 'w1, #0x27'),
        (0xfffffe000be7e834, 'bl', '#0xfffffe000c5b07cc'),
        (0xfffffe000be7e858, 'blraa', 'x8, x16'),
        (0xfffffe000be7e85c, 'mov', 'x0, x20'),
    ),
    'port_registry_and_send_reference': (
        (0xfffffe000c5b0808, 'and', 'w24, w8, #0xfff'),
        (0xfffffe000c5b083c, 'ldr', 'x21, [x25, w24, uxtw #3]'),
        (0xfffffe000c5b0844, 'bl', '#0xfffffe000c5b0980'),
        (0xfffffe000c5b0850, 'bl', '#0xfffffe000be7e8cc'),
        (0xfffffe000c5b0854, 'str', 'x0, [x21, #0x18]'),
        (0xfffffe000c5b0868, 'str', 'x21, [x25, w24, uxtw #3]'),
        (0xfffffe000c5b087c, 'bl', '#0xfffffe000bd3ce94'),
        (0xfffffe000c5b08bc, 'ldr', 'x21, [x21, #0x10]'),
        (0xfffffe000c5b08d4, 'autda', 'x16, x17'),
        (0xfffffe000c5b08d8, 'cmp', 'x16, x0'),
        (0xfffffe000c5b08e8, 'cmp', 'w9, w20'),
        (0xfffffe000c5b08f0, 'b', '#0xfffffe000c5b0870'),
        (0xfffffe000c5b09f8, 'adrp', 'x16, #0xfffffe0007f5c000'),
        (0xfffffe000c5b09fc, 'add', 'x16, x16, #0xaa0'),
        (0xfffffe000c5b0a00, 'add', 'x16, x16, #0x10'),
        (0xfffffe000c5b0a10, 'str', 'x16, [x20]'),
        (0xfffffe000be7e8d4, 'b.ne', '#0xfffffe000be7e928'),
        (0xfffffe000be7e928, 'mov', 'x2, #0'),
        (0xfffffe000be7e930, 'orr', 'x1, x8, #0x100'),
        (0xfffffe000be7e938, 'b', '#0xfffffe000bd3c950'),
        (0xfffffe000bd3c9ac, 'bl', '#0xfffffe000bd15064'),
        (0xfffffe000bd3c9cc, 'eor', 'x8, x8, x9'),
        (0xfffffe000bd3c9d4, 'pacda', 'x17, x16'),
        (0xfffffe000bd3c9d8, 'str', 'x17, [x19, #0x50]'),
        (0xfffffe000bd3cee4, 'cmp', 'w8, w21'),
        (0xfffffe000bd3cef8, 'eor', 'w8, w2, w8'),
        (0xfffffe000bd3cf00, 'autda', 'x16, x17'),
        (0xfffffe000bd3cf08, 'ccmp', 'x20, x16, #4, ne'),
        (0xfffffe000bd3cf14, 'bl', '#0xfffffe000bd17b88'),
        (0xfffffe000bd17bb0, 'stp', 'w8, w9, [x0, #0x84]'),
        (0xfffffe000bd17bc4, 'ldadd', 'w9, w9, [x8]'),
    ),
    'descriptor_copyout_and_packing': (
        (0xfffffe000bd0d720, 'autda', 'x16, x17'),
        (0xfffffe000bd0d740, 'str', 'x8, [x19]'),
        (0xfffffe000bd0d778, 'ubfx', 'w2, w21, #0x10, #8'),
        (0xfffffe000bd0d790, 'bl', '#0xfffffe000bd11bd8'),
        (0xfffffe000bd0d7a4, 'ldur', 'w16, [x29, #-0x58]'),
        (0xfffffe000bd11da0, 'bl', '#0xfffffe000bd1af80'),
        (0xfffffe000bd11db8, 'bl', '#0xfffffe000bd04088'),
        (0xfffffe000bd11dbc, 'cmp', 'w20, #0x10'),
        (0xfffffe000bd11dc0, 'b.ne', '#0xfffffe000bd11e10'),
        (0xfffffe000bd11e38, 'bl', '#0xfffffe000bd1da84'),
        (0xfffffe000bd11e48, 'str', 'w24, [x22]'),
        (0xfffffe000bd0e4a8, 'str', 'w0, [x6, #-0xc]!'),
        (0xfffffe000bd0e4b0, 'stp', 'w24, w7, [x15, #-8]'),
        (0xfffffe000bd0e524, 'cbz', 'w6, #0xfffffe000bd0e49c'),
    ),
    'import_and_close': (
        (0xfffffe000be7e1c4, 'cmp', 'w8, #0x28'),
        (0xfffffe000be7e1d4, 'movk', 'x17, #0x72, lsl #48'),
        (0xfffffe000be7e2ec, 'tst', 'w8, #7'),
        (0xfffffe000be7e2f8, 'cmp', 'w8, #0x27'),
        (0xfffffe000be7e304, 'ldr', 'x16, [x17, #0x50]!'),
        (0xfffffe000be7e308, 'movk', 'x17, #0x7d, lsl #48'),
        (0xfffffe000be7e30c, 'autda', 'x16, x17'),
        (0xfffffe000be7e334, 'blraa', 'x8, x16'),
        (0xfffffe000be81644, 'bl', '#0xfffffe000be7e2c0'),
        (0xfffffe000be816b4, 'bl', '#0xfffffe000c5bff74'),
        (0xfffffe000be816dc, 'blraa', 'x9, x16'),
        (0xfffffe000be85554, 'bl', '#0xfffffe000be7e2c0'),
        (0xfffffe000be8555c, 'bl', '#0xfffffe000c5be78c'),
        (0xfffffe000be85560, 'str', 'w0, [x19, #8]'),
        (0xfffffe000be85584, 'blraa', 'x8, x16'),
        (0xfffffe000c5be880, 'mov', 'x17, #0x920'),
        (0xfffffe000c5be890, 'movk', 'x16, #0x18b8, lsl #48'),
        (0xfffffe000c5be894, 'blraa', 'x8, x16'),
        (0xfffffe000c5be8a0, 'bl', '#0xfffffe000c5b64cc'),
        (0xfffffe000c5be8a4, 'mov', 'w20, #0'),
        (0xfffffe000a54560c, 'mov', 'x17, #0x630'),
        (0xfffffe000a545618, 'mov', 'w1, #0'),
        (0xfffffe000a54561c, 'movk', 'x16, #0x5ec5, lsl #48'),
        (0xfffffe000a545620, 'blraa', 'x8, x16'),
        (0xfffffe000a545624, 'mov', 'w0, #0'),
    ),
}
FRAMEWORK = (
    (0x184ebdd40, 'ldr', 'w9, [sp, #0x1c]'),
    (0x184ebdd48, 'str', 'w9, [x19]'),
    (0x184ebe05c, 'stp', 'w9, w0, [sp, #0x18]'),
    (0x184ebe090, 'bl', '#0x188088af0'),
    (0x184ec19b0, 'bl', '#0x184ec19dc'),
    (0x184ec19b4, 'mov', 'x20, x0'),
    (0x184ec19c0, 'ldr', 'w0, [x8]'),
    (0x184ec19c4, 'mov', 'x1, x19'),
    (0x184ec19c8, 'bl', '#0x18806c480'),
    (0x184ec19cc, 'mov', 'x0, x20'),
    (0x184ec19fc, 'bl', '#0x188076d50'),
    (0x184ec1a0c, 'stp', 'w19, w0, [sp, #8]'),
    (0x184ec1a30, 'mov', 'x2, #0x1513'),
    (0x184ec1a34, 'movk', 'x2, #0x18, lsl #32'),
    (0x184ec1a38, 'mov', 'x4, #0xb0000000000'),
    (0x184ec1a44, 'bl', '#0x188088af0'),
    (0x184ec1a90, 'cmp', 'w8, #0xb64'),
    (0x184ec1aa8, 'cmp', 'w8, #0x24'),
    (0x18806c480, 'adrp', 'x17, #0x1e20f3000'),
    (0x18806c484, 'add', 'x17, x17, #0x7e0'),
    (0x18806c488, 'ldr', 'x16, [x17]'),
    (0x18806c48c, 'braa', 'x16, x17'),
)
SDK_CHECKS = (
    ('MACH_MSG_TYPE_PORT_SEND', 17),
    ('MACH_MSG_TYPE_COPY_SEND', 19),
    ('MACH_MSG_TYPE_MAKE_SEND_ONCE', 21),
    ('sizeof(mach_msg_header_t)', 24),
    ('sizeof(mach_msg_port_descriptor_t)', 12),
    ('offsetof(mach_msg_header_t, msgh_id)', 20),
)


def sdk_contract():
    lines = ['#include <mach/message.h>', '#include <stddef.h>']
    lines.extend(f'_Static_assert({expression} == {value}, "{expression}");'
                 for expression, value in SDK_CHECKS)
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-x', 'c', '-fsyntax-only', '-'],
                   input='\n'.join(lines), text=True, check=True, timeout=30)
    return dict(SDK_CHECKS)


def audit(path):
    assert command('sw_vers', '-buildVersion').strip() == b'26C5035r'
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    assert image.named('__ZTV10IOMachPort') == 0xfffffe0007f5caa0
    routines = mig_map(image)['routines']
    for message_id, stub in ((2816, 0xfffffe000be85524), (2862, 0xfffffe000be81ac4),
                             (2865, 0xfffffe000be8152c)):
        assert routines[message_id]['stub']['target'] == hex(stub)
    slots = {}
    for offset, name, diversity in (
        (0x630, '__ZN9IOService9terminateEj', '0x5ec5'),
        (0x920, f'__ZN{CLIENT}11clientCloseEv', '0x18b8'),
    ):
        slot = image.pointer(image.named('__ZTV' + CLIENT) + 16 + offset)
        assert slot['target'] == hex(image.named(name))
        assert (slot['auth'], slot['address_diversity'], slot['key'], slot['diversity']) == (1, 1, 0, diversity)
        slots[slot['slot']] = dict(symbol=name, **slot)
    metadata = image.read(0xfffffe000700de30, 8)
    assert struct.unpack('<II', metadata) == (17 << 16, 0)

    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    io = Dylib(cache, IOKIT)
    assert io.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert io.exports['_IOServiceClose']['address'] == 0x184ec199c
    libkernel = Dylib(cache, LIBKERNEL)
    slot = clean_pointer(cache.pointer(0x1e20f37e0))
    assert slot['authenticated'] and slot['chain_membership_verified']
    assert int(slot['target'], 16) == libkernel.exports['_mach_port_deallocate']['address']
    return dict(build='26C5035r', kernel_identity=IDENTITIES[1], cache_uuid=cache.uuid,
                iokit_uuid=io.uuid, routines=routines, close_slots=slots,
                open_descriptor_metadata=metadata.hex(), deallocate_binding=slot,
                kernel={name: assert_instructions(image.read, checks) for name, checks in KERNEL.items()},
                framework=assert_instructions(cache.read, FRAMEWORK), sdk=sdk_contract(),
                live_connection_name_observed=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection), indent=2))
