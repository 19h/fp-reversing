#!/usr/bin/env python3
"""Verify startup registration and last-send retirement for the installed connection ABI."""

import argparse
import json
import struct
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_kext_selector26 import CLIENT, Collection, IDENTITIES

CONNECTION_TYPE = 0x27
POLICY_TABLE = 0xfffffe0007e6eb70
POLICY_STRIDE = 40
NOTIFY_OFFSET = 24
DESCRIPTOR = 0xfffffe000cc597e8
CHECKS = {
    'startup_registration': (
        (0xfffffe000c679294, 'ldrb', 'w8, [x0]'),
        (0xfffffe000c679298, 'add', 'x8, x8, x8, lsl #2'),
        (0xfffffe000c67929c, 'adrp', 'x9, #0xfffffe0007e6e000'),
        (0xfffffe000c6792a0, 'add', 'x9, x9, #0xb70'),
        (0xfffffe000c6792a4, 'add', 'x8, x9, x8, lsl #3'),
        (0xfffffe000c6792bc, 'ldr', 'x10, [x0, #0x10]'),
        (0xfffffe000c6792c0, 'cbz', 'x10, #0xfffffe000c6792cc'),
        (0xfffffe000c6792c4, 'orr', 'w9, w9, #0x20'),
        (0xfffffe000c6792c8, 'strh', 'w9, [x8, #8]'),
        (0xfffffe000c6792cc, 'ldr', 'x10, [x0, #8]'),
        (0xfffffe000c6792d0, 'str', 'x10, [x8]'),
        (0xfffffe000c6792f8, 'ldr', 'x10, [x0, #0x10]'),
        (0xfffffe000c6792fc, 'str', 'x10, [x8, #0x18]'),
        (0xfffffe000c679388, 'ldr', 'x12, [x11, #0x18]'),
        (0xfffffe000c67938c, 'cbnz', 'x12, #0xfffffe000c6793a4'),
    ),
    'release_and_dispatch': (
        (0xfffffe000bd18258, 'ldr', 'w9, [x0, #0x88]'),
        (0xfffffe000bd1825c, 'sub', 'w8, w9, #1'),
        (0xfffffe000bd18260, 'str', 'w8, [x0, #0x88]'),
        (0xfffffe000bd18264, 'cbz', 'w9, #0xfffffe000bd1832c'),
        (0xfffffe000bd18270, 'cmp', 'w8, #0'),
        (0xfffffe000bd18274, 'ccmp', 'w9, #0, #4, eq'),
        (0xfffffe000bd18278, 'b.ne', '#0xfffffe000bd18288'),
        (0xfffffe000bd1828c, 'bl', '#0xfffffe000bd10f08'),
        (0xfffffe000bd10f10, 'cmp', 'w8, #0xd'),
        (0xfffffe000bd10f14, 'b.lo', '#0xfffffe000bd10f6c'),
        (0xfffffe000bd10f20, 'b.eq', '#0xfffffe000bd10fac'),
        (0xfffffe000bd10f38, 'add', 'x8, x9, x8, lsl #3'),
        (0xfffffe000bd10f40, 'tbz', 'w8, #5, #0xfffffe000bd10fac'),
        (0xfffffe000bd10f4c, 'ldadd', 'w9, w9, [x8]'),
        (0xfffffe000bd10f60, 'ldr', 'w8, [x0, #0x84]'),
        (0xfffffe000bd10f64, 'orr', 'x1, x8, #0x100000000'),
        (0xfffffe000bd10f9c, 'ldr', 'w1, [x0, #0x84]'),
        (0xfffffe000bd10fa0, 'str', 'xzr, [x0, #0x50]'),
        (0xfffffe000bd182c0, 'cbz', 'x21, #0xfffffe000bd1831c'),
        (0xfffffe000bd182cc, 'lsr', 'x8, x20, #0x20'),
        (0xfffffe000bd182d0, 'cbnz', 'x8, #0xfffffe000bd182e8'),
        (0xfffffe000bd182e4, 'b', '#0xfffffe000bd10fe4'),
        (0xfffffe000bd182f8, 'b', '#0xfffffe000bd1105c'),
        (0xfffffe000bd11010, 'str', 'w1, [sp, #0x28]'),
        (0xfffffe000bd11020, 'stp', 'x0, xzr, [sp, #8]'),
        (0xfffffe000bd11028, 'ldr', 'd0, [x8, #0xd18]'),
        (0xfffffe000bd11034, 'mov', 'w1, #0x2c'),
        (0xfffffe000bd11048, 'bl', '#0xfffffe000bd3d4d0'),
        (0xfffffe000bd11078, 'b.eq', '#0xfffffe000bd110a8'),
        (0xfffffe000bd1107c, 'ldrb', 'w8, [x19]'),
        (0xfffffe000bd11088, 'add', 'x8, x8, x8, lsl #2'),
        (0xfffffe000bd1108c, 'adrp', 'x9, #0xfffffe0007e6e000'),
        (0xfffffe000bd11090, 'add', 'x9, x9, #0xb70'),
        (0xfffffe000bd11094, 'add', 'x8, x9, x8, lsl #3'),
        (0xfffffe000bd11098, 'ldr', 'x8, [x8, #0x18]'),
        (0xfffffe000bd110a0, 'mov', 'x17, #0xd507'),
        (0xfffffe000bd110a4, 'blraa', 'x8, x17'),
        (0xfffffe000bd110b0, 'ldaddl', 'w8, w8, [x0]'),
    ),
    'registry_retirement': (
        (0xfffffe000c5b69b4, 'mov', 'x2, x1'),
        (0xfffffe000c5b69b8, 'mov', 'w1, #0x27'),
        (0xfffffe000c5b69bc, 'bl', '#0xfffffe000c5b58a4'),
        (0xfffffe000c5b69c0, 'cbz', 'x0, #0xfffffe000c5b6a34'),
        (0xfffffe000c5b58c4, 'mov', 'x23, x2'),
        (0xfffffe000c5b58c8, 'mov', 'x21, x1'),
        (0xfffffe000c5b590c, 'b.eq', '#0xfffffe000c5b5950'),
        (0xfffffe000c5b5918, 'b.ne', '#0xfffffe000c5b5964'),
        (0xfffffe000c5b5920, 'ldr', 'x16, [x17, #0x50]!'),
        (0xfffffe000c5b5930, 'autda', 'x16, x17'),
        (0xfffffe000c5b5938, 'ldr', 'w8, [x22, #0x88]'),
        (0xfffffe000c5b593c, 'cbz', 'w8, #0xfffffe000c5b5970'),
        (0xfffffe000c5b5940, 'mov', 'w23, #0'),
        (0xfffffe000c5b5970, 'ldr', 'w8, [x22, #0x84]'),
        (0xfffffe000c5b5974, 'cmp', 'w8, w23'),
        (0xfffffe000c5b5978, 'cset', 'w23, eq'),
        (0xfffffe000c5b598c, 'cbz', 'x19, #0xfffffe000c5b59c4'),
        (0xfffffe000c5b5990, 'cbz', 'w23, #0xfffffe000c5b5aa8'),
        (0xfffffe000c5b5a08, 'strb', 'wzr, [x19, #0xc]'),
        (0xfffffe000c5b5a2c, 'str', 'x8, [x9, #0x10]'),
        (0xfffffe000c5b5a38, 'str', 'x8, [x10, w9, uxtw #3]'),
        (0xfffffe000c5b5a44, 'bl', '#0xfffffe000bd3d0f4'),
        (0xfffffe000bd3d140, 'cmp', 'w20, w9, uxtb'),
        (0xfffffe000bd3d16c, 'mov', 'x17, #0'),
        (0xfffffe000bd3d174, 'pacda', 'x17, x16'),
        (0xfffffe000bd3d178, 'str', 'x17, [x10]'),
        (0xfffffe000c5b5c14, 'csel', 'x0, x19, xzr, ne'),
    ),
    'client_died_and_close': (
        (0xfffffe000c5b6a18, 'adrp', 'x9, #0xfffffe000cbd7000'),
        (0xfffffe000c5b6a1c, 'add', 'x9, x9, #0xd20'),
        (0xfffffe000c5b6a20, 'cmp', 'x8, x9'),
        (0xfffffe000c5b6a70, 'bl', '#0xfffffe000bd4e450'),
        (0xfffffe000c5b6a7c, 'mov', 'x17, #0x928'),
        (0xfffffe000c5b6a8c, 'movk', 'x16, #0xea14, lsl #48'),
        (0xfffffe000c5b6a90, 'blraa', 'x8, x16'),
        (0xfffffe000c5b6a98, 'bl', '#0xfffffe000bd50068'),
        (0xfffffe000c5b6ad4, 'braa', 'x16, x17'),
        (0xfffffe000a545634, 'mov', 'w8, #1'),
        (0xfffffe000a545638, 'strb', 'w8, [x0, #0xf4]'),
        (0xfffffe000a545640, 'ldr', 'x8, [x8, #0x80]'),
        (0xfffffe000a545648, 'ldr', 'x16, [x8, #0x938]'),
        (0xfffffe000a545654, 'braa', 'x16, x17'),
        (0xfffffe000c5b203c, 'ldrb', 'w8, [x0, #0x98]'),
        (0xfffffe000c5b2044, 'add', 'x9, x0, #0x99'),
        (0xfffffe000c5b204c, 'casalb', 'w8, w10, [x9]'),
        (0xfffffe000c5b2050, 'cbnz', 'w8, #0xfffffe000c5b2084'),
        (0xfffffe000c5b2064, 'mov', 'x17, #0x920'),
        (0xfffffe000c5b2080, 'braa', 'x16, x17'),
        (0xfffffe000c5b2084, 'mov', 'w0, #0x2d8'),
        (0xfffffe000c5b2088, 'movk', 'w0, #0xe000, lsl #16'),
        (0xfffffe000c5be84c, 'ldrb', 'w8, [x19, #0x98]'),
        (0xfffffe000c5be85c, 'casalb', 'w8, w10, [x9]'),
        (0xfffffe000c5be860, 'cbnz', 'w8, #0xfffffe000c5be8c0'),
        (0xfffffe000c5be894, 'blraa', 'x8, x16'),
        (0xfffffe000a545618, 'mov', 'w1, #0'),
        (0xfffffe000a545620, 'blraa', 'x8, x16'),
    ),
}


def verify_fixup(image, address, target, modifier='0x0', address_diversity=0):
    fixup = image.pointer(address)
    assert fixup['target'] == hex(target)
    assert (fixup['format'], fixup['auth'], fixup['key']) == (8, int(modifier != '0x0'), 0)
    assert (fixup['diversity'], fixup['address_diversity']) == (modifier, address_diversity)
    return fixup


def audit(collection):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(collection, IDENTITIES[1])
    startup_record = 0xfffffe000cc6d790
    assert struct.unpack('<II', image.read(startup_record, 8)) == (14, 0)
    assert struct.unpack('<Q', image.read(DESCRIPTOR, 8)) == (CONNECTION_TYPE,)
    label = b'IKOT_IOKIT_CONNECT\0'
    label_address = 0xfffffe000705e29d
    assert image.read(label_address, len(label)) == label
    fixups = {
        'startup_function': verify_fixup(image, startup_record + 8, 0xfffffe000c679290, '0x2abe'),
        'startup_argument': verify_fixup(image, startup_record + 16, DESCRIPTOR),
        'descriptor_name': verify_fixup(image, DESCRIPTOR + 8, label_address),
        'descriptor_callback': verify_fixup(image, DESCRIPTOR + 16, 0xfffffe000c5b69a0, '0xd507'),
    }
    policy_callback = POLICY_TABLE + CONNECTION_TYPE * POLICY_STRIDE + NOTIFY_OFFSET
    assert policy_callback == 0xfffffe0007e6f1a0
    assert image.read(policy_callback, 8) == bytes(8)
    notify_words = struct.unpack('<II', image.read(0xfffffe000700dd18, 8))
    assert notify_words == (0, 70)
    assert image.named('__ZN12IOUserClient10gMetaClassE') == 0xfffffe000cbd7d20
    base = image.named('__ZTV12IOUserClient')
    driver = image.named('__ZTV' + CLIENT)
    fixups.update(
        base_vtable=verify_fixup(image, 0xfffffe0008493080, base),
        base_client_died=verify_fixup(
            image, base + 16 + 0x928, image.named('__ZN12IOUserClient10clientDiedEv'), '0xea14', 1),
        fairplay_client_died=verify_fixup(
            image, driver + 16 + 0x928, image.named(f'__ZN{CLIENT}10clientDiedEv'), '0xea14', 1),
        fairplay_client_close=verify_fixup(
            image, driver + 16 + 0x920, image.named(f'__ZN{CLIENT}11clientCloseEv'), '0x18b8', 1),
        fairplay_terminate=verify_fixup(
            image, driver + 16 + 0x630, image.named('__ZN9IOService9terminateEj'), '0x5ec5', 1),
    )
    return dict(build=build, kernel_identity=IDENTITIES[1], connection_type=CONNECTION_TYPE,
                startup_descriptor=hex(DESCRIPTOR), policy_table=hex(POLICY_TABLE),
                policy_stride_bytes=POLICY_STRIDE, policy_callback_slot=hex(policy_callback),
                policy_callback_zero_before_startup=True, ordinary_notification_id=notify_words[1],
                fixups=fixups, native_retirement_observed=False,
                instructions={group: assert_instructions(image.read, checks)
                              for group, checks in CHECKS.items()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection), indent=2))
