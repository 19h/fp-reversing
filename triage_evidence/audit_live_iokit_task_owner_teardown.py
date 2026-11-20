#!/usr/bin/env python3
"""Audit task-side IOUserClient ownership teardown and notification dispatch."""

import argparse
import json
from pathlib import Path
from struct import iter_unpack, unpack

from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_iokit_reference_cleanup import verify_host_identity
from audit_live_kext_selector26 import CLIENT, IDENTITIES, Collection

TASK_HOOK = 0xfffffe000c5b7f30
CALLERS = {
    0xfffffe000bd86ed4: 1,
    0xfffffe000bd8c27c: 2,
    0xfffffe000bd8cdc4: 1,
    0xfffffe000bd8dd6c: 1,
    0xfffffe000bd8ddd0: 2,
}

INSTRUCTIONS = {
    'task_lifecycle': (
        (0xfffffe000bd86ed0, 'mov w1, #1'),
        (0xfffffe000bd86ed4, 'bl #0xfffffe000c5b7f30'),
        (0xfffffe000bd86ed8, 'ldr x16, [x20, #0x318]'),
        (0xfffffe000bd86ee8, 'autda x16, x17'),
        (0xfffffe000bd86ef8, 'bl #0xfffffe000bd1e5f8'),
        (0xfffffe000bd8c270, 'bl #0xfffffe000bd3f0bc'),
        (0xfffffe000bd8c278, 'mov w1, #2'),
        (0xfffffe000bd8c27c, 'bl #0xfffffe000c5b7f30'),
        (0xfffffe000bd8cdc0, 'mov w1, #1'),
        (0xfffffe000bd8cdc4, 'bl #0xfffffe000c5b7f30'),
        (0xfffffe000bd8cdc8, 'ldr x16, [x19, #0x318]'),
        (0xfffffe000bd8cdd8, 'autda x16, x17'),
        (0xfffffe000bd8cde8, 'bl #0xfffffe000bd1e5f8'),
        (0xfffffe000bd8dd68, 'mov w1, #1'),
        (0xfffffe000bd8dd6c, 'bl #0xfffffe000c5b7f30'),
        (0xfffffe000bd8dd70, 'ldr x16, [x19, #0x318]'),
        (0xfffffe000bd8dd80, 'autda x16, x17'),
        (0xfffffe000bd8dd90, 'bl #0xfffffe000bd1e5f8'),
        (0xfffffe000bd8ddb4, 'bl #0xfffffe000be183b8'),
        (0xfffffe000bd8ddbc, 'mov w1, #2'),
        (0xfffffe000bd8ddd0, 'b #0xfffffe000c5b7f30'),
        (0xfffffe000bd9a16c, 'b #0xfffffe000bd8c114'),
        (0xfffffe000bd9a18c, 'b #0xfffffe000bd8c114'),
    ),
    'phase_dispatch_and_driverkit_guard': (
        (0xfffffe000c5b7f54, 'cmp w1, #2'),
        (0xfffffe000c5b7f58, 'b.eq #0xfffffe000c5b80a8'),
        (0xfffffe000c5b7f5c, 'cmp w1, #1'),
        (0xfffffe000c5b7f60, 'b.ne #0xfffffe000c5b84a8'),
        (0xfffffe000c5b7f64, 'cbz x0, #0xfffffe000c5b83b4'),
        (0xfffffe000c5b7f68, 'ldr x8, [x0, #0x4d8]'),
        (0xfffffe000c5b7f6c, 'and x8, x8, #0xf000000000000'),
        (0xfffffe000c5b7f70, 'mov x9, #0x7000000000000'),
        (0xfffffe000c5b7f74, 'cmp x8, x9'),
        (0xfffffe000c5b7f78, 'b.ne #0xfffffe000c5b83b4'),
        (0xfffffe000bd987c8, 'ldr x8, [x0, #0x4d8]'),
        (0xfffffe000bd987cc, 'and x8, x8, #0xf000000000000'),
        (0xfffffe000bd987d0, 'mov x9, #0x7000000000000'),
        (0xfffffe000bd987d4, 'cmp x8, x9'),
        (0xfffffe000c5b8048, 'ldr x1, [x25, #0x18]'),
        (0xfffffe000c5b8068, 'blraa x8, x16'),
        (0xfffffe000c5b82e4, 'add x22, x22, #0xc80'),
        (0xfffffe000c5b8308, 'blraa x8, x16'),
        (0xfffffe000c5b837c, 'cmp x0, x22'),
        (0xfffffe000c5b8380, 'b.eq #0xfffffe000c5b82ec'),
        (0xfffffe000c5b84bc, 'adrp x0, #0xfffffe00070e1000'),
        (0xfffffe000c5b84c0, 'add x0, x0, #0xf1'),
    ),
    'right_termination_and_notifications': (
        (0xfffffe000bd1e824, 'tbz w8, #0x11, #0xfffffe000bd1e7ec'),
        (0xfffffe000bd1e838, 'bl #0xfffffe000bd1b694'),
        (0xfffffe000bd1e888, 'tst w8, #0x1f0000'),
        (0xfffffe000bd1e8a0, 'bl #0xfffffe000bd1b694'),
        (0xfffffe000bd1b75c, 'bl #0xfffffe000bd14d10'),
        (0xfffffe000bd1b764, 'tbnz w25, #0x10, #0xfffffe000bd1b774'),
        (0xfffffe000bd1b774, 'ldr w9, [x21, #0x88]'),
        (0xfffffe000bd1b778, 'sub w8, w9, #1'),
        (0xfffffe000bd1b77c, 'str w8, [x21, #0x88]'),
        (0xfffffe000bd1b784, 'cbz w8, #0xfffffe000bd1b7e8'),
        (0xfffffe000bd1b7ec, 'bl #0xfffffe000bd10f08'),
        (0xfffffe000bd1b7f0, 'mov x24, x0'),
        (0xfffffe000bd1b7f4, 'mov x23, x1'),
        (0xfffffe000bd1b808, 'mov x0, x24'),
        (0xfffffe000bd1b80c, 'mov x1, x23'),
        (0xfffffe000bd1b810, 'lsr x8, x23, #0x20'),
        (0xfffffe000bd1b814, 'cbnz x8, #0xfffffe000bd1b824'),
        (0xfffffe000bd1b818, 'bl #0xfffffe000bd10fe4'),
        (0xfffffe000bd1b824, 'bl #0xfffffe000bd1105c'),
        (0xfffffe000bd1b82c, 'mov x0, x22'),
        (0xfffffe000bd1b830, 'mov x1, x20'),
        (0xfffffe000bd1b834, 'bl #0xfffffe000bd10e90'),
        (0xfffffe000bd11098, 'ldr x8, [x8, #0x18]'),
        (0xfffffe000bd110a4, 'blraa x8, x17'),
        (0xfffffe000bd10f60, 'ldr w8, [x0, #0x84]'),
        (0xfffffe000bd10f64, 'orr x1, x8, #0x100000000'),
        (0xfffffe000bd11010, 'str w1, [sp, #0x28]'),
        (0xfffffe000bd11020, 'stp x0, xzr, [sp, #8]'),
        (0xfffffe000bd11028, 'ldr d0, [x8, #0xd18]'),
        (0xfffffe000bd11048, 'bl #0xfffffe000bd3d4d0'),
        (0xfffffe000bd10e9c, 'b.eq #0xfffffe000bd10f04'),
        (0xfffffe000bd10ebc, 'str w1, [sp, #0x28]'),
        (0xfffffe000bd10ecc, 'stp x0, xzr, [sp, #8]'),
        (0xfffffe000bd10ed4, 'ldr d0, [x8, #0xd10]'),
        (0xfffffe000bd10ee0, 'mov w1, #0x2c'),
        (0xfffffe000bd10ef4, 'bl #0xfffffe000bd3d4d0'),
    ),
    'owner_queue_removal': (
        (0xfffffe000c5b80b0, 'ldr x8, [x26, #0x898]'),
        (0xfffffe000c5b80c8, 'casa x2, x9, [x11]'),
        (0xfffffe000c5b80d4, 'add x21, x0, #0x650'),
        (0xfffffe000c5b80d8, 'ldr x22, [x0, #0x650]'),
        (0xfffffe000c5b80e0, 'b.eq #0xfffffe000c5b8280'),
        (0xfffffe000c5b80f0, 'add x23, x23, #0x7d4'),
        (0xfffffe000c5b80f8, 'add x24, x24, #0x1c8'),
        (0xfffffe000c5b8108, 'bl #0xfffffe000bd46f04'),
        (0xfffffe000c5b810c, 'ldr x22, [x21]'),
        (0xfffffe000c5b8118, 'ldp x8, x9, [x22, #8]'),
        (0xfffffe000c5b8148, 'ldr x25, [x22, #0x18]'),
        (0xfffffe000c5b8154, 'str x9, [x11]'),
        (0xfffffe000c5b8178, 'stp xzr, xzr, [x22, #8]'),
        (0xfffffe000c5b817c, 'add x8, x25, #0xa0'),
        (0xfffffe000c5b8180, 'ldp x9, x10, [x22, #0x20]'),
        (0xfffffe000c5b81bc, 'str x10, [x13]'),
        (0xfffffe000c5b81e0, 'stp xzr, xzr, [x22, #0x20]'),
        (0xfffffe000c5b81e4, 'ldr x9, [x8]'),
        (0xfffffe000c5b81ec, 'b.ne #0xfffffe000c5b8100'),
        (0xfffffe000c5b8208, 'movk x16, #0x2e4a, lsl #48'),
        (0xfffffe000c5b820c, 'blraa x8, x16'),
        (0xfffffe000c5b8248, 'stp xzr, x20, [x25, #0xa0]'),
        (0xfffffe000c5b824c, 'mov x20, x25'),
        (0xfffffe000c5b8268, 'casl w2, wzr, [x9]'),
        (0xfffffe000c5b8278, 'cbnz x20, #0xfffffe000c5b8444'),
    ),
    'post_unlock_death_dispatch': (
        (0xfffffe000c5b840c, 'mov x17, #0x928'),
        (0xfffffe000c5b8418, 'mov x0, x20'),
        (0xfffffe000c5b841c, 'movk x16, #0xea14, lsl #48'),
        (0xfffffe000c5b8420, 'blraa x8, x16'),
        (0xfffffe000c5b8438, 'blraa x8, x16'),
        (0xfffffe000c5b8444, 'ldr x19, [x20, #0xa8]'),
        (0xfffffe000c5b8448, 'str xzr, [x20, #0xa8]'),
        (0xfffffe000c5b844c, 'ldrb w8, [x20, #0x98]'),
        (0xfffffe000c5b8450, 'cbnz w8, #0xfffffe000c5b83f4'),
        (0xfffffe000c5b8454, 'ldrb w8, [x20, #0x99]'),
        (0xfffffe000c5b8458, 'cbz w8, #0xfffffe000c5b83f4'),
        (0xfffffe000c5b8464, 'b #0xfffffe000c5b8424'),
        (0xfffffe000a545634, 'mov w8, #1'),
        (0xfffffe000a545638, 'strb w8, [x0, #0xf4]'),
        (0xfffffe000a545640, 'ldr x8, [x8, #0x80]'),
        (0xfffffe000a545648, 'ldr x16, [x8, #0x938]'),
        (0xfffffe000a545654, 'braa x16, x17'),
        (0xfffffe000c5b203c, 'ldrb w8, [x0, #0x98]'),
        (0xfffffe000c5b204c, 'casalb w8, w10, [x9]'),
        (0xfffffe000c5b2050, 'cbnz w8, #0xfffffe000c5b2084'),
        (0xfffffe000c5b2064, 'mov x17, #0x920'),
        (0xfffffe000c5b2080, 'braa x16, x17'),
    ),
}


def verify_callers(image):
    text, = (
        section for section in image.entries['com.apple.kernel']['sections']
        if (section['segment'], section['section']) == ('__TEXT_EXEC', '__text')
    )
    base, size = text['address'], text['size']
    assert (base, size) == (0xfffffe000bce1000, 10_181_168)
    sites = []
    for index, (word,) in enumerate(iter_unpack('<I', image.read(base, size))):
        if word >> 26 not in (0b000101, 0b100101):
            continue
        imm26 = ((word & 0x3ffffff) ^ 0x2000000) - 0x2000000
        pc = base + index * 4
        if pc + 4 * imm26 == TASK_HOOK:
            sites.append(pc)
    assert sites == list(CALLERS)
    return {
        'hook': hex(TASK_HOOK),
        'code_extent_bytes': size,
        'direct_callers_and_phases': {hex(pc): CALLERS[pc] for pc in sites},
    }


def verify_image(image):
    evidence = {}
    for group, sites in INSTRUCTIONS.items():
        evidence[group] = {}
        for pc, expected in sites:
            instruction, = image.instructions(pc, 4)
            actual = f'{instruction.mnemonic} {instruction.op_str}'.rstrip()
            assert actual == expected, (hex(pc), expected, actual)
            evidence[group][hex(pc)] = {
                'bytes': instruction.bytes.hex(), 'instruction': actual,
            }

    assert image.named('__ZN12IOUserServer10gMetaClassE') == 0xfffffe000cbd7c80
    assert image.named('_task_is_driver') == 0xfffffe000bd987c0
    assert image.named('_task_deallocate') == 0xfffffe000bd9a14c
    literals = {
        0xfffffe00070e10f1: 'iokit_task_terminate phase %d @%s:%d',
        0xfffffe00070e17d4: 'destroying out of band connect for %s\n',
        0xfffffe00070e10d3: 'site.IOUserClientOwner',
        0xfffffe00070e10ea: '111111',
    }
    for addr, name in literals.items():
        assert image.read(addr, len(name) + 1) == name.encode() + bytes(1), hex(addr)

    allocation_site, free_site = 0xfffffe0007e63048, 0xfffffe0007e631c8
    assert image.read(allocation_site, 48) == image.read(free_site, 48)
    assert unpack('<I', image.read(free_site + 0x2c, 4)) == (48,)
    owner_type = {
        'allocation_descriptor': hex(allocation_site),
        'free_descriptor': hex(free_site),
        'owner_record_bytes': 48,
        'site': verify_fixup(image, free_site + 0x10, 0xfffffe00070e10d3),
        'signature': verify_fixup(image, free_site + 0x20, 0xfffffe00070e10ea),
    }
    base = image.named('__ZTV12IOUserClient')
    bindings = {'base_vtable': verify_fixup(image, 0xfffffe0008493080, base)}
    for class_name, offset, symbol, modifier in (
        (CLIENT, 0x20, '__ZNK8OSObject6retainEv', '0x2e4a'),
        (CLIENT, 0x28, '__ZNK8OSObject7releaseEv', '0x3a87'),
        (CLIENT, 0x920, f'__ZN{CLIENT}11clientCloseEv', '0x18b8'),
        (CLIENT, 0x928, f'__ZN{CLIENT}10clientDiedEv', '0xea14'),
        ('12IOUserClient', 0x928, '__ZN12IOUserClient10clientDiedEv', '0xea14'),
    ):
        table = image.named(f'__ZTV{class_name}') + 0x10
        bindings[f'{class_name}+{offset:#x}'] = verify_fixup(
            image, table + offset, image.named(symbol), modifier, 1,
        )
    notify = {}
    for addr, number in ((0xfffffe000700dd10, 65), (0xfffffe000700dd18, 70)):
        assert unpack('<2I', image.read(addr, 8)) == (0, number)
        notify[hex(addr)] = number
    return {
        'collection_identities': IDENTITIES[1],
        'caller_census': verify_callers(image),
        'instruction_count': sum(map(len, evidence.values())),
        'original_instructions': evidence,
        'task_owner_typing': owner_type,
        'vtable_bindings': bindings,
        'notification_id_literals': notify,
        'literals': {hex(addr): label for addr, label in literals.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true', help='check host identities')
    args = parser.parse_args()
    result = verify_image(Collection(args.collection, IDENTITIES[1]))
    if args.observe:
        result['host_identity'] = verify_host_identity()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
