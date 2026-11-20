#!/usr/bin/env python3
"""Verify installed IOKit connection-reference and owner-record cleanup."""

import argparse
import json
import struct
import subprocess
from pathlib import Path

from audit_live_iokit_open_owner import BUILD
from audit_live_kext_selector26 import CLIENT, DRIVER, IDENTITIES, Collection

INSTRUCTIONS = {
    'phase_one': (
        (0xfffffe000c52646c, 'adrp x8, #0xfffffe000700e000'),
        (0xfffffe000c526470, 'ldr d8, [x8, #0xb10]'),
        (0xfffffe000c526478, 'ldr d9, [x8, #0xb18]'),
        (0xfffffe000c5264d8, 'tst w9, #1'),
        (0xfffffe000c5264e0, 'tbz w21, #0, #0xfffffe000c526614'),
        (0xfffffe000c5264e4, 'ldr d0, [x19, #0x48]'),
        (0xfffffe000c5264e8, 'and v0.8b, v0.8b, v8.8b'),
        (0xfffffe000c5264ec, 'orr v0.8b, v0.8b, v9.8b'),
        (0xfffffe000c5264f0, 'str d0, [x19, #0x48]'),
        (0xfffffe000c526ae4, 'blraa x8, x16'),
        (0xfffffe000c526af8, 'cbz w21, #0xfffffe000c526e2c'),
        (0xfffffe000c526b10, 'bl #0xfffffe000c520fa0'),
        (0xfffffe000c526b14, 'cbz x0, #0xfffffe000c526bb0'),
        (0xfffffe000c526b60, 'bl #0xfffffe000c5212d0'),
        (0xfffffe000c526bb0, 'mov x0, x19'),
        (0xfffffe000c526bb4, 'bl #0xfffffe000c5b60dc'),
    ),
    'association_lookup_and_disable': (
        (0xfffffe000c5b60f8, 'mov x22, x0'),
        (0xfffffe000c5b60fc, 'mov w1, #0x28'),
        (0xfffffe000c5b6100, 'bl #0xfffffe000c5b5ea8'),
        (0xfffffe000c5b5fe0, 'ldrb w8, [x21, #0x69]'),
        (0xfffffe000c5b5fe4, 'tbnz w8, #0, #0xfffffe000c5b5f1c'),
        (0xfffffe000c5b5fe8, 'strb wzr, [x20, #0xc]'),
        (0xfffffe000c5b6020, 'bl #0xfffffe000bd3d0f4'),
        (0xfffffe000c5b6128, 'adrp x8, #0xfffffe000cbd7000'),
        (0xfffffe000c5b612c, 'add x8, x8, #0xd20'),
        (0xfffffe000c5b6130, 'cmp x0, x8'),
        (0xfffffe000c5b6168, 'and w25, w8, #0xfff'),
        (0xfffffe000c5b6170, 'ldr x0, [x23, #0x240]'),
        (0xfffffe000c5b6188, 'casa x2, x8, [x10]'),
        (0xfffffe000c5b619c, 'ldr x20, [x8, w25, uxtw #3]'),
        (0xfffffe000c5b61a0, 'cbnz x20, #0xfffffe000c5b61e8'),
        (0xfffffe000c5b61e4, 'cbz x20, #0xfffffe000c5b61a4'),
        (0xfffffe000c5b61ec, 'ldr x16, [x9, #0x20]!'),
        (0xfffffe000c5b61fc, 'autda x16, x17'),
        (0xfffffe000c5b6200, 'cmp x16, x22'),
        (0xfffffe000c5b6210, 'cmp w9, #0x27'),
        (0xfffffe000c5b6214, 'b.ne #0xfffffe000c5b61e0'),
        (0xfffffe000c5b6218, 'strb wzr, [x20, #0xc]'),
        (0xfffffe000c5b623c, 'str x9, [x8, #0x10]'),
        (0xfffffe000c5b6248, 'str x9, [x8, w25, uxtw #3]'),
        (0xfffffe000c5b624c, 'ldr x0, [x20, #0x18]'),
        (0xfffffe000c5b6250, 'mov w1, #0x27'),
        (0xfffffe000c5b6254, 'bl #0xfffffe000bd3d0f4'),
        (0xfffffe000bd3d140, 'cmp w20, w9, uxtb'),
        (0xfffffe000bd3d14c, 'ldr x16, [x10, #0x50]!'),
        (0xfffffe000bd3d16c, 'mov x17, #0'),
        (0xfffffe000bd3d174, 'pacda x17, x16'),
        (0xfffffe000bd3d178, 'str x17, [x10]'),
    ),
    'mapping_adoption_and_close': (
        (0xfffffe000c5b6258, 'cbz x21, #0xfffffe000c5b62d8'),
        (0xfffffe000c5b625c, 'ldr x22, [x21, #0x90]'),
        (0xfffffe000c5b6260, 'str xzr, [x21, #0x90]'),
        (0xfffffe000c5b6264, 'mov x0, x21'),
        (0xfffffe000c5b6268, 'bl #0xfffffe000c5b5c80'),
        (0xfffffe000c5b626c, 'cbz x22, #0xfffffe000c5b62d8'),
        (0xfffffe000c5b6270, 'mov x0, x22'),
        (0xfffffe000c5b6274, 'bl #0xfffffe000c5b0980'),
        (0xfffffe000c5b6278, 'mov x1, x0'),
        (0xfffffe000c5b627c, 'ldr x0, [x20, #0x18]'),
        (0xfffffe000c5b6280, 'str x0, [x1, #0x18]'),
        (0xfffffe000c5b6284, 'mov w2, #0x27'),
        (0xfffffe000c5b6288, 'bl #0xfffffe000bd3cfa8'),
        (0xfffffe000c5b628c, 'str xzr, [x20, #0x18]'),
        (0xfffffe000c5b0a00, 'add x16, x16, #0x10'),
        (0xfffffe000c5b0a10, 'str x16, [x20]'),
        (0xfffffe000c5b0a5c, 'pacda x17, x16'),
        (0xfffffe000c5b0a70, 'str x17, [x20, #0x20]'),
        (0xfffffe000c5b62d0, 'blraa x8, x16'),
        (0xfffffe000c5b6338, 'movk x17, #0x3a87, lsl #48'),
        (0xfffffe000c5b633c, 'braa x16, x17'),
        (0xfffffe000bd3cfdc, 'cmp w8, w20'),
        (0xfffffe000bd3cfe4, 'mov x17, x21'),
        (0xfffffe000bd3cfe8, 'add x16, x19, #0x50'),
        (0xfffffe000bd3cff8, 'pacda x17, x16'),
        (0xfffffe000bd3cffc, 'str x17, [x19, #0x50]'),
        (0xfffffe000c5be7d8, 'adrp x8, #0xfffffe000cbce000'),
        (0xfffffe000c5be7e0, 'cmp x0, x8'),
        (0xfffffe000c5be7e4, 'b.eq #0xfffffe000c5be8a4'),
        (0xfffffe000c5be8a4, 'mov w20, #0'),
    ),
    'owner_cleanup_join': (
        (0xfffffe000c5b5a44, 'bl #0xfffffe000bd3d0f4'),
        (0xfffffe000c5b5be4, 'mov x0, x21'),
        (0xfffffe000c5b5be8, 'bl #0xfffffe000c5b5c80'),
        (0xfffffe000c5b5ca4, 'ldr x8, [x22, #0x898]'),
        (0xfffffe000c5b5cbc, 'casa x2, x9, [x11]'),
        (0xfffffe000c5b5ccc, 'ldr x1, [x20, #0xa0]!'),
        (0xfffffe000c5b5d10, 'add x8, x11, #0x650'),
        (0xfffffe000c5b5d50, 'str x10, [x13]'),
        (0xfffffe000c5b5d74, 'stp xzr, xzr, [x1, #8]'),
        (0xfffffe000c5b5d84, 'ldr x10, [x9, #0x18]'),
        (0xfffffe000c5b5d88, 'ldrb w10, [x10, #0x9b]'),
        (0xfffffe000c5b5d8c, 'tbnz w10, #0, #0xfffffe000c5b5db0'),
        (0xfffffe000c5b5da8, 'ldclr w25, w10, [x10]'),
        (0xfffffe000c5b5db8, 'ldset w25, w9, [x9]'),
        (0xfffffe000c5b5dc0, 'strb w9, [x8, #0x17]'),
        (0xfffffe000c5b5dc4, 'ldp x8, x9, [x1, #0x20]'),
        (0xfffffe000c5b5cf4, 'stp xzr, xzr, [x1, #0x20]'),
        (0xfffffe000c5b5cfc, 'bl #0xfffffe000bd46f04'),
        (0xfffffe000c5b5e20, 'stp xzr, xzr, [x20]'),
    ),
}

SYMBOLS = {
    '__ZN9IOService15terminatePhase1Ej': 0xfffffe000c5262a4,
    '__ZN12IOUserClient21destroyUserReferencesEP8OSObject': 0xfffffe000c5b60dc,
    '__ZN12IOUserClient10gMetaClassE': 0xfffffe000cbd7d20,
    '__ZN5OSSet10gMetaClassE': 0xfffffe000cbce000,
    '__ZN9IOService20unlockForArbitrationEv': 0xfffffe000c5255b0,
    '__ZNK8OSObject7releaseEv': 0xfffffe000c493f98,
    '__ZTV10IOMachPort': 0xfffffe0007f5caa0,
}


def verify_image(image):
    evidence = {}
    for group, sites in INSTRUCTIONS.items():
        evidence[group] = {}
        for pc, expected in sites:
            instruction, = image.instructions(pc, 4)
            actual = f'{instruction.mnemonic} {instruction.op_str}'.strip()
            assert actual == expected, (hex(pc), expected, actual)
            evidence[group][hex(pc)] = {
                'bytes': instruction.bytes.hex(), 'instruction': actual,
            }

    for name, address in SYMBOLS.items():
        assert image.named(name) == address, name

    state_masks = struct.unpack('<4I', image.read(0xfffffe000700eb10, 16))
    assert state_masks == (0xffffffe0, 0xffafffff, 1, 0x400000)

    bindings = {}
    for name, vtable, offset, diversity in (
        ('__ZN9IOService20unlockForArbitrationEv', f'__ZTV{CLIENT}', 0x648, '0x8a43'),
        ('__ZNK8OSObject7releaseEv', '__ZTV10IOMachPort', 0x28, '0x3a87'),
    ):
        slot = image.named(vtable) + 0x10 + offset
        binding = image.pointer(slot)
        assert (binding['target'], binding['auth'], binding['diversity']) == (
            hex(SYMBOLS[name]), 1, diversity,
        )
        bindings[name] = {'slot': hex(slot), 'pointer': binding}

    return {
        'collection_identities': IDENTITIES[1],
        'instruction_count': sum(map(len, evidence.values())),
        'original_instructions': evidence,
        'phase_one_state_masks': {
            'address': '0xfffffe000700eb10',
            'and': [hex(value) for value in state_masks[:2]],
            'or': [hex(value) for value in state_masks[2:]],
        },
        'symbols': {name: hex(address) for name, address in SYMBOLS.items()},
        'vtable_bindings': bindings,
    }


def verify_host_identity():
    build = subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip()
    kernel_uuid = subprocess.check_output(
        ['sysctl', '-n', 'kern.uuid'], text=True,
    ).strip().lower()
    loaded = subprocess.check_output(['kmutil', 'showloaded'], text=True)
    row, = (line for line in loaded.splitlines() if f'{DRIVER} (' in line)
    driver_uuid = IDENTITIES[1][2]
    assert build == BUILD
    assert kernel_uuid == IDENTITIES[1][1]
    assert driver_uuid in row.lower()
    return {'build': build, 'kernel_uuid': kernel_uuid, 'driver_uuid': driver_uuid}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true', help='check host identities')
    args = parser.parse_args()
    evidence = verify_image(Collection(args.collection, IDENTITIES[1]))
    if args.observe:
        evidence['host_identity'] = verify_host_identity()
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
