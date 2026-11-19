#!/usr/bin/env python3
"""Verify the current IOService termination handoff to FairPlay context cleanup."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_kext_selector26 import CLIENT, CS, DRIVER, Collection, IDENTITIES

PROVIDER = '30com_apple_driver_FairPlayIOKit'
CHECKS = {
    'termination_dispatch': """
        fffffe000a54560c mov x17, #0x630
        fffffe000a545618 mov w1, #0
        fffffe000a545620 blraa x8, x16
        fffffe000a545624 mov w0, #0
        fffffe000c52629c orr w1, w1, #4
        fffffe000c5262a0 b #0xfffffe000c5262a4
        fffffe000c5262cc mov x20, x1
        fffffe000c5272c8 orr w8, w8, #0x2000
        fffffe000c5272cc str w8, [x19, #0x4c]
        fffffe000c5272d0 mov x0, x19
        fffffe000c5272d4 mov x1, x20
        fffffe000c5272d8 bl #0xfffffe000c51f03c
        fffffe000c51f044 tbz w8, #0, #0xfffffe000c51f628
        fffffe000c51f078 tbz w8, #5, #0xfffffe000c51f604
        fffffe000c51f07c mov x21, x1
        fffffe000c51f0fc tbz w21, #1, #0xfffffe000c51f4dc
        fffffe000c51f4d8 tbnz w21, #1, #0xfffffe000c51f100
        fffffe000c51f4dc adrp x8, #0xfffffe000cc21000
        fffffe000c51f4e0 ldr x0, [x8, #0xf98]
        fffffe000c51f4f4 mov x17, #0x1e8
        fffffe000c51f500 mov x1, x23
        fffffe000c51f508 blraa x8, x16
        fffffe000c51f514 add w10, w9, #1
        fffffe000c51f518 str w10, [x8, #0xff8]
        fffffe000c51f51c cbnz w9, #0xfffffe000c51f5a4
        fffffe000c51f5a0 bl #0xfffffe000bdb6120
        fffffe000c51f9e8 adrp x23, #0xfffffe000cc21000
        fffffe000c51fa0c adrp x23, #0xfffffe000cc21000
        fffffe000c51fa1c ldr x0, [x23, #0xf98]
        fffffe000c51fa30 mov x17, #0x218
        fffffe000c51fa3c mov w1, #0
        fffffe000c51fa44 blraa x8, x16
    """,
    'worker_and_action': """
        fffffe000c520640 mov x17, #0x6b8
        fffffe000c52064c mov x0, x24
        fffffe000c520654 blraa x8, x16
        fffffe000c520658 cbz x0, #0xfffffe000c5206f8
        fffffe000c52068c mov x17, #0x1c0
        fffffe000c52069c adrp x16, #0xfffffe000c521000
        fffffe000c5206a0 add x16, x16, #0xea4
        fffffe000c5206a4 mov x17, #0xbd41
        fffffe000c5206a8 pacia x16, x17
        fffffe000c5206ac mov x1, x16
        fffffe000c5206b0 mov x0, x23
        fffffe000c5206b4 mov x2, x24
        fffffe000c5206b8 mov x3, x28
        fffffe000c5206d0 blraa x9, x17
        fffffe000c5206f8 mov x0, x24
        fffffe000c5206fc mov x1, x28
        fffffe000c520700 bl #0xfffffe000c521ea4
        fffffe000c569000 mov x22, x3
        fffffe000c569004 mov x23, x2
        fffffe000c569008 mov x24, x1
        fffffe000c569030 blraa x8, x16
        fffffe000c569034 mov x0, x23
        fffffe000c569038 mov x1, x22
        fffffe000c569048 mov x17, #0xbd41
        fffffe000c56904c blraa x24, x17
        fffffe000c569078 blraa x9, x17
        fffffe000c521ec4 mov x20, x1
        fffffe000c521ec8 mov x19, x0
        fffffe000c521fac mov x17, #0x5f8
        fffffe000c521fb8 mov x0, x20
        fffffe000c521fbc mov x1, x19
        fffffe000c521fc0 movk x16, #0xb085, lsl #48
        fffffe000c521fc4 blraa x8, x16
        fffffe000c521ff8 blraa x9, x17
        fffffe000c521ffc cbz w0, #0xfffffe000c522028
        fffffe000c522024 blraa x8, x16
        fffffe000c5220b8 mov x17, #0x6a8
        fffffe000c5220f8 braa x16, x17
    """,
    'fairplay_context_abi': """
        fffffe000a544bb8 mov w3, #0xf8
        fffffe000a545470 stp xzr, x20, [x19, #0xd8]
        fffffe000a545478 strb wzr, [x19, #0xf4]
        fffffe000a5454d4 str xzr, [x19, #0xe8]!
        fffffe000a545524 str x0, [x20, #0xd8]
        fffffe000a545528 cbz x0, #0xfffffe000a545560
        fffffe000a54552c ldr w2, [x20, #0xf0]
        fffffe000a545530 ldr x3, [x20, #0xe0]
        fffffe000a545544 mov x17, #0xa10
        fffffe000a545550 mov x1, x19
        fffffe000a545558 blraa x8, x16
        fffffe000a54555c mov w0, #1
        fffffe000a545584 mov x19, x1
        fffffe000a545588 mov x20, x0
        fffffe000a54558c ldr x0, [x0, #0xd8]
        fffffe000a5455a0 mov x17, #0xa18
        fffffe000a5455ac add x1, x20, #0xe8
        fffffe000a5455b0 movk x16, #0x7e4c, lsl #48
        fffffe000a5455b4 blraa x8, x16
        fffffe000a5455bc ldr x8, [x8, #0x80]
        fffffe000a5455c4 ldr x8, [x8, #0x608]
        fffffe000a5455c8 mov x0, x20
        fffffe000a5455cc mov x1, x19
        fffffe000a5455d8 blraa x8, x17
        fffffe000a5455dc stp xzr, xzr, [x20, #0xd8]
        fffffe000a545634 mov w8, #1
        fffffe000a545638 strb w8, [x0, #0xf4]
        fffffe000a545654 braa x16, x17
        fffffe000a54630c mov x0, x1
        fffffe000a546310 b #0xfffffe000a6677d8
        fffffe000a546318 mov x0, x1
        fffffe000a54631c mov x1, x2
        fffffe000a546320 mov x2, x3
        fffffe000a546324 b #0xfffffe000a5f7470
    """,
}


def scan_displacement(image):
    section, = (entry for entry in image.entries[DRIVER]['sections']
                if (entry['segment'], entry['section']) == ('__TEXT_EXEC', '__text'))
    start, size = section['address'], section['size']
    assert (start, size) == (0xfffffe000a544360, 1687188)
    source = image.read(start, size)
    operand = re.compile(r'\[(?:x(?:[12]?\d|30)|sp), #0xf4\]!?(?:$|,)')
    undecoded = []
    matches = []
    CS.skipdata = True
    try:
        for offset in range(0, size, 65536):
            for address, width, mnemonic, arguments in CS.disasm_lite(
                    source[offset:offset + 65536], start + offset):
                assert width == 4
                if mnemonic == '.byte':
                    undecoded.append(hex(address))
                if operand.search(arguments):
                    matches.append(dict(address=hex(address), mnemonic=mnemonic,
                                        operands=arguments))
    finally:
        CS.skipdata = False
    assert Counter(row['mnemonic'] for row in matches) == {
        'ldr': 23, 'str': 16, 'strb': 2, 'ldur': 2, 'stp': 1,
    }
    assert len(undecoded) == 51
    assert [row['address'] for row in matches if row['mnemonic'] == 'strb'] == [
        '0xfffffe000a545478', '0xfffffe000a545638']
    return dict(section_start=hex(start), section_size_bytes=size, word_count=size // 4,
                undecoded_words=undecoded, displacement_matches=matches)


def audit(collection):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(collection, IDENTITIES[1])
    assert image.named('_lapsl183ah') == 0xfffffe000a5f7470
    assert image.named('_kratpzs81h') == 0xfffffe000a6677d8
    bindings = (
        ('__ZTV' + CLIENT, 0x630, '__ZN9IOService9terminateEj', '0x5ec5'),
        ('__ZTV' + CLIENT, 0x5f8, f'__ZN{CLIENT}4stopEP9IOService', '0xb085'),
        ('__ZTV12IOUserClient', 0x5f8, '__ZN9IOService4stopEPS_', '0xb085'),
        ('__ZTV' + PROVIDER, 0xa10, f'__ZN{PROVIDER}11Trped0719abEPPvjS0_', '0x173'),
        ('__ZTV' + PROVIDER, 0xa18, f'__ZN{PROVIDER}12LasdMdn12casEPPv', '0x7e4c'),
        ('__ZTV' + PROVIDER, 0x6b8, '__ZNK9IOService11getWorkLoopEv', '0x638e'),
        ('__ZTV' + PROVIDER, 0x610, '__ZNK9IOService6isOpenEPKS_', '0xccfb'),
        ('__ZTV' + PROVIDER, 0x608, '__ZN9IOService5closeEPS_j', '0x639f'),
        ('__ZTV' + CLIENT, 0x6a8, '__ZN9IOService6detachEPS_', '0x7318'),
        ('__ZTV7OSArray', 0x1e8, '__ZN7OSArray9setObjectEPK15OSMetaClassBase', '0xc302'),
        ('__ZTV10IOWorkLoop', 0x1c0,
         '__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_', '0x7dda'),
        ('__ZTV10IOWorkLoop', 0x1a0, '__ZN10IOWorkLoop9closeGateEv', '0x3946'),
        ('__ZTV10IOWorkLoop', 0x198, '__ZN10IOWorkLoop8openGateEv', '0x1ba6'),
    )
    fixups = {}
    for vtable, offset, method, modifier in bindings:
        slot = image.named(vtable) + 16 + offset
        fixups[f'{vtable}+{offset:#x}'] = dict(
            method=method, **verify_fixup(image, slot, image.named(method), modifier, 1))
    fixups['base_vtable'] = verify_fixup(image, 0xfffffe0008493080,
                                        image.named('__ZTV12IOUserClient'))
    instructions = {}
    for group, expected in CHECKS.items():
        rows = [line.split(maxsplit=2) for line in expected.strip().splitlines()]
        instructions[group] = assert_instructions(
            image.read, [(int(address, 16), mnemonic, arguments)
                         for address, mnemonic, arguments in rows])
    return dict(build=build, kernel_identity=IDENTITIES[1], fixups=fixups,
                instructions=instructions, displacement_scan=scan_displacement(image),
                native_stop_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection), indent=2))
