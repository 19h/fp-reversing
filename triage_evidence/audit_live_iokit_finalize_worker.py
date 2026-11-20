#!/usr/bin/env python3
"""Verify the installed IOKit phase-three finalize and provider-stop handoff."""

import argparse
import json
from pathlib import Path
from struct import iter_unpack

from audit_live_iokit_reference_cleanup import verify_host_identity
from audit_live_kext_selector26 import CLIENT, IDENTITIES, PROVIDER, Collection

WORKER = 0xfffffe000c51f840
EXPECTED_CALLERS = (0xfffffe000c51f290, 0xfffffe000c537f9c)
INSTRUCTIONS = {
    'worker_entry_and_options': (
        (0xfffffe000c51f28c, 'orr w0, w21, #1'),
        (0xfffffe000c51f290, 'bl #0xfffffe000c51f840'),
        (0xfffffe000c51f294, 'ldr w8, [x26, #0xff8]'),
        (0xfffffe000c51f298, 'cbnz w8, #0xfffffe000c51f28c'),
        (0xfffffe000c537f98, 'mov x0, x19'),
        (0xfffffe000c537f9c, 'bl #0xfffffe000c51f840'),
        (0xfffffe000c537fa0, 'ldr w8, [x22, #0xff8]'),
        (0xfffffe000c537fa4, 'cbnz w8, #0xfffffe000c537f98'),
        (0xfffffe000c537fd0, 'add x2, x2, #0xff8'),
        (0xfffffe000c537fd8, 'bl #0xfffffe000bd547e8'),
        (0xfffffe000c51f864, 'mov x22, x0'),
        (0xfffffe000c51f9dc, 'orr w22, w22, #1'),
        (0xfffffe000c51fa00, 'subs w8, w8, w10'),
        (0xfffffe000c51fa04, 'str w8, [x9, #0xff8]'),
    ),
    'phase_three_mark_and_admit': (
        (0xfffffe000c52004c, 'adrp x27, #0xfffffe000cb87000'),
        (0xfffffe000c520048, 'blraa x8, x16'),
        (0xfffffe000c5200e4, 'blraa x8, x16'),
        (0xfffffe000c5200e8, 'cbz w0, #0xfffffe000c520148'),
        (0xfffffe000c5200ec, 'ldr w8, [x24, #0x4c]'),
        (0xfffffe000c5200f0, 'orr w8, w8, #0x800000'),
        (0xfffffe000c5200f4, 'str w8, [x24, #0x4c]'),
        (0xfffffe000c520114, 'blraa x8, x16'),
        (0xfffffe000c52011c, 'cmp x0, #0'),
        (0xfffffe000c520120, 'cset w21, eq'),
        (0xfffffe000c520140, 'blraa x9, x17'),
        (0xfffffe000c520228, 'bl #0xfffffe000c521824'),
        (0xfffffe000c520230, 'tbz w8, #3, #0xfffffe000c5202f0'),
        (0xfffffe000c5202f0, 'cbz w21, #0xfffffe000c520064'),
        (0xfffffe000c5202f4, 'mov x0, x24'),
        (0xfffffe000c5202f8, 'mov w1, #0'),
        (0xfffffe000c5202fc, 'bl #0xfffffe000c51f638'),
        (0xfffffe000c51f6c8, 'tbnz w20, #0, #0xfffffe000c51f6d8'),
        (0xfffffe000c51f6d0, 'bl #0xfffffe000c5b663c'),
        (0xfffffe000c51f6d4, 'cbz w0, #0xfffffe000c51f7f0'),
        (0xfffffe000c51f708, 'ldr x0, [x8, #0xfb0]'),
        (0xfffffe000c51f71c, 'mov x17, #0x1e8'),
        (0xfffffe000c51f728, 'mov x1, x19'),
        (0xfffffe000c51f730, 'blraa x8, x16'),
        (0xfffffe000c51f740, 'str w10, [x8, #0xff8]'),
        (0xfffffe000c51f744, 'cbnz w9, #0xfffffe000c51f7cc'),
        (0xfffffe000c51f7c8, 'bl #0xfffffe000bdb6120'),
    ),
    'queue_head_arbitration_and_dispatch': (
        (0xfffffe000c520844, 'ldr x0, [x23, #0xfb0]'),
        (0xfffffe000c520858, 'mov x17, #0x218'),
        (0xfffffe000c520864, 'mov w1, #0'),
        (0xfffffe000c520868, 'movk x16, #0x8453, lsl #48'),
        (0xfffffe000c52086c, 'blraa x8, x16'),
        (0xfffffe000c520878, 'cbz x0, #0xfffffe000c520adc'),
        (0xfffffe000c52087c, 'mov x25, x0'),
        (0xfffffe000c520884, 'ldr x0, [x21, #0xf18]'),
        (0xfffffe000c520898, 'casl w2, wzr, [x9]'),
        (0xfffffe000c5208b8, 'mov x17, #0x640'),
        (0xfffffe000c5208c4, 'mov x0, x25'),
        (0xfffffe000c5208c8, 'mov w1, #1'),
        (0xfffffe000c5208cc, 'movk x16, #0xc6b2, lsl #48'),
        (0xfffffe000c5208d0, 'blraa x8, x16'),
        (0xfffffe000c5208d4, 'cbz w0, #0xfffffe000c520a18'),
        (0xfffffe000c5208e0, 'ldr w8, [x25, #0x4c]'),
        (0xfffffe000c5208e4, 'tbnz w8, #0x10, #0xfffffe000c5209d8'),
        (0xfffffe000c5208e8, 'orr w8, w8, #0x10000'),
        (0xfffffe000c5208ec, 'str w8, [x25, #0x4c]'),
        (0xfffffe000c52090c, 'blraa x8, x16'),
        (0xfffffe000c520920, 'ldr x9, [x16, #0x6b8]'),
        (0xfffffe000c52092c, 'movk x17, #0x638e, lsl #48'),
        (0xfffffe000c520930, 'blraa x9, x17'),
        (0xfffffe000c520934, 'cbz x0, #0xfffffe000c5209fc'),
        (0xfffffe000c520954, 'blraa x8, x16'),
        (0xfffffe000c520968, 'mov x17, #0x1c0'),
        (0xfffffe000c520978, 'adrp x16, #0xfffffe000c521000'),
        (0xfffffe000c52097c, 'add x16, x16, #0xda4'),
        (0xfffffe000c520980, 'mov x17, #0xbd41'),
        (0xfffffe000c520984, 'pacia x16, x17'),
        (0xfffffe000c520988, 'mov x1, x16'),
        (0xfffffe000c52098c, 'mov x0, x23'),
        (0xfffffe000c520990, 'mov x2, x25'),
        (0xfffffe000c520994, 'mov x3, x22'),
        (0xfffffe000c520998, 'mov x4, #0'),
        (0xfffffe000c52099c, 'mov x5, #0'),
        (0xfffffe000c5209a0, 'mov x6, #0'),
        (0xfffffe000c5209a8, 'movk x17, #0x7dda, lsl #48'),
        (0xfffffe000c5209ac, 'blraa x9, x17'),
        (0xfffffe000c5209d0, 'blraa x8, x16'),
        (0xfffffe000c5209f4, 'blraa x8, x16'),
        (0xfffffe000c5209fc, 'mov x0, x25'),
        (0xfffffe000c520a00, 'mov x1, x22'),
        (0xfffffe000c520a10, 'bl #0xfffffe000c521da4'),
    ),
    'action_and_base_finalize': (
        (0xfffffe000c569030, 'blraa x8, x16'),
        (0xfffffe000c569034, 'mov x0, x23'),
        (0xfffffe000c569038, 'mov x1, x22'),
        (0xfffffe000c56904c, 'blraa x24, x17'),
        (0xfffffe000c569078, 'blraa x9, x17'),
        (0xfffffe000c521dbc, 'mov x19, x1'),
        (0xfffffe000c521dc0, 'mov x20, x0'),
        (0xfffffe000c521e58, 'mov x17, #0x638'),
        (0xfffffe000c521e60, 'ldr x8, [x16]'),
        (0xfffffe000c521e6c, 'mov x0, x20'),
        (0xfffffe000c521e70, 'mov x1, x19'),
        (0xfffffe000c521e8c, 'movk x17, #0x5219, lsl #48'),
        (0xfffffe000c521e90, 'braa x16, x17'),
        (0xfffffe000c525d94, 'blraa x8, x16'),
        (0xfffffe000c525d98, 'cbz x0, #0xfffffe000c525ff4'),
        (0xfffffe000c525dc8, 'blraa x8, x16'),
        (0xfffffe000c525dcc, 'cbz x0, #0xfffffe000c525fdc'),
        (0xfffffe000c525e0c, 'blraa x8, x16'),
        (0xfffffe000c525e38, 'ldrb w8, [x19, #0x4e]'),
        (0xfffffe000c525e3c, 'tbnz w8, #7, #0xfffffe000c525f5c'),
        (0xfffffe000c525ef4, 'blraa x8, x16'),
        (0xfffffe000c525f20, 'blraa x9, x17'),
        (0xfffffe000c525f24, 'cbz w0, #0xfffffe000c525dec'),
        (0xfffffe000c525f4c, 'mov w2, #0'),
        (0xfffffe000c525f54, 'blraa x8, x16'),
        (0xfffffe000c525f7c, 'mov w1, #1'),
        (0xfffffe000c525f84, 'blraa x8, x16'),
        (0xfffffe000c525f88, 'cbz w0, #0xfffffe000c525e10'),
        (0xfffffe000c525f8c, 'ldrb w8, [x23, #0x4e]'),
        (0xfffffe000c525f90, 'tbnz w8, #7, #0xfffffe000c525fa0'),
        (0xfffffe000c525f94, 'mov x0, x19'),
        (0xfffffe000c525f98, 'mov x1, x23'),
        (0xfffffe000c525f9c, 'bl #0xfffffe000c526018'),
        (0xfffffe000c525fc4, 'blraa x8, x16'),
        (0xfffffe000c525ff0, 'blraa x8, x16'),
        (0xfffffe000c525ff4, 'mov w0, #1'),
    ),
    'stop_publication_and_check': (
        (0xfffffe000c526034, 'mov x19, x1'),
        (0xfffffe000c526038, 'mov x20, x0'),
        (0xfffffe000c5260f4, 'ldr x0, [x22, #0xf18]'),
        (0xfffffe000c52610c, 'casa x2, x8, [x10]'),
        (0xfffffe000c52611c, 'ldr x0, [x8, #0xfa0]'),
        (0xfffffe000c52613c, 'mov x1, x20'),
        (0xfffffe000c526144, 'blraa x8, x16'),
        (0xfffffe000c52614c, 'ldr x0, [x8, #0xfa8]'),
        (0xfffffe000c526168, 'mov x1, x19'),
        (0xfffffe000c526174, 'blraa x9, x17'),
        (0xfffffe000c526184, 'str w10, [x8, #0xff8]'),
        (0xfffffe000c526188, 'cbnz w9, #0xfffffe000c526210'),
        (0xfffffe000c52620c, 'bl #0xfffffe000bdb6120'),
        (0xfffffe000c520454, 'ldr w23, [x28, #0x48]'),
        (0xfffffe000c520488, 'tbz w23, #0, #0xfffffe000c520638'),
        (0xfffffe000c5204b4, 'blraa x8, x16'),
        (0xfffffe000c5204c4, 'ldr w8, [x28, #0x4c]'),
        (0xfffffe000c5204e8, 'blraa x8, x16'),
        (0xfffffe000c5204f0, 'tbnz w8, #0x10, #0xfffffe000c520638'),
        (0xfffffe000c520654, 'blraa x8, x16'),
        (0xfffffe000c520700, 'bl #0xfffffe000c521ea4'),
    ),
    'result_retention_and_queue_removal': (
        (0xfffffe000c51f968, 'adrp x0, #0xfffffe000cbce000'),
        (0xfffffe000c51f98c, 'cbz x0, #0xfffffe000c520b2c'),
        (0xfffffe000c51f9c0, 'blraa x8, x16'),
        (0xfffffe000c51f9c4, 'tbz w0, #0, #0xfffffe000c520b14'),
        (0xfffffe000c520a1c, 'ldr x0, [x21, #0xf18]'),
        (0xfffffe000c520a2c, 'casa x2, x8, [x10]'),
        (0xfffffe000c520a40, 'mov x17, #0x1f0'),
        (0xfffffe000c520a4c, 'mov x0, x26'),
        (0xfffffe000c520a50, 'mov x1, x25'),
        (0xfffffe000c520a58, 'blraa x8, x16'),
        (0xfffffe000c520a5c, 'ldr x0, [x23, #0xfb0]'),
        (0xfffffe000c520a74, 'ldr x9, [x16, #0x208]'),
        (0xfffffe000c520a78, 'mov w1, #0'),
        (0xfffffe000c520a84, 'blraa x9, x17'),
        (0xfffffe000c520aa0, 'ldr x9, [x16, #0x218]'),
        (0xfffffe000c520aa4, 'mov w1, #0'),
        (0xfffffe000c520ab0, 'blraa x9, x17'),
        (0xfffffe000c520ab8, 'cbnz x0, #0xfffffe000c520884'),
    ),
}

BINDINGS = (
    (CLIENT, 0x638, '__ZN9IOService8finalizeEj', '0x5219'),
    (CLIENT, 0x640, '__ZN9IOService18lockForArbitrationEb', '0xc6b2'),
    (CLIENT, 0x648, '__ZN9IOService20unlockForArbitrationEv', '0x8a43'),
    (CLIENT, 0x6b8, '__ZNK9IOService11getWorkLoopEv', '0x638e'),
    (CLIENT, 0x6c0, '__ZNK9IOService19getProviderIteratorEv', '0x61a6'),
    (CLIENT, 0x6d0, '__ZNK9IOService9getClientEv', '0x136b'),
    (CLIENT, 0x5f8, f'__ZN{CLIENT}4stopEP9IOService', '0xb085'),
    (CLIENT, 0x6a8, '__ZN9IOService6detachEPS_', '0x7318'),
    (PROVIDER, 0x608, '__ZN9IOService5closeEPS_j', '0x639f'),
    (PROVIDER, 0x610, '__ZNK9IOService6isOpenEPKS_', '0xccfb'),
    (PROVIDER, 0x640, '__ZN9IOService18lockForArbitrationEb', '0xc6b2'),
    (PROVIDER, 0x648, '__ZN9IOService20unlockForArbitrationEv', '0x8a43'),
    ('7OSArray', 0x1e8, '__ZN7OSArray9setObjectEPK15OSMetaClassBase', '0xc302'),
    ('7OSArray', 0x208, '__ZN7OSArray12removeObjectEj', '0x404b'),
    ('7OSArray', 0x218, '__ZNK7OSArray9getObjectEj', '0x8453'),
    ('5OSSet', 0x1f0, '__ZN5OSSet9setObjectEPK15OSMetaClassBase', '0x5467'),
    ('10IOWorkLoop', 0x198, '__ZN10IOWorkLoop8openGateEv', '0x1ba6'),
    ('10IOWorkLoop', 0x1a0, '__ZN10IOWorkLoop9closeGateEv', '0x3946'),
    ('10IOWorkLoop', 0x1c0,
     '__ZN10IOWorkLoop9runActionEPFiP8OSObjectPvS2_S2_S2_ES1_S2_S2_S2_S2_', '0x7dda'),
)


def worker_callers(image):
    section, = (
        section for section in image.entries['com.apple.kernel']['sections']
        if (section['segment'], section['section']) == ('__TEXT_EXEC', '__text')
    )
    start, size = section['address'], section['size']
    assert (start, size) == (0xfffffe000bce1000, 10_181_168)
    callers = []
    for index, (word,) in enumerate(iter_unpack('<I', image.read(start, size))):
        if word >> 26 not in (0b000101, 0b100101):  # B or BL immediate
            continue
        imm26 = ((word & 0x3ffffff) ^ 0x2000000) - 0x2000000
        pc = start + 4 * index
        if pc + 4 * imm26 == WORKER:
            callers.append(pc)
    assert tuple(callers) == EXPECTED_CALLERS
    return {
        'section_start': hex(start),
        'section_size_bytes': size,
        'words_scanned': size // 4,
        'direct_branch_sites': [hex(site) for site in callers],
    }


def verify_image(image):
    assert image.named('__ZN9IOService15terminateWorkerEj') == WORKER
    assert image.named('__ZN9IOService8finalizeEj') == 0xfffffe000c525d34

    evidence = {}
    for group, sites in INSTRUCTIONS.items():
        evidence[group] = {}
        for pc, expected in sites:
            word, = image.instructions(pc, 4)
            actual = f'{word.mnemonic} {word.op_str}'.rstrip()
            assert actual == expected, (hex(pc), expected, actual)
            evidence[group][hex(pc)] = {'bytes': word.bytes.hex(), 'instruction': actual}

    bindings = {}
    for class_name, offset, target_name, diversity in BINDINGS:
        slot = image.named(f'__ZTV{class_name}') + 0x10 + offset
        pointer = image.pointer(slot)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (
            hex(image.named(target_name)), 1, diversity,
        )
        bindings[f'{class_name}+{offset:#x}'] = {'symbol': target_name, **pointer}
    return {
        'collection_identities': IDENTITIES[1],
        'instruction_count': sum(map(len, evidence.values())),
        'original_instructions': evidence,
        'vtable_bindings': bindings,
        'worker_callers': worker_callers(image),
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
