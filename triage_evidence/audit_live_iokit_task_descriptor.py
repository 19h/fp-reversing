#!/usr/bin/env python3
"""Capture the installed selector 26 task descriptor and its VM segment contract."""

import argparse
import json
from pathlib import Path

from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import descriptor_slots, imported_call, words


def audit(image):
    slots = descriptor_slots(image, 'IOGeneralMemoryDescriptor', {
        0x138: 'initWithOptions', 0x150: 'dmaCommandOperation',
        0x158: 'getPhysicalSegment', 0x218: 'prepare', 0x220: 'complete',
    })
    expected_targets = {
        '0x138': '0xfffffe000c586d74', '0x150': '0xfffffe000c585c3c',
        '0x158': '0xfffffe000c585958', '0x218': '0xfffffe000c584a08',
        '0x220': '0xfffffe000c584080',
    }
    assert {slot: entry['address'] for slot, entry in slots.items()} == expected_targets
    assert slots['0x150']['fixup']['slot'] == '0xfffffe0007f50fe8'
    assert slots['0x150']['fixup']['diversity'] == '0xa8a7'

    factory_pc = 0xfffffe000a546364
    factory = imported_call(image, factory_pc, 'withAddressRange')
    assert factory['address'] == '0xfffffe000c589f88'
    calls = {'factory': {'call': hex(factory_pc), **factory}}
    for name, pc, target in (
        ('wire', 0xfffffe000c584b44, 0xfffffe000c584c78),
        ('task_map_upl', 0xfffffe000c585320, 0xfffffe000be4734c),
        ('first_pfn', 0xfffffe000c586484, 0xfffffe000be4c244),
        ('following_pfn', 0xfffffe000c5864e0, 0xfffffe000be4c244),
        ('upl_commit_family', 0xfffffe000c584364, 0xfffffe000be74870),
        ('upl_deallocation_family', 0xfffffe000c58436c, 0xfffffe000be45170),
    ):
        assert image.branch(pc, 'bl') == target
        calls[name] = {'call': hex(pc), 'target': hex(target), 'symbols': image.names(target)}
    assert '_upl_phys_page' in calls['first_pfn']['symbols']

    checks = (
        (0xfffffe000a54635c, 'mov', 'w2, #3'),
        (0xfffffe000a546360, 'mov', 'x3, x4'),
        (0xfffffe000a54639c, 'blraa', 'x8, x16'),
        (0xfffffe000a5463a0, 'cbz', 'w0, #0xfffffe000a5463b4'),
        (0xfffffe000a54654c, 'blraa', 'x8, x16'),
        (0xfffffe000a546564, 'blraa', 'x8, x16'),
        (0xfffffe000c589fa4, 'stp', 'x0, x1, [sp]'),
        (0xfffffe000c589fd4, 'mov', 'w8, #0x10'),
        (0xfffffe000c589fd8, 'mov', 'w9, #0x20'),
        (0xfffffe000c589fdc, 'csel', 'w8, w9, w8, eq'),
        (0xfffffe000c58a000, 'orr', 'w5, w8, w20'),
        (0xfffffe000c58a01c, 'blraa', 'x9, x16'),
        (0xfffffe000c584ae0, 'str', 'w9, [x0, #0x88]'),
        (0xfffffe000c585054, 'and', 'x9, x26, #0x3fff'),
        (0xfffffe000c585058, 'and', 'x26, x26, #0xffffffffffffc000'),
        (0xfffffe000c5853a8, 'stp', 'x8, x9, [sp, #0x68]'),
        (0xfffffe000c585430, 'ldp', 'q0, q1, [sp, #0x60]'),
        (0xfffffe000c58543c, 'str', 'x9, [x8, #0x20]'),
        (0xfffffe000c585ae0, 'strb', 'w8, [sp, #0x20]'),
        (0xfffffe000c585b08, 'mov', 'w1, #1'),
        (0xfffffe000c585b0c, 'movk', 'w1, #0x100, lsl #16'),
        (0xfffffe000c585b10, 'mov', 'w3, #0x40'),
        (0xfffffe000c585b18, 'blraa', 'x8, x16'),
        (0xfffffe000c586230, 'ldr', 'w10, [x0, #0x88]'),
        (0xfffffe000c586234, 'cbz', 'w10, #0xfffffe000c5865b0'),
        (0xfffffe000c586284, 'lsr', 'x14, x14, #5'),
        (0xfffffe000c586478, 'lsr', 'w20, w23, #0xe'),
        (0xfffffe000c586490, 'and', 'x9, x23, #0x3fff'),
        (0xfffffe000c586494, 'orr', 'x23, x9, x8, lsl #14'),
        (0xfffffe000c5864d4, 'b.ne', '#0xfffffe000c5864fc'),
        (0xfffffe000c586500, 'csel', 'x21, x26, x21, lo'),
        (0xfffffe000c586550, 'stp', 'x23, x21, [x2, #8]'),
        (0xfffffe000c5841cc, 'str', 'w8, [x0, #0x88]'),
        (0xfffffe000c5841d4, 'cbnz', 'w8, #0xfffffe000c584428'),
        (0xfffffe000c5842b4, 'ldrh', 'w8, [x0, #0x34]'),
        (0xfffffe000c5843d8, 'mov', 'w1, #0x30'),
    )
    for check in checks:
        image.instruction(*check)

    bounds = {
        'provider': (0xfffffe000a546350, 0xfffffe000a546574),
        'range': (0xfffffe000c589f88, 0xfffffe000c58a05c),
        'prepare': (0xfffffe000c584a08, 0xfffffe000c584c78),
        'wire': (0xfffffe000c584c78, 0xfffffe000c58545c),
        'segment': (0xfffffe000c585958, 0xfffffe000c585c3c),
        'walk_selector': (0xfffffe000c585c3c, 0xfffffe000c585ef0),
        'virtual_walk': (0xfffffe000c5861b0, 0xfffffe000c586584),
        'complete': (0xfffffe000c584080, 0xfffffe000c5843f4),
    }
    windows = {name: words(image, start, end - start) for name, (start, end) in bounds.items()}
    return {
        'scope': 'Static data flow in the installed collection, ordinary virtual-range branch',
        'identity': dict(zip(('sha256', 'kernel_uuid', 'kext_uuid'), IDENTITIES[1])),
        'slots': slots, 'bindings': calls, 'checks': len(checks), 'windows': windows,
        'instruction_count': sum(map(len, windows.values())),
        'native_transfer_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(audit(image), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
