#!/usr/bin/env python3
"""Verify task provenance across the installed FairPlayIOKit open and selector 26."""

import argparse
import json
from pathlib import Path

from audit_live_kext_selector26 import (
    CLIENT, IDENTITIES, PROVIDER, Collection, method_map, mig_map, selector26,
    synchronous_path,
)
from audit_live_kext_selector26_transfer import descriptor_slots, words


def audit(image):
    methods = method_map(image)
    mig = mig_map(image)
    dispatch = synchronous_path(image, methods, mig)
    method = selector26(image, methods)
    assert mig['routines'][2862]['stub']['target'] == '0xfffffe000be81ac4'
    assert mig['routines'][2865]['stub']['target'] == '0xfffffe000be8152c'
    assert dispatch['connection_import'] == '0xfffffe000be7e2c0'
    assert method['provider_slot']['target'] == '0xfffffe000a546328'
    assert method['factory_slot']['target'] == '0xfffffe000c589f88'
    slots = {
        'provider': descriptor_slots(image, PROVIDER[2:], {0x7a0: 'newUserClient'}),
        'client': descriptor_slots(image, CLIENT[2:], {
            0x6a0: 'attach', 0x5f0: 'start', 0x910: 'initWithTask', 0x918: 'initWithTask',
        }),
    }
    for bindings, expected in (
        (slots['provider'], {0x7a0: (0xfffffe000c51b630, '0x82cd')}),
        (slots['client'], {
            0x6a0: (0xfffffe000c5248c4, '0x9be9'),
            0x5f0: (0xfffffe000a5454b0, '0x3c68'),
            0x910: (0xfffffe000c5b2194, '0xbde5'),
            0x918: (0xfffffe000a545264, '0x5cf5'),
        }),
    ):
        for slot, (target, diversity) in expected.items():
            match = bindings[hex(slot)]
            assert (match['address'], match['fixup']['auth'],
                    match['fixup']['diversity']) == (hex(target), 1, diversity)

    checks = (
        (0xfffffe000be81b64, 'ldr', 'x16, [x25, #0x24]!'),
        (0xfffffe000be81bf0, 'mov', 'x1, x21'),
        (0xfffffe000be81c84, 'stur', 'x17, [x24, #0x24]'),
        (0xfffffe000bd41f34, 'ldr', 'x16, [x17, #0xc0]!'),
        (0xfffffe000bd41f44, 'cmp', 'x19, x16'),
        (0xfffffe000c5bdd38, 'cbz', 'x20, #0xfffffe000c5bdd10'),
        (0xfffffe000c5bdd48, 'cmp', 'x20, x0'),
        (0xfffffe000c5bdd4c, 'b.eq', '#0xfffffe000c5bdd58'),
        (0xfffffe000c5bdda8, 'mov', 'x1, x20'),
        (0xfffffe000c5bddac, 'mov', 'x2, x20'),
        (0xfffffe000c51b664, 'mov', 'x24, x1'),
        (0xfffffe000c51b8d4, 'mov', 'x1, x24'),
        (0xfffffe000c51b94c, 'str', 'x26, [x20]'),
        (0xfffffe000c5b21b4, 'mov', 'x21, x1'),
        (0xfffffe000c5b21e8, 'mov', 'x1, x21'),
        (0xfffffe000a545290, 'mov', 'x20, x1'),
        (0xfffffe000a545448, 'mov', 'x1, x20'),
        (0xfffffe000a545468, 'cbz', 'x20, #0xfffffe000a5453b0'),
        (0xfffffe000a54546c, 'cbz', 'w8, #0xfffffe000a5453b0'),
        (0xfffffe000a545470, 'stp', 'xzr, x20, [x19, #0xd8]'),
        (0xfffffe000a545524, 'str', 'x0, [x20, #0xd8]'),
        (0xfffffe000a545530, 'ldr', 'x3, [x20, #0xe0]'),
        (0xfffffe000a5455dc, 'stp', 'xzr, xzr, [x20, #0xd8]'),
        (0xfffffe000be7e830, 'mov', 'w1, #0x27'),
        (0xfffffe000be7e2f8, 'cmp', 'w8, #0x27'),
        (0xfffffe000be7e304, 'ldr', 'x16, [x17, #0x50]!'),
        (0xfffffe000be7e30c, 'autda', 'x16, x17'),
        (0xfffffe000be7e334, 'blraa', 'x8, x16'),
        (0xfffffe000a5451f0, 'ldp', 'x4, x3, [x0, #0xe0]'),
        (0xfffffe000a546360, 'mov', 'x3, x4'),
        (0xfffffe000c589f9c, 'mov', 'x19, x3'),
        (0xfffffe000c58a010, 'mov', 'x4, x19'),
        (0xfffffe000c586fd0, 'str', 'x4, [x19, #0x70]'),
        (0xfffffe000c584f10, 'ldr', 'x17, [x19, #0x70]'),
        (0xfffffe000c584f2c, 'ldr', 'x16, [x17, #0x28]!'),
        (0xfffffe000c584f3c, 'autda', 'x16, x17'),
        (0xfffffe000c584f40, 'str', 'x16, [sp, #0x40]'),
        (0xfffffe000c585090, 'ldr', 'x8, [sp, #0x40]'),
        (0xfffffe000c585094, 'mov', 'x22, x8'),
        (0xfffffe000c585310, 'mov', 'x0, x22'),
    )
    for check in checks:
        image.instruction(*check)

    branches = {
        0xfffffe000be81bb4: 0xfffffe000bd41ef4,
        0xfffffe000bd41f18: 0xfffffe000bdc68b8,
        0xfffffe000bd41fb0: 0xfffffe000bd99ff0,
        0xfffffe000be81bf4: 0xfffffe000c5bdc84,
        0xfffffe000be81c00: 0xfffffe000bd9a07c,
        0xfffffe000be81c64: 0xfffffe000be7e814,
        0xfffffe000be7e834: 0xfffffe000c5b07cc,
        0xfffffe000c5bdd44: 0xfffffe000bdc68b8,
        0xfffffe000c5c00e4: 0xfffffe000bdc68b8,
        0xfffffe000c5c00f8: 0xfffffe000c589f88,
        0xfffffe000c5c0148: 0xfffffe000bdc68b8,
        0xfffffe000c5c015c: 0xfffffe000c589f88,
        0xfffffe000c585320: 0xfffffe000be4734c,
    }
    for call, target in branches.items():
        assert image.branch(call, 'bl') == target

    bounds = {
        'open_stub': (0xfffffe000be81b4c, 0xfffffe000be81cac),
        'open_task_conversion': (0xfffffe000bd41ef4, 0xfffffe000bd41fc8),
        'open_impl': (0xfffffe000c5bdc84, 0xfffffe000c5bdde8),
        'constructor_inlet': (0xfffffe000c51b630, 0xfffffe000c51b6fc),
        'constructor_publication': (0xfffffe000c51b8bc, 0xfffffe000c51b950),
        'generic_initializer': (0xfffffe000c5b2194, 0xfffffe000c5b2214),
        'fairplay_initializer': (0xfffffe000a545264, 0xfffffe000a5454b0),
        'fairplay_start_stop': (0xfffffe000a5454b0, 0xfffffe000a5455f4),
        'connection_export': (0xfffffe000be7e814, 0xfffffe000be7e870),
        'connection_import': (0xfffffe000be7e2c0, 0xfffffe000be7e3b8),
        'method_stub': (0xfffffe000be81620, 0xfffffe000be816fc),
        'method_optional_descriptors': (0xfffffe000c5c00dc, 0xfffffe000c5c0178),
        'fairplay_handler': (0xfffffe000a5451c4, 0xfffffe000a545264),
        'fairplay_range_factory': (0xfffffe000a546350, 0xfffffe000a546368),
        'range_factory': (0xfffffe000c589f88, 0xfffffe000c58a020),
        'descriptor_initializer_task': (0xfffffe000c586f78, 0xfffffe000c586fe0),
        'wire_task_map': (0xfffffe000c584ef4, 0xfffffe000c584f68),
        'wire_ordinary_map_selection': (0xfffffe000c585090, 0xfffffe000c5850cc),
        'wire_task_map_request': (0xfffffe000c585300, 0xfffffe000c585324),
    }
    windows = {name: words(image, start, end - start) for name, (start, end) in bounds.items()}
    return {
        'scope': 'Installed static object and task lineage, normal open and inline method',
        'identity': dict(zip(('sha256', 'kernel_uuid', 'kext_uuid'), IDENTITIES[1])),
        'port_dispatch': {str(msg): mig['routines'][msg] for msg in (2862, 2865)},
        'slots': slots, 'method_dispatch': dispatch, 'selector26': method,
        'direct_calls': {hex(k): hex(v) for k, v in branches.items()},
        'checks': len(checks), 'windows': windows,
        'instruction_count': sum(map(len, windows.values())),
        'native_join_observed': False,
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
