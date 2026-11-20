#!/usr/bin/env python3
"""Verify task-suspension notification bindings for the installed FairPlay classes."""

import argparse
import json
import plistlib
import re
import subprocess
from pathlib import Path

from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_iokit_open_owner import SERVICE
from audit_live_iokit_reference_cleanup import verify_host_identity
from audit_live_kext_selector26 import CLIENT, IDENTITIES, PROVIDER, Collection

PROPERTY = 'IOUserClientMessageAppSuspended'
PROPERTY_ADDRESS = 0xfffffe00070e12de
BLOCK = 0xfffffe0007f5d960
INSTRUCTIONS = {
    'open_subscription_and_owner_publication': (
        (0xfffffe000c5bdf38, 'ldrb w8, [x0, #0x9b]'),
        (0xfffffe000c5bdf40, 'tbnz w8, #5, #0xfffffe000c5be004'),
        (0xfffffe000c5bdf44, 'orr w8, w8, #0x20'),
        (0xfffffe000c5bdf48, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5bdf5c, 'mov x17, #0x2d8'),
        (0xfffffe000c5bdf68, 'adrp x1, #0xfffffe00070e1000'),
        (0xfffffe000c5bdf6c, 'add x1, x1, #0x2de'),
        (0xfffffe000c5bdf70, 'movk x16, #0x37a5, lsl #48'),
        (0xfffffe000c5bdf74, 'blraa x8, x16'),
        (0xfffffe000c5bdf78, 'cmp x0, #0'),
        (0xfffffe000c5bdf80, 'ldrb w8, [x0, #0x9b]'),
        (0xfffffe000c5bdf84, 'and w8, w8, #0xfe'),
        (0xfffffe000c5bdf88, 'cinc w8, w8, ne'),
        (0xfffffe000c5bdf8c, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5b7c30, 'str x0, [x8]'),
        (0xfffffe000c5b7c34, 'ldrb w8, [x21, #0x9b]'),
        (0xfffffe000c5b7c38, 'tbz w8, #0, #0xfffffe000c5b7c50'),
        (0xfffffe000c5b7c3c, 'add x8, x20, #0x6c8'),
        (0xfffffe000c5b7c40, 'mov w9, #0x80'),
        (0xfffffe000c5b7c44, 'ldset w9, w8, [x8]'),
        (0xfffffe000c5b7c4c, 'strb w8, [x20, #0x17]'),
    ),
    'task_state_and_notification_callers': (
        (0xfffffe000bd8ed34, 'ldrb w8, [x19, #0x442]'),
        (0xfffffe000bd8ed38, 'tbnz w8, #0, #0xfffffe000bd8edc4'),
        (0xfffffe000bd8ed3c, 'mov w8, #1'),
        (0xfffffe000bd8ed40, 'strb w8, [x19, #0x442]'),
        (0xfffffe000bd8edc0, 'strb wzr, [x19, #0x442]'),
        (0xfffffe000bd8ee78, 'casl w2, wzr, [x10]'),
        (0xfffffe000bd8ee84, 'b.ne #0xfffffe000bd8ef28'),
        (0xfffffe000bd8ee88, 'ldr w8, [x19, #0x6c8]'),
        (0xfffffe000bd8ee8c, 'tbnz w8, #7, #0xfffffe000bd8ef3c'),
        (0xfffffe000bd8ef34, 'ldr w8, [x19, #0x6c8]'),
        (0xfffffe000bd8ef38, 'tbz w8, #7, #0xfffffe000bd8ee90'),
        (0xfffffe000bd8ef3c, 'mov x0, x19'),
        (0xfffffe000bd8ef40, 'bl #0xfffffe000c5b7cb4'),
        (0xfffffe000bd8efb8, 'mov w1, #1'),
        (0xfffffe000bd8efbc, 'bl #0xfffffe000bd87cb0'),
        (0xfffffe000bd8efcc, 'casl w2, wzr, [x21]'),
        (0xfffffe000bd8efdc, 'cbnz w0, #0xfffffe000bd8eff4'),
        (0xfffffe000bd8efe0, 'ldr w8, [x19, #0x6c8]'),
        (0xfffffe000bd8efe4, 'tbz w8, #7, #0xfffffe000bd8eff0'),
        (0xfffffe000bd8efe8, 'mov x0, x19'),
        (0xfffffe000bd8efec, 'bl #0xfffffe000c5b7cb4'),
        (0xfffffe000bd87d98, 'ldrb w8, [x0, #0x442]'),
        (0xfffffe000bd87db0, 'strb wzr, [x0, #0x442]'),
        (0xfffffe000bdc6dfc, 'ldrb w8, [x0, #0x442]'),
        (0xfffffe000bdc6e00, 'and w0, w8, #1'),
    ),
    'owner_scan_and_dispatch': (
        (0xfffffe000c5b7cd8, 'ldr x8, [x22, #0x898]'),
        (0xfffffe000c5b7cf0, 'casa x2, x9, [x11]'),
        (0xfffffe000c5b7cfc, 'add x24, x0, #0x650'),
        (0xfffffe000c5b7d00, 'ldr x25, [x0, #0x650]'),
        (0xfffffe000c5b7d08, 'b.eq #0xfffffe000c5b7e58'),
        (0xfffffe000c5b7d2c, 'mov x17, #0x1f0'),
        (0xfffffe000c5b7d40, 'blraa x8, x16'),
        (0xfffffe000c5b7d44, 'ldr x25, [x25, #8]'),
        (0xfffffe000c5b7d50, 'ldr x1, [x25, #0x18]'),
        (0xfffffe000c5b7d54, 'ldrb w8, [x1, #0x9b]'),
        (0xfffffe000c5b7d58, 'tbz w8, #0, #0xfffffe000c5b7d44'),
        (0xfffffe000c5b7d5c, 'cbnz x20, #0xfffffe000c5b7d1c'),
        (0xfffffe000c5b7dac, 'mov w1, #4'),
        (0xfffffe000c5b7db4, 'blraa x8, x16'),
        (0xfffffe000c5b7db8, 'tbz w0, #0, #0xfffffe000c5b7e40'),
        (0xfffffe000c5b7dd8, 'casl w2, wzr, [x9]'),
        (0xfffffe000c5b7de8, 'cbz x20, #0xfffffe000c5b7e7c'),
        (0xfffffe000c5b7dec, 'adrp x1, #0xfffffe0007f5d000'),
        (0xfffffe000c5b7df0, 'add x1, x1, #0x960'),
        (0xfffffe000c5b7df4, 'mov x0, x20'),
        (0xfffffe000c5b7df8, 'bl #0xfffffe000c497f68'),
        (0xfffffe000c5b7e3c, 'braa x16, x17'),
        (0xfffffe000c5b7eec, 'mov x0, x1'),
        (0xfffffe000c5b7f00, 'mov x17, #0x760'),
        (0xfffffe000c5b7f0c, 'mov w1, #0x800'),
        (0xfffffe000c5b7f10, 'movk w1, #0xe000, lsl #16'),
        (0xfffffe000c5b7f14, 'mov x2, #0'),
        (0xfffffe000c5b7f18, 'mov x3, #0'),
        (0xfffffe000c5b7f1c, 'movk x16, #0x7f14, lsl #48'),
        (0xfffffe000c5b7f20, 'blraa x8, x16'),
        (0xfffffe000c5b7f24, 'mov w0, #0'),
    ),
    'base_reply_and_removal_update': (
        (0xfffffe000c51cc14, 'mov w0, #0x2c7'),
        (0xfffffe000c51cc18, 'movk w0, #0xe000, lsl #16'),
        (0xfffffe000c51cc1c, 'ret'),
        (0xfffffe000c5b5d84, 'ldr x10, [x9, #0x18]'),
        (0xfffffe000c5b5d88, 'ldrb w10, [x10, #0x9b]'),
        (0xfffffe000c5b5d8c, 'tbnz w10, #0, #0xfffffe000c5b5db0'),
        (0xfffffe000c5b5d98, 'b.ne #0xfffffe000c5b5d84'),
        (0xfffffe000c5b5d9c, 'mov w9, #0'),
        (0xfffffe000c5b5da4, 'add x10, x8, #0x6c8'),
        (0xfffffe000c5b5da8, 'ldclr w25, w10, [x10]'),
        (0xfffffe000c5b5db4, 'add x9, x8, #0x6c8'),
        (0xfffffe000c5b5db8, 'ldset w25, w9, [x9]'),
        (0xfffffe000c5b5dbc, 'mov w9, #1'),
        (0xfffffe000c5b5dc0, 'strb w9, [x8, #0x17]'),
    ),
}


def verify_image(image):
    groups = {}
    for label, sites in INSTRUCTIONS.items():
        group = {}
        for pc, expected in sites:
            word, = image.instructions(pc, 4)
            actual = f'{word.mnemonic} {word.op_str}'.rstrip()
            assert actual == expected, (hex(pc), expected, actual)
            group[hex(pc)] = {'bytes': word.bytes.hex(), 'instruction': actual}
        groups[label] = group

    encoded = PROPERTY.encode() + bytes(1)
    assert image.read(PROPERTY_ADDRESS, len(encoded)) == encoded
    assert image.named('_task_is_app_suspended') == 0xfffffe000bdc6df8
    assert image.named('__ZN12OSCollection14iterateObjectsEU13block_pointerFbP8OSObjectE') == (
        0xfffffe000c497f68
    )
    message = image.named('__ZN9IOService7messageEjPS_Pv')
    assert message == 0xfffffe000c51cc10
    bindings = {}
    for class_name in (CLIENT, PROVIDER):
        table = image.named(f'__ZTV{class_name}') + 0x10
        bindings[class_name] = verify_fixup(image, table + 0x760, message, '0x7f14', 1)
    client_table = image.named(f'__ZTV{CLIENT}') + 0x10
    get_property = image.named('__ZNK15IORegistryEntry11getPropertyEPKc')
    bindings['client_get_property'] = verify_fixup(
        image, client_table + 0x2d8, get_property, '0x37a5', 1,
    )
    insert = image.named('__ZN5OSSet9setObjectEPK15OSMetaClassBase')
    set_table = image.named('__ZTV5OSSet') + 0x10
    bindings['snapshot_insert'] = verify_fixup(
        image, set_table + 0x1f0, insert, '0x5467', 1,
    )

    callback = image.pointer(BLOCK + 16)
    assert (callback['target'], callback['format'], callback['auth'],
            callback['address_diversity'], callback['key'], callback['diversity']) == (
        '0xfffffe000c5b7ee0', 8, 1, 1, 0, '0x0',
    )
    return {
        'collection_identities': IDENTITIES[1],
        'instruction_count': sum(map(len, groups.values())),
        'original_instructions': groups,
        'opt_in_property': {'address': hex(PROPERTY_ADDRESS), 'name': PROPERTY},
        'vtable_bindings': bindings,
        'owner_snapshot_block': callback,
        'static_message_type': '0xe0000800',
        'base_message_result': '0xe00002c7',
    }


def snapshot_registry():
    service, = plistlib.loads(subprocess.check_output(
        ['ioreg', '-a', '-r', '-c', SERVICE, '-l', '-d', '2'],
    ))
    children = []
    for child in service.get('IORegistryEntryChildren', ()):
        if child['IOObjectClass'] != SERVICE + 'UserClient':
            continue
        pid, creator = re.fullmatch(
            r'pid (\d+), ([a-zA-Z0-9_.-]+)', child['IOUserClientCreator'],
        ).groups()
        children.append({
            'entry': hex(child['IORegistryEntryID']),
            'pid': int(pid),
            'creator': creator,
            'property_present': PROPERTY in child,
        })
    return {
        'service_entry': hex(service['IORegistryEntryID']),
        'provider_property_present': PROPERTY in service,
        'children': sorted(children, key=lambda entry: entry['entry']),
    }


def observe():
    identity = verify_host_identity()
    first = snapshot_registry()
    assert first == snapshot_registry()
    return {'host_identity': identity, 'registry': first}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true', help='check host and registry')
    args = parser.parse_args()
    result = {'kernel': verify_image(Collection(args.collection, IDENTITIES[1]))}
    if args.observe:
        result['current_observation'] = observe()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
