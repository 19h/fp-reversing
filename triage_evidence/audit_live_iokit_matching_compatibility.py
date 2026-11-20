#!/usr/bin/env python3
"""Check installed registry matching and compatible property selection."""

import argparse
from itertools import product
import json
from pathlib import Path
import struct

from audit_live_iokit_discovery import archived_discovery
from audit_live_iokit_mach_transport import record_windows
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map


def installed(image):
    subsystem = int(mig_map(image)['subsystem'], 16)
    stubs = {}
    for msg_id, address in ((2804, 0xfffffe000be86344), (2857, 0xfffffe000be82270),
                            (2881, 0xfffffe000be7fe24)):
        pointer = image.pointer(subsystem + 40 + 32 * (msg_id - 2800))
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (
            hex(address), 1, '0x3a83')
        stubs[msg_id] = {'reply_id': msg_id + 100, **pointer}
    symbols = {}
    for symbol, address in (
        ('_get_bsdtask_info', 0xfffffe000bdc5de0),
        ('_proc_is_translated', 0xfffffe000c30e1a4),
        ('__ZN22IOServiceCompatibility10gMetaClassE', 0xfffffe000cbd7940),
        ('__ZNK11OSMetaClass16getInstanceCountEv', 0xfffffe000c492ee0),
        ('__ZNK11OSMetaClass19instanceConstructedEv', 0xfffffe000c4922b4),
        ('__ZNK11OSMetaClass18instanceDestructedEv', 0xfffffe000c4922d4),
        ('__ZN9IOService19getMatchingServicesEP12OSDictionary', 0xfffffe000c53bd24),
        ('_gIOCompatibilityMatchKey', 0xfffffe000cbd78b8),
        ('_gIOCompatibilityPropertiesKey', 0xfffffe000cbd78c8),
        ('_kOSBooleanTrue', 0xfffffe0007f97cd8),
    ):
        assert image.named(symbol) == address
        symbols[symbol] = hex(address)
    boolean_true = image.pointer(image.named('_kOSBooleanTrue'))
    assert boolean_true['target'] == '0xfffffe000cc1ed10'
    dictionary_slots = {}
    for offset, name, discriminator in (
        (0x1f0, '__ZN12OSDictionary9setObjectEPK8OSSymbolPK15OSMetaClassBase', '0x8d9e'),
        (0x228, '__ZNK12OSDictionary9getObjectEPK8OSSymbol', '0x5837'),
    ):
        pointer = image.pointer(image.named('__ZTV12OSDictionary') + 16 + offset)
        assert (int(pointer['target'], 16), pointer['auth'], pointer['diversity']) == (
            image.named(name), 1, discriminator)
        dictionary_slots[name] = pointer

    literals = {}
    for string, literal, start, store in (
        ('IOServiceNotificationUser', 0xfffffe00070dbc99, 0xfffffe000c537410, 0x910),
        ('IOCompatibilityMatch', 0xfffffe00070db8e8, 0xfffffe000c536f60, 0x8b8),
        ('IOCompatibilityProperties', 0xfffffe00070db8fd, 0xfffffe000c536f74, 0x8c8),
        ('IOUserServiceProperties', 0xfffffe00070e00c2, 0xfffffe000c536fb0, 0xc48),
    ):
        word = string.encode() + b'\0'
        assert image.read(literal, len(word)) == word
        image.instruction(start, 'adrp', f'x0, #{literal & ~0xfff:#x}')
        image.instruction(start + 4, 'add', f'x0, x0, #{literal & 0xfff:#x}')
        assert image.branch(start + 8, 'bl') == image.named('__ZN8OSSymbol17withCStringNoCopyEPKc')
        image.instruction(start + 12, 'adrp', 'x8, #0xfffffe000cbd7000')
        image.instruction(start + 16, 'str', f'x0, [x8, #{store:#x}]')
        literals[string] = {'literal': hex(literal), 'init': hex(start), 'cell': hex(0xfffffe000cbd7000 + store)}
    instructions = (
        (0xfffffe000be7fec0, 'bl', '#0xfffffe000c5b9628'),
        (0xfffffe000be82330, 'bl', '#0xfffffe000c5b9580'),
        (0xfffffe000c5b95f4, 'bl', '#0xfffffe000c5b9628'),
        (0xfffffe000c5b95f8, 'str', 'w0, [x20]'),
        (0xfffffe000be82388, 'mov', 'w9, #0x40'),
        (0xfffffe000be863d0, 'mov', 'w8, #0x2c7'),
        (0xfffffe000be863d4, 'movk', 'w8, #0xe000, lsl #16'),
        (0xfffffe000be863f8, 'str', 'w8, [x3, #0x28]'),
        (0xfffffe000bd3c678, 'add', 'w8, w8, #0x64'),
        (0xfffffe000bd0f208, 'bl', '#0xfffffe000bd0fbf0'),
        (0xfffffe000c5b96c0, 'mrs', 'x0, tpidr_el1'),
        (0xfffffe000c5b96c4, 'bl', '#0xfffffe000bdc68b8'),
        (0xfffffe000bdc6930, 'ldr', 'x0, [x1, #0x28]'),
        (0xfffffe000bdc5de4, 'subs', 'x1, x0, #0x7c0'),
        (0xfffffe000bdc5e3c, 'csel', 'x0, xzr, x1, eq'),
        (0xfffffe000c5b96d0, 'ldr', 'x1, [x8, #0x910]'),
        (0xfffffe000c5b96d4, 'adrp', 'x21, #0xfffffe000cc1e000'),
        (0xfffffe000c5b96d8, 'ldr', 'x2, [x21, #0xd10]'),
        (0xfffffe000c5b96f8, 'blraa', 'x8, x16'),
        (0xfffffe000c5b96fc, 'cbz', 'x20, #0xfffffe000c5b9760'),
        (0xfffffe000c5b9704, 'bl', '#0xfffffe000bdc5de0'),
        (0xfffffe000c5b9708, 'cbz', 'x0, #0xfffffe000c5b9760'),
        (0xfffffe000c5b970c, 'ldrb', 'w8, [x0, #0x456]'),
        (0xfffffe000c5b9710, 'tbz', 'w8, #1, #0xfffffe000c5b9760'),
        (0xfffffe000c5b9714, 'ldr', 'w8, [x0, #0x620]'),
        (0xfffffe000c5b971c, 'ldr', 'w9, [x9, #0x964]'),
        (0xfffffe000c5b9720, 'mov', 'w10, #7'),
        (0xfffffe000c5b9724, 'movk', 'w10, #0x100, lsl #16'),
        (0xfffffe000c5b972c, 'ccmp', 'w9, #0, #4, eq'),
        (0xfffffe000c5b9730, 'b.eq', '#0xfffffe000c5b9760'),
        (0xfffffe000c5b9738, 'ldr', 'x1, [x8, #0x8b8]'),
        (0xfffffe000c5b975c, 'blraa', 'x8, x16'),
        (0xfffffe000c5b9764, 'bl', '#0xfffffe000c53bd24'),
        (0xfffffe000c30e1ac, 'ldr', 'w8, [x0, #0x454]'),
        (0xfffffe000c30e1b0, 'ubfx', 'w0, w8, #0x11, #1'),
        (0xfffffe000c492ee4, 'ldr', 'w0, [x0, #0x24]'),
        (0xfffffe000c4922bc, 'add', 'x9, x0, #0x24'),
        (0xfffffe000c4922c0, 'ldadd', 'w8, w9, [x9]'),
        (0xfffffe000c4922f0, 'add', 'x8, x0, #0x24'),
        (0xfffffe000c4922f8, 'ldadd', 'w9, w8, [x8]'),
        (0xfffffe000c53bd50, 'bl', '#0xfffffe000c523bbc'),
        (0xfffffe000c523d98, 'ldr', 'x1, [x9, #0x8b8]'),
        (0xfffffe000c523db8, 'blraa', 'x8, x16'),
        (0xfffffe000c523dbc, 'cbz', 'x0, #0xfffffe000c523de4'),
        (0xfffffe000c523dc4, 'add', 'x0, x0, #0x940'),
        (0xfffffe000c523de0, 'bl', '#0xfffffe000c4929dc'),
        (0xfffffe000c522ac8, 'ldr', 'x1, [x8, #0x8b8]'),
        (0xfffffe000c522af0, 'cbz', 'x0, #0xfffffe000c522b80'),
        (0xfffffe000c522afc, 'ldr', 'x1, [x8, #0x8c8]'),
        (0xfffffe000c522b1c, 'blraa', 'x8, x16'),
        (0xfffffe000c522c54, 'blraa', 'x8, x16'),
        (0xfffffe000c5bc008, 'bl', '#0xfffffe000c5bbdc0'),
        (0xfffffe000c5bcab0, 'bl', '#0xfffffe000c5bbdc0'),
        (0xfffffe000c5bbe00, 'cbnz', 'x0, #0xfffffe000c5bbf2c'),
        (0xfffffe000c5bbe10, 'ldr', 'x1, [x8, #0xc48]'),
        (0xfffffe000c5bbe34, 'cbz', 'x0, #0xfffffe000c5bbe7c'),
        (0xfffffe000c5bbe90, 'ldrb', 'w8, [x0, #0x456]'),
        (0xfffffe000c5bbe94, 'tbz', 'w8, #1, #0xfffffe000c5bbeb8'),
        (0xfffffe000c5bbe98, 'ldr', 'w8, [x0, #0x620]'),
        (0xfffffe000c5bbea0, 'ldr', 'w9, [x9, #0x964]'),
        (0xfffffe000c5bbeb0, 'ccmp', 'w9, #0, #4, eq'),
        (0xfffffe000c5bbeb4, 'b.ne', '#0xfffffe000c5bbf3c'),
        (0xfffffe000c5bbf40, 'ldr', 'x1, [x8, #0x8c8]'),
        (0xfffffe000c5bbee0, 'blraa', 'x8, x16'),
    )
    for pc, mnemonic, operands in instructions:
        image.instruction(pc, mnemonic, operands)
    truth_table = []
    for x86, has_instances in product((False, True), repeat=2):
        # CCMP compares the count on CPU equality and otherwise sets Z=1.
        zero_flag = not has_instances if x86 else True
        add_key = not zero_flag
        assert add_key == (x86 and has_instances)
        truth_table.append({'x86_64': x86, 'nonzero_instance_count': has_instances,
                            'add_compatibility_key_after_translation_check': add_key})
    return {
        'identity': IDENTITIES[1], 'stubs': stubs, 'symbols': symbols,
        'true_singleton': boolean_true, 'dictionary_slots': dictionary_slots,
        'literals': literals, 'instruction_assertion_count': len(instructions), 'truth_table': truth_table,
        'predicate_inputs': {'proc_translated_mask': '0x20000', 'proc_discriminator_offset_bytes': 0x620,
                             'x86_64': '0x1000007', 'compat_meta_instance_count_offset_bytes': 0x24},
        'windows': record_windows(image.read, (
            (0xfffffe000be86344, 0xc8), (0xfffffe000be82270, 0x13c), (0xfffffe000be7fe24, 0x140),
            (0xfffffe000c5b9580, 0xa8), (0xfffffe000c5b9628, 0x280), (0xfffffe000bdc68b8, 0x90),
            (0xfffffe000bdc5de0, 0x78), (0xfffffe000c30e1a4, 0x14),
            (0xfffffe000c492ee0, 0xc), (0xfffffe000c4922b4, 0x60),
            (0xfffffe000c523bbc, 0x244), (0xfffffe000c5229e8, 0x29c),
            (0xfffffe000c5bbdc0, 0x1ac),
        )),
    }


def archived(trace):
    record = archived_discovery(trace)
    packet = bytes.fromhex(record['transactions'][2]['send_hex'])
    # Exact serialized dictionary distinguishes an inserted kernel key from wire input.
    dictionary = (struct.pack('<III', 0xd3, 0x81000001, 0x08000010) + b'IOProviderClass\0'
                  + struct.pack('<I', 0x8900001e) + b'com_apple_driver_FairPlayIOKit\0\0')
    assert len(dictionary) == 64 and packet[36:] == dictionary
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps({'installed': installed(Collection(args.collection, IDENTITIES[1])),
                      'archive': archived(args.trace), 'native_compatibility_matching_observed': False},
                     indent=2, sort_keys=True))
