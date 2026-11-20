#!/usr/bin/env python3
"""Verify the kernel metaclass handoff for the registered FairPlay service."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from audit_live_fairplay_iokit_open import historical
from audit_live_fairplay_personality import CLIENT as CLASS_NAME, SERVICE, registry
from audit_live_iokit_mach_transport import record_windows
from audit_live_iokit_main_port import BUILD
from audit_live_kext_selector26 import CLIENT, PROVIDER, Collection, IDENTITIES


def installed(image):
    key = 'IOUserClientClass'
    for address, name in ((0xfffffe00070db808, key), (0xfffffe000791518a, CLASS_NAME)):
        assert image.read(address, len(name) + 1) == name.encode() + b'\0'
    assert image.named('_gIOUserClientClassKey') == 0xfffffe000cbd8400
    assert image.named('__ZN8OSSymbol10gMetaClassE') == 0xfffffe000cbce050
    assert image.named('__ZN8OSString10gMetaClassE') == 0xfffffe000cbce078
    assert image.named('__ZN12IOUserClient10gMetaClassE') == 0xfffffe000cbd7d20
    assert image.named('__ZN' + CLIENT + '10gMetaClassE') == 0xfffffe000cd47600

    instructions = (
        (0xfffffe000c536e28, 'bl', '#0xfffffe000c4d2ebc'),
        (0xfffffe000c536e30, 'str', 'x0, [x8, #0x400]'),
        (0xfffffe000c51b6ec, 'blraa', 'x8, x16'),
        (0xfffffe000c51b708, 'ldr', 'x1, [x8, #0x400]'),
        (0xfffffe000c51b728, 'blraa', 'x8, x16'),
        (0xfffffe000c51b764, 'b.eq', '#0xfffffe000c51b7c4'),
        (0xfffffe000c51b794, 'b.eq', '#0xfffffe000c51b7cc'),
        (0xfffffe000c51b7d4, 'bl', '#0xfffffe000c4d2dd8'),
        (0xfffffe000c51b820, 'blraa', 'x8, x16'),
        (0xfffffe000c51b82c, 'bl', '#0xfffffe000c4930c0'),
        (0xfffffe000c51b850, 'blraa', 'x8, x16'),
        (0xfffffe000c51b854, 'cbz', 'x26, #0xfffffe000c51b8b4'),
        (0xfffffe000c51b884, 'add', 'x8, x8, #0xd20'),
        (0xfffffe000c51b890, 'ldr', 'x0, [x0, #0x10]'),
        (0xfffffe000c51b8b4, 'sub', 'w19, w19, #0xa'),
        (0xfffffe000c51b8e8, 'blraa', 'x8, x16'),
        (0xfffffe000c4921a4, 'bl', '#0xfffffe000c4d2ebc'),
        (0xfffffe000c4921ac, 'str', 'x0, [x19, #0x18]'),
        (0xfffffe000c4921b0, 'ldr', 'x0, [x22, #0xd00]'),
        (0xfffffe000c4921cc, 'mov', 'x2, x19'),
        (0xfffffe000c4921d8, 'blraa', 'x9, x17'),
        (0xfffffe000c49310c, 'ldr', 'x0, [x8, #0xd00]'),
        (0xfffffe000c493138, 'blraa', 'x8, x16'),
        (0xfffffe000c49314c, 'ldadd', 'w9, w8, [x8]'),
        (0xfffffe000c493164, 'casl', 'w2, wzr, [x10]'),
        (0xfffffe000c493184, 'ldr', 'x8, [x16, #0xa8]!'),
        (0xfffffe000c493190, 'blraa', 'x8, x16'),
        (0xfffffe000c4931a0, 'ldadd', 'w9, w8, [x8]'),
        (0xfffffe000a545f0c, 'ldr', 'x2, [x2, #0x58]'),
        (0xfffffe000a545f10, 'mov', 'w3, #0xf8'),
        (0xfffffe000a545f14, 'bl', '#0xfffffe000a6e0304'),
        (0xfffffe000a545f30, 'str', 'x16, [x0]'),
        (0xfffffe000a544d44, 'mov', 'w1, #0xf8'),
        (0xfffffe000a544d48, 'bl', '#0xfffffe000a6e02f4'),
        (0xfffffe000a544d5c, 'bl', '#0xfffffe000a6e0334'),
        (0xfffffe000a544d78, 'str', 'x16, [x0]'),
        (0xfffffe000a544d80, 'bl', '#0xfffffe000a6e0414'),
    )
    for pc, mnemonic, operands in instructions:
        image.instruction(pc, mnemonic, operands)
    bindings = {}
    for table, offset, symbol, diversity in (
        (PROVIDER, 0x7a8, '__ZN9IOService13newUserClientEP4taskPvjPP12IOUserClient', '0x808e'),
        (PROVIDER, 0x2f8, '__ZNK15IORegistryEntry12copyPropertyEPK8OSSymbol', '0xb3b6'),
        (PROVIDER, 0x278, '__ZN15IORegistryEntry11setPropertyEPK8OSSymbolP8OSObject', '0x4578'),
        ('12OSDictionary', 0x228, '__ZNK12OSDictionary9getObjectEPK8OSSymbol', '0x5837'),
        ('12OSDictionary', 0x1f0, '__ZN12OSDictionary9setObjectEPK8OSSymbolPK15OSMetaClassBase', '0x8d9e'),
        ('N' + CLIENT + '9MetaClassE', 0xa8, '__ZNK' + CLIENT + '9MetaClass5allocEv', '0x1601'),
        (CLIENT, 0x38, '__ZNK' + CLIENT + '12getMetaClassEv', '0xfffc'),
        (CLIENT, 0x910, '__ZN12IOUserClient12initWithTaskEP4taskPvjP12OSDictionary', '0xbde5'),
    ):
        pointer = image.pointer(image.named('__ZTV' + table) + 16 + offset)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (
            hex(image.named(symbol)), 1, diversity)
        bindings[symbol] = pointer
    for pc, slot, symbol in (
        (0xfffffe000a6e0304, 0xfffffe0008492e88, '__ZN11OSMetaClassC2EPKcPKS_j'),
        (0xfffffe000a6e02f4, 0xfffffe0008492e80, '_OSObject_typed_operator_new'),
        (0xfffffe000a6e0334, 0xfffffe0008492ea0, '__ZN12IOUserClientC2EPK11OSMetaClass'),
        (0xfffffe000a6e0414, 0xfffffe0008492f10, '__ZNK11OSMetaClass19instanceConstructedEv'),
    ):
        image.instruction(pc, 'adrp', f'x17, #{slot & ~0xfff:#x}')
        image.instruction(pc + 4, 'add', f'x17, x17, #{slot & 0xfff:#x}')
        image.instruction(pc + 12, 'braa', 'x16, x17')
        pointer = image.pointer(slot)
        assert pointer['auth'] == 1 and int(pointer['target'], 16) == image.named(symbol)
        bindings[symbol] = pointer
    init = image.pointer(0xfffffe0008481058)
    assert int(init['target'], 16) == image.named('__GLOBAL__sub_I_FairPlayIOKitUserClient.cpp')
    assert image.pointer(0xfffffe0008493058)['target'] == '0xfffffe000cbd7d20'
    return {'fileset_identity': IDENTITIES[1], 'bindings': bindings, 'init_entry': init,
            'instruction_assertions': len(instructions) + 12, 'class_size_bytes': 248,
            'windows': record_windows(image.read, (
                (0xfffffe000c51b704, 0x194), (0xfffffe000c4921a0, 0x3c),
                (0xfffffe000c493108, 0xa0), (0xfffffe000a545ee8, 0x54),
                (0xfffffe000a544d28, 0x6c),
            ))}


def extracts(decompilation, calls):
    result = {}
    for path, token in (
        (decompilation, f'__ZNK{CLIENT}9MetaClass5allocEv'),
        (calls, f'__ZNK{CLIENT}9MetaClass5allocEv ->'),
    ):
        raw = path.read_bytes()
        lines = raw.decode().splitlines()
        if path == decompilation:
            offsets = [i for i, line in enumerate(lines) if token in line and '// --- Function:' in line]
            offset, = offsets
            body = '\n'.join(lines[offset:offset + 22])
            assert all(s in body for s in ('size: 0xF8u', 'OSObject_typed_operator_new',
                                           'IOUserClient::IOUserClient', 'OSMetaClass::instanceConstructed'))
        else:
            offset, = (i for i, line in enumerate(lines) if token in line)
            body = lines[offset]
            assert all(s in body for s in ('_OSObject_typed_operator_new', '__ZN12IOUserClientC2',
                                           '__ZNK11OSMetaClass19instanceConstructedEv'))
        result[path.suffix] = {'sha256': hashlib.sha256(raw).hexdigest(), 'allocator_line': offset + 1}
    return result


def observe():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]

    def counts():
        line = subprocess.check_output(['ioclasscount', SERVICE, CLASS_NAME], text=True)
        match = re.fullmatch(fr'{SERVICE} = (\d+), {CLASS_NAME} = (\d+)\s*', line)
        assert match
        return list(map(int, match.groups()))

    first = counts()
    provider, = registry(SERVICE, 2)
    children = []
    for child in provider['IORegistryEntryChildren']:
        if child['IOObjectClass'] == CLASS_NAME:
            label = re.fullmatch(r'pid (\d+), (fairplayd|adid|lskdd|fairplaydeviceidentityd)',
                                 child['IOUserClientCreator'])
            assert label
            children.append({'entry_id': hex(child['IORegistryEntryID']), 'creator': label[2]})
    second = counts()
    assert provider['IOUserClientClass'] == CLASS_NAME
    assert first == second
    assert first[0] == 1 and first[1] == len(children)
    return {'provider_entry_id': hex(provider['IORegistryEntryID']),
            'provider_client_class': CLASS_NAME, 'metaclass_count_samples': [first, second],
            'client_entries': sorted(children, key=lambda entry: entry['entry_id'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('collection', 'trace', 'decompilation', 'calls'):
        parser.add_argument(key, type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    result = {'installed': installed(image), 'native_registry': observe(),
              'archive': historical(args.trace), 'reference_extracts': extracts(args.decompilation, args.calls)}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
