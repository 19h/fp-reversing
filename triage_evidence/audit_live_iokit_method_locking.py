#!/usr/bin/env python3
"""Verify installed FairPlayIOKit method locking and deferred finalization."""

import argparse
import json
import plistlib
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from audit_live_kext_selector26 import (
    CLIENT, DRIVER, IDENTITIES, Collection, method_map, mig_map, synchronous_path,
)
from audit_live_iokit_open_owner import BUILD, SERVICE

PROPERTIES = {
    0xfffffe00070e4fc7: 'IOUserClientDefaultLocking',
    0xfffffe00070e4fe2: 'IOUserClientDefaultLockingSetProperties',
    0xfffffe00070e500a: 'IOUserClientDefaultLockingSingleThreadExternalMethod',
}

INSTRUCTIONS = {
    'open_policy': (
        (0xfffffe000c5bdf38, 'ldrb w8, [x0, #0x9b]'),
        (0xfffffe000c5bdf40, 'tbnz w8, #5, #0xfffffe000c5be004'),
        (0xfffffe000c5bdf44, 'orr w8, w8, #0x20'),
        (0xfffffe000c5bdf48, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be020, 'and w9, w9, #0xfffffffd'),
        (0xfffffe000c5be028, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be03c, 'ldr x26, [x8, #0xd18]'),
        (0xfffffe000c5be050, 'mov x17, #0x2d8'),
        (0xfffffe000c5be05c, 'adrp x1, #0xfffffe00070e4000'),
        (0xfffffe000c5be060, 'add x1, x1, #0xfc7'),
        (0xfffffe000c5be064, 'movk x16, #0x37a5, lsl #48'),
        (0xfffffe000c5be068, 'blraa x8, x16'),
        (0xfffffe000c5be07c, 'cmp x26, x8'),
        (0xfffffe000c5be080, 'mov w8, #4'),
        (0xfffffe000c5be084, 'csel w8, wzr, w8, eq'),
        (0xfffffe000c5be088, 'and w9, w9, #0xfffffffb'),
        (0xfffffe000c5be090, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be0ec, 'adrp x1, #0xfffffe00070e4000'),
        (0xfffffe000c5be0f0, 'add x1, x1, #0xfe2'),
        (0xfffffe000c5be0f4, 'movk x16, #0x37a5, lsl #48'),
        (0xfffffe000c5be0f8, 'blraa x8, x16'),
        (0xfffffe000c5be108, 'cmp x24, x8'),
        (0xfffffe000c5be10c, 'mov w8, #0x10'),
        (0xfffffe000c5be110, 'csel w8, wzr, w8, eq'),
        (0xfffffe000c5be114, 'and w9, w9, #0xffffffef'),
        (0xfffffe000c5be11c, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be190, 'adrp x1, #0xfffffe00070e5000'),
        (0xfffffe000c5be194, 'add x1, x1, #0xa'),
        (0xfffffe000c5be198, 'movk x16, #0x37a5, lsl #48'),
        (0xfffffe000c5be19c, 'blraa x8, x16'),
        (0xfffffe000c5be1ac, 'cmp x24, x8'),
        (0xfffffe000c5be1b0, 'mov w8, #8'),
        (0xfffffe000c5be1b4, 'csel w8, wzr, w8, eq'),
        (0xfffffe000c5be1b8, 'and w9, w9, #0xfffffff7'),
        (0xfffffe000c5be1c0, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be248, 'tbnz w24, #0, #0xfffffe000c5be2d4'),
        (0xfffffe000c5be288, 'tbnz w0, #0, #0xfffffe000c5be2d4'),
        (0xfffffe000c5be294, 'and w8, w8, #0xffffffe7'),
        (0xfffffe000c5be298, 'orr w8, w8, #4'),
        (0xfffffe000c5be29c, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be2a4, 'ldr x2, [x8, #0xd10]'),
        (0xfffffe000c5be2b8, 'mov x17, #0x288'),
        (0xfffffe000c5be2c8, 'add x1, x1, #0xfc7'),
        (0xfffffe000c5be2d0, 'blraa x8, x16'),
        (0xfffffe000c5b7aec, 'add x0, x19, #0xb0'),
        (0xfffffe000c5b7af0, 'bl #0xfffffe000c50ad18'),
    ),
    'synchronous_method': (
        (0xfffffe000c5bfe84, 'ldrb w8, [x0, #0x9b]'),
        (0xfffffe000c5bfe88, 'lsl w9, w8, #0x1d'),
        (0xfffffe000c5bfe8c, 'tst w8, #8'),
        (0xfffffe000c5bfe90, 'mov w20, #1'),
        (0xfffffe000c5bfe94, 'cinc w8, w20, ne'),
        (0xfffffe000c5bfe98, 'ands w8, w8, w9, asr #31'),
        (0xfffffe000c5bfe9c, 'b.eq #0xfffffe000c5bfedc'),
        (0xfffffe000c5bfea0, 'cmp w8, #1'),
        (0xfffffe000c5bfea4, 'b.ne #0xfffffe000c5bfec4'),
        (0xfffffe000c5bfea8, 'add x0, x19, #0xb0'),
        (0xfffffe000c5bfeb4, 'bl #0xfffffe000bd4ef3c'),
        (0xfffffe000c5bfec0, 'b #0xfffffe000c5bfedc'),
        (0xfffffe000c5bfecc, 'add x0, x19, #0xb0'),
        (0xfffffe000c5bfed0, 'bl #0xfffffe000bd4e450'),
        (0xfffffe000c5bfedc, 'add x8, x19, #0x9c'),
        (0xfffffe000c5bfee0, 'ldadd w20, w8, [x8]'),
        (0xfffffe000c5bfef8, 'tbnz w8, #1, #0xfffffe000c5bff24'),
        (0xfffffe000c5bff08, 'mov x3, #0'),
        (0xfffffe000c5bff0c, 'mov x4, #0'),
        (0xfffffe000c5bff10, 'mov x5, #0'),
        (0xfffffe000c5bff3c, 'mov x20, x0'),
        (0xfffffe000c5bff40, 'ldrb w8, [x19, #0x9b]'),
        (0xfffffe000c5bff44, 'lsl w9, w8, #0x1d'),
        (0xfffffe000c5bff48, 'tst w8, #8'),
        (0xfffffe000c5bff4c, 'mov w8, #1'),
        (0xfffffe000c5bff50, 'cinc w8, w8, ne'),
        (0xfffffe000c5bff54, 'and w1, w8, w9, asr #31'),
        (0xfffffe000c5bff58, 'mov x0, x19'),
        (0xfffffe000c5bff5c, 'bl #0xfffffe000c5b64cc'),
        (0xfffffe000c5bff60, 'mov x0, x20'),
    ),
    'explicit_close': (
        (0xfffffe000be85554, 'bl #0xfffffe000be7e2c0'),
        (0xfffffe000be8555c, 'bl #0xfffffe000c5be78c'),
        (0xfffffe000c5be84c, 'ldrb w8, [x19, #0x98]'),
        (0xfffffe000c5be850, 'cbnz w8, #0xfffffe000c5be864'),
        (0xfffffe000c5be854, 'add x9, x19, #0x99'),
        (0xfffffe000c5be85c, 'casalb w8, w10, [x9]'),
        (0xfffffe000c5be860, 'cbnz w8, #0xfffffe000c5be8c0'),
        (0xfffffe000c5be864, 'add x0, x19, #0xb0'),
        (0xfffffe000c5be868, 'bl #0xfffffe000bd4e450'),
        (0xfffffe000c5be86c, 'add x8, x19, #0x9c'),
        (0xfffffe000c5be870, 'mov w9, #1'),
        (0xfffffe000c5be874, 'ldadd w9, w8, [x8]'),
        (0xfffffe000c5be880, 'mov x17, #0x920'),
        (0xfffffe000c5be890, 'movk x16, #0x18b8, lsl #48'),
        (0xfffffe000c5be894, 'blraa x8, x16'),
        (0xfffffe000c5be89c, 'mov w1, #2'),
        (0xfffffe000c5be8a0, 'bl #0xfffffe000c5b64cc'),
    ),
    'exit_and_finalize': (
        (0xfffffe000c5b64e8, 'add x8, x0, #0x9c'),
        (0xfffffe000c5b64ec, 'mov w9, #-1'),
        (0xfffffe000c5b64f0, 'ldadd w9, w8, [x8]'),
        (0xfffffe000c5b64f4, 'cmp w8, #1'),
        (0xfffffe000c5b64f8, 'b.ne #0xfffffe000c5b65e0'),
        (0xfffffe000c5b650c, 'mov x17, #0x5d8'),
        (0xfffffe000c5b651c, 'movk x16, #0xc90d, lsl #48'),
        (0xfffffe000c5b6520, 'blraa x8, x16'),
        (0xfffffe000c5b6524, 'tbz w0, #0, #0xfffffe000c5b65e0'),
        (0xfffffe000c52e414, 'ldr w0, [x0, #0x48]'),
        (0xfffffe000c5b652c, 'adrp x8, #0xfffffe000cc22000'),
        (0xfffffe000c5b6530, 'ldr x0, [x8, #0x240]'),
        (0xfffffe000c5b6554, 'ldrb w10, [x20, #0x9a]'),
        (0xfffffe000c5b6558, 'cbz w10, #0xfffffe000c5b65bc'),
        (0xfffffe000c5b655c, 'strb wzr, [x20, #0x9a]'),
        (0xfffffe000c5b6588, 'mov w1, #1'),
        (0xfffffe000c5b658c, 'bl #0xfffffe000c51f638'),
        (0xfffffe000c5b65b4, 'ldrb w10, [x20, #0x9a]'),
        (0xfffffe000c5b65b8, 'cbnz w10, #0xfffffe000c5b655c'),
        (0xfffffe000c5b65e0, 'sub w8, w19, #1'),
        (0xfffffe000c5b65e4, 'cmp w8, #2'),
        (0xfffffe000c5b65e8, 'b.hs #0xfffffe000c5b6604'),
        (0xfffffe000c5b65ec, 'add x0, x20, #0xb0'),
        (0xfffffe000c5b6600, 'b #0xfffffe000bd50068'),
        (0xfffffe000c51f6c8, 'tbnz w20, #0, #0xfffffe000c51f6d8'),
        (0xfffffe000c51f6d0, 'bl #0xfffffe000c5b663c'),
        (0xfffffe000c51f6d4, 'cbz w0, #0xfffffe000c51f7f0'),
        (0xfffffe000c5b66a4, 'adrp x21, #0xfffffe000cc22000'),
        (0xfffffe000c5b66a8, 'ldr x0, [x21, #0x240]'),
        (0xfffffe000c5b66cc, 'ldr w8, [x19, #0x9c]'),
        (0xfffffe000c5b66d4, 'cset w0, eq'),
        (0xfffffe000c5b66d8, 'cset w8, ne'),
        (0xfffffe000c5b66dc, 'strb w8, [x19, #0x9a]'),
        (0xfffffe000c51f730, 'blraa x8, x16'),
        (0xfffffe000c51f740, 'str w10, [x8, #0xff8]'),
        (0xfffffe000c51f7c8, 'bl #0xfffffe000bdb6120'),
    ),
}


def verify_image(image):
    evidence = {}
    for group, sites in INSTRUCTIONS.items():
        words = {}
        for pc, asm in sites:
            instruction, = image.instructions(pc, 4)
            assert f'{instruction.mnemonic} {instruction.op_str}' == asm, hex(pc)
            words[hex(pc)] = {'bytes': instruction.bytes.hex(), 'instruction': asm}
        evidence[group] = words

    for address, name in PROPERTIES.items():
        assert image.read(address, len(name) + 1) == name.encode() + bytes(1)
    booleans = {}
    for name, target in (('_kOSBooleanFalse', '0xfffffe000cc1ed18'),
                         ('_kOSBooleanTrue', '0xfffffe000cc1ed10')):
        pointer = image.pointer(image.named(name))
        assert pointer['target'] == target
        booleans[name] = pointer

    mig = mig_map(image)
    path = synchronous_path(image, method_map(image), mig)
    assert path['dispatch_helper'] == '0xfffffe000c5bfe6c'
    assert mig['routines'][2816]['stub']['target'] == '0xfffffe000be85524'
    client_vtable = image.named(f'__ZTV{CLIENT}') + 0x10
    bindings = {}
    for name, offset, address, diversity in (
        ('getProperty', 0x2d8, '0xfffffe000c51700c', '0x37a5'),
        ('getState', 0x5d8, '0xfffffe000c52e410', '0xc90d'),
        ('clientClose', 0x920, '0xfffffe000a5455ec', '0x18b8'),
    ):
        pointer = image.pointer(client_vtable + offset)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (address, 1, diversity)
        bindings[name] = pointer

    superclasses = {}
    for child, parent in ((CLIENT, '12IOUserClient'), ('12IOUserClient', '9IOService')):
        pointer = image.pointer(image.named(f'__ZN{child}10superClassE'))
        assert int(pointer['target'], 16) == image.named(f'__ZN{parent}10gMetaClassE')
        superclasses[child] = pointer
    locks = {}
    for name, address in (('_IORWLockRead', 0xfffffe000bd4ef3c),
                          ('_IORWLockWrite', 0xfffffe000bd4e450),
                          ('_IORWLockUnlock', 0xfffffe000bd50068)):
        assert image.named(name) == address
        locks[name] = {'address': hex(address), 'aliases': image.names(address)}

    counts = [0, 0, 0]
    for flags in range(256):
        # Reconstruct the verified LSL, ASR, TST, CINC and AND sequences.
        sign_mask = -(((flags << 29) & 0xffffffff) >> 31)
        instruction_result = (1 + bool(flags & 8)) & sign_mask
        policy_result = 0 if not flags & 4 else 2 if flags & 8 else 1
        assert instruction_result == policy_result
        counts[policy_result] += 1
    assert counts == [128, 64, 64]
    return {
        'collection_identities': IDENTITIES[1],
        'original_instructions': evidence,
        'property_literals': {hex(pc): text for pc, text in PROPERTIES.items()},
        'boolean_bindings': booleans,
        'method_path': path,
        'close_stub': mig['routines'][2816],
        'client_bindings': bindings,
        'superclass_bindings': superclasses,
        'lock_symbols': locks,
        'mode_case_counts': dict(zip(('none', 'shared', 'exclusive'), counts)),
    }


def snapshot():
    service, = plistlib.loads(subprocess.check_output(
        ['ioreg', '-a', '-r', '-c', SERVICE, '-l', '-d', '2']))
    children = []
    for child in service['IORegistryEntryChildren']:
        if child['IOObjectClass'] != SERVICE + 'UserClient':
            continue
        pid, name = re.fullmatch(
            r'pid (\d+), ([a-zA-Z0-9_.-]+)', child['IOUserClientCreator']).groups()
        properties = {key: child.get(key) for key in (
            *PROPERTIES.values(), 'IOUserClientSharedInstance',
        )}
        assert all(value is None or isinstance(value, bool) for value in properties.values())
        children.append({
            'pid': int(pid), 'creator': name,
            'entry': hex(child['IORegistryEntryID']), 'properties': properties,
        })
    return {'service_entry': hex(service['IORegistryEntryID']),
            'children': sorted(children, key=lambda child: child['entry'])}


def observe_registry():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    loaded = subprocess.check_output(['kmutil', 'showloaded'], text=True)
    row, = (line for line in loaded.splitlines() if f'{DRIVER} (' in line)
    assert IDENTITIES[1][2] in row.lower()
    timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
    first = snapshot()
    assert first == snapshot()
    return {'build': BUILD, 'observed_utc': timestamp, 'registry': first}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    result = {'kernel': verify_image(Collection(args.collection, IDENTITIES[1]))}
    if args.observe:
        result['current_observation'] = observe_registry()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
