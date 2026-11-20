#!/usr/bin/env python3
"""Join boot personality metadata, matching code, the registry, and the archived query."""

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess

from audit_live_iokit_discovery import archived_discovery
from audit_live_iokit_mach_transport import record_windows
from audit_live_iokit_main_port import BUILD
from audit_live_kext_selector26 import Collection, DRIVER, IDENTITIES
from resolve_kernel_collection_interfaces import commands, string

PRIMARY = 'FairPlayIOKit'
ALTERNATE = 'AvpFairPlayDriver'
ALTERNATE_BUNDLE = 'com.apple.driver.' + ALTERNATE
SERVICE = 'com_apple_driver_FairPlayIOKit'
CLIENT = SERVICE + 'UserClient'
EXTENSIONS = Path('/System/Library/Extensions')


def bundle(name, digest):
    raw = (EXTENSIONS / (name + '.kext') / 'Contents' / 'Info.plist').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    info = plistlib.loads(raw)
    return {'digest': digest, 'bundle_id': info['CFBundleIdentifier'],
            'version': info['CFBundleVersion'], 'personalities': info['IOKitPersonalities']}


def prelink(image, primary, alternate):
    found = []
    entries = set()
    for offset, command, _ in commands(image.data, 0):
        if command == 0x80000035:
            relative, = struct.unpack_from('<I', image.data, offset + 24)
            entries.add(string(image.data, offset + relative))
        if command == 0x19 and image.data[offset + 8:offset + 24].rstrip(b'\0') == b'__PRELINK_INFO':
            count, = struct.unpack_from('<I', image.data, offset + 64)
            for index in range(count):
                name, _, address, size, file_offset = struct.unpack_from(
                    '<16s16sQQI', image.data, offset + 72 + index * 80)
                if name.rstrip(b'\0') == b'__info':
                    found.append((address, size, file_offset))
    (address, size, file_offset), = found
    raw = image.read(address, size)
    assert raw == image.data[file_offset:file_offset + size]
    mark = b'</plist>'
    records = plistlib.loads(raw[:raw.index(mark) + len(mark)])['_PrelinkInfoDictionary']
    row, = (item for item in records if item.get('CFBundleIdentifier') == DRIVER)
    assert DRIVER in entries and alternate['bundle_id'] not in entries
    assert not any(item.get('CFBundleIdentifier') == alternate['bundle_id'] for item in records)
    assert primary['bundle_id'] == DRIVER and row['CFBundleVersion'] == primary['version']
    personality, = row['IOKitPersonalities'].values()
    assert personality == {**primary['personalities'][PRIMARY], 'IOPersonalityPublisher': DRIVER}
    assert personality['IOClass'] == SERVICE and personality['IOUserClientClass'] == CLIENT
    assert personality['IOProviderClass'] == 'IOResources' and personality['IOResourceMatch'] == 'IOKit'
    return {'section': {'address': hex(address), 'size_bytes': size, 'file_offset_bytes': file_offset,
                        'sha256': hashlib.sha256(raw).hexdigest()},
            'record_count': len(records), 'fileset_identity': IDENTITIES[1], 'personality': personality,
            'version': row['CFBundleVersion'], 'alternate_in_fileset': False,
            'load_address': hex(row['_PrelinkExecutableLoadAddr'] % (1 << 64)),
            'executable_size_bytes': row['_PrelinkExecutableSize']}


def code(image):
    instructions = (
        (0xfffffe000c5283bc, 'bl', '#0xfffffe000c55dcb4'),
        (0xfffffe000c5288c0, 'bl', '#0xfffffe000c528b48'),
        (0xfffffe000c529a08, 'mov', 'x17, #0x5e8'),
        (0xfffffe000c529a24, 'movk', 'x16, #0x4897, lsl #48'),
        (0xfffffe000c529a28, 'blraa', 'x8, x16'),
        (0xfffffe000c531b80, 'ldr', 'x1, [x8, #0xc78]'),
        (0xfffffe000c531b94, 'mov', 'x17, #0x228'),
        (0xfffffe000c531ba8, 'blraa', 'x8, x16'),
        (0xfffffe000c531bec, 'str', 'x16, [sp, #0x10]'),
        (0xfffffe000c531c0c, 'str', 'x19, [sp, #0x28]'),
        (0xfffffe000c531e20, 'mov', 'x17, #0x2d0'),
        (0xfffffe000c531e30, 'blraa', 'x8, x16'),
        (0xfffffe000c531e34, 'cmp', 'x0, #0'),
        (0xfffffe000c531e38, 'cset', 'w8, ne'),
        (0xfffffe000c52ad10, 'ccmp', 'x19, x9, #4, ne'),
        (0xfffffe000c52ad14, 'b.eq', '#0xfffffe000c52ad28'),
        (0xfffffe000c52ad1c, 'bl', '#0xfffffe000c52b528'),
        (0xfffffe000c52ad24, 'bl', '#0xfffffe000c52b528'),
        (0xfffffe000c52ae18, 'mov', 'x17, #0x5f0'),
        (0xfffffe000c52ae30, 'blraa', 'x8, x16'),
        (0xfffffe000c539a58, 'ldr', 'x0, [x19, #0xf48]'),
        (0xfffffe000c539a80, 'blraa', 'x9, x16'),
        (0xfffffe000a54bce4, 'braa', 'x16, x17'),
        (0xfffffe000a54bd18, 'blraa', 'x8, x17'),
        (0xfffffe000a54bd68, 'blraa', 'x8, x16'),
        (0xfffffe000a54bd6c, 'mov', 'w0, #1'),
    )
    for pc, mnemonic, operands in instructions:
        image.instruction(pc, mnemonic, operands)
    assert image.named('_gIOResourceMatchKey') == 0xfffffe000cbcec78
    slots = {}
    for table, offset, target, diversity in (
        ('__ZTV11IOResources', 0x670, 0xfffffe000c531b38, '0xc4f9'),
        ('__ZTV11IOResources', 0x2d0, image.named('__ZNK15IORegistryEntry11getPropertyEPK8OSString'), '0x164e'),
        ('__ZTV12OSDictionary', 0x228, image.named('__ZNK12OSDictionary9getObjectEPK8OSSymbol'), '0x5837'),
        ('__ZTV30' + SERVICE, 0x5e8, 0xfffffe000a54bcc8, '0x4897'),
        ('__ZTV30' + SERVICE, 0x5f0, 0xfffffe000a54bce8, '0x3c68'),
        ('__ZTV30' + SERVICE, 0x5e0, image.named('__ZN9IOService15registerServiceEj'), '0x7d59'),
    ):
        pointer = image.pointer(image.named(table) + 16 + offset)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (hex(target), 1, diversity)
        slots[f'{table}+{offset:#x}'] = pointer
    base = int(image.pointer(0xfffffe0008493090)['target'], 16)
    for offset, symbol in ((0x5f8, '__ZN9IOService5probeEPS_Pi'), (0x600, '__ZN9IOService5startEPS_')):
        pointer = image.pointer(base + offset)
        assert int(pointer['target'], 16) == image.named(symbol)
        slots[symbol] = pointer
    return {'instruction_assertions': len(instructions), 'slots': slots,
            'windows': record_windows(image.read, (
                (0xfffffe000c5283b0, 0x18), (0xfffffe000c5288b0, 0x24),
                (0xfffffe000c529a08, 0x28), (0xfffffe000c531b7c, 0x40),
                (0xfffffe000c531e0c, 0x40), (0xfffffe000c52ad00, 0x2c),
                (0xfffffe000c52ae10, 0x28), (0xfffffe000c539a30, 0x58),
                (0xfffffe000a54bcc8, 0xac),
            ))}


def registry(root, depth):
    raw = subprocess.check_output(['ioreg', '-a', '-l', '-p', 'IOService', '-r', '-c', root, '-d', str(depth)])
    return plistlib.loads(raw) if raw.strip() else []


def live(boot):
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    root, = registry('IOResources', 2)
    child, = (row for row in root['IORegistryEntryChildren'] if row['IOObjectClass'] == SERVICE)
    props = {key: child[key] for key in boot['personality']}
    assert props == boot['personality'] and child['IOMatchedAtBoot'] is True
    assert root['IOObjectClass'] == 'IOResources' and root['IOKit'] == 'IOService'
    counts = {cls: len(registry(cls, 1)) for cls in (ALTERNATE, 'AppleVirtIOTransport', 'AppleVirtIOPCITransport')}
    assert set(counts.values()) == {0}
    hv = int(subprocess.check_output(['sysctl', '-n', 'kern.hv_vmm_present'], text=True))
    assert hv == 0
    rows = subprocess.check_output(['kmutil', 'showloaded', '--list-only'], text=True, stderr=subprocess.DEVNULL)
    fields, = (line.split() for line in rows.splitlines() if DRIVER in line.split())
    assert fields[5:8] == [DRIVER, f"({boot['version']})", IDENTITIES[1][2].upper()]
    assert not any(ALTERNATE_BUNDLE in line.split() for line in rows.splitlines())
    assert int(fields[3], 16) == boot['executable_size_bytes']
    return {'build': BUILD, 'kernel_uuid': IDENTITIES[1][1], 'kext_uuid': fields[7].lower(),
            'kext_version': boot['version'], 'provider_registry_id': hex(root['IORegistryEntryID']),
            'provider_IOKit_value': root['IOKit'], 'service_registry_id': hex(child['IORegistryEntryID']),
            'matched_at_boot': child['IOMatchedAtBoot'], 'personality_properties': props,
            'alternate_registry_root_counts': counts, 'vmm_present': hv}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    primary = bundle(PRIMARY, 'f4500107bdaf52441c36fad8cf085b0da5283e3444bdd39e06deb194a49f66e8')
    alternate = bundle(ALTERNATE, '5f474c28b9dcb88843f0d687b05a956fba11410c2cd2c6dd3fdd0db8e45d9f88')
    assert alternate['bundle_id'] == ALTERNATE_BUNDLE
    assert alternate['personalities'][ALTERNATE]['IOVirtIOPrimaryMatch'] == '0x1a08106b'
    assert alternate['personalities'][ALTERNATE]['IOProviderClass'] == 'AppleVirtIOTransport'
    assert alternate['personalities'][ALTERNATE + ' Transport']['IOPCIPrimaryMatch'] == '0x1a08106b'
    boot = prelink(image, primary, alternate)
    archived = archived_discovery(args.trace)
    match = archived['transactions'][2]
    assert bytes.fromhex(match['send_hex'])[36:] == (
        struct.pack('<III', 0xd3, 0x81000001, 0x08000010) + b'IOProviderClass\0' +
        struct.pack('<I', 0x8900001e) + SERVICE.encode() + b'\0\0')
    result = {'boot': boot, 'code': code(image), 'primary_bundle': primary, 'alternate_bundle': alternate,
              'registry': live(boot), 'archive': {'trace_sha256': archived['trace_sha256'], 'match': match}}
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
