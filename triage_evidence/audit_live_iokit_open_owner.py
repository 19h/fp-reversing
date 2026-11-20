#!/usr/bin/env python3
"""Verify FairPlayIOKit attachment, creator attribution and owner publication."""

import argparse
import json
import plistlib
import re
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from audit_fairplay_live_slice_identity import (
    CS_OPS_CDHASH, CS_OPS_PIDOFFSET, installed_slices, query_cs,
)
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from audit_live_kext_selector26 import DRIVER, IDENTITIES, Collection

SERVICE = 'com_apple_driver_FairPlayIOKit'
CLIENT = SERVICE + 'UserClient'
BUILD = '26C5035r'
ACCESS = (
    'com.apple.private.FairPlayIOKitUserClient.access',
    'com.apple.private.ProvInfoIOKitUserClient.access',
    'com.apple.private.FairPlayIOKitUserClient.Virtual.access',
)


def verify_image(image):
    evidence = {}
    for pc, asm in (
        (0xfffffe000c5bdd44, 'bl #0xfffffe000bdc68b8'),
        (0xfffffe000c5bdd48, 'cmp x20, x0'),
        (0xfffffe000c5bdd58, 'bl #0xfffffe000bdc5f78'),
        (0xfffffe000bdc5f84, 'mrs x0, tpidr_el1'),
        (0xfffffe000bdc5f88, 'ldr x1, [x0, #0x420]'),
        (0xfffffe000bdc5ff4, 'mov x0, x1'),
        (0xfffffe000c51b8e8, 'blraa x8, x16'),
        (0xfffffe000c51b914, 'blraa x9, x17'),
        (0xfffffe000c51b940, 'blraa x9, x17'),
        (0xfffffe000c51b94c, 'str x26, [x20]'),
        (0xfffffe000c51b9b4, 'blraa x8, x16'),
        (0xfffffe000a54552c, 'ldr w2, [x20, #0xf0]'),
        (0xfffffe000a545530, 'ldr x3, [x20, #0xe0]'),
        (0xfffffe000a545558, 'blraa x8, x16'),
        (0xfffffe000c5bddbc, 'blraa x8, x16'),
        (0xfffffe000c5bddc8, 'cbz w8, #0xfffffe000c5bdde8'),
        (0xfffffe000c5bde40, 'ldr x8, [x21, #0x18]'),
        (0xfffffe000c5bde58, 'ldr w0, [x8, #0x60]'),
        (0xfffffe000c5bde64, 'bl #0xfffffe000c50a4d0'),
        (0xfffffe000c5bde94, 'add x1, x1, #0x58d'),
        (0xfffffe000c5bde98, 'mov x2, x21'),
        (0xfffffe000c5bdea0, 'blraa x8, x16'),
        (0xfffffe000c308100, 'ldr w0, [x1, #0x60]'),
        (0xfffffe000c50a514, 'add x2, x2, #0xcd1'),
        (0xfffffe000c50a528, 'mov w1, #0x80'),
        (0xfffffe000c50a52c, 'bl #0xfffffe000c34e4f0'),
        (0xfffffe000c50a554, 'bl #0xfffffe000c30a10c'),
        (0xfffffe000c50a5a8, 'blraa x8, x16'),
        (0xfffffe000c5bdf20, 'strb w9, [x0, #0x98]'),
        (0xfffffe000c5be29c, 'strb w8, [x0, #0x9b]'),
        (0xfffffe000c5be31c, 'blraa x8, x16'),
        (0xfffffe000c5be614, 'bl #0xfffffe000c5b7b0c'),
        (0xfffffe000c5be644, 'cbz w25, #0xfffffe000c5be6cc'),
        (0xfffffe000c5be690, 'blraa x8, x16'),
        (0xfffffe000c5be6c4, 'mov x0, #0'),
        (0xfffffe000c5be6d4, 'bl #0xfffffe000c539c00'),
        (0xfffffe000c5bdddc, 'str x0, [x10]'),
        (0xfffffe000c5bdde0, 'str w25, [x9]'),
        (0xfffffe000c5b7b4c, 'casa x2, x8, [x10]'),
        (0xfffffe000c5b7b5c, 'ldr x8, [x22, #0xa0]!'),
        (0xfffffe000c5b7b70, 'cmp x20, x9'),
        (0xfffffe000c5b7bac, 'bl #0xfffffe000bd46a80'),
        (0xfffffe000c5b7bb0, 'str x20, [x0]'),
        (0xfffffe000c5b7bb4, 'str x21, [x0, #0x18]'),
        (0xfffffe000c5b7bd8, 'stp x10, x22, [x0, #0x20]'),
        (0xfffffe000c5b7bf0, 'str x0, [x22]'),
        (0xfffffe000c5b7bf4, 'add x8, x20, #0x650'),
        (0xfffffe000c5b7c18, 'stp x11, x8, [x0, #8]'),
        (0xfffffe000c5b7c30, 'str x0, [x8]'),
        (0xfffffe000c5b7c74, 'mov w0, #0'),
    ):
        instruction, = image.instructions(pc, 4)
        assert f'{instruction.mnemonic} {instruction.op_str}'.strip() == asm, hex(pc)
        evidence[hex(pc)] = {'bytes': instruction.bytes.hex(), 'instruction': asm}

    vtable = image.named(f'__ZTV{len(CLIENT)}{CLIENT}') + 0x10
    virtual = {}
    for offset, symbol, modifier in (
        (0x288, '__ZN15IORegistryEntry11setPropertyEPKcP8OSObject', '0xff53'),
        (0x5f0, f'__ZN{len(CLIENT)}{CLIENT}5startEP9IOService', '0x3c68'),
        (0x6a0, '__ZN9IOService6attachEPS_', '0x9be9'),
        (0x6a8, '__ZN9IOService6detachEPS_', '0x7318'),
        (0x910, '__ZN12IOUserClient12initWithTaskEP4taskPvjP12OSDictionary', '0xbde5'),
        (0x920, f'__ZN{len(CLIENT)}{CLIENT}11clientCloseEv', '0x18b8'),
    ):
        record = image.pointer(vtable + offset)
        assert (record['format'], record['auth'], record['diversity']) == (8, 1, modifier)
        assert (record['key'], record['address_diversity']) == (0, 1)
        assert int(record['target'], 16) == image.named(symbol)
        virtual[hex(offset)] = dict(record, symbol=symbol)

    for name, address in (
        ('_kernproc', 0xfffffe0007f98a28), ('_snprintf', 0xfffffe000c34e4f0),
        ('_proc_name', 0xfffffe000c30a10c), ('_proc_pid', 0xfffffe000c30809c),
    ):
        assert image.named(name) == address

    descriptor = 0xfffffe0007e63048
    literals = {
        0xfffffe00070e358d: 'IOUserClientCreator',
        0xfffffe00070e12c3: 'IOUserClientSharedInstance',
        0xfffffe00070e4fc7: 'IOUserClientDefaultLocking',
        0xfffffe00070dacd1: 'pid %d, ',
        0xfffffe00070e10d3: 'site.IOUserClientOwner',
        0xfffffe00070e10ea: '111111',
    }
    for address, value in literals.items():
        encoded = value.encode() + b'\0'
        assert image.read(address, len(encoded)) == encoded
    links = [image.pointer(descriptor + offset) for offset in (0x10, 0x20)]
    assert [item['target'] for item in links] == ['0xfffffe00070e10d3', '0xfffffe00070e10ea']
    assert struct.unpack('<I', image.read(descriptor + 0x2c, 4)) == (48,)
    return {
        'collection_identities': IDENTITIES[1], 'instructions': evidence,
        'client_vtable_slots': virtual, 'literals': {hex(k): v for k, v in literals.items()},
        'owner_descriptor': {'address': hex(descriptor), 'size': 48, 'links': links},
    }


def snapshot():
    current, = plistlib.loads(subprocess.check_output(
        ['ioreg', '-a', '-r', '-c', SERVICE, '-l', '-d', '2']))
    children = []
    for child in current['IORegistryEntryChildren']:
        if child['IOObjectClass'] != CLIENT:
            continue
        pid, name = re.fullmatch(r'pid (\d+), ([a-zA-Z0-9_.-]+)', child['IOUserClientCreator']).groups()
        children.append({
            'pid': int(pid), 'creator': name, 'entry': hex(child['IORegistryEntryID']),
            'properties': {key: child.get(key) for key in (
                'IOUserClientDefaultLocking', 'IOUserClientSharedInstance', 'IOUserClientEntitlements',
            )},
        })
    return {'service_id': hex(current['IORegistryEntryID']),
            'children': sorted(children, key=lambda child: child['entry'])}


def live_observation():
    started = datetime.now(timezone.utc).isoformat(timespec='seconds')
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    loaded = subprocess.check_output(['kmutil', 'showloaded'], text=True)
    row, = (line for line in loaded.splitlines() if f'{DRIVER} (' in line)
    assert IDENTITIES[1][2] in row.lower()
    before = snapshot()
    processes = {}
    for client in before['children']:
        name = client['creator']
        if name not in ('adid', 'fairplayd'):
            continue
        pid = client['pid']
        query = ['ps', '-ww', '-p', str(pid), '-o']
        start = subprocess.check_output(query + ['lstart='], text=True).strip()
        executable = Path(subprocess.check_output(query + ['comm='], text=True).strip())
        assert start and executable.name == name
        assert executable.is_relative_to('/System/Library/PrivateFrameworks')
        hash_result = query_cs(pid, CS_OPS_CDHASH, 20)
        offset_result = query_cs(pid, CS_OPS_PIDOFFSET, 8)
        assert hash_result[:2] == offset_result[:2] == (0, 0)
        offset, = struct.unpack('<q', offset_result[2])
        selected, = (item for item in installed_slices(executable)
                     if item['file_offset_bytes'] == offset)
        assert selected['arch'] == 'arm64e'
        assert selected['codesign_cdhash'] == hash_result[2].hex()
        raw = subprocess.check_output([
            'codesign', '-d', '--arch', selected['arch'], '--entitlements', ':-', str(executable),
        ], stderr=subprocess.DEVNULL)
        entitlements = plistlib.loads(raw)
        assert query_cs(pid, CS_OPS_CDHASH, 20) == hash_result
        assert query_cs(pid, CS_OPS_PIDOFFSET, 8) == offset_result
        assert subprocess.check_output(query + ['lstart='], text=True).strip() == start
        processes[name] = {
            'slice': selected, 'pid': pid, 'client_entry': client['entry'],
            'signed_entitlements': {key: entitlements.get(key) for key in ACCESS},
        }
    assert set(processes) == {'adid', 'fairplayd'}
    assert snapshot() == before
    return {'observed_utc': started, 'build': BUILD, 'registry': before, 'processes': processes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    result = {'kernel': verify_image(Collection(args.collection, IDENTITIES[1]))}
    if args.observe:
        result['current_observation'] = live_observation()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
