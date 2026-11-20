#!/usr/bin/env python3
"""Verify installed FPDI startup, named sandbox, and XPC activity interfaces."""

import argparse
import json
from pathlib import Path
import plistlib
import re
from struct import unpack_from

from audit_live_fpdi_allocation import (
    SHA256, UUID, ThinView, bindings, daemon_slices, digest, selected_identity, window,
)
from resolve_kernel_collection_interfaces import commands

SERVICE = 'com.apple.fairplaydeviceidentityd'
ACTIVITY = SERVICE + '.baa-prefetch'
CALLS = {
    0x100002014: (0x10054bb94, 0x1005e9e30, 'libSystem/_getenv'),
    0x100002030: (0x10054bbb4, 0x1005e9e40, 'libSystem/_getuid'),
    0x100002034: (0x10054bba4, 0x1005e9e38, 'libSystem/_getpwuid'),
    0x100002044: (0x10054bc54, 0x1005e9e70, 'libSystem/_realpath$DARWIN_EXTSN'),
    0x100002058: (0x10054bac4, 0x1005e9dd0, 'libSystem/__set_user_dir_suffix'),
    0x100002070: (0x10054bb04, 0x1005e9de8, 'libSystem/_confstr'),
    0x100002098: (0x10054bb04, 0x1005e9de8, 'libSystem/_confstr'),
    0x1000020ec: (0x10054bc64, 0x1005e9e78, 'libSystem/_sandbox_init_with_parameters'),
    0x100002210: (0x10054bb74, 0x1005e9e20, 'libSystem/_exit'),
    0x1000022ac: (0x10054bc84, 0x1005e9e88, 'libSystem/_xpc_activity_register'),
    0x1000022c8: (0x10054bb34, 0x1005e9e00, 'libSystem/_dispatch_queue_create'),
    0x1000022e4: (0x10054bcc4, 0x1005e9ea8, 'libSystem/_xpc_connection_create_mach_service'),
    0x100002348: (0x10054bce4, 0x1005e9eb8, 'libSystem/_xpc_connection_set_event_handler'),
    0x100002350: (0x10054bca4, 0x1005e9e98, 'libSystem/_xpc_connection_activate'),
    0x100002354: (0x10054bb14, 0x1005e9df0, 'libSystem/_dispatch_main'),
    0x100002378: (0x10054bc74, 0x1005e9e80, 'libSystem/_xpc_activity_get_state'),
    0x1000023a0: (0x10054b9d4, 0x1005e9d48, 'CoreFoundation/_CFPreferencesCopyAppValue'),
    0x100002400: (0x10054b9e4, 0x1005e9d50, 'CoreFoundation/_CFPreferencesSetAppValue'),
    0x100002548: (0x10054bc94, 0x1005e9e90, 'libSystem/_xpc_activity_unregister'),
    0x10000117c: (0x10054ba14, 0x1005e9cf8, 'DeviceIdentity/_DeviceIdentityIsSupported'),
    0x1000013dc: (0x10054ba24, 0x1005e9d00,
                   'DeviceIdentity/_DeviceIdentityIssueClientCertificateWithCompletion'),
    0x1000013e8: (0x10054bb64, 0x1005e9e18, 'libSystem/_dispatch_semaphore_wait'),
}
STRINGS = {
    0x1005be933: SERVICE,
    0x1005bea62: ACTIVITY,
    0x1005bea23: 'HOME',
    0x1005bea28: 'TMPDIR',
    0x1005bea2f: 'DARWIN_CACHE_DIR',
    0x1005be912: 'BAAScheduledPrefetchAbsoluteTime',
    0x1005beb06: 'BackgroundActivityLastRan',
}
WINDOWS = {
    'sandbox_setup': (0x100001fd0, 0x100002214),
    'main': (0x100002264, 0x100002358),
    'activity_handler': (0x100002358, 0x1000025a8),
    'prefetch_dispatch': (0x100000d40, 0x100000e44),
    'prefetch_request': (0x100000e44, 0x100000f4c),
    'device_identity_bridge': (0x100001130, 0x100001410),
}


def inspect(daemon, launch_plist, sandbox):
    _, _, thin = next(row for row in daemon_slices(daemon.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == UUID and digest(thin) == SHA256
    image = ThinView(thin)
    entry, = (unpack_from('<Q', thin, offset + 8)[0]
              for offset, kind, _ in commands(thin, 0) if kind == 0x80000028)
    assert entry == 0x2264
    fixups = bindings(daemon, '-arch', 'arm64e')
    checked_calls = []
    for pc, (stub, slot, name) in CALLS.items():
        image.instruction(pc, 'bl', f'#{stub:#x}')
        page, offset = slot & ~0xfff, slot & 0xfff
        image.instruction(stub, 'adrp', f'x17, #{page:#x}')
        image.instruction(stub + 4, 'add', f'x17, x17, #{offset:#x}')
        image.instruction(stub + 8, 'ldr', 'x16, [x17]')
        image.instruction(stub + 12, 'braa', 'x16, x17')
        assert fixups[slot] == f'auth-bind {name} (div=0x0000 ad=1 key=IA)'
        checked_calls.append({'pc': hex(pc), 'stub': hex(stub), 'slot': hex(slot),
                              'word': image.read(slot, 8).hex(), 'binding': fixups[slot]})
    for address, expected in STRINGS.items():
        encoded = expected.encode('ascii') + b'\0'
        assert image.read(address, len(encoded)) == encoded
    block = {
        0x1005c00c0: 'auth-bind libSystem/__NSConcreteGlobalBlock (div=0x6AE1 ad=1 key=DA)',
        0x1005c00d0: 'auth-rebase 0x100002358 (div=0x0000 ad=1 key=IA)',
        0x1005e9f88: 'bind libSystem/_XPC_ACTIVITY_CHECK_IN',
        0x1005e9bd0: 'rebase 0x1005BE912',
        0x1005e9c30: 'rebase 0x1005BEB06',
    }
    for slot, row in block.items():
        assert fixups[slot] == row

    plist_bytes = launch_plist.read_bytes()
    startup = plistlib.loads(plist_bytes)
    assert startup['MachServices'] == {SERVICE: True}
    assert startup['UserName'] == '_fpsd'
    assert startup['EnvironmentVariables']['DYLD_PAGEIN_LINKING'] == '0'
    schedule = startup['LaunchEvents']['com.apple.xpc.activity'][ACTIVITY]
    assert schedule == {
        'Priority': 'Maintenance', 'RequireNetworkConnectivity': True, 'AllowBattery': True,
        'RandomInitialDelay': 21600, 'Repeating': True, 'Interval': 43200,
        'RequiresClassC': True, 'PowerNap': True,
    }
    sandbox_bytes = sandbox.read_bytes()
    profile = sandbox_bytes.decode()
    clients = re.findall(r'\(allow iokit-open \(iokit-user-client-class "([^"]+)"\)\)', profile)
    assert clients == ['AppleKeyStoreUserClient', 'AvpFairPlayUserClient',
                       'com_apple_driver_FairPlayIOKitUserClient']
    assert f'(allow mach-register\n    (global-name "{SERVICE}")' in profile
    lookup = re.search(r'\(allow mach-lookup\n(.*?)\n\)', profile, re.S).group(1)
    services = re.findall(r'\(global-name "([^"]+)"\)', lookup)
    assert len(services) == 7
    for parameter in ('HOME', 'TMPDIR', 'DARWIN_CACHE_DIR'):
        assert f'(param "{parameter}")' in profile
    windows = {name: window(image, low, high) for name, (low, high) in WINDOWS.items()}
    return {
        'uuid': UUID, 'sha256': SHA256, 'entry_offset': hex(entry),
        'launch_plist_sha256': digest(plist_bytes), 'sandbox_profile_sha256': digest(sandbox_bytes),
        'configured_user': startup['UserName'], 'mach_service': SERVICE, 'activity': ACTIVITY,
        'activity_configuration': schedule, 'pagein_linking': startup['EnvironmentVariables']['DYLD_PAGEIN_LINKING'],
        'explicit_iokit_clients': clients, 'explicit_mach_lookup_names': services,
        'calls': checked_calls, 'strings': {hex(address): value for address, value in STRINGS.items()},
        'additional_fixups': {hex(slot): row for slot, row in block.items()},
        'windows': windows, 'instruction_count': sum(map(len, windows.values())),
        'native_delivery_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('launch_plist', type=Path)
    parser.add_argument('sandbox_profile', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.daemon, args.launch_plist, args.sandbox_profile),
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
