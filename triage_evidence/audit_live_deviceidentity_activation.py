#!/usr/bin/env python3
"""Verify the installed DeviceIdentity to mobileactivationd certificate RPC."""

import argparse
import json
from pathlib import Path
import plistlib
import re
from struct import unpack
import subprocess

from audit_live_fpdi_startup import ThinView, daemon_slices, digest, selected_identity, window
from bootpolicy_cache_reader import CS, Cache, Dylib

CACHE_UUID = '8b1e17c6-72d6-3017-91a4-916022e3612e'
PROVIDER_UUID = 'cab8c302-6770-316e-878e-bc2db99fcbd8'
SERVER_UUID = '828906ff-d325-3bc9-9f28-0b3a8fd7af5b'
SERVER_SHA256 = 'd6c33e737346613383570a14f5be5ff87e27cfabf87a955b2cfaaf210f7f658d'
PROVIDER = '/System/Library/PrivateFrameworks/DeviceIdentity.framework/Versions/A/DeviceIdentity'
FOUNDATION = '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation'
DISPATCH = '/usr/lib/system/libdispatch.dylib'
SECURITY = '/System/Library/Frameworks/Security.framework/Versions/A/Security'
SERVICE = 'com.apple.mobileactivationd'
METHOD = 'issueClientCertificateWithReferenceKey:options:completion:'
PROTOCOL = 'MobileActivationMacOSProtocol'
PROVIDER_WINDOWS = {
    'certificate_entry_and_queue_selection': (0x1b78964c0, 0x1b78967b4),
    'client_support_error': (0x1b78967b4, 0x1b78968ac),
    'vm_support_error': (0x1b789693c, 0x1b7896a34),
    'skip_network_option': (0x1b78981f0, 0x1b7898258),
    'skip_network_after_local_lookup': (0x1b7898860, 0x1b78988b0),
    'key_and_cached_certificates': (0x1b78985d0, 0x1b78986d8),
    'attestation_call': (0x1b7898aa0, 0x1b7898b88),
    'xpc_connection_and_request': (0x1b7898b98, 0x1b7898d7c),
    'proxy_error_block': (0x1b789b2ac, 0x1b789b320),
    'proxy_reply_block': (0x1b789b320, 0x1b789b418),
    'completion_enqueue': (0x1b78975ec, 0x1b7897640),
    'completion_invoke': (0x1b789b548, 0x1b789b57c),
}
PROVIDER_CHECKS = (
    (0x1b7896578, 'mov', 'w0, #0'),
    (0x1b789657c, 'bl', '#0x1b788efe8'),
    (0x1b7896590, 'tbz', 'w24, #0, #0x1b789666c'),
    (0x1b7896594, 'bl', '#0x1b78948c4'),
    (0x1b7896598, 'cbz', 'w0, #0x1b78965c4'),
    (0x1b78965ac, 'bl', '#0x1b789e66c'),
    (0x1b78965c0, 'tbz', 'w24, #0, #0x1b7896728'),
    (0x1b789660c, 'add', 'x16, x16, #0xa34'),
    (0x1b789662c, 'stp', 'x0, x8, [sp, #0x30]'),
    (0x1b7896638, 'str', 'x0, [sp, #0x20]'),
    (0x1b7896644, 'str', 'x0, [sp, #0x28]'),
    (0x1b789669c, 'add', 'x16, x16, #0x7b4'),
    (0x1b7896758, 'add', 'x16, x16, #0x93c'),
    (0x1b7896898, 'blraa', 'x9, x8'),
    (0x1b7896a20, 'blraa', 'x9, x8'),
    (0x1b7898210, 'bl', '#0x1b788ef74'),
    (0x1b7898244, 'str', 'w0, [sp, #0xc8]'),
    (0x1b7898254, 'str', 'wzr, [sp, #0xc8]'),
    (0x1b7898610, 'bl', '#0x1b7891544'),
    (0x1b7898670, 'bl', '#0x1b7891fe4'),
    (0x1b78986d0, 'bl', '#0x1b789ebf0'),
    (0x1b789886c, 'cbz', 'w11, #0x1b78989dc'),
    (0x1b7898888, 'add', 'x5, x5, #0x498'),
    (0x1b7898b1c, 'bl', '#0x1b78a2630'),
    (0x1b7898ba4, 'ldr', 'x2, [x8, #0xe10]'),
    (0x1b7898bc4, 'add', 'x8, x8, #0x988'),
    (0x1b7898bcc, 'mov', 'w3, #0x1000'),
    (0x1b7898cc4, 'add', 'x16, x16, #0x2ac'),
    (0x1b7898cf4, 'str', 'x0, [sp, #0xb0]'),
    (0x1b7898d20, 'add', 'x16, x16, #0x320'),
    (0x1b7898d34, 'str', 'x8, [sp, #0x2e0]'),
    (0x1b7898d40, 'str', 'x8, [sp, #0x2e8]'),
    (0x1b7898d44, 'str', 'x9, [sp, #0x2f0]'),
    (0x1b7898d4c, 'str', 'x8, [sp, #0x2f8]'),
    (0x1b7898d50, 'add', 'x4, sp, #0x2c8'),
    (0x1b7898d54, 'ldr', 'x0, [sp, #0xb0]'),
    (0x1b7898d58, 'mov', 'x2, x25'),
    (0x1b7898d5c, 'ldr', 'x3, [sp, #0xe0]'),
    (0x1b789b2fc, 'str', 'x0, [x9, #0x28]'),
    (0x1b789b370, 'bl', '#0x1b788f348'),
    (0x1b789b384, 'str', 'x0, [x9, #0x28]'),
    (0x1b789b3c0, 'bl', '#0x1b788f4a4'),
    (0x1b789b3d4, 'str', 'x0, [x9, #0x28]'),
    (0x1b789b3f4, 'str', 'x20, [x8, #0x28]'),
    (0x1b78975f8, 'add', 'x16, x16, #0x4c8'),
    (0x1b789b558, 'ldr', 'x1, [x8, #0x18]'),
    (0x1b789b564, 'ldr', 'x2, [x8, #0x28]'),
    (0x1b789b56c, 'ldr', 'x3, [x8, #0x28]'),
    (0x1b789b578, 'blraa', 'x9, x8'),
)
SELECTORS = {
    0x1b7898204: 'objectForKeyedSubscript:', 0x1b7898240: 'boolValue',
    0x1b7898ba8: 'interfaceWithProtocol:', 0x1b7898bd0: 'initWithMachServiceName:options:',
    0x1b7898be0: 'setRemoteObjectInterface:', 0x1b7898be8: 'resume',
    0x1b7898bf0: 'mutableCopy', 0x1b7898c1c: 'removeObjectForKey:',
    0x1b7898c38: 'setObject:forKeyedSubscript:', 0x1b7898c4c: 'removeObjectForKey:',
    0x1b7898c64: 'setObject:forKeyedSubscript:', 0x1b7898c7c: 'setObject:forKeyedSubscript:',
    0x1b7898c90: 'setObject:forKeyedSubscript:',
    0x1b7898cec: 'synchronousRemoteObjectProxyWithErrorHandler:',
    0x1b7898d60: METHOD, 0x1b7898d68: 'invalidate',
    0x1b789b364: 'objectForKeyedSubscript:', 0x1b789b3a8: 'objectForKeyedSubscript:',
}
C_CALLS = {
    0x1b7896650: (DISPATCH, '_dispatch_async'),
    0x1b78966cc: (DISPATCH, '_dispatch_async'),
    0x1b7896788: (DISPATCH, '_dispatch_async'),
    0x1b7897638: (DISPATCH, '_dispatch_async'),
    0x1b78917e0: (SECURITY, '_SecItemCopyMatching'),
    0x1b7892108: (SECURITY, '_SecItemCopyMatching'),
    0x1b78a24c0: (SECURITY, '_SecKeyCopySystemKey'),
    0x1b78a276c: (SECURITY, '_SecKeyCreateAttestation'),
}
CONSTANTS = {
    0x1e1738988: SERVICE, 0x1e1738ae8: 'SkipNetworkRequest', 0x1e1738a70: 'AccessControls',
    0x1e1738ac8: 'UseRKSigningInterface', 0x1e17389b0: 'LocalAuthenticationContext',
    0x1e1738a30: 'AppID', 0x1e1738a90: 'RKAttestationData', 0x1e1738a98: 'RKAttestationPublicKey',
    0x1e1738978: 'RKCertification', 0x1e1738958: 'ServerResponseDate',
}
SERVER_WINDOWS = {
    'listener_accept': (0x100018228, 0x1000182e0),
    'public_receiver': (0x100020da4, 0x100021388),
}
SERVER_NAMES = {
    0x100018228: '-[MobileActivationMacOSDaemon listener:shouldAcceptNewConnection:]',
    0x100020da4: f'-[MobileActivationMacOSDaemon {METHOD}]',
    0x10001c024: '-[MobileActivationMacOSDaemon _issueClientCertificateWithReferenceKey:rkData:baaCertificateType:options:completion:]',
}
SERVER_CALLS = {
    0x100018264: 'interfaceWithProtocol:', 0x10001827c: 'setExportedInterface:',
    0x100018288: 'setExportedObject:', 0x1000182a8: '_setQueue:', 0x1000182b8: 'resume',
    0x100020f9c: '_isSupportedDeviceIdentityClient', 0x100020fc8: 'isEntitled:',
    0x100021094: 'isEntitled:',
    0x100021240: '_issueClientCertificateWithReferenceKey:rkData:baaCertificateType:options:completion:',
}


def instruction(cache, address):
    pc, _, mnemonic, operands = next(CS.disasm_lite(cache.read(address, 4), address))
    assert pc == address
    return mnemonic, operands


def direct_call(cache, address):
    mnemonic, operand = instruction(cache, address)
    assert mnemonic == 'bl'
    return int(operand.removeprefix('#'), 16)


def immediate(operand):
    return int(operand.rsplit('#', 1)[1], 16)


def pointer(cache, address):
    record = cache.pointer(address)
    return int(record['target'], 16), {key: value for key, value in record.items() if key != 'path'}


def cfstring(cache, address):
    storage, row = pointer(cache, address)
    chars, backing = pointer(cache, storage + 16)
    text = cache.cstring(chars, 128)
    assert unpack('<Q', cache.read(storage + 24, 8))[0] == len(text)
    return text, [row, backing]


def cache_window(cache, start, stop):
    raw = cache.read(start, stop - start)
    rows = [[hex(pc), raw[pc-start:pc-start+size].hex(), m, o]
            for pc, size, m, o in CS.disasm_lite(raw, start)]
    assert len(rows) == len(raw) // 4
    return {'sha256': digest(raw), 'instructions': rows}


def dyld_info(path, flag):
    return subprocess.check_output(['xcrun', 'dyld_info', '-arch', 'arm64e', flag, path], text=True)


def inspect(server, plist, sdk_header):
    cache = Cache()
    provider = Dylib(cache, PROVIDER)
    assert cache.uuid == CACHE_UUID and provider.uuid == PROVIDER_UUID
    entry = provider.exports['_DeviceIdentityIssueClientCertificateWithCompletion']['address']
    assert entry == 0x1b78964c0
    for pc, mnemonic, operands in PROVIDER_CHECKS:
        assert instruction(cache, pc) == (mnemonic, operands), hex(pc)
    selectors = {}
    for pc, name in SELECTORS.items():
        stub = direct_call(cache, pc)
        a, b, pivot = (instruction(cache, stub + 4 * index) for index in range(3))
        assert a[0] == 'adrp' and a[1].startswith('x1, #')
        assert b[0] == 'add' and b[1].startswith('x1, x1, #')
        assert pivot == ('b', '#0x1b8000800')
        address = immediate(a[1]) + immediate(b[1])
        assert cache.cstring(address, 128) == name
        selectors[hex(pc)] = {'stub': hex(stub), 'selector_address': hex(address), 'name': name}
    calls = {}
    libs = {name: Dylib(cache, name) for name in (FOUNDATION, SECURITY, DISPATCH)}
    for pc, (lib, symbol) in C_CALLS.items():
        stub = direct_call(cache, pc)
        a, b, load, branch = (instruction(cache, stub + 4 * index) for index in range(4))
        assert a[0] == 'adrp' and a[1].startswith('x17, #')
        assert b[0] == 'add' and b[1].startswith('x17, x17, #')
        assert (load, branch) == (('ldr', 'x16, [x17]'), ('braa', 'x16, x17'))
        address, fixup = pointer(cache, immediate(a[1]) + immediate(b[1]))
        assert fixup['authenticated'] and libs[lib].exports[symbol]['address'] == address
        calls[hex(pc)] = {'stub': hex(stub), 'pointer': fixup, 'symbol': symbol}
    constants = {}
    for pc, expected in CONSTANTS.items():
        text, chain = cfstring(cache, pc)
        assert text == expected
        constants[hex(pc)] = {'text': text, 'pointers': chain}
    protocol, protocol_slot = pointer(cache, 0x1e173ce10)
    chars, name_slot = pointer(cache, protocol + 8)
    assert cache.cstring(chars, 128) == PROTOCOL
    classes = {}
    for slot, name in ((0x1e0172118, 'NSXPCInterface'), (0x1e01720f8, 'NSXPCConnection')):
        address, fixup = pointer(cache, slot)
        assert libs[FOUNDATION].exports['_OBJC_CLASS_$_' + name]['address'] == address
        classes[name] = fixup
    signatures = {}
    for desc, signature in ((0x1e655b728, 'v16@?0@"NSError"8'),
                            (0x1e655b888, 'v24@?0@"NSDictionary"8@"NSError"16')):
        address, fixup = pointer(cache, desc + 32)
        assert cache.cstring(address, 128) == signature
        signatures[hex(desc)] = {'signature': signature, 'pointer': fixup}

    _, _, thin = next(row for row in daemon_slices(server.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == SERVER_UUID and digest(thin) == SERVER_SHA256
    objc = dyld_info(server, '-objc')
    for pc, name in SERVER_NAMES.items():
        assert re.search(rf'{pc:#x} +{re.escape(name)}$', objc, re.I | re.M)
    disassembly = dyld_info(server, '-disassemble')
    for pc, name in SERVER_CALLS.items():
        assert re.search(rf'^{pc:#x} +bl +.*{re.escape(name)}', disassembly, re.I | re.M)
    plist_data = plist.read_bytes()
    assert plistlib.loads(plist_data)['MachServices'][SERVICE] is True
    header_data = sdk_header.read_bytes()
    assert b'NSXPCConnectionPrivileged = (1 << 12UL)' in header_data
    return {
        'cache_uuid': CACHE_UUID, 'provider_uuid': PROVIDER_UUID, 'provider_entry': hex(entry),
        'server_uuid': SERVER_UUID, 'server_sha256': SERVER_SHA256,
        'launch_plist_sha256': digest(plist_data), 'sdk_header_sha256': digest(header_data),
        'service': SERVICE, 'protocol': PROTOCOL, 'protocol_pointers': [protocol_slot, name_slot],
        'connection_option': 4096, 'classes': classes, 'block_signatures': signatures,
        'constants': constants, 'selectors': selectors, 'provider_calls': calls,
        'provider_anchor_checks': len(PROVIDER_CHECKS),
        'provider_windows': {k: cache_window(cache, *v) for k, v in PROVIDER_WINDOWS.items()},
        'server_methods': {hex(k): v for k, v in SERVER_NAMES.items()},
        'server_calls': {hex(k): v for k, v in SERVER_CALLS.items()},
        'server_windows': {k: window(ThinView(thin), *v) for k, v in SERVER_WINDOWS.items()},
        'native_message_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server', type=Path)
    parser.add_argument('launch_plist', type=Path)
    parser.add_argument('sdk_header', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.server, args.launch_plist, args.sdk_header), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
