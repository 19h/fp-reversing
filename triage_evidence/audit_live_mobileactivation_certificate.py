#!/usr/bin/env python3
"""Audit the installed mobileactivationd certificate path with static reads."""

import argparse
import json
from pathlib import Path
import re
from struct import unpack

from audit_live_deviceidentity_activation import SERVER_SHA256, SERVER_UUID, dyld_info
from audit_live_fpdi_startup import ThinView, bindings, daemon_slices, digest, selected_identity, window

WINDOWS = {
    'public_call_and_abi': (0x100021228, 0x100021244),
    'receiver_arguments_and_options': (0x10001c024, 0x10001c3a0),
    'creation_dispatch': (0x10001c740, 0x10001c894),
    'creation_error_reply': (0x10001c9e8, 0x10001ca08),
    'request_worker': (0x10001cad4, 0x10001ce78),
    'transport_dispatch': (0x10001d1a4, 0x10001d284),
    'transport_and_http_status': (0x10001d2c0, 0x10001d4c4),
    'http_response_decode': (0x10001d8b4, 0x10001da00),
    'http_server_error': (0x10001da00, 0x10001dab0),
    'certificate_trust_and_reply': (0x10001dd50, 0x10001e0f8),
    'xpc_reply_invoke': (0x10001d740, 0x10001d76c),
    'http_task': (0x1000425b8, 0x100042734),
    'http_task_completion': (0x100042b7c, 0x100042c34),
    'xml_request_builder': (0x10004667c, 0x1000467cc),
    'macos_baa_reference_key_and_options': (0x10000787c, 0x100007940),
    'macos_baa_attestation_and_serialization': (0x100007c4c, 0x100007d14),
    'non_vm_key_query_branch': (0x100004f28, 0x100004f5c),
    'primary_public_key': (0x1000051ac, 0x10000520c),
    'secondary_public_key': (0x1000055e8, 0x100005628),
    'public_key_wrapper': (0x100029218, 0x100029238),
    'public_key_request_builder': (0x10005be1c, 0x10005bebc),
    'aks_operation': (0x10005b714, 0x10005b828),
    'aks_connection_getter': (0x10004845c, 0x10004849c),
    'aks_connection_open': (0x1000484d0, 0x1000485bc),
}

CALLS = {
    0x10001c0f4: '_dispatch_assert_queue$V2',
    0x10001c778: '_networkReachable',
    0x10001c794: 'creationQueue',
    0x10001c890: '_dispatch_async',
    0x10001cb04: '_createBAAClientName',
    0x10001cb5c: '_create_baa_info_macos',
    0x10001cbf8: 'propertyListWithData:options:format:error:',
    0x10001cc98: '_createXMLRequest',
    0x10001cd34: 'setValue:forHTTPHeaderField:',
    0x10001cd40: '_is_virtual_machine',
    0x10001cd7c: 'setURL:',
    0x10001cd98: 'setTimeoutInterval:',
    0x10001cd9c: '_is_internal_build',
    0x10001cdc4: 'persistentDomainForName:',
    0x10001ce64: 'setURL:',
    0x10001d1b0: '_dispatch_get_global_queue',
    0x10001d280: '_dispatch_async',
    0x10001d414: '_talkToServerWithError',
    0x10001d910: 'dateFromServerString:withError:',
    0x10001d954: '_lockcrypto_decode_pems',
    0x10001de10: '_copyRootCertificate',
    0x10001de94: '_SecCertificateCreateWithData',
    0x10001dec8: '_SecCertificateCreateWithData',
    0x10001df14: '_evaluateAccessoryTrustWithCerts',
    0x10001e054: '_evaluateBAATrustWithCerts',
    0x10001e0e4: 'dictionaryWithObjects:forKeys:count:',
    0x100021240: '_issueClientCertificateWithReferenceKey:rkData:baaCertificateType:options:completion:',
    0x100042604: 'sessionWithConfiguration:delegate:delegateQueue:',
    0x1000426e0: 'dataTaskWithRequest:completionHandler:',
    0x10004271c: 'resume',
    0x10004272c: '_dispatch_semaphore_wait',
    0x100042bd0: 'statusCode',
    0x100042be4: 'allHeaderFields',
    0x1000466cc: 'dataWithPropertyList:format:options:error:',
    0x100046728: 'setHTTPMethod:',
    0x1000467b8: 'setHTTPBody:',
    0x100004f44: '_is_virtual_machine',
    0x1000051cc: '_libaks_system_key_get_public',
    0x1000055f8: '_libaks_system_key_get_public',
    0x100007c70: '_security_create_system_key_attestation',
    0x100007d00: '_create_baa_info',
    0x100029230: '_aks_system_key_get_public',
    0x10005beac: '__aks_operation',
    0x10005b77c: '_get_aks_client_connection',
    0x10005b7e4: '_IOConnectCallMethod',
    0x100048488: '__copy_aks_client_connection',
    0x100048504: '_IORegistryEntryFromPath',
    0x100048524: '_IOServiceOpen',
    0x100048544: '_IOServiceMatching',
    0x100048568: '_IOServiceOpen',
    0x1000485a4: '_IOConnectCallMethod',
    0x1000485b4: '_IOServiceClose',
}

CHECKS = (
    (0x100021234, 'mov', 'w4, #0'),
    (0x10001c7d4, 'add', 'x16, x16, #0xad4'),
    (0x10001cb40, 'ldp', 'x0, x1, [x21, #0x30]'),
    (0x10001cb44, 'ldr', 'x2, [x21, #0x40]'),
    (0x10001cd58, 'csel', 'x8, x8, x9, ne'),
    (0x10001d1f0, 'add', 'x16, x16, #0x2c0'),
    (0x10001d408, 'mov', 'w1, #0'),
    (0x10001d40c, 'mov', 'w2, #0'),
    (0x10001d410, 'mov', 'x3, #0'),
    (0x10001d4b8, 'cmp', 'x20, #0xc8'),
    (0x10001d4bc, 'b.eq', '#0x10001d8b4'),
    (0x10001d970, 'stp', 'x22, x21, [sp, #0x48]'),
    (0x10001d980, 'cmp', 'x0, #2'),
    (0x10001def0, 'cmp', 'w9, #1'),
    (0x10001def4, 'b.ne', '#0x10001e038'),
    (0x10001e0cc, 'stp', 'x9, x8, [x29, #-0x70]'),
    (0x10001e0f4, 'b', '#0x10001d5a0'),
    (0x10001d748, 'ldr', 'x0, [x19, #0x50]'),
    (0x10001d758, 'ldr', 'x2, [x8, #0x28]'),
    (0x10001d764, 'mov', 'x1, x20'),
    (0x10001d768, 'blraa', 'x9, x8'),
    (0x1000466c4, 'mov', 'w3, #0x64'),
    (0x100004f48, 'cbz', 'w0, #0x1000051ac'),
    (0x1000051b8, 'cbz', 'x8, #0x10000520c'),
    (0x1000051c4, 'mov', 'w0, #1'),
    (0x1000051c8, 'mov', 'w1, #1'),
    (0x100005200, 'tbz', 'w0, #0, #0x1000055e8'),
    (0x1000055f0, 'mov', 'w0, #2'),
    (0x1000055f4, 'mov', 'w1, #2'),
    (0x10005b780, 'cbz', 'w0, #0x10005b878'),
    (0x10005b7c8, 'mov', 'x0, x24'),
    (0x10005b7cc, 'mov', 'w1, #0x2b'),
    (0x10005b7d0, 'mov', 'w3, #1'),
    (0x100048520, 'mov', 'w2, #0'),
    (0x100048564, 'mov', 'w2, #0'),
    (0x100048588, 'mov', 'w1, #0'),
)

CF_STRINGS = {
    0x1000ae018: 'https://humb.apple.com/humbug/baa',
    0x1000ae020: 'https://humb.apple.com/humbug/vmbaa',
    0x100098ef8: 'BAAOverrideURL',
    0x100099290: 'RKCertification',
    0x1000990c8: 'ServerResponseDate',
    0x100099650: 'RKProperties',
    0x100099940: 'Date',
}

C_STRINGS = {
    0x100093ddc: 'IOService:/IOResources/AppleKeyStore',
    0x100093e01: 'AppleKeyStore',
    0x10008a4b0: 'CERTIFICATE',
}


def rebased_pointer(fixups, slot):
    kind, address = fixups[slot].split()
    assert kind == 'rebase'
    return int(address, 16)


def inspect(server):
    thin = next(row[2] for row in daemon_slices(server.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == SERVER_UUID and digest(thin) == SERVER_SHA256
    image = ThinView(thin)
    disassembly = dyld_info(server, '-disassemble')
    fixups = bindings(server, '-arch', 'arm64e')
    calls = {}
    for address, symbol in CALLS.items():
        match = re.search(rf'^0x{address:X} +bl +("?)(\S+?)\1 *$', disassembly, re.M)
        assert match and match[2] in (symbol, '_objc_msgSend$' + symbol), (hex(address), symbol)
        calls[hex(address)] = match[2]
    for address, mnemonic, operands in CHECKS:
        image.instruction(address, mnemonic, operands)
    constants = {}
    for slot, expected in CF_STRINGS.items():
        obj = rebased_pointer(fixups, slot)
        chars = rebased_pointer(fixups, obj + 16)
        size = unpack('<Q', image.read(obj + 24, 8))[0]
        assert image.read(chars, size + 1) == expected.encode() + b'\0', hex(slot)
        constants[hex(slot)] = {'object': hex(obj), 'characters': hex(chars), 'value': expected}
    for address, expected in C_STRINGS.items():
        assert image.read(address, len(expected) + 1) == expected.encode() + b'\0', hex(address)
        constants[hex(address)] = {'value': expected}
    return {
        'server_uuid': SERVER_UUID,
        'server_arm64e_sha256': SERVER_SHA256,
        'calls': calls,
        'instruction_checks': len(CHECKS),
        'windows': {label: window(image, *bounds) for label, bounds in WINDOWS.items()},
        'constants': constants,
        'native_message_observed': False,
        'native_network_request_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.server), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
