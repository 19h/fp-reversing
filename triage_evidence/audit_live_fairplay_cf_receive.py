#!/usr/bin/env python3
"""Read installed CoreFoundation and verify the FairPlay RPC receive interface."""

import argparse
import json
from pathlib import Path
import struct
import subprocess

from audit_live_fairplay_rpc_abi import Daemon, PINNED_DAEMON_SHA, command, digest
from audit_live_xpc_log_sites import connect_stub, direct_call
from bootpolicy_cache_reader import Cache, Dylib, CS

HERE = Path(__file__).resolve().parent

FUNCTIONS = {
    0x184772fc8: '_CFMachPortCreateWithPort',
    0x184858190: '__CFMachPortCreateWithPort4',
    0x184773158: '_CFMachPortCreateRunLoopSource',
    0x1847732fc: '_CFRunLoopSourceCreate',
    0x184773914: '_CFRunLoopAddSource',
    0x1848776dc: '___CFRunLoopCopyMode',
    0x18482e904: '___CFMachPortGetPort',
    0x18479ce5c: '___CFRunLoopRun',
    0x18479ea08: '___CFRunLoopServiceMachPort',
    0x18479eba8: '___CFRunLoopDoSource1',
    0x18479eea0: '___CFRUNLOOP_IS_CALLING_OUT_TO_A_SOURCE1_PERFORM_FUNCTION__',
    0x1847ca030: '___CFMachPortPerform',
}

FRAMEWORK_CHECKS = (
    (0x184772fcc, 'b', '#0x184858190'),
    (0x1848582f4, 'ldr', 'w8, [x0, #0x14]'),
    (0x1848582fc, 'b.eq', '#0x18485851c'),
    (0x184858328, 'str', 'w19, [x0, #0x14]'),
    (0x18485832c, 'str', 'x24, [x0, #0x30]'),
    (0x184858374, 'stp', 'x0, x9, [x20, #0x40]'),
    (0x18485853c, 'tbnz', 'w0, #0, #0x184858560'),
    (0x18477321c, 'mov', 'w8, #1'),
    (0x184773220, 'stp', 'x8, x19, [sp]'),
    (0x184773274, 'adrp', 'x16, #0x18482e000'),
    (0x184773278, 'add', 'x16, x16, #0x904'),
    (0x184773280, 'str', 'x16, [sp, #0x38]'),
    (0x184773284, 'adrp', 'x16, #0x1847ca000'),
    (0x184773288, 'add', 'x16, x16, #0x30'),
    (0x184773290, 'str', 'x16, [sp, #0x40]'),
    (0x184773570, 'str', 'x16, [x20, #0xa0]'),
    (0x184773574, 'add', 'x8, x20, #0xa8'),
    (0x18477359c, 'movk', 'x17, #0xc0b6, lsl #48'),
    (0x1847735a4, 'b', '#0x184773718'),
    (0x184773718, 'str', 'x16, [x8]'),
    (0x184877830, 'mov', 'w1, #3'),
    (0x184877838, 'cbnz', 'w0, #0x184877990'),
    (0x184877848, 'stur', 'w8, [x23, #-0x20]'),
    (0x184773bc8, 'blraa', 'x9, x17'),
    (0x184773bcc, 'cbz', 'w0, #0x184773bfc'),
    (0x184773bd4, 'ldr', 'x0, [x22, #0x80]'),
    (0x184773be4, 'ldr', 'w2, [x22, #0x88]'),
    (0x184773bfc, 'add', 'x0, x20, #0x10'),
    (0x18482e904, 'ldr', 'w0, [x0, #0x14]'),
    (0x18479d138, 'ldr', 'w28, [x19, #0x88]'),
    (0x18479d2e4, 'mov', 'x0, x28'),
    (0x18479d2f0, 'ldr', 'w8, [sp, #0x64]'),
    (0x18479ea48, 'mov', 'w27, #0x806'),
    (0x18479ea4c, 'movk', 'w27, #0x700, lsl #16'),
    (0x18479ea50, 'mov', 'w26, #0xc00'),
    (0x18479ea6c, 'cmn', 'w23, #1'),
    (0x18479ea78, 'add', 'w1, w27, #0x100'),
    (0x18479ea8c, 'ldr', 'w3, [x25, #4]'),
    (0x18479ea98, 'mov', 'x4, x24'),
    (0x18479eb04, 'add', 'w8, w8, #0x44'),
    (0x18479eb0c, 'and', 'x26, x8, #0x1fffffffc'),
    (0x18479eb54, 'ldr', 'w8, [x25, #0xc]'),
    (0x18479eb7c, 'str', 'w8, [x9]'),
    (0x18479d6c8, 'ldr', 'x0, [x19, #0x80]'),
    (0x18479d6d0, 'mov', 'x1, x25'),
    (0x18479d6e4, 'ldr', 'x3, [sp, #0x68]'),
    (0x18479d6e8, 'ldr', 'w4, [x3, #4]'),
    (0x18479d704, 'cbz', 'x26, #0x18479d734'),
    (0x18479ed78, 'ldr', 'x16, [x17, #0xa8]!'),
    (0x18479ed80, 'movk', 'x17, #0xc0b6, lsl #48'),
    (0x18479eed8, 'blraaz', 'x8'),
    (0x18479eedc, 'str', 'x0, [x19]'),
    (0x1847ca108, 'ldr', 'x8, [x19, #0x30]'),
    (0x1847ca11c, 'blraaz', 'x8'),
    (0x1847ca138, 'ldr', 'x8, [x19, #0x30]'),
    (0x1847ca14c, 'blraaz', 'x8'),
    (0x1847ca1b0, 'mov', 'x0, #0'),
)

DAEMON_CHECKS = (
    (0x10044038c, 'blraa', 'x8, x17'),
    (0x1003ad1c8, 'ldr', 'w0, [sp, #0x24]'),
    (0x100001fc0, 'adrp', 'x16, #0x100425000'),
    (0x100001fc4, 'add', 'x16, x16, #0xf78'),
    (0x100001fc8, 'paciza', 'x16'),
    (0x100001fdc, 'bl', '#0x100e2a8f0'),
    (0x10031733c, 'blraa', 'x8, x17'),
    (0x100315264, 'blraa', 'x8, x17'),
    (0x100315300, 'blraa', 'x8, x17'),
    (0x100315354, 'str', 'x20, [x8]'),
    (0x1000050e0, 'cmp', 'w8, #0x50'),
    (0x10000511c, 'ldr', 'w8, [x10, #0x50]!'),
    (0x1000051ac, 'ldr', 'w8, [x0, #0xc]'),
    (0x1000051cc, 'ldur', 'q0, [x10, #0x14]'),
    (0x1000051d0, 'ldur', 'q1, [x10, #0x24]'),
    (0x1000051d4, 'stp', 'q0, q1, [sp, #0x30]'),
    (0x1000051e0, 'add', 'x6, sp, #0x30'),
    (0x1000051f8, 'bl', '#0x100422d48'),
    (0x100035184, 'blraa', 'x8, x17'),
)

BANKS = {
    'bootstrap checkin': 0x101039ef0, 'CF existing name wrapper': 0x101039ef0,
    'CF source': 0x101039ef0, 'CF main run loop': 0x101039ef0,
    'CF default mode data': 0x1010a1960, 'CF add source': 0x101039ef0,
}


def assert_instructions(read, checks):
    result = []
    for address, mnemonic, operands in checks:
        raw = read(address, 4)
        insn, = CS.disasm(raw, address)
        assert (insn.mnemonic, insn.op_str) == (mnemonic, operands), hex(address)
        result.append(dict(address=hex(address), bytes=raw.hex(), mnemonic=mnemonic, operands=operands))
    return result


def prior_receipt(name):
    return json.loads(command('zstd', '-dc', str(HERE / (name + '.json.zst'))))


def daemon_evidence(path, framework):
    daemon = Daemon(path)
    assert digest(daemon.data) == PINNED_DAEMON_SHA
    registration = prior_receipt('daemon_registration_contracts')
    prior_abi = prior_receipt('live_fairplay_rpc_abi_audit')
    assert prior_abi['daemon']['thin_sha256'] == PINNED_DAEMON_SHA
    assert prior_abi['runtime_identity']['build'] == '26C5035r'
    fixups = {' '.join(line.split()) for line in
              command('xcrun', 'dyld_info', '-fixups', str(path)).decode().splitlines()}
    pins = dict()
    for proof in registration['bank_proofs']:
        name = proof['label']
        if name not in BANKS:
            continue
        left, right = (daemon.read(int(proof[k], 16), 256) for k in ('left', 'right'))
        key = int(proof['key'], 16)
        constant = int(proof['constant'], 16)
        assert {byte ^ right[left[byte] ^ key] for byte in range(256)} == {constant}
        slot = BANKS[name] + 8 * (constant + int(proof['additive'], 16))
        assert slot == int(proof['slot'], 16)
        assert daemon.read(slot, 8).hex() == proof['original_slot_word']
        assert ' '.join(proof['fixup']['line'].split()) in fixups
        pins[name] = dict(slot=hex(slot), word=proof['original_slot_word'], target=proof['target'],
                          inputs_checked=256)
    assert pins.keys() == BANKS.keys()
    create, = (row for row in registration['imports'] if row['symbol'] == '_CFMachPortCreateWithPort')
    emitter, = (row for row in prior_abi['daemon']['fixups'] if row['address'] == '0x1010a1288')
    assert ' '.join(create['dyld_info_line'].split()) in fixups
    assert any(emitter['address'] in line.lower() and line.endswith(' '.join(emitter['target'].split()))
               for line in fixups)
    create_word, = struct.unpack('<Q', daemon.read(int(create['slot'], 16), 8))
    assert create_word == int(create['word'], 16)
    assert daemon.read(int(emitter['address'], 16), 8).hex() == emitter['raw']
    pins['_CFMachPortCreateWithPort'] = dict(slot=create['slot'], word=create['word'], target=create['symbol'])
    pins['_mach_msg'] = dict(slot=emitter['address'], word=emitter['raw'], target=emitter['target'])
    record = next(row for row in registration['services'] if row['name'] == 'com.apple.unfreed')
    cipher_address = int(record['source_address'], 16)
    cipher = daemon.read(cipher_address, len(bytes.fromhex(record['source_bytes'])))
    assert bytes((byte * -5 + 0x6c) & 255 for byte in cipher) == b'com.apple.unfreed\0'
    assert record['destination_cell'] == '0x1010c4cf0'
    exports = ['_CFMachPortCreateWithPort', *[pins[name]['target'].split('/')[-1]
               for name in ('CF source', 'CF main run loop', 'CF default mode data', 'CF add source')]]
    return dict(thin_sha256=PINNED_DAEMON_SHA, service=record['name'], destination=record['destination_cell'],
                service_cipher=cipher.hex(), prior_installed_slice=prior_abi['runtime_identity']['matched_process']['matched_slice']['uuid'],
                import_pins=pins, current_cf_exports={name: framework.exports[name] for name in exports},
                instructions=assert_instructions(daemon.read, DAEMON_CHECKS))


def sdk_contract():
    sdk = command('xcrun', '--show-sdk-path').decode().strip()
    program = b"""
#include <stddef.h>
#include <mach/message.h>
#include <mach/port.h>
_Static_assert(sizeof(mach_msg_header_t) == 24, "header bytes");
_Static_assert(offsetof(mach_msg_header_t, msgh_size) == 4, "size offset");
_Static_assert(offsetof(mach_msg_header_t, msgh_local_port) == 12, "local-name offset");
_Static_assert(MACH_PORT_RIGHT_PORT_SET == 3, "port set flavor");
_Static_assert(sizeof(mach_msg_mac_trailer_t) == 68, "AV trailer bytes");
_Static_assert(sizeof(audit_token_t) == 32, "audit bytes");
_Static_assert(offsetof(mach_msg_mac_trailer_t, msgh_audit) == 20, "audit offset");
_Static_assert((MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_VOUCHER |
    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AV)) == 0x07000806, "receive options");
_Static_assert(MACH_RCV_TIMEOUT == 0x100, "timeout option");
"""
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-isysroot', sdk, '-fsyntax-only', '-x', 'c', '-'],
                   input=program, check=True)
    return dict(sdk_version=command('xcrun', '--show-sdk-version').decode().strip(),
                header_bytes=24, receive_flags=['MACH_RCV_MSG', 'MACH_RCV_LARGE', 'MACH_RCV_VOUCHER'],
                no_timeout_option='0x07000806', timeout_option='0x07000906', trailer_format=0,
                trailer_elements=7, capacity_bytes=3072, inline_bytes=80, trailer_bytes=68,
                footprint_bytes=80 + 68, spare_capacity_bytes=3072 - (80 + 68),
                audit_offset_in_trailer_bytes=20, audit_span_in_receive_buffer=[80 + 20, 80 + 20 + 32])


def audit(path):
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    cache = Cache()
    cf = Dylib(cache, '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation')
    libkernel = Dylib(cache, '/usr/lib/system/libsystem_kernel.dylib')
    assert (cache.uuid, cf.uuid, libkernel.uuid) == ('8b1e17c6-72d6-3017-91a4-916022e3612e',
        '14db37b1-11f1-31ad-9c07-74bed59a8036', '780a6c1f-be02-34cc-84dd-00e05f61c89b')
    ranges = {}
    for address, name in FUNCTIONS.items():
        assert name in {row['name'] for row in cf.symbols_at(address)}
        function = cf.function(address)
        assert len(function['instructions']) * 4 == len(bytes.fromhex(function['bytes']))
        ranges[name] = function

    stubs = {name: connect_stub(cache, site, libkernel, name) for name, site in (
        ('_mach_port_allocate', 0x188076b90), ('_mach_port_insert_member', 0x188085bf0),
        ('_mach_msg', 0x188076b70))}
    cf_calls = [(0x184773a78, 0x1848776dc), (0x1847732a0, 0x1847732fc),
                (0x184773be0, cf.exports['_CFDictionarySetValue']['address']),
                (0x18479d6d4, cf.exports['_CFDictionaryGetValue']['address']),
                (0x18479d2ec, 0x18479ea08), (0x18479d6f8, 0x18479eba8), (0x18479ee00, 0x18479eea0)]
    kernel_calls = [(site, int(stubs[name]['stub'], 16)) for site, name in (
        (0x184877834, '_mach_port_allocate'), (0x184773bf8, '_mach_port_insert_member'),
        (0x18479eaa4, '_mach_msg'), (0x18479d724, '_mach_msg'))]
    return dict(build=build, cache_uuid=cache.uuid, corefoundation_uuid=cf.uuid,
                libsystem_kernel_uuid=libkernel.uuid, function_ranges=ranges, kernel_stubs=stubs,
                direct_calls=[direct_call(cache, site, target) for site, target in cf_calls + kernel_calls],
                instructions=assert_instructions(cache.read, FRAMEWORK_CHECKS),
                daemon=daemon_evidence(path, cf), sdk=sdk_contract(), native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    print(json.dumps(audit(parser.parse_args().daemon), indent=2))
