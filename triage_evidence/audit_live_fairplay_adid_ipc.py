#!/usr/bin/env python3
"""Check the installed FairPlay/CoreADI XPC and notification interfaces without sending IPC."""

import argparse
import json
from pathlib import Path
import re
import struct

from audit_daemon_iokit_native_registry import PINNED_DAEMON_SHA, command, daemon_slices, digest
from audit_fairplay_live_slice_identity import audit as live_slice_audit
from audit_live_fairplay_rpc_abi import Daemon
from resolve_kernel_collection_interfaces import commands

ROOT = Path(__file__).resolve().parent
POOL = 0x1010b1720
TABLE = 0x1010abb60
PROVIDER_SHA = 'b9e0043fbbc4525ad1a78545155c6c096422688de2ce3a3fc0144ab6adab9895'
ARM64E = (0x0100000c, 0x80000002)
CREATE = (0x1010331e0, 0x101033600)
TYPED = (0x101033700, 0x101033a30)
QUEUE = (0x1010332e0, 0x101033800)
PAYLOAD = (0x101033930, 0x101032e80)
ACTIVATE = (0x1010330e0, 0x101033500)
NAMES = (
    ('com.apple.adid.midchangedV1', 0x101032fa3, 0x100e1fe88),
    ('com.apple.adid.midchangedV1.5', 0x101032f85, 0x100e1ff5c),
    ('com.apple.adid.midchangedV3', 0x101032fbf, 0x100e20054),
)


class ThinView(Daemon):
    def __init__(self, blob):
        self.data = blob
        self.segments = []
        for offset, command_id, _ in commands(blob, 0):
            if command_id == 0x19:
                vm, _, file_offset, size = struct.unpack_from('<4Q', blob, offset + 24)
                self.segments.append((vm, file_offset, size))


def reference(name):
    return json.loads(command('zstd', '-dcq', str(ROOT / (name + '.json.zst'))))


def bindings(path, *arch):
    out = command('xcrun', 'dyld_info', '-fixups', *arch, str(path)).decode()
    return {int(pc, 16): ' '.join(row.split()) for pc, row in re.findall(
        r'^\s*\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+((?:auth-)?(?:rebase|bind)\s+.*)$', out, re.M)}


def selection(image, fixups, banks, key, bias, base, expected, adjustment=0):
    left, right = (image.read(address, 256) for address in banks)
    values = {i ^ right[left[i] ^ key] for i in range(256)}
    assert len(values) == 1
    constant = values.pop()
    index = constant + bias
    slot = base + 8 * index
    row = fixups[slot]
    kind, target, *_ = row.split()
    actual = (int(target, 16) + adjustment) if 'rebase' in kind else target
    assert actual == expected
    return {'bank_addresses': list(map(hex, banks)), 'key': hex(key),
            'constant': hex(constant), 'bias': bias, 'slot': hex(slot),
            'slot_word': image.read(slot, 8).hex(), 'binding': row,
            'adjustment': adjustment, 'inputs_checked': 256}


def fairplay(path):
    image = Daemon(path)
    assert digest(image.data) == PINNED_DAEMON_SHA
    fixups = bindings(path)
    selections = {
        'queue label and service name': selection(image, fixups, (0x101032d80, 0x101032fe0),
                                                    0xe0, -0x36, POOL, 0x101033900),
        'dispatch table': selection(image, fixups, TYPED, 0x6a, -0x61, POOL, TABLE, -8),
        'dictionary key': selection(image, fixups, PAYLOAD, 0x8d, -0x10, POOL, 0x101032f80, -2),
        'global callback block': selection(image, fixups, PAYLOAD, 0x8d, -0x1a, POOL, 0x1010abb40),
        'error type': selection(image, fixups, QUEUE, 0x3e, -0x9a, POOL, 'libSystem/__xpc_type_error'),
        'interrupted singleton': selection(image, fixups, TYPED, 0x1d, -0x15, POOL,
                                           'libSystem/__xpc_error_connection_interrupted'),
    }
    assert selections['interrupted singleton']['binding'].endswith(' + 0x4')
    assert fixups[0x1010abb40].startswith('auth-bind libSystem/__NSConcreteGlobalBlock ')
    assert fixups[0x1010abb50] == 'auth-rebase 0x100DFDE94 (div=0x0000 ad=1 key=IA)'
    assert image.read(0x101033900, 15) == b'com.apple.adid\0'
    assert image.read(0x101032f80, 5) == b'data\0'

    calls = (
        (0x100e21370, PAYLOAD, 0x8d, 0xb39, '_xpc_dictionary_create_empty', 'x8', 0x89e0),
        (0x100e21448, PAYLOAD, 0x4a, 0xace, '_xpc_dictionary_set_data', 'x10', 0x70e2),
        (0x100e214ac, QUEUE, 0x3e, 0xa80, '_dispatch_queue_create', 'x8', 0x6463),
        (0x100e21578, CREATE, 0xba, 0xadd, '_xpc_connection_create_mach_service', 'x8', 0x7d61),
        (0x100e21678, TYPED, 0x1d, 0xb38, '_xpc_connection_set_event_handler', 'x11', 0x7d61),
        (0x100e216c8, ACTIVATE, 0xa0, 0xaca, '_xpc_connection_activate', 'x8', 0x89e0),
        (0x100e21718, TYPED, 0x1d, 0xb0d, '_xpc_connection_send_message_with_reply_sync', 'x8', 0x57e4),
        (0x100e21770, CREATE, 0xba, 0xacf, '_xpc_get_type', 'x8', 0x57e4),
        (0x100e218dc, TYPED, 0x7b, 0xa58, '_xpc_connection_send_message_with_reply_sync', 'x8', 0x57e4),
        (0x100e21930, PAYLOAD, 0xaa, 0xa92, '_xpc_get_type', 'x8', 0x57e4),
        (0x100e21a08, QUEUE, 0xde, 0xa7b, '_xpc_dictionary_get_data', 'x8', 0x70e2),
    )
    for pc, banks, key, bias, symbol, register, diversity in calls:
        row = selection(image, fixups, banks, key, bias, TABLE, 'libSystem/' + symbol)
        assert row['binding'].endswith(f'(div=0x{diversity:04X} ad=0 key=IA)')
        image.instruction(pc - 4, 'mov', f'x17, #{diversity:#x}')
        image.instruction(pc, 'blraa', f'{register}, x17')
        selections[hex(pc)] = row

    instructions = (
        (0x100e1e668, 'str', 'x10, [sp, #0x128]'),
        (0x100e1e684, 'str', 'x14, [sp, #0x130]'),
        (0x100e1e6d0, 'stp', 'x14, x16, [sp, #0xf8]'),
        (0x100e1e84c, 'str', 'x15, [sp, #0xc8]'),
        (0x100e1e864, 'str', 'x14, [sp, #0xc0]'),
        (0x100e1e8b8, 'str', 'x17, [sp, #0x10]'),
        (0x100e1e954, 'stp', 'x11, x10, [sp, #0x18]'),
        (0x100e1e964, 'stp', 'x10, x9, [sp, #0xd8]'),
        (0x100e1e978, 'str', 'x3, [sp, #0x148]'),
        (0x100e212ac, 'ldr', 'x21, [sp, #0x1c0]'),
        (0x100e212b0, 'str', 'xzr, [sp, #0x1b0]'),
        (0x100e21308, 'braa', 'x8, x17'),
        (0x100e21390, 'ldr', 'x2, [x8]'),
        (0x100e213a8, 'ldr', 'w8, [x8]'),
        (0x100e213b8, 'add', 'w3, w8, w9'),
        (0x100e21438, 'sub', 'x21, x8, #2'),
        (0x100e2143c, 'str', 'x0, [sp, #0xe8]'),
        (0x100e21440, 'mov', 'x1, x21'),
        (0x100e214a0, 'ldr', 'x0, [sp, #0x10]'),
        (0x100e214a4, 'mov', 'x1, #0'),
        (0x100e214f4, 'braa', 'x8, x17'),
        (0x100e214f8, 'mov', 'x1, x0'),
        (0x100e21554, 'ldp', 'x0, x11, [sp, #0x10]'),
        (0x100e21570, 'mov', 'x2, #0'),
        (0x100e215c8, 'braa', 'x8, x17'),
        (0x100e215cc, 'str', 'x21, [sp, #0xa0]'),
        (0x100e21600, 'ldp', 'x21, x22, [sp, #0x128]'),
        (0x100e21670, 'mov', 'x25, x0'),
        (0x100e216c0, 'mov', 'x0, x25'),
        (0x100e21708, 'str', 'x25, [sp, #0x98]'),
        (0x100e2170c, 'mov', 'x0, x25'),
        (0x100e21710, 'ldr', 'x1, [sp, #0xe8]'),
        (0x100e2171c, 'mov', 'x25, x0'),
        (0x100e217e0, 'braa', 'x8, x17'),
        (0x100e2182c, 'sub', 'x26, x8, #4'),
        (0x100e21830, 'cmp', 'x25, x26'),
        (0x100e21850, 'braa', 'x8, x17'),
        (0x100e218d0, 'ldr', 'x0, [sp, #0x98]'),
        (0x100e218d4, 'ldr', 'x1, [sp, #0xe8]'),
        (0x100e218e0, 'mov', 'x25, x0'),
        (0x100e21940, 'mov', 'x0, x25'),
        (0x100e2196c, 'braa', 'x8, x17'),
        (0x100e21978, 'str', 'x0, [x22, #0x130]'),
        (0x100e2197c, 'b', '#0x100e21988'),
        (0x100e21984, 'mov', 'x0, x25'),
        (0x100e219fc, 'add', 'x2, sp, #0x1b0'),
        (0x100e21a00, 'ldr', 'x1, [sp, #0xa0]'),
        (0x100e21a10, 'str', 'x0, [x22, #0x138]'),
    )
    for pc, mnemonic, operands in instructions:
        image.instruction(pc, mnemonic, operands)
    edges = branch_edges(fixups)
    for name, addr, pc in NAMES:
        assert image.read(addr, len(name) + 1) == name.encode() + b'\0'
        assert image.instructions(pc, 4)[0].mnemonic == 'blraa'
    windows = {hex(start): image.read(start, end - start).hex() for start, end in (
        (0x100e1e5ec, 0x100e1e984), (0x100e21294, 0x100e21a4c),
    )}
    return {'selections': selections, 'branch_edges': edges, 'original_windows': windows,
            'instruction_assertions': len(instructions) + 2 * len(calls),
            'notification_registration_sites': {name: hex(pc) for name, _, pc in NAMES}}


def branch_edges(fixups):
    # Call-return cuts preserve callee-saved registers. CSET outputs are 0 or 1.
    # Start at 0x100e21294 with w8=0 and the ordinary, non-sentinel record.
    entry_index = 0x42f
    queue_tag = (entry_index + 0x4b1) | 0x210
    queue_live = (queue_tag, 0xb0a)
    new_connection = queue_tag ^ 0xb75
    first_send = (new_connection ^ 0x186) * 0x23d
    parity = new_connection ^ 0x21ef67a4
    connection_indices = tuple(
        new_connection ^ (((parity ^ flag) & 1) * (0x68e ^ first_send)) for flag in (0, 1))
    saved = first_send ^ 0x61c
    error = (first_send - 0x277) | 0x122
    first_reply = (first_send, first_send ^ (((error ^ -0x54d) + saved) & 0xffffffff))
    retry_tag = saved ^ 0x201
    interruption = (saved, saved ^ (retry_tag + 0x4df))
    retry_state = (retry_tag + 0xf94d3d4d) & 0xffffffff
    retry_reply = tuple(
        retry_tag ^ (((retry_state ^ flag) & 1) * 0x17) for flag in (0, 1))
    rows = (
        (0x100e21308, (entry_index,), 0x94ac, (0x100e2130c,)),
        (0x100e214f4, queue_live, 0xe76d, (0x100e214f8, 0x100e22fc0)),
        (0x100e215c8, connection_indices, 0x2387, (0x100e215cc, 0x100e22fc0)),
        (0x100e217e0, first_reply, 0x3de1, (0x100e21980, 0x100e217e4)),
        (0x100e21850, interruption, 0x2330, (0x100e22d44, 0x100e21854)),
        (0x100e2196c, retry_reply, 0xf1e2, (0x100e21970, 0x100e22d14)),
    )
    for pc, indices, diversity, targets in rows:
        for index, target in zip(indices, targets, strict=True):
            assert fixups[TABLE + 8 * index] == (
                f'auth-rebase 0x{target:X} (div=0x{diversity:04X} ad=0 key=IA)')
    return {hex(pc): [{'index': hex(index), 'target': hex(target)} for index, target in
                      zip(indices, targets, strict=True)] for pc, indices, _, targets in rows}


def provider(path):
    blob, = [data for cpu, subtype, data in daemon_slices(path.read_bytes())
             if (cpu, subtype) == ARM64E]
    assert digest(blob) == PROVIDER_SHA
    image = ThinView(blob)
    fixups = bindings(path, '-arch', 'arm64e')
    startup = reference('adid_startup_contracts')
    receiver = reference('adid_receiver_contracts')
    notification = reference('adid_notification_contracts')
    listener, = [row for row in startup['original_windows'] if row['start'] == '0x10001a780']
    post, = [row for row in notification['original_windows'] if row['image'] == 'provider']
    adapter = [row for row in receiver['small_original_functions']
               if row['start'] in ('0x1000009f8', '0x100029fc8', '0x1000aa0ec')]
    assert len(adapter) == 3
    windows = {}
    for row in (listener, post, *adapter):
        expected = bytes.fromhex(row['bytes'])
        assert image.read(int(row['start'], 16), len(expected)) == expected
        windows[row['start']] = {'bytes': len(expected), 'sha256': digest(expected)}
    chain = {}
    for row in notification['provider_chain_members']:
        address = int(row['address'], 16)
        assert struct.unpack('<Q', image.read(address, 8))[0] == int(row['word'], 16)
        assert fixups[address].split()[1].lower() == row['target'].lower()
        chain[row['address']] = fixups[address]
    assert fixups[0x1002d83c8] == 'auth-bind libSystem/_notify_post (div=0xD825 ad=0 key=IA)'
    interface_calls = {}
    for pc, slot, api, register, diversity in (
        (0x10001a7b4, 0x1002d8790, '_xpc_connection_create_mach_service', 'x10', 0x4b7d),
        (0x10001a980, 0x1002d86c0, '_xpc_connection_activate', 'x8', 0xaa6f),
        (0x1000aa3f0, 0x1002d8610, '_xpc_dictionary_create_reply', 'x8', 0x70c3),
        (0x1000aa4c0, 0x1002d8a18, '_xpc_dictionary_get_audit_token', 'x8', 0xd178),
        (0x1000aa598, 0x1002d89f0, '_xpc_dictionary_get_data', 'x9', 0xa1ff),
        (0x1000aa9fc, 0x1002d8720, '_xpc_dictionary_set_data', 'x8', 0x7af6),
        (0x1000aaa70, 0x1002d8690, '_xpc_dictionary_send_reply', 'x8', 0x8d99),
        (0x100219198, 0x1002d83c8, '_notify_post', 'x8', 0xd825),
    ):
        assert fixups[slot] == f'auth-bind libSystem/{api} (div=0x{diversity:04X} ad=0 key=IA)'
        image.instruction(pc - 4, 'mov', f'x17, #{diversity:#x}')
        image.instruction(pc, 'blraa', f'{register}, x17')
        interface_calls[hex(pc)] = {'slot': hex(slot), 'binding': fixups[slot]}
    image.instruction(0x10001a7ac, 'mov', 'w2, #1')
    assert image.read(0x1002a8c40, 5) == b'data\0'
    banks = set()
    for row in notification['provider_byte_banks']:
        bank_bytes = []
        for label in ('first', 'second'):
            address = int(row[f'{label}_address'], 16)
            expected = bytes.fromhex(row[f'{label}_bytes'])
            assert len(expected) == 256 and image.read(address, 256) == expected
            banks.add(address)
            bank_bytes.append(expected)
        first, second = bank_bytes
        key = row['input_XOR_u8']
        assert {i ^ second[first[i] ^ key] for i in range(256)} == {row['low_byte_result']}
    names = {}
    for row in notification['original_names']:
        if row['image'] == 'provider':
            original = bytes.fromhex(row['bytes'])
            assert blob.count(original) == 1
            assert image.read(int(row['address'], 16), len(original)) == original
            names[row['name']] = row['address']
    assert set(names) == {name for name, _, _ in NAMES}
    return {'sha256': PROVIDER_SHA, 'matching_prior_windows': windows,
            'interface_calls': interface_calls, 'notification_bank_evaluations': 256 * len(notification['provider_byte_banks']),
            'matching_notification_fixups': chain, 'notification_banks': sorted(map(hex, banks)),
            'notification_names': names, 'notification_post_site': notification['provider_post_site']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fairplayd', type=Path)
    parser.add_argument('adid', type=Path)
    parser.add_argument('--observe', action='store_true', help='also match current process slice identities')
    args = parser.parse_args()
    result = {'fairplayd': fairplay(args.fairplayd), 'adid': provider(args.adid),
              'native_xpc_or_notification_transaction_observed': False}
    if args.observe:
        live = live_slice_audit(args.fairplayd)
        assert live['processes']['adid']['matched_slice']['sha256'] == PROVIDER_SHA
        result['live_image_identity'] = live
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
