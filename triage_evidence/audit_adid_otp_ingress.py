#!/usr/bin/env python3
"""Check existing OTP ABI traces against installed adid bytes without sending IPC."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import zlib

from audit_live_fairplay_adid_ipc import ARM64E, PROVIDER_SHA, ThinView, daemon_slices, reference

MASK64 = (1 << 64) - 1
OPERAND_MASK = 0xda8ca8cae5dfbd2d
COMMAND = 0xcfe0b46a
DISPATCH = 0x10016d454
READ = (0x1001af0ec, 0x1001af0f8, 0x1001af104, 0x1001af110,
        0x1001af11c, 0x1001af128, 0x1001af134, 0x1001af140)
EDGES = (
    (DISPATCH, 0x10016dab8),
    (0x10016db00, 0x10016db04),
    (0x10016db5c, 0x10016e388),
    (0x10016e450, 0x10016e454),
    (0x10016e4c8, 0x1001af094),
    (0x1001af0d0, 0x1001af0d4),
    (0x1001af178, 0x1001c0208),
    (0x1001c0240, 0x1001c0244),
    (0x1001c0314, 0x10002ba5c),
    (0x10002bdd4, 0x1001c0318),
    (0x100219edc, 0x100219ee0),
    (0x100219f38, 0x10024d5f8),
)
IOKIT_SITES = (0x1000208fc, 0x10002af70, 0x10001f908, 0x10004967c, 0x100058a1c)


def unpack(row, name):
    return zlib.decompress(base64.b64decode(row[name], validate=True))


def signed(data):
    return int.from_bytes(data, 'big', signed=True)


def named_event(events, name, site):
    event, = [event for event in events
              if event.get('name') == name and event.get('callsite') == hex(site)]
    assert event['native_API_executed'] is False
    return event


def original_sequence(image, profile, records):
    archived = {int(row['ea'], 16): bytes.fromhex(row['bytes']) for row in records}
    packed = unpack(profile, 'visited_original_instructions_zlib_base64')
    visits = [pc for pc, in struct.iter_unpack('<Q', packed)]
    assert len(visits) == profile['visited_original_instruction_count']
    current = {pc: image.read(pc, 4) for pc in set(visits)}
    assert all(archived[pc] == word for pc, word in current.items())
    ordered = hashlib.sha256()
    for pc in visits:
        ordered.update(struct.pack('<Q', pc))
        ordered.update(current[pc])
    assert ordered.hexdigest() == profile['ordered_original_instruction_sha256']
    return visits, current, ordered.hexdigest()


def encoded_operand(value):
    return (value + OPERAND_MASK - ((2 * OPERAND_MASK) & (value << 1))) & MASK64


def audit_profile(image, profile, records, expected_request):
    visits, current, ordered_hash = original_sequence(image, profile, records)
    assert profile['stop_reason'] == 'returned_to_private_fixture'
    events = json.loads(unpack(profile, 'records_zlib_base64'))
    request = named_event(events, '_xpc_dictionary_get_data', 0x1000aa598)
    payload = bytes.fromhex(request['payload_bytes'])
    assert payload == expected_request == bytes.fromhex(profile['fixture']['payload_hex'])
    assert request['key'] == 'data' and request['size_bytes'] == len(payload)
    assert struct.unpack_from('>III', payload) == (1, COMMAND, 1)

    observed_reads = [event for event in events if event['kind'] == 'original_payload_read']
    base = int(request['result'], 16)
    offsets = [int(event['address'], 16) - base for event in observed_reads]
    assert offsets == list(range(20))
    assert all(event['size_bytes'] == 1 for event in observed_reads)
    assert bytes(int(event['bytes'], 16) for event in observed_reads) == payload[:20]
    assert tuple(int(event['pc'], 16) for event in observed_reads[-8:]) == READ

    start = visits.index(DISPATCH)
    edges = list(zip(visits[start:], visits[start + 1:]))
    edge_positions = [edges.index(pair) for pair in EDGES]
    assert edge_positions == sorted(edge_positions)
    verification_sites = (0x1001af170, 0x1001c0250, 0x1001c0314, 0x10002bd94,
                          0x10002bdac, 0x1001c0318, 0x100219ec0, 0x100219eec,
                          0x100219f04, 0x1000aa910, 0x1000aa9fc, 0x1000aaa70)
    positions = [visits.index(pc, start) for pc in verification_sites]
    assert positions == sorted(positions)
    assert not set(IOKIT_SITES).intersection(current)
    assert not any(event.get('name', '').startswith(('_IO', '_mach_msg', '_mach_port', '_notify_post'))
                   for event in events)

    query = named_event(events, '_sysctlbyname', 0x10002bd94)
    assert (query['name_string'], query['old_size_u64'],
            query['modeled_value_u32'], query['result']) == ('kern.hv_vmm_present', 4, 0, '0x0')

    status, = [event for event in events if event['kind'] == 'original_core_record_return']
    reply = named_event(events, '_xpc_dictionary_set_data', 0x1000aa9fc)
    send = named_event(events, '_xpc_dictionary_send_reply', 0x1000aaa70)
    assert (status['pc'], status['status_u32'], status['output_length_u64']) == ('0x1000aa910', 0, 4)
    assert reply['args_x0_x7'][2] == status['output_pointer_value']
    assert (reply['key'], reply['size_bytes'], reply['payload_bytes']) == ('data', 4, 'ffff4ffb')
    assert send['result'] == '0x0'

    value = int.from_bytes(payload[12:20], 'big')
    fs_calls = sorted({event['name'] for event in events[events.index(query) + 1:events.index(status)]
                       if 'name' in event and event['name'] in
                       ('_lstat', '_open', '_fstat', '_fchmod', '_statfs', '_lockf', '_close', '_unlink')})
    assert fs_calls
    return {
        'request_hex': payload.hex(),
        'read_offsets_bytes': offsets,
        'operand_read_sites': list(map(hex, READ)),
        'operand_u64': hex(value),
        'operand_staged_u64_derived': hex(encoded_operand(value)),
        'matched_original_visits': len(visits),
        'matched_unique_words': len(current),
        'ordered_pc_and_word_sha256': ordered_hash,
        'matched_edge_visits': [{'source': hex(a), 'target': hex(b), 'visit_index': start + i}
                                for (a, b), i in zip(EDGES, edge_positions)],
        'modeled_query_value': query['modeled_value_u32'],
        'modeled_query_status': int(query['result'], 16),
        'derived_environment_byte': 9 + (query['modeled_value_u32'] == 1 and query['result'] == '0x0'),
        'modeled_filesystem_calls_after_query': fs_calls,
        'known_iokit_sites_visited': [],
        'core_status_u32': status['status_u32'],
        'reply_key': reply['key'],
        'reply_hex': reply['payload_bytes'],
        'reply_signed32': signed(bytes.fromhex(reply['payload_bytes'])),
        'reply_send_site': send['callsite'],
    }


def source_anchor_checks(image):
    # Check the source operands that define the architectural interpretation.
    instructions = {
        0x10016d448: ('mov', 'w9, #0x8b90'),
        0x10016d44c: ('movk', 'w9, #0xd027, lsl #16'),
        DISPATCH: ('b.eq', '#0x10016dab8'),
        0x10016e460: ('ldr', 'x9, [sp, #0x2728]'),
        0x1001af0f0: ('lsl', 'x14, x14, #0x38'),
        0x1001af0fc: ('orr', 'x14, x14, x15, lsl #48'),
        0x1001af108: ('orr', 'x14, x14, x15, lsl #40'),
        0x1001af114: ('orr', 'x14, x14, x15, lsl #32'),
        0x1001af120: ('orr', 'x14, x14, x15, lsl #24'),
        0x1001af12c: ('orr', 'x14, x14, x15, lsl #16'),
        0x1001af138: ('orr', 'x14, x14, x15, lsl #8'),
        0x1001af144: ('orr', 'x9, x14, x9'),
        0x1001af158: ('and', 'x13, x13, x9, lsl #1'),
        0x1001af16c: ('add', 'x9, x9, x14'),
        0x1001af170: ('sub', 'x19, x9, x13'),
        0x1001c0250: ('str', 'x19, [sp, #0x16e8]'),
        0x1001c0308: ('sub', 'x0, x29, #0xa8'),
        0x10002bd9c: ('cmp', 'w8, #1'),
        0x10002bda0: ('ccmp', 'w0, #0, #0, eq'),
        0x10002bda8: ('cinc', 'w8, w8, eq'),
        0x10002bdac: ('strb', 'w8, [x19, #4]'),
        0x1001c0318: ('ldrb', 'w20, [x22, #4]'),
        0x100219ec0: ('ldr', 'x19, [sp, #0x16e8]'),
        0x100219eec: ('str', 'x19, [sp, #0x1e90]'),
        0x100219f04: ('cmp', 'x19, x9'),
    }
    for base, reg, immediate, width in ((0x1001af148, 'x13', (2 * OPERAND_MASK) & MASK64, 4),
                                        (0x1001af15c, 'x14', OPERAND_MASK, 4),
                                        (0x100219ef4, 'x9', OPERAND_MASK, 4)):
        for index in range(width):
            shift = 16 * index
            const = (immediate >> shift) & 0xffff
            suffix = f', lsl #{shift}' if index else ''
            instructions[base + 4 * index] = ('movk' if index else 'mov', f'{reg}, #{const:#x}{suffix}')

    for pc, (mnemonic, operands) in instructions.items():
        image.instruction(pc, mnemonic, operands)
    return [{'pc': hex(pc), 'word_hex': image.read(pc, 4).hex(),
             'instruction': ' '.join(ins)} for pc, ins in sorted(instructions.items())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('adid', type=Path, help='installed universal adid Mach-O')
    args = parser.parse_args()
    arm64e, = [blob for cpu, subtype, blob in daemon_slices(args.adid.read_bytes())
               if (cpu, subtype) == ARM64E]
    digest = hashlib.sha256(arm64e).hexdigest()
    assert digest == PROVIDER_SHA
    image = ThinView(arm64e)
    anchors = source_anchor_checks(image)

    fairplay = reference('daemon_adid_request_origin_audit')
    pair_data = reference('akd_adid_pair_profiles')
    otp, = [pair for pair in pair_data['pairs'] if pair['label'] == 'otp']
    canonical = bytes.fromhex(otp['source_request_bytes'])
    assert fairplay['provider_and_akd']['akd_otp_request_bytes'] == canonical.hex()
    expected = struct.pack('>IIIQ', 1, COMMAND, 1, 0x1122334455667788)
    assert canonical == expected
    producer_payloads = {case['request']['buffer']['bytes_hex']
                         for case in fairplay['cases'] if case['request'] is not None}
    from_fairplay = struct.pack('>IIIQ', 1, COMMAND, 1, MASK64 - 1)
    assert from_fairplay.hex() in producer_payloads and canonical.hex() in producer_payloads

    dispatch = reference('adid_command_dispatch_profiles')
    baseline, = [row for row in dispatch['profiles'] if row['fixture']['label'] == 'command_0xcfe0b46a']
    expected_baseline = struct.pack('>IIIQQ', 1, COMMAND, 1, MASK64 - 7, 0)
    traces = {
        'akd_otp': audit_profile(image, otp['provider_profile'],
                                 pair_data['original_instruction_records']['provider'], canonical),
        'dispatch_baseline': audit_profile(image, baseline, dispatch['original_instruction_records'],
                                           expected_baseline),
    }
    assert otp['source_reply_bytes'] == traces['akd_otp']['reply_hex']
    controls = [0, MASK64, *(1 << i for i in range(64)), 0x1122334455667788, MASK64 - 1, MASK64 - 7]
    assert all(encoded_operand(value) == value ^ OPERAND_MASK for value in controls)
    assert (COMMAND + 0x0046d726) & 0xffffffff == 0xd0278b90
    out = {
        'installed_adid_arm64e_sha256': digest,
        'archived_adid_arm64e_sha256': {'akd_otp': pair_data['provider_thin_sha256'],
                                       'dispatch_baseline': dispatch['thin_sha256']},
        'matched_source_anchors': anchors,
        'producer_schema': {'fairplayd_request_hex': from_fairplay.hex(),
                            'fairplayd_operand_u64': hex(MASK64 - 1),
                            'fairplayd_operand_staged_u64_derived': hex(encoded_operand(MASK64 - 1)),
                            'raw_command': hex(COMMAND), 'encoded_command': '0xd0278b90'},
        'operand_xor_mask': hex(OPERAND_MASK),
        'operand_arithmetic_control_count': len(controls),
        'known_iokit_sites_checked': list(map(hex, IOKIT_SITES)),
        'provider_traces': traces,
        'fairplayd_payload_provider_replayed': False,
        'native_api_or_ipc_executed': False,
        'native_daemon_kext_pairing_established': False,
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
