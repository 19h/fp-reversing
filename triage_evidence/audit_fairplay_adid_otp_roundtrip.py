#!/usr/bin/env python3
"""Compose retained CoreADI client and provider source paths in separate private guests."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import plistlib
import subprocess
from unittest.mock import patch

import adid_reader as reader
from audit_adid_otp_ingress import IOKIT_SITES, named_event
from audit_daemon_adid_reply_fields import FieldReplay, opaque_dependency_check
from audit_daemon_adid_reply_reader import RESPONSE_BUFFER, environment
from audit_fairplay_live_slice_identity import installed_slices, selected_identity
from audit_live_fairplay_adid_ipc import PROVIDER_SHA, bindings, reference
from daemon_receive_tools import SOURCE as PINNED_DAEMON
from probe_adid_command_dispatch import Commands, Lifecycle
from probe_adid_startup import unpack_records

PROVIDER_UNIVERSAL_SHA = '9c872e64548288f7d1a9db5e2dbd97311e30b4df5745f52936ae277c80a4abe1'
OPERAND = 0xfffffffffffffffe
SEND_PC = '0x1000aaa70'
STATUS_WRITERS = (0x1002028bc, 0x1002028a8, 0x1002028c4, 0x1002028d0)


class ObservedProvider(Commands):
    def __init__(self, source, profile, checkpoint, tree):
        # The same callback harness, with the command tree loaded from its
        # canonical compressed artifact and with additional read-only hooks.
        Lifecycle.__init__(self, source, profile, checkpoint)
        self.copy_writes = []
        self.external_allocations = []
        self.tree = tree
        self.leaves = {int(row['parser_entry'], 16) for row in tree['accepted']}
        self.status_reads = []
        self.writes = []

    def read_hook(self, u, kind, address, size, value, data):
        if self.reg('pc') == 0x1001fcca0:
            self.status_reads.append((address, size, bytes(u.mem_read(address, size)), len(self.visited)))
        return super().read_hook(u, kind, address, size, value, data)

    def write(self, u, kind, address, size, value, data):
        value = int(value) & ((1 << (8 * size)) - 1)
        self.writes.append((self.reg('pc'), address, size, value, len(self.visited)))
        return super().write(u, kind, address, size, value, data)


def signed_metadata(path):
    selected, = [row for row in installed_slices(path) if row['arch'] == 'arm64e']
    pinned = selected_identity(PINNED_DAEMON.read_bytes())
    assert selected['uuid'] == pinned['uuid']
    assert selected['codesign_cdhash'] in pinned['cdhash_candidates']

    def dictionary(binary):
        return plistlib.loads(subprocess.check_output(
            ['codesign', '-d', '--arch', 'arm64e', '--entitlements', ':-', str(binary)],
            stderr=subprocess.PIPE, timeout=30))

    embedded = dictionary(path)
    assert embedded == dictionary(PINNED_DAEMON)
    assert 'adi-client' not in embedded
    return {'selected_installed_slice_sha256': selected['sha256'], 'uuid': selected['uuid'],
            'cdhash': selected['codesign_cdhash'], 'embedded_key_count': len(embedded),
            'embedded_entitlements_sha256': sha256(plistlib.dumps(embedded)).hexdigest(),
            'adi_client_declaration_present': False, 'matches_pinned_dictionary': True,
            'effective_runtime_entitlement_observed': False}


def current_provider(path):
    with patch.multiple(reader, SOURCE=path, SOURCE_SHA=PROVIDER_UNIVERSAL_SHA, THIN_SHA=PROVIDER_SHA):
        source = reader.Adid()
    actual = bindings(path, '-arch', 'arm64e')
    assert set(actual) == set(source.fixups)
    for slot, row in source.fixups.items():
        assert row['kind'] == actual[slot].split()[0]
        target = actual[slot].split()[1]
        assert row['target'] == (int(target, 16) if isinstance(row['target'], int) else target)
        assert row['annotation'].split() == actual[slot].split()[2:]
    return source


def wire_fields(probe, delivered, origin, have_command):
    # Check the final write of each output byte, including reuse of a previous
    # allocation address under the fixture's allocator model.
    writes = [row for row in probe.writes if row[1] < origin + len(delivered) and origin < row[1] + row[2]]
    final = writes[-4:]
    assert all(size == 1 for _, _, size, _, _ in final)
    expected_order = list(range(4)) if have_command else list(reversed(range(4)))
    assert [address - origin for _, address, _, _, _ in final] == expected_order
    assert bytes(value for _, _, _, value, _ in sorted(final, key=lambda row: row[1])) == delivered
    assert {pc for pc, _, _, _, _ in final} == {0x1001fcca8 if have_command else 0x1001fcd80}
    if have_command:
        assert len(probe.status_reads) == 4
        assert b''.join(row[2] for row in probe.status_reads) == delivered
        last_writers = []
        for address, size, raw, index in probe.status_reads:
            assert size == 1
            pc, start, width, value, _ = next(row for row in reversed(probe.writes)
                                            if row[1] <= address < row[1] + row[2] and row[4] < index)
            assert width == 1 and start == address and raw == bytes([value])
            last_writers.append(pc)
        assert tuple(last_writers) == STATUS_WRITERS
    else:
        last_writers = []
    return {'final_byte_store': hex(final[0][0]), 'output_store_offsets': expected_order,
            'status_source_writers_offset_order': list(map(hex, last_writers))}


def run_provider(source, fixture, checkpoint, tree, label, packet, declared_null):
    assert fixture['instruction_or_frame_overrides'] is False
    probe = ObservedProvider(source, {**fixture, 'payload_hex': packet}, checkpoint, tree)
    result = probe.result()
    assert result['stop_reason'] == 'returned_to_private_fixture'
    assert result['resume_pc'] == '0x100029fc8'
    events = unpack_records(result)
    security = named_event(events, '_SecTaskCopyValueForEntitlement', 0x1001691c8)
    path_lookup = named_event(events, '_proc_pidpath', 0x100169ac8)
    request = named_event(events, '_xpc_dictionary_get_data', 0x1000aa598)
    assert request['key'] == 'data' and request['payload_bytes'] == packet and request['size_bytes'] == 20
    calls = [event.get('name', '') for event in events]
    actual_reads = [event for event in events if event['kind'] == 'original_payload_read']
    entered = 0x10016dab8 in probe.visited
    assert entered == (not declared_null) and (int(security['result'], 16) == 0) == declared_null
    assert len(actual_reads) == (0 if declared_null else 20)
    if actual_reads:
        assert bytes(int(row['bytes'], 16) for row in actual_reads).hex() == packet
    assert not set(IOKIT_SITES).intersection(probe.visited)
    assert not any(name.startswith(('_IO', '_mach_msg', '_mach_port', '_notify_post')) for name in calls)
    assert ('_sysctlbyname' in calls) == entered

    status, = [event for event in events if event['kind'] == 'original_core_record_return']
    assert status['status_u32'] == 0 and status['output_length_u64'] == 4
    setter = named_event(events, '_xpc_dictionary_set_data', 0x1000aa9fc)
    emitter = named_event(events, '_xpc_dictionary_send_reply', int(SEND_PC, 16))
    assert setter['key'] == 'data' and setter['size_bytes'] == 4
    assert setter['args_x0_x7'][0] == emitter['args_x0_x7'][0]
    assert setter['args_x0_x7'][2] == status['output_pointer_value']
    reply = bytes.fromhex(setter['payload_bytes'])
    assert reply.hex() == ('ffff4ff2' if declared_null else 'ffff4ffb')
    custody = wire_fields(probe, reply, int(status['output_pointer_value'], 16), entered)
    return {'label': label, 'request_hex': packet, 'provider_original_visits': len(probe.visited),
            'provider_ordered_pc_and_word_sha256': result['ordered_original_instruction_sha256'],
            'modeled_entitlement_lookup_returned_null': declared_null,
            'modeled_pidpath_result': int(path_lookup['result'], 16),
            'provider_core_wrapper_status': status['status_u32'], 'provider_reply_hex': reply.hex(),
            'provider_reply_signed32': int.from_bytes(reply, 'big', signed=True),
            'provider_otp_parser_entered': entered, 'original_request_byte_reads': len(actual_reads),
            'reply_setter_pc': setter['callsite'], 'reply_emitter_pc': emitter['callsite'],
            'known_iokit_sites_visited': [], **custody}


def run_client(parent, before_send, wire, reply):
    probe = FieldReplay(parent, before_send, reply, 0x18)
    probe.run()
    assert probe.prefix_rechecked and probe.request['buffer']['bytes_hex'] == wire
    assert probe.boundary['pc'] == hex(environment.RETURN)
    value = int.from_bytes(reply, 'big')
    assert probe.reg(0) == value and not probe.owners
    after = [probe.snapshot(probe.C + offset, size) for _, offset, size in environment.OUTPUTS]
    assert [row['bytes_hex'] for row in after] == ['00' * width for width in (8, 4, 8, 4)]
    parsed = [row for row in probe.reads if RESPONSE_BUFFER <= int(row['address'], 16) < RESPONSE_BUFFER + 4096]
    assert bytes(int(row['bytes_hex'], 16) for row in parsed) == reply
    assert [int(row['address'], 16) - RESPONSE_BUFFER for row in parsed] == list(range(4))
    return {'client_original_visits': len(probe.visits), 'client_return_u32': hex(value),
            'client_return_pc': probe.boundary['pc'], 'client_output_hex': [row['bytes_hex'] for row in after],
            'client_read_sites': [row['pc'] for row in parsed], 'opaque_dependencies': opaque_dependency_check(probe)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('adid', type=Path, help='installed universal provider binary')
    parser.add_argument('fairplayd', type=Path, help='installed universal client binary')
    args = parser.parse_args()
    source = current_provider(args.adid)
    metadata = signed_metadata(args.fairplayd)
    checkpoints = reference('adid_peer_checkpoint')
    tree = reference('adid_command_dispatch_contracts')['command_tree']
    past, = [row for row in reference('akd_adid_pair_profiles')['pairs'] if row['label'] == 'otp']
    archived = past['provider_profile']['fixture']
    no_declaration = {**archived, 'entitlement_result': 'NULL', 'entitlement_type': 'null'}
    no_declaration.pop('entitlement_string', None)
    no_declaration.pop('entitlement_number', None)
    parents = [case for case in reference('daemon_environment_outputs_checks')['cases']
               if case['configuration']['kind'] == 'caller' and case['boundary']['pc'] == '0x100e1ea4c']
    sends = [case for case in reference('daemon_adid_request_origin_audit')['cases']
             if case['prefix_rechecked'] and case['request']]
    assert len(parents) == len(sends) == 8
    wire, = {case['request']['buffer']['bytes_hex'] for case in sends}
    assert int.from_bytes(bytes.fromhex(wire)[12:], 'big') == OPERAND
    cases = [
        run_provider(source, archived, checkpoints, tree,
                     'archived_otp_control', past['source_request_bytes'], False),
        run_provider(source, archived, checkpoints, tree, 'fairplayd_wire_archived_peer', wire, False),
        run_provider(source, no_declaration, checkpoints, tree, 'null_entitlement_path_control', wire, True),
        run_provider(source, {**no_declaration, 'process_path': str(args.fairplayd)}, checkpoints, tree,
                     'fairplayd_wire_null_entitlement', wire, True),
    ]
    assert cases[0]['provider_ordered_pc_and_word_sha256'] == cases[1]['provider_ordered_pc_and_word_sha256']
    assert cases[0]['provider_ordered_pc_and_word_sha256'] == past['provider_profile']['ordered_original_instruction_sha256']
    assert cases[0]['provider_reply_hex'] == past['source_reply_bytes']
    assert cases[2]['provider_ordered_pc_and_word_sha256'] == cases[3]['provider_ordered_pc_and_word_sha256']
    for case in (cases[1], cases[3]):
        reply = bytes.fromhex(case['provider_reply_hex'])
        case['client_continuations'] = [
            run_client(parent, next(row for row in sends if row['configuration'] == parent['configuration']), wire, reply)
            for parent in parents
        ]
    print(json.dumps({
        'provider_installed_arm64e_sha256': sha256(source.data).hexdigest(),
        'independently_checked_fixups': len(source.fixups), 'client_signature': metadata,
        'cases': cases, 'native_ipc_executed': False, 'native_daemon_kext_pairing_established': False,
    }, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
