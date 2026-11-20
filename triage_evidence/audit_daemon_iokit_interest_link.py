#!/usr/bin/env python3
"""Compare FairPlay daemon imports, archived wire records and registration markers."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from analyze_zut_trace import digest, image_info
from audit_archived_iokit_open_retirement import (
    GUEST_MESSAGE, HOST_RECEIVE, HOST_SEND, THIN_SHA, TRACE_SHA, decode_guest,
)
from audit_daemon_iokit_retirement import SYMBOL, fixups, xcrun
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_iokit_mig_trace import dispatch, event_ids, rebuild_registry, sandbox_table
from audit_live_iokit_open_owner import BUILD
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_fairplay_vmm_context import DAEMON_UUID


PROBES = (
    'IOServiceAddInterestNotification', 'io_service_add_interest_notification',
    'IONotificationPort', 'IODispatchCalloutFromMessage', 'IOServiceAddMatchingNotification',
    'IOServiceAddNotification', 'IORegistryEntryGetChildIterator',
    'IORegistryEntryGetRegistryEntryID', 'mach_port_kobject_description',
)
CONTROLS = {
    '_IOServiceOpen', '_IOConnectCallStructMethod', '_IOObjectRelease', '_IORegistryEntryGetParentEntry',
    '_notify_register_check', '_dlsym', '_dlopen', '_mach_msg', '_mach_msg2_internal',
}
IMPORT_NAMES = re.compile(r'^\s+0x[0-9a-fA-F]+\s+(_\S+?)(?:\+0x[0-9a-fA-F]+)?\s+\(from ([^)]*)\)', re.M)
REGISTRATION = {
    2850: (102, 0xfffffe0007e78260, '0xfffffe000be82b9c', (0xff000199, 0xff00019a)),
    2869: (121, 0xfffffe0007e784c0, '0xfffffe000be80da4', (0xff0001e5, 0xff0001e6)),
}
TRACKED = {53, 2816, 2862, 2865, 2866, 2867, 2868, 2870, 2916, 2962, 2965, 2966, 2967, 2968, 2970}
TRACKED |= set(REGISTRATION) | {request + 100 for request in REGISTRATION}


def image_audit(path):
    data = path.read_bytes().lower()
    identity = image_info(path)
    imports_text = xcrun('dyld_info', path, '-imports')
    imported = set(SYMBOL.findall(imports_text))
    bindings = {pc: row['target'] for pc, row in fixups(path).items()
                if row['kind'].endswith('bind')}
    names = imported | set(bindings.values())
    missing_controls = CONTROLS - imported
    assert not missing_controls, missing_controls
    absent = []
    for probe in PROBES:
        assert not any(probe.lower() in name.lower() for name in names), probe
        assert probe.lower().encode() not in data, probe
        absent.append(probe)
    iokit = [symbol for symbol, library in IMPORT_NAMES.findall(imports_text) if library == 'IOKit']
    assert len(iokit) == len(set(iokit)) == 12
    assert {'_IOServiceOpen', '_IOConnectCallStructMethod', '_IOObjectRelease'} <= set(iokit)
    selected = {hex(pc): name for pc, name in bindings.items() if name.split('/')[-1] in CONTROLS}
    return {'uuid': identity['uuid'], 'sha256': identity['sha256'], 'size_bytes': len(data),
            'iokit_imports': sorted(iokit), 'matching_bind_slots': selected,
            'checked_absent_literals_and_imports': absent, 'decoded_bind_slot_count': len(bindings)}


def installed_audit(path, reference):
    raw = path.read_bytes()
    by_arch = {row['arch']: row for row in installed_slices(path)}
    assert set(by_arch) == {'x86_64', 'arm64e', 'arm64e.x1'}
    result = {}
    with tempfile.TemporaryDirectory() as work:
        for arch, uuid in (('arm64e', DAEMON_UUID), ('arm64e.x1', 'd4e1629f-019b-38c3-9f31-3f203e58d440')):
            row = by_arch[arch]
            assert row['uuid'] == uuid
            start = row['file_offset_bytes']
            slice_path = Path(work) / arch
            slice_path.write_bytes(raw[start:start + row['slice_size_bytes']])
            result[arch] = image_audit(slice_path)
            assert result[arch]['sha256'] == row['sha256']
            assert result[arch]['iokit_imports'] == reference['iokit_imports']
    assert result['arm64e']['matching_bind_slots'] == reference['matching_bind_slots']
    return result


def wire_audit(path):
    raw = path.read_bytes()
    assert digest(raw) == TRACE_SHA
    lines = raw.decode().splitlines()
    assert len(lines) == 1748
    guest = {'send': Counter(), 'received': Counter()}
    bridge = {'sent': Counter(), 'received': Counter()}
    selected = []
    for number, line in enumerate(lines, 1):
        if hit := GUEST_MESSAGE.fullmatch(line):
            message, body = decode_guest(lines, number, hit[2], tuple(int(value, 0) for value in hit.groups()[2:]))
            message_id = message['id']
            guest[hit[2]][message_id] += 1
            if message_id in TRACKED:
                selected.append(message)
            if message_id == 2962:
                assert (len(body), message['descriptors'][0]['name']) == (52, '0x0')
                assert struct.unpack_from('<I', body, 48) == (0xe00002c2,)
        if hit := HOST_SEND.fullmatch(line):
            bridge['sent'][int(hit[1])] += 1
        if hit := HOST_RECEIVE.fullmatch(line):
            bridge['received'][int(hit[1])] += 1
    assert all(sum(counts.values()) == 22 for counts in guest.values())
    assert [(m['line'], m['id']) for m in selected] == [(1726, 2862), (1736, 2962)]
    assert not any(TRACKED.intersection(counts) - {2862, 2962} for counts in bridge.values())
    assert bridge['sent'][2862] == bridge['received'][2962] == 1
    assert all(65 not in counts for counts in guest.values())
    assert bridge['received'][65] == 2
    return {'sha256': TRACE_SHA, 'lines': len(lines), 'guest_counts_by_id': guest,
            'bridge_counts_by_id': bridge, 'selected_lifecycle_messages': selected,
            'open_application_result': '0xe00002c2', 'returned_connection_name': '0x0'}


def registration_audit(image):
    table = sandbox_table(image)
    ids = table['message_ids_by_filter_index']
    checked = dispatch(image, ids)
    service = next(row for row in rebuild_registry(image)['subsystems'] if row['start'] == 2800)
    base = int(service['pointer']['target'], 16)
    events = {}
    for request, (index, slot, target, markers) in REGISTRATION.items():
        actual = image.pointer(base + 40 + (request - 2800) * 32)
        assert (actual['slot'], actual['target'], actual['auth']) == (hex(slot), target, 1)
        assert ids[index] == request and event_ids(index) == markers
        events[request] = {'stub': actual, 'index': index, 'markers': [hex(value) for value in markers],
                           'reply_id': request + 100}
    assert not {53, 2950, 2969}.intersection(ids)
    return {'kernel_uuid': IDENTITIES[1][1], 'kernel_sha256': image.digest,
            'sandbox_uuid': table['uuid'], 'sandbox_table_sha256': table['table_sha256'],
            'dispatch_instructions_checked': len(checked['instructions']),
            'registration_requests': events}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('daemon', 'installed_daemon', 'trace', 'collection'):
        parser.add_argument(argument, type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    reference = image_audit(args.daemon)
    assert (reference['uuid'], reference['sha256']) == (DAEMON_UUID, THIN_SHA)
    installed = installed_audit(args.installed_daemon, reference)
    wire = wire_audit(args.trace)
    registration = registration_audit(Collection(args.collection, IDENTITIES[1]))
    print(json.dumps({'build': BUILD, 'historical_daemon': reference, 'installed_daemon': installed,
                      'archived_wire': wire, 'installed_registration': registration},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
