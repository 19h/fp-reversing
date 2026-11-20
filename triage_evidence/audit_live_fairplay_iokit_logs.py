#!/usr/bin/env python3
"""Trace selected FairPlayIOKit log sites and count retained matching records."""

import argparse
from collections import Counter
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess

from audit_archived_iokit_open_retirement import trace_record
from audit_fairplay_native_xpc_observation import run
from audit_live_fairplay_personality import CLIENT, SERVICE, registry
from audit_live_iokit_mach_transport import record_windows
from audit_live_iokit_main_port import BUILD
from audit_live_kext_selector26 import Collection, IDENTITIES

PROCESSES = ('fairplayd', 'adid', 'lskdd', 'fairplaydeviceidentityd')
LABELS = {
    'init_missing': '[FairPlayIOKitUserClient::initWithTask] Error: entitlement not found',
    'init_invalid': '[FairPlayIOKitUserClient::initWithTask] Error: caller does not have a valid entitlement',
    'method_provider_error': '[FairPlayIOKitUserClient::ucSendFPMessage got error back from FPIOKit->SendFPMessage',
}
PREDICATE = ('(process IN {"fairplayd","adid","lskdd","fairplaydeviceidentityd"} '
             'OR senderImagePath ENDSWITH "/FairPlayIOKit" '
             'OR eventMessage CONTAINS[c] "FairPlayIOKitUserClient")')


def installed(image):
    sites = {}
    for key, pc, addr in (
        ('init_missing', 0xfffffe000a5452e8, 0xfffffe00079152f5),
        ('init_invalid', 0xfffffe000a54533c, 0xfffffe000791529c),
        ('method_provider_error', 0xfffffe000a545234, 0xfffffe0007915910),
    ):
        text = image.read(addr, 160).split(b'\0', 1)[0].decode()
        assert text.startswith(LABELS[key])
        image.instruction(pc - 8, 'adrp', f'x0, #{addr & ~0xfff:#x}')
        image.instruction(pc - 4, 'add', f'x0, x0, #{addr & 0xfff:#x}')
        assert image.branch(pc, 'bl') == 0xfffffe000a6e0264
        sites[key] = {'format': text, 'literal': hex(addr), 'call': hex(pc), 'return_pc': hex(pc + 4)}
    pointer = image.pointer(0xfffffe0008492e38)
    assert int(pointer['target'], 16) == image.named('_IOLog')
    assert pointer['auth'] == 1 and pointer['address_diversity'] == 1
    for pc, mnemonic, arguments in (
        (0xfffffe000a6e0264, 'adrp', 'x17, #0xfffffe0008492000'),
        (0xfffffe000a6e0268, 'add', 'x17, x17, #0xe38'),
        (0xfffffe000a6e0270, 'braa', 'x16, x17'),
        (0xfffffe000a54521c, 'blraa', 'x9, x16'),
        (0xfffffe000a545220, 'mov', 'x21, x0'),
        (0xfffffe000a545224, 'cbz', 'w0, #0xfffffe000a54523c'),
        (0xfffffe000a545228, 'str', 'x21, [sp]'),
        (0xfffffe000a54524c, 'mov', 'x0, x21'),
        (0xfffffe000c50a1f8, 'mov', 'x4, x30'),
        (0xfffffe000c50a1fc, 'xpaci', 'x4'),
        (0xfffffe000c50a25c, 'bl', '#0xfffffe000c4df754'),
    ):
        image.instruction(pc, mnemonic, arguments)
    return {'identity': IDENTITIES[1], 'sites': sites, 'iolog_import': pointer,
            'windows': record_windows(image.read, (
                (0xfffffe000a5451c4, 0xa0), (0xfffffe000a545264, 0x108),
                (0xfffffe000a6e0264, 0x10), (0xfffffe000c50a1cc, 0xb0),
            ))}


def native(start, end):
    epochs = [int(datetime.fromisoformat(value).timestamp()) for value in (start, end)]
    assert epochs[0] < epochs[1]
    snapshot, = registry(SERVICE, 2)
    attached = {}
    for child in snapshot['IORegistryEntryChildren']:
        if child.get('IOObjectClass') != CLIENT:
            continue
        label = re.fullmatch(r'pid (\d+), ([a-zA-Z0-9_.-]+)', child['IOUserClientCreator'])
        if label and label[2] in PROCESSES:
            attached[label[2]] = {'pid': int(label[1]), 'entry': hex(child['IORegistryEntryID'])}
    raw = run('/usr/bin/log', 'show', '--start', f'@{epochs[0]}', '--end', f'@{epochs[1]}',
              '--info', '--debug', '--style', 'json', '--predicate', PREDICATE)
    rows = [row for row in json.loads(raw) if row.get('eventType') == 'logEvent']
    general = Counter()
    classifiers = Counter(dict.fromkeys(LABELS, 0))
    attached_pid_hits = Counter()
    images = {}
    for row in rows:
        process = os.path.basename(row.get('processImagePath') or '')
        sender = os.path.basename(row.get('senderImagePath') or '')
        message = row.get('eventMessage') or ''
        if process in PROCESSES:
            general[process] += 1
            if process in attached and row.get('processID') == attached[process]['pid']:
                attached_pid_hits[process] += 1
            uuid = row.get('processImageUUID') or ''
            if re.fullmatch(r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}', uuid):
                images.setdefault(process, set()).add(uuid)
        else:
            general['other'] += 1
        if sender == 'FairPlayIOKit' or (row.get('senderImageUUID') or '').lower() == IDENTITIES[1][2]:
            classifiers['driver_image'] += 1
        for key, prefix in LABELS.items():
            if prefix in message:
                classifiers[key] += 1
    for key in PROCESSES:
        general.setdefault(key, 0)
        attached_pid_hits.setdefault(key, 0)
    classifiers.setdefault('driver_image', 0)
    return {'window_utc': [start, end], 'log_events': len(rows), 'process_counts': dict(general),
            'attached_pid_events': dict(attached_pid_hits), 'attached': attached,
            'event_class_counts': dict(classifiers),
            'boot_count': len({r['bootUUID'] for r in rows if r.get('bootUUID')}),
            'process_image_uuids': {p: sorted(u) for p, u in images.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--log-window', nargs=2, metavar=('START_UTC', 'END_UTC'))
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    result = {'installed': installed(Collection(args.collection, IDENTITIES[1])),
              'archive': trace_record(args.trace)}
    if args.log_window:
        result['retained_log_observation'] = native(*args.log_window)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
