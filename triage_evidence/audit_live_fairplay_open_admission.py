#!/usr/bin/env python3
"""Trace the FairPlayIOKit entitlement lookup and correlate a native denial."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

from audit_live_fairplay_iokit_logs import installed as installed_logs, LABELS
from audit_live_iokit_mach_headers import VERIFIER
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid, record_windows
from audit_live_iokit_main_port import BUILD
from audit_live_kext_selector26 import Collection, DRIVER, IDENTITIES
from resolve_kernel_collection_interfaces import commands, macho, string

AMFI = 'com.apple.driver.AppleMobileFileIntegrity'
AMFI_UUID = '7f801ed8-bced-3049-a63e-8db71f0ba765'
ENTITLEMENTS = (
    'com.apple.private.FairPlayIOKitUserClient.access',
    'com.apple.private.ProvInfoIOKitUserClient.access',
    'com.apple.private.FairPlayIOKitUserClient.Virtual.access',
)
MARKER_SUBSYSTEM = 'org.fp-reversing.open-audit'
MATCH = ('subsystem == "' + MARKER_SUBSYSTEM + '" OR '
         'eventMessage CONTAINS "[FairPlayIOKitUserClient::initWithTask]"')

PROBE_PREFIX = r"""
#include <IOKit/IOKitLib.h>
#include <Security/SecTask.h>
#include <os/log.h>
#include <stdio.h>
#include <unistd.h>

static kern_return_t observe_open(io_service_t service, task_port_t task_port, uint32_t type,
    io_connect_t *connection)
{
    SecTaskRef task = SecTaskCreateFromSelf(NULL);
    if (task == NULL) {
        return kIOReturnInternalError;
    }
    const CFStringRef keys[] = {
        CFSTR("@KEY0@"),
        CFSTR("@KEY1@"),
        CFSTR("@KEY2@"),
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        CFErrorRef error = NULL;
        CFTypeRef value = SecTaskCopyValueForEntitlement(task, keys[i], &error);
        const char *state = "absent";
        if (value != NULL) {
            state = CFGetTypeID(value) == CFBooleanGetTypeID()
                ? (CFBooleanGetValue((CFBooleanRef)value) ? "true" : "false")
                : "other";
            CFRelease(value);
        }
        printf("entitlement %zu %s %d %ld\n", i, state, error != NULL,
            error == NULL ? 0 : CFErrorGetCode(error));
        if (error != NULL) {
            CFRelease(error);
        }
    }
    CFRelease(task);
    os_log_t log = os_log_create("@SUBSYSTEM@", "open");
    int pid = getpid();
    os_log(log, "FP native open begin %{public}d", pid);
    kern_return_t result = IOServiceOpen(service, task_port, type, connection);
    os_log(log, "FP native open end %{public}d", pid);
    printf("open %d %08x %08x\n", pid, (uint32_t)result, *connection);
    return result;
}

#define IOServiceOpen(service, task, type, connection) observe_open(service, task, type, connection)
"""


def installed(image):
    def bindings():
        for slot, expected, discriminator, address_diversity in (
            (0xfffffe0008492e98, 0xfffffe000c5b78f0, '0x0', 1),
            (0xfffffe00082a0a28, 0xfffffe000c4ee3a4, '0x0', 1),
            (0xfffffe000829ad28, 0xfffffe0009b518c8, '0xbcad', 0),
        ):
            pointer = image.pointer(slot)
            assert (int(pointer['target'], 16), pointer['auth'],
                    pointer['diversity'], pointer['address_diversity']) == (
                expected, 1, discriminator, address_diversity)
            yield hex(slot), pointer

    obj = None
    for offset, cmd, _ in commands(image.data, 0):
        if cmd != 0x80000035:
            continue
        _, header, name_offset, _ = struct.unpack_from('<QQII', image.data, offset + 8)
        if string(image.data, offset + name_offset) == AMFI:
            obj = macho(image.data, header, AMFI)
            break
    assert obj and obj['uuid'] == AMFI_UUID
    symtab, count, strings, _ = obj['symtab']
    named = {}
    for index in range(count):
        name, kind, _, _, pc = struct.unpack_from('<IBBHQ', image.data, symtab + index * 16)
        if name and kind & 0x0e == 0x0e and not kind & 0xe0:
            named[string(image.data, strings + name)] = pc
    for name, pc in (
        ('_AMFI', 0xfffffe000829ab40),
        ('_initializeCoreEntitlementsSupport', 0xfffffe0009b5103c),
        ('__Z38OSEntitlementsBridge_copyValueWithProcP4procPKcPPv', 0xfffffe0009b518c8),
        ('__Z30OSEntitlementsBridge_copyValuePKvPKcPPv', 0xfffffe0009b51840),
        ('__ZN14OSEntitlements9copyValueEPKc', 0xfffffe0009b64888),
    ):
        assert named[name] == pc
    assert image.named('_amfi_interface_register') == 0xfffffe000c4ee3a4
    assert image.named('__ZN12IOUserClient21copyClientEntitlementEP4taskPKc') == 0xfffffe000c5b78f0
    assert image.named('_get_bsdtask_info') == 0xfffffe000bdc5de0
    pointers = dict(bindings())

    checks = [
        (0xfffffe000a545290, 'mov', 'x20, x1'),
        (0xfffffe000a5452d4, 'cbnz', 'x25, #0xfffffe000a5452f0'),
        (0xfffffe000a5452d8, 'cbnz', 'x24, #0xfffffe000a5452f0'),
        (0xfffffe000a5452dc, 'cbnz', 'x21, #0xfffffe000a5452f0'),
        (0xfffffe000a5452ec, 'b', '#0xfffffe000a5453ac'),
        (0xfffffe000a545304, 'cmp', 'x25, x9'),
        (0xfffffe000a545318, 'cmp', 'x24, x9'),
        (0xfffffe000a54532c, 'cmp', 'x21, x8'),
        (0xfffffe000a5453ac, 'mov', 'w0, #0'),
        (0xfffffe000a6e0324, 'adrp', 'x17, #0xfffffe0008492000'),
        (0xfffffe000a6e0328, 'add', 'x17, x17, #0xe98'),
        (0xfffffe000a6e032c, 'ldr', 'x16, [x17]'),
        (0xfffffe000a6e0330, 'braa', 'x16, x17'),
        (0xfffffe000c5b7904, 'mov', 'x19, x1'),
        (0xfffffe000c5b7908, 'str', 'xzr, [sp, #8]'),
        (0xfffffe000c5b7930, 'bl', '#0xfffffe000bdc5de0'),
        (0xfffffe000c5b7938, 'adrp', 'x8, #0xfffffe0007f8e000'),
        (0xfffffe000c5b793c, 'ldr', 'x8, [x8, #0xc0]'),
        (0xfffffe000c5b7940, 'ldr', 'x8, [x8, #0x1e8]'),
        (0xfffffe000c5b7944, 'add', 'x2, sp, #8'),
        (0xfffffe000c5b7948, 'mov', 'x1, x19'),
        (0xfffffe000c5b794c, 'mov', 'x17, #0xbcad'),
        (0xfffffe000c5b7950, 'blraa', 'x8, x17'),
        (0xfffffe000c5b795c, 'csel', 'x8, x8, xzr, eq'),
        (0xfffffe0009b5106c, 'adrp', 'x8, #0xfffffe000829a000'),
        (0xfffffe0009b51070, 'add', 'x8, x8, #0xb40'),
        (0xfffffe0009b510ec, 'mov', 'x0, x8'),
        (0xfffffe0009b510f0, 'bl', '#0xfffffe0009b79ad8'),
        (0xfffffe0009b79ad8, 'adrp', 'x17, #0xfffffe00082a0000'),
        (0xfffffe0009b79adc, 'add', 'x17, x17, #0xa28'),
        (0xfffffe0009b79ae0, 'ldr', 'x16, [x17]'),
        (0xfffffe0009b79ae4, 'braa', 'x16, x17'),
        (0xfffffe000c4ee3a8, 'adrp', 'x8, #0xfffffe0007f8e000'),
        (0xfffffe000c4ee3b4, 'str', 'x0, [x8, #0xc0]'),
        (0xfffffe0009b518ec, 'bl', '#0xfffffe0009b50bcc'),
        (0xfffffe0009b518f8, 'bl', '#0xfffffe0009b514e4'),
        (0xfffffe0009b518fc, 'mov', 'x1, x20'),
        (0xfffffe0009b51900, 'mov', 'x2, x19'),
        (0xfffffe0009b51920, 'b', '#0xfffffe0009b51840'),
        (0xfffffe0009b51874, 'bl', '#0xfffffe0009b64888'),
        (0xfffffe0009b51878, 'cbz', 'x0, #0xfffffe0009b51890'),
        (0xfffffe0009b51884, 'mov', 'w0, #0'),
        (0xfffffe0009b51888, 'str', 'x8, [x19]'),
        (0xfffffe0009b51890, 'mov', 'w0, #0x38'),
        (0xfffffe000c51b6fc, 'mov', 'w19, #0x2c7'),
        (0xfffffe000c51b700, 'movk', 'w19, #0xe000, lsl #16'),
        (0xfffffe000c51b8f8, 'tbz', 'w0, #0, #0xfffffe000c51b954'),
        (0xfffffe000c51b964, 'sub', 'w19, w19, #5'),
    ]
    for index, (name, slot, reg) in enumerate(
        zip(ENTITLEMENTS, (0x201, 0x232, 0x263), (25, 24, 21), strict=True)
    ):
        literal = name.encode() + b'\0'
        assert image.read(0xfffffe0007915000 + slot, len(literal)) == literal
        pc = 0xfffffe000a5452a4 + 0x14 * index
        checks.extend((
            (pc - 12, 'adrp', 'x1, #0xfffffe0007915000'),
            (pc - 8, 'add', f'x1, x1, #{slot:#x}'),
            (pc - 4, 'mov', 'x0, x20'), (pc, 'bl', '#0xfffffe000a6e0324'),
            (pc + 4, 'mov', f'x{reg}, x0'),
        ))
    for check in checks:
        image.instruction(*check)

    logs = installed_logs(image)['sites']
    text_base = next(s['address'] for s in image.entries[DRIVER]['segments'] if s['name'] == '__TEXT_EXEC')
    return {
        'identity': IDENTITIES[1], 'amfi_uuid': AMFI_UUID, 'bindings': pointers,
        'kext_text_exec_base': hex(text_base),
        'expected_sender_offsets': {key: int(site['return_pc'], 16) - text_base for key, site in logs.items()},
        'instruction_assertions': len(checks),
        'windows': record_windows(image.read, (
            (0xfffffe000a545264, 0x110), (0xfffffe000a6e0324, 16),
            (0xfffffe000c5b78f0, 0x8c), (0xfffffe0009b5103c, 0xd0),
            (0xfffffe000c4ee3a4, 0x44), (0xfffffe0009b51840, 0xe4),
            (0xfffffe0009b79ad8, 16), (0xfffffe000c51b6fc, 8), (0xfffffe000c51b8f8, 0x70),
        )),
    }


def native(installed_record):
    loaded = subprocess.check_output(['kmutil', 'showloaded', '--list-only'], text=True, timeout=20)
    images = {AMFI: AMFI_UUID, DRIVER: IDENTITIES[1][2]}
    for name, uuid in images.items():
        row, = [line for line in loaded.splitlines() if name in line.split()]
        assert uuid in row.lower().split()

    prefix = PROBE_PREFIX.replace('@SUBSYSTEM@', MARKER_SUBSYSTEM)
    for i, key in enumerate(ENTITLEMENTS):
        prefix = prefix.replace(f'@KEY{i}@', key)
    source = prefix + VERIFIER
    with tempfile.TemporaryDirectory(prefix='fp-open-admission-') as folder:
        src, probe = Path(folder) / 'probe.c', Path(folder) / 'probe'
        src.write_text(source)
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O0', '-Wall', '-Wextra', '-Werror',
                        '-framework', 'IOKit', '-framework', 'Security',
                        '-framework', 'CoreFoundation', str(src), '-o', str(probe)], check=True)
        with subprocess.Popen(
            ['/usr/bin/log', 'stream', '--level', 'debug', '--style', 'ndjson', '--timeout', '8',
             '--predicate', MATCH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        ) as stream:
            try:
                time.sleep(0.75)
                output = subprocess.check_output([str(probe)], text=True, timeout=6)
                log, _ = stream.communicate(timeout=12)
                assert stream.returncode == 0
            finally:
                if stream.poll() is None:
                    stream.kill()
                    stream.wait()

    observations = re.findall(r'^entitlement (\d) (absent|true|false|other) ([01]) (-?\d+)$',
                              output, re.MULTILINE)
    assert observations == [(str(i), 'absent', '0', '0') for i in range(3)]
    opened = re.search(r'^open (\d+) ([0-9a-f]{8}) ([0-9a-f]{8})$', output, re.MULTILINE)
    assert opened and opened.groups()[1:] == ('e00002c2', '00000000')
    pid = int(opened[1])
    events = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
    begin, end = [
        next(event for event in events if event.get('processID') == pid
             and event.get('eventMessage') == f'FP native open {kind} {pid}')
        for kind in ('begin', 'end')
    ]
    assert begin['threadID'] and begin['threadID'] == end['threadID']
    assert begin['bootUUID'] == end['bootUUID']
    assert begin['senderImageUUID'] == end['senderImageUUID']
    bracketed = [event for event in events
                 if (event.get('senderImageUUID') or '').lower() == IDENTITIES[1][2]
                 and event.get('bootUUID') == begin['bootUUID']
                 and begin['machTimestamp'] < event['machTimestamp'] < end['machTimestamp']]
    failure, = bracketed
    assert failure['eventMessage'] == LABELS['init_missing']
    assert failure['senderProgramCounter'] == installed_record['expected_sender_offsets']['init_missing']
    assert failure['processID'] == 0
    assert failure['threadID'] == begin['threadID']
    keys = ('processID', 'threadID', 'machTimestamp', 'senderProgramCounter', 'senderImageUUID', 'eventMessage')
    return {
        'probe_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'stream_boot_uuid': begin['bootUUID'] or None, 'loaded_kext_uuids': images,
        'self_entitlements': {ENTITLEMENTS[int(i)]: {
            'value': value, 'error_present': bool(int(present)), 'error_code': int(code),
        } for i, value, present, code in observations},
        'open_status': '0xe00002c2', 'connection_name': '0x0',
        'events_in_timestamp_order': [{key: event[key] for key in keys} for event in (begin, failure, end)],
        'diagnostic_thread_matches_caller': failure['threadID'] == begin['threadID'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    result = {'installed': installed(Collection(args.collection, IDENTITIES[1]))}
    if args.observe:
        result['native'] = native(result['installed'])
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
