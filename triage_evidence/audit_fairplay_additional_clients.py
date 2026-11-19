#!/usr/bin/env python3
"""Capture two additional native FairPlayIOKit clients and their installed interfaces."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess

from audit_daemon_iokit_native_registry import CLIENT, SERVICE, command, daemon_slices, digest
from audit_fairplay_live_slice_identity import (
    CS_OPS_CDHASH, CS_OPS_PIDOFFSET, installed_slices, query_cs,
)
from audit_live_fairplay_adid_ipc import ThinView, bindings, selection
from bootpolicy_cache_reader import CS

CLIENTS = {
    'fairplaydeviceid': 'fairplaydeviceidentityd',
    'lskdd': 'lskdd',
}
BINDINGS = {
    'fairplaydeviceidentityd': {
        '_IOConnectCallStructMethod': (0x1005e7300, 0xb0da),
        '_IOServiceOpen': (0x1005e75c0, 0x1fd2),
        '_IOServiceMatching': (0x1005e7690, 0x730c),
        '_IOServiceGetMatchingServices': (0x1005e7ad8, 0xd889),
    },
    'lskdd': {
        '_IOConnectCallStructMethod': (0x100e738d0, 0x21c3),
        '_IOServiceOpen': (0x100e735e8, 0xe1df),
        '_IOServiceMatching': (0x100e735b8, 0x129),
        '_IOServiceGetMatchingServices': (0x100e73aa8, 0xa1fb),
    },
}
ENTITLEMENTS = (
    'AvpFairPlayUserClient.access',
    'com.apple.private.FairPlayIOKitUserClient.access',
    'com.apple.security.iokit-user-client-class',
)
TRACE_SHA256 = '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def registry():
    root, = plistlib.loads(command('ioreg', '-r', '-c', SERVICE, '-a', '-l', '-w', '0'))
    children = []
    for child in root['IORegistryEntryChildren']:
        if child['IOObjectClass'] != CLIENT:
            continue
        pid, process = re.fullmatch(r'pid (\d+), (.+)', child['IOUserClientCreator']).groups()
        assert re.fullmatch(r'[A-Za-z0-9_.-]+', process)
        children.append(dict(registry_id=hex(child['IORegistryEntryID']), pid=int(pid),
                             process=process, class_name=CLIENT))
    assert root['IOUserClientClass'] == CLIENT and root['IOProviderClass'] == 'IOResources'
    return dict(service_id=hex(root['IORegistryEntryID']), service_class=SERVICE,
                provider_class=root['IOProviderClass'],
                children=sorted(children, key=lambda row: row['registry_id']))


def endpoints(executable, pid):
    job = f'com.apple.{executable}'
    raw = command('launchctl', 'print', f'system/{job}').decode()
    assert re.search(r'^\tstate = running$', raw, re.M)
    assert re.search(rf'^\tpid = {pid}$', raw, re.M)
    section, = re.findall(r'^\tendpoints = \{\n(.*?)^\t\}', raw, re.M | re.S)
    rows = {}
    for name, fields in re.findall(r'^\t\t"([A-Za-z0-9_.-]+)" = \{\n(.*?)^\t\t\}',
                                   section, re.M | re.S):
        port, = re.findall(r'^\t\t\tport = (0x[0-9a-f]+)$', fields, re.M)
        active, = re.findall(r'^\t\t\tactive = ([01])$', fields, re.M)
        rows[name] = dict(reported_port=port, active=active == '1')
    assert rows[job]['active']
    return dict(job=job, endpoints=rows)


def window(image, start, end):
    raw = image.read(start, end - start)
    words = list(CS.disasm(raw, start))
    assert len(words) * 4 == len(raw)
    return [[hex(word.address), word.bytes.hex(), word.mnemonic, word.op_str] for word in words]


def installed_interface(path, matched):
    _, _, thin = next(row for row in daemon_slices(path.read_bytes())
                      if hex(row[1]) == matched['cpu_subtype'])
    assert digest(thin) == matched['sha256'] and matched['arch'] == 'arm64e'
    image = ThinView(thin)
    fixups = bindings(path, '-arch', matched['arch'])
    imports = {}
    for name, (slot, modifier) in BINDINGS[path.name].items():
        expected = f'auth-bind IOKit/{name} (div=0x{modifier:04X} ad=0 key=IA)'
        assert fixups[slot] == expected
        raw, = struct.unpack('<Q', image.read(slot, 8))
        assert raw >> 62 == 3 and (raw >> 32) & 0x7ffff == modifier
        imports[name] = dict(slot=hex(slot), raw=hex(raw), binding=expected)
    result = dict(imports=imports)
    if path.name == 'fairplaydeviceidentityd':
        listener = 0x1000022e4
        image.instruction(listener - 4, 'mov', 'w2, #1')
        service_name = b'com.apple.fairplaydeviceidentityd\0'
        assert image.read(0x1005be933, len(service_name)) == service_name
        stubs = command('otool', '-arch', matched['arch'], '-Iv', str(path)).decode()
        for pc, stub, symbol in (
            (listener, 0x10054bcc4, '_xpc_connection_create_mach_service'),
            (0x100002348, 0x10054bce4, '_xpc_connection_set_event_handler'),
            (0x100002350, 0x10054bca4, '_xpc_connection_activate'),
        ):
            image.instruction(pc, 'bl', f'#{stub:#x}')
            assert re.search(rf'^0x0*{stub:x}\s+\d+\s+{symbol}$', stubs, re.M)
        image.instruction(0x100002324, 'adrp', 'x16, #0x100002000')
        image.instruction(0x100002328, 'add', 'x16, x16, #0x5a8')
        image.instruction(0x10000232c, 'pacia', 'x16, x8')
        assert fixups[0x1005e9ea8] == (
            'auth-bind libSystem/_xpc_connection_create_mach_service (div=0x0000 ad=1 key=IA)')
        result['listener_window'] = window(image, 0x1000022d4, 0x100002354)
        first = int(fixups[0x1005e8888].split()[1], 16) - 0x37e16e8b
        second = int(fixups[0x1005e8ec8].split()[1], 16) - 0x37a99043
        assert (first, second) == (0x10057a0e0, 0x1005a5d90)
        result['selector26_candidate'] = selection(
            image, fixups, (first, second), 0xfd, 0x4c6b, 0x1005c0a80,
            'IOKit/_IOConnectCallStructMethod',
        )
        sites = ((0x1000159c4, 26, None, 0x100015948),)
    else:
        sites = ((0x100474e38, 19, 3088, 0x100474dc0),
                 (0x100584cc8, 18, 3096, 0x100584c54))
    result['method_site_candidates'] = {}
    modifier = BINDINGS[path.name]['_IOConnectCallStructMethod'][1]
    for pc, selector, size, start in sites:
        image.instruction(pc - 4, 'mov', f'x17, #{modifier:#x}')
        image.instruction(pc, 'blraa', 'x8, x17')
        words = window(image, start, pc + 8)
        assert any(row[2:] == ['mov', f'w1, #{selector:#x}'] for row in words)
        if size is not None:
            assert any(row[2:] == ['mov', f'w3, #{size:#x}'] for row in words)
        result['method_site_candidates'][hex(pc)] = dict(
            selector_operand=selector, input_extent_bytes=size, instructions=words)
    details = subprocess.run(
        ['codesign', '-d', '--arch', matched['arch'], '--entitlements', ':-', str(path)],
        capture_output=True, check=True, timeout=30)
    entitlements = plistlib.loads(details.stdout)
    assert entitlements[ENTITLEMENTS[1]] is True
    result['selected_signed_entitlements'] = {
        name: entitlements[name] for name in ENTITLEMENTS if name in entitlements}
    return result


def capture(trace):
    start = timestamp()
    before = registry()
    processes = {}
    for child in before['children']:
        executable = CLIENTS.get(child['process'])
        if executable is None:
            continue
        pid = child['pid']
        start_time = command('ps', '-p', str(pid), '-o', 'lstart=').strip()
        path = Path(command('ps', '-ww', '-p', str(pid), '-o', 'comm=').decode().strip())
        assert path.name == executable and start_time
        offset = query_cs(pid, CS_OPS_PIDOFFSET, 8)
        cdh = query_cs(pid, CS_OPS_CDHASH, 20)
        assert offset[:2] == cdh[:2] == (0, 0)
        byte_offset, = struct.unpack('<q', offset[2])
        slices = installed_slices(path)
        matched, = [row for row in slices if row['file_offset_bytes'] == byte_offset]
        matching_hash, = [row for row in slices if cdh[2].hex() in row['cdhash_candidates']]
        assert matched == matching_hash and matched['codesign_cdhash'] == cdh[2].hex()
        endpoint_rows = endpoints(executable, pid)
        interface = installed_interface(path, matched)
        assert cdh == query_cs(pid, CS_OPS_CDHASH, 20)
        assert offset == query_cs(pid, CS_OPS_PIDOFFSET, 8)
        assert start_time == command('ps', '-p', str(pid), '-o', 'lstart=').strip()
        assert endpoints(executable, pid) == endpoint_rows
        processes[executable] = dict(registry=child, live_slice=matched, launchd=endpoint_rows,
                                     installed_interface=interface)
    assert set(processes) == set(CLIENTS.values()) and before == registry()

    source = trace.read_bytes()
    assert digest(source) == TRACE_SHA256
    messages = re.findall(rb'\b(send|received) bits=.*?\bid=(\d+)\b', source)
    counts = Counter((direction.decode(), int(mid)) for direction, mid in messages)
    context_ids = (502, 602, 700, 800, 2862, 2962, 2865, 2965)
    assert counts['send', 2862] == counts['received', 2962] == 1
    assert all(counts[direction, mid] == 0 for direction in ('send', 'received')
               for mid in context_ids if mid not in (2862, 2962))
    dtrace = subprocess.run(['dtrace', '-l', '-n', 'syscall::mach_msg_trap:entry'],
                            capture_output=True, timeout=10)
    probe_listing = dict(exit_status=dtrace.returncode,
                         privilege_error=b'DTrace requires additional privileges' in dtrace.stderr,
                         integrity_protection_reported=b'system integrity protection is on' in dtrace.stderr)
    return dict(probe_listing=probe_listing, start_utc=start, end_utc=timestamp(),
                build=command('sw_vers', '-buildVersion').decode().strip(),
                registry=before, processes=processes,
                historical_trace=dict(sha256=TRACE_SHA256, message_lines=len(messages),
                    counts={str(mid): {d: counts[d, mid] for d in ('send', 'received')}
                            for mid in context_ids}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('historical_trace', type=Path)
    print(json.dumps(capture(parser.parse_args().historical_trace), indent=2, sort_keys=True))
