#!/usr/bin/env python3
"""Correlate launchd endpoint metadata and bootstrap send rights in this task."""

from concurrent.futures import ThreadPoolExecutor
import ctypes as ct
from datetime import datetime, timezone
import json
from pathlib import Path
import plistlib
import re

from audit_daemon_iokit_native_registry import SERVICE, command, snapshot

LABELS = ('com.apple.fairplayd', 'com.apple.adid')
PORT_SEND = 0x10000
RIGHT_SEND = 0
INVALID_NAME = 15
INVALID_ARGUMENT = 4
LOCAL_NODE = -1
HOST_SLOTS = {'com.apple.unfreed': 17, 'com.apple.arcade.fpsd': 31}
U32 = ct.c_uint32
P32 = ct.POINTER(U32)
LIB = ct.CDLL(None)


def bind(name, args, result=ct.c_int):
    fn = getattr(LIB, name)
    fn.argtypes = args
    fn.restype = result
    return fn


def job(label):
    declaration = Path('/System/Library/LaunchDaemons', label + '.plist')
    plist = plistlib.loads(declaration.read_bytes())
    assert plist['Label'] == label
    text = command('launchctl', 'print', 'system/' + label).decode()
    assert re.search(r'^\tstate = running$', text, re.M)
    pid, = re.findall(r'^\tpid = (\d+)$', text, re.M)
    block, = re.findall(r'^\tendpoints = \{\n(.*?)^\t\}', text, re.M | re.S)
    endpoints = {}
    for name, fields in re.findall(r'^\t\t"([^"]+)" = \{\n(.*?)^\t\t\}', block, re.M | re.S):
        assert name not in endpoints
        port, = re.findall(r'^\t\t\tport = (0x[0-9a-f]+)$', fields, re.M)
        slot = re.findall(r'^\t\t\thost-special port = (\d+) \(', fields, re.M)
        assert len(slot) <= 1
        for field in ('active', 'managed'):
            assert re.search(rf'^\t\t\t{field} = 1$', fields, re.M)
        endpoints[name] = {'printed_port': port, 'active': True, 'managed': True,
                           'host_special_slot': int(slot[0]) if slot else None}
    declarations = plist['MachServices']
    assert declarations.keys() == endpoints.keys()
    for name, value in declarations.items():
        expected = HOST_SLOTS.get(name)
        assert value == ({'HostSpecialPort': expected} if expected is not None else True)
        assert endpoints[name]['host_special_slot'] == expected
    return {'pid': int(pid), 'state': 'running', 'endpoints': endpoints}


def jobs():
    with ThreadPoolExecutor(max_workers=len(LABELS)) as pool:
        return dict(zip(LABELS, pool.map(job, LABELS), strict=True))


def task_rights(names):
    bootstrap = U32.in_dll(LIB, 'bootstrap_port').value
    task = U32.in_dll(LIB, 'mach_task_self_').value
    lookup = bind('bootstrap_look_up', (U32, ct.c_char_p, P32))
    special = bind('host_get_special_port', (U32, ct.c_int, ct.c_int, P32))
    port_type = bind('mach_port_type', (U32, U32, P32))
    get_refs = bind('mach_port_get_refs', (U32, U32, ct.c_int, P32))
    deallocate = bind('mach_port_deallocate', (U32, U32))
    host = bind('mach_host_self', (), U32)()
    acquired = []
    results, slots = {}, {}

    def service(name, expected_refs):
        port = U32()
        code = lookup(bootstrap, name.encode(), ct.byref(port))
        if code == 0 and port.value not in (0, 0xffffffff):
            acquired.append(port.value)
        assert code == 0 and port.value not in (0, 0xffffffff)
        bits, refs = U32(), U32()
        assert port_type(task, port, ct.byref(bits)) == 0 and bits.value == PORT_SEND
        assert get_refs(task, port, RIGHT_SEND, ct.byref(refs)) == 0
        assert refs.value == expected_refs
        return {'lookup_status': code, 'task_local_name': hex(port.value),
                'type_bits': hex(bits.value), 'send_user_refs': refs.value}

    try:
        for name in names:
            results[name] = service(name, 1)
        assert len({item['task_local_name'] for item in results.values()}) == len(names)
        for name, slot in HOST_SLOTS.items():
            repeat = service(name, 2)
            assert repeat['task_local_name'] == results[name]['task_local_name']
            results[name]['repeat'] = repeat
            port = U32()
            result = special(host, LOCAL_NODE, slot, ct.byref(port))
            if result == 0 and port.value not in (0, 0xffffffff):
                acquired.append(port.value)
            slots[name] = {'slot': slot, 'query_status': result, 'returned_name': hex(port.value)}
    finally:
        releases = [deallocate(task, value) for value in reversed(acquired)]
        host_release = deallocate(task, host)
    assert all(value == 0 for value in releases) and host_release == 0
    retired = [port_type(task, int(row['task_local_name'], 16), ct.byref(U32()))
               for row in results.values()]
    assert retired == [INVALID_NAME] * len(names)
    assert all(row['query_status'] == INVALID_ARGUMENT and row['returned_name'] == '0x0'
               for row in slots.values())
    return {'bootstrap_lookups': results, 'host_queries': slots,
            'released_bootstrap_refs': len(releases), 'retired_bootstrap_names': len(retired)}


def audit():
    started = datetime.now(timezone.utc).isoformat()
    root, = snapshot()[SERVICE]
    previous = jobs()
    creators = {entry['creator']: entry['pid'] for entry in root['selected_children']}
    assert creators == {label.split('.')[-1]: item['pid'] for label, item in previous.items()}
    names = sorted({name for item in previous.values() for name in item['endpoints']})
    assert len(names) == 7
    rights = task_rights(names)
    assert previous == jobs() and snapshot()[SERVICE] == [root]
    return {'started_utc': started, 'build': command('sw_vers', '-buildVersion').decode().strip(),
            'jobs': previous, 'registry_service_id': root['service']['IORegistryEntryID'],
            'namespace': 'Audit process Mach namespace', **rights, 'daemon_payload_sent': False}


if __name__ == '__main__':
    print(json.dumps(audit(), indent=2))
