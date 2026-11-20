#!/usr/bin/env python3
"""Verify IOKit main-port publication and version negotiation."""

import argparse
import ctypes
import json
from pathlib import Path
import struct
import subprocess

from audit_live_iokit_discovery import archived_discovery, installed_discovery
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, LIBKERNEL, dyld_uuid, record_windows
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map

BUILD = '26C5035r'
VERSION = 0x0134647a
ARCHIVED_VERSION_OFFSET = 36
MAIN_CELL = 0xfffffe0007f5da98
SEND_RIGHT = 0
INVALID_NAME = 15


def mig_record(image, subsystem, base_id, msg_id, address, fields):
    slot = subsystem + 40 + 32 * (msg_id - base_id)
    pointer = image.pointer(slot)
    assert (pointer['target'], pointer['auth'], pointer['diversity']) == (
        hex(address), 1, '0x3a83')
    assert struct.unpack('<4I', image.read(slot + 8, 16)) == fields
    return {'request_id': msg_id, 'reply_id': msg_id + 100,
            'routine': pointer, 'record_fields': fields}


def installed(image):
    host = 0xfffffe0007e73668
    assert struct.unpack('<4I', image.read(host + 8, 16)) == (200, 236, 1072, 0)
    host_dispatch = image.pointer(host)
    assert (host_dispatch['target'], host_dispatch['auth'], host_dispatch['diversity']) == (
        '0xfffffe000bdced24', 1, '0x423')
    io = int(mig_map(image)['subsystem'], 16)
    assert io == 0xfffffe0007e77bf8
    records = {
        'host_get_io_main': mig_record(image, host, 200, 205, 0xfffffe000bdce7e8, (2, 0, 1, 52)),
        'io_server_version': mig_record(image, io, 2800, 2877, 0xfffffe000be803ac, (2, 0, 0, 52)),
    }
    instructions = (
        (0xfffffe000bd8321c, 'mov', 'w1, #0x125'),
        (0xfffffe000bd83228, 'bl', '#0xfffffe000bd3c950'),
        (0xfffffe000bd8322c, 'adrp', 'x8, #0xfffffe0007f5d000'),
        (0xfffffe000bd83230, 'str', 'x0, [x8, #0xa98]'),
        (0xfffffe000bd83238, 'mov', 'w2, #0x25'),
        (0xfffffe000bd8323c, 'bl', '#0xfffffe000bd3ce94'),
        (0xfffffe000bd8324c, 'mov', 'w1, #3'),
        (0xfffffe000bd83250, 'bl', '#0xfffffe000bd3a088'),
        (0xfffffe000bd3c9c4, 'and', 'x8, x20, #0xff'),
        (0xfffffe000bd3c9d8, 'str', 'x17, [x19, #0x50]'),
        (0xfffffe000bd3cee4, 'cmp', 'w8, w21'),
        (0xfffffe000bd3cf14, 'bl', '#0xfffffe000bd17b88'),
        (0xfffffe000bdce7f8, 'cmp', 'w8, #0x20'),
        (0xfffffe000bdce82c, 'bl', '#0xfffffe000bd3b1a8'),
        (0xfffffe000bdce834, 'bl', '#0xfffffe000bd3a5d8'),
        (0xfffffe000bdce87c, 'stur', 'x17, [x19, #0x24]'),
        (0xfffffe000bdce894, 'str', 'w8, [x19, #0x20]'),
        (0xfffffe000bdce888, 'mov', 'w9, #0x34'),
        (0xfffffe000bd3a620, 'adrp', 'x8, #0xfffffe0007f5d000'),
        (0xfffffe000bd3a624, 'ldr', 'x0, [x8, #0xa98]'),
        (0xfffffe000bd3a628, 'bl', '#0xfffffe000bd17e98'),
        (0xfffffe000bd3a634, 'str', 'x8, [x20]'),
        (0xfffffe000bd3a668, 'mov', 'w0, #4'),
        (0xfffffe000bd3a54c, 'ldr', 'x0, [x8, #0xa98]'),
        (0xfffffe000bd3a550, 'bl', '#0xfffffe000bd17e98'),
        (0xfffffe000bd17f2c, 'str', 'w8, [x0, #0x88]'),
        (0xfffffe000bd3c678, 'add', 'w8, w8, #0x64'),
        (0xfffffe000bd0f208, 'bl', '#0xfffffe000bd0fbf0'),
        (0xfffffe000be803c4, 'mov', 'w8, #0x647a'),
        (0xfffffe000be803c8, 'movk', 'w8, #0x134, lsl #16'),
        (0xfffffe000be803cc, 'stur', 'x8, [x4, #0xc]'),
        (0xfffffe000be803d0, 'str', 'wzr, [x4, #8]'),
        (0xfffffe000be803e4, 'str', 'w8, [x3, #4]'),
        (0xfffffe000c5b964c, 'ldr', 'x8, [x8, #0xa98]'),
        (0xfffffe000c5b9650, 'cmp', 'x0, x8'),
    )
    for pc, mnemonic, operands in instructions:
        image.instruction(pc, mnemonic, operands)
    return {
        'fileset_identity': IDENTITIES[1], 'main_cell': hex(MAIN_CELL), 'object_kind': '0x25',
        'host_slot': 3, 'host_dispatch': host_dispatch, 'iokit_subsystem': hex(io),
        'records': records, 'version': hex(VERSION), 'instruction_assertions': len(instructions),
        'windows': record_windows(image.read, (
            (0xfffffe000bd83210, 0x48), (0xfffffe000bd3c9b4, 0x30),
            (0xfffffe000bd3ce94, 0x94), (0xfffffe000bd3a510, 0x60),
            (0xfffffe000bd3a5d8, 0x98), (0xfffffe000bd17f10, 0x34),
            (0xfffffe000bd3b1a8, 0x64), (0xfffffe000bdce7e8, 0xb8),
            (0xfffffe000be803ac, 0x50), (0xfffffe000c5b9628, 0x40),
        )),
    }


def archived(trace):
    evidence = archived_discovery(trace)
    acquired, version, matching = evidence['transactions'][:3]
    assert acquired['guest_output_send_name'] == version['guest_destination'] == matching['guest_destination']
    assert struct.unpack_from('<Q', bytes.fromhex(version['reply_hex']), ARCHIVED_VERSION_OFFSET) == (VERSION,)
    return {'trace_sha256': evidence['trace_sha256'], 'transactions': [acquired, version, matching]}


def observe():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    kernel, iokit = ctypes.CDLL(LIBKERNEL), ctypes.CDLL(IOKIT)
    name_type = ctypes.c_uint32
    name_out = ctypes.POINTER(name_type)

    def bind(library, name, *arguments):
        call = getattr(library, name)
        call.argtypes = arguments
        call.restype = ctypes.c_int
        return call

    task = name_type.in_dll(kernel, 'mach_task_self_').value
    main = bind(iokit, 'IOMainPort', name_type, name_out)
    get_refs = bind(kernel, 'mach_port_get_refs', name_type, name_type, ctypes.c_int, name_out)
    deallocate = bind(kernel, 'mach_port_deallocate', name_type, name_type)
    port_type = bind(kernel, 'mach_port_type', name_type, name_type, name_out)
    names, counts = [], []
    count = name_type()
    try:
        for _ in range(2):
            name = name_type()
            assert main(0, ctypes.byref(name)) == 0 and name.value
            names.append(name.value)
            assert get_refs(task, name.value, SEND_RIGHT, ctypes.byref(count)) == 0
            counts.append(count.value)
        assert names[0] == names[1] and counts == [1, 2]
        version = ctypes.c_uint64.in_dll(iokit, 'gIOKitLibServerVersion').value
        assert version == VERSION
    finally:
        releases = [deallocate(task, name) for name in reversed(names)]
        assert releases == [0] * len(names)
    after = port_type(task, names[0], ctypes.byref(count))
    assert after == INVALID_NAME
    return {'build': BUILD, 'kernel_uuid': IDENTITIES[1][1], 'cache_uuid': CACHE_UUID,
            'same_task_local_name': True, 'send_user_refs': counts, 'version': hex(version),
            'deallocation_statuses': releases, 'post_release_lookup_status': after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    installed_discovery()
    result = {'installed': installed(Collection(args.collection, IDENTITIES[1])),
              'archived': archived(args.trace), 'framework_cache_uuid': CACHE_UUID}
    if args.observe:
        result['verifier_process'] = observe()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
