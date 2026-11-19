#!/usr/bin/env python3
"""Verify set readiness and member-name return using installed bytes and private ports."""

import argparse
import ctypes as ct
import json
from pathlib import Path
import subprocess

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_host_special_lookup import check_branch
from audit_live_host_special_publication import windows
from audit_live_iokit_mach_transport import CACHE_UUID, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES


def static_evidence(path):
    image = Collection(path, IDENTITIES[1])
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    for site, target in (
        (0xfffffe000bd0fae4, 0xfffffe000bdb5758),
        (0xfffffe000bd103c0, 0xfffffe000bd104d0),
        (0xfffffe000bd10524, 0xfffffe000bdb3ea4),
        (0xfffffe000bd10534, 0xfffffe000bd52a0c),
        (0xfffffe000bd24e1c, 0xfffffe000bd0ce54),
        (0xfffffe000bd0d280, 0xfffffe000bd12120),
        (0xfffffe000bd24e90, 0xfffffe000bd0e28c),
    ):
        check_branch(image, site, target, 'bl')
    pins = assert_instructions(image.read, (
        (0xfffffe000bd0f8d4, 'ldr', 'x25, [x21]'),
        (0xfffffe000bdb587c, 'str', 'x8, [x1, #0x18]'),
        (0xfffffe000bd10514, 'cmp', 'w8, #5'),
        (0xfffffe000bd10520, 'mov', 'w1, #2'),
        (0xfffffe000bd10528, 'cbz', 'x0, #0xfffffe000bd105d0'),
        (0xfffffe000bdb3ed0, 'ldr', 'x24, [x20, #0x18]'),
        (0xfffffe000bdb3efc, 'sub', 'x23, x24, #0x18'),
        (0xfffffe000bdb3f00, 'ldr', 'x22, [x24, #0x10]'),
        (0xfffffe000bdb3ff8, 'mov', 'x0, x22'),
        (0xfffffe000bd10538, 'sub', 'x20, x21, #0x10'),
        (0xfffffe000bd1053c, 'ldr', 'x21, [x21, #0x18]'),
        (0xfffffe000bd122a8, 'ldr', 'w23, [x20, #0x34]'),
        (0xfffffe000bd1228c, 'str', 'w23, [x19]'),
        (0xfffffe000bd0d270, 'add', 'x3, sp, #0x4c'),
        (0xfffffe000bd0d384, 'ldp', 'w9, w8, [sp, #0x48]'),
        (0xfffffe000bd0d398, 'stp', 'x9, x8, [x22, #8]'),
        (0xfffffe000bd0e5f0, 'ldur', 'q1, [x8, #8]'),
        (0xfffffe000bd0e5f8, 'xtn', 'v1.2s, v1.2d'),
        (0xfffffe000bd0e608, 'stp', 'd1, d0, [x0, #8]'),
    ))
    compiler = compiler_ranges(image)
    starts = {'check_ready_when_attached': 0xfffffe000bd0f864,
              'mark_member_ready': 0xfffffe000bdb5758,
              'select_ready_member': 0xfffffe000bdb3ea4, 'receive_selector': 0xfffffe000bd104d0,
              'destination_name_translation': 0xfffffe000bd12120}
    spans = {key: (addr, compiler[addr][1] - addr) for key, addr in starts.items()}
    spans.update(header_destination=(0xfffffe000bd0d260, 0x178),
                 pack_user_header=(0xfffffe000bd0e5e4, 0x30))
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    cf = Dylib(cache, next(row['path'] for row in cache.images if Path(row['path']).name == 'CoreFoundation'))
    assert cf.uuid == '14db37b1-11f1-31ad-9c07-74bed59a8036'
    cf_pins = assert_instructions(cache.read, (
        (0x18479d138, 'ldr', 'w28, [x19, #0x88]'),
        (0x18479eb54, 'ldr', 'w8, [x25, #0xc]'),
        (0x18479eb7c, 'str', 'w8, [x9]'),
        (0x18479d6c8, 'ldr', 'x0, [x19, #0x80]'),
        (0x18479d6d0, 'mov', 'x1, x25'),
        (0x18479d6d4, 'bl', '#0x184723c8c'),
    ))
    return dict(kernel_identity=IDENTITIES[1], cache_uuid=cache.uuid, cf_uuid=cf.uuid,
                kernel_pins=pins, kernel_windows=windows(image.read, spans), cf_pins=cf_pins)


class Header(ct.Structure):
    _fields_ = [(key, ct.c_uint32) for key in ('bits', 'size', 'remote', 'local', 'voucher', 'id')]


class Message(ct.Structure):
    _fields_ = [('header', Header), ('marker', ct.c_uint32)]


def private_control():
    constants = dict(MACH_PORT_RIGHT_RECEIVE=1, MACH_PORT_RIGHT_PORT_SET=3,
                     MACH_MSG_TYPE_MAKE_SEND=20, MACH_MSG_TYPE_COPY_SEND=19,
                     MACH_SEND_MSG=1, MACH_SEND_TIMEOUT=16, MACH_RCV_MSG=2,
                     MACH_RCV_TIMEOUT=256, MACH_RCV_TIMED_OUT=0x10004003)
    source = '#include <mach/mach.h>\n#include <stddef.h>\n' + ''.join(
        f'_Static_assert({key} == {value}, "{key}");\n' for key, value in constants.items())
    source += '''
_Static_assert(sizeof(mach_msg_header_t) == 24, "header extent");
_Static_assert(offsetof(mach_msg_header_t, msgh_local_port) == 12, "member offset");
'''
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fsyntax-only', '-x', 'c', '-'],
                   input=source.encode(), check=True)
    assert (ct.sizeof(Header), Header.local.offset, ct.sizeof(Message)) == (24, 12, 28)
    lib = ct.CDLL(None)
    u32 = ct.c_uint32
    task = u32.in_dll(lib, 'mach_task_self_').value
    for symbol, args in {
        'mach_port_allocate': (u32, u32, ct.POINTER(u32)),
        'mach_port_insert_right': (u32, u32, u32, ct.c_int),
        'mach_port_insert_member': (u32, u32, u32),
        'mach_port_extract_member': (u32, u32, u32),
        'mach_port_destroy': (u32, u32),
        'mach_msg': (ct.POINTER(Header), ct.c_int, u32, u32, u32, u32, u32),
    }.items():
        function = getattr(lib, symbol)
        function.argtypes = args
        function.restype = ct.c_int

    ports = {}
    trace = []
    mid = 0x46410001

    def send(label, marker):
        message = Message(Header(19, ct.sizeof(Message), ports[label], 0, 0, mid), marker)
        status = lib.mach_msg(ct.byref(message.header), 1 | 16, message.header.size, 0, 0, 0, 0)
        assert status == 0
        trace.append(dict(op='send', destination=label, marker=marker, status=status))

    def receive(label, expected_member=None, marker=None):
        data = (ct.c_uint64 * 16)()
        header = Header.from_buffer(data)
        status = lib.mach_msg(ct.byref(header), 2 | 256, 0, ct.sizeof(data), ports[label], 0, 0)
        if expected_member is None:
            assert status == constants['MACH_RCV_TIMED_OUT']
            trace.append(dict(op='poll', source=label, status=status))
            return
        message = Message.from_buffer(data)
        assert status == 0 and header.local == ports[expected_member]
        assert (header.id, header.size, header.remote, message.marker) == (mid, ct.sizeof(Message), 0, marker)
        trace.append(dict(op='receive', source=label, member=expected_member,
                          inline_bytes=header.size, marker=marker, status=status))

    def link(label, add):
        method = lib.mach_port_insert_member if add else lib.mach_port_extract_member
        assert method(task, ports[label], ports['set']) == 0
        trace.append(dict(op='attach' if add else 'detach', member=label))

    try:
        for label, kind in (('A', 1), ('B', 1), ('set', 3)):
            name = u32()
            assert lib.mach_port_allocate(task, kind, ct.byref(name)) == 0
            ports[label] = name.value
            if label != 'set':
                assert lib.mach_port_insert_right(task, name, name, 20) == 0
        assert len(set(ports.values())) == 3
        send('A', 1)
        receive('set')
        link('A', True)
        receive('set', 'A', 1)
        receive('set')
        link('B', True)
        send('B', 2)
        receive('set', 'B', 2)
        send('A', 3)
        link('A', False)
        receive('set')
        receive('A', 'A', 3)
    finally:
        for value in reversed(ports.values()):
            assert lib.mach_port_destroy(task, value) == 0
    return dict(sdk_constants=constants, inline_message_bytes=ct.sizeof(Message), events=trace,
                all_ports_destroyed=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    print(json.dumps(dict(build=build, source=static_evidence(args.collection),
                          private_receive=private_control(), native_fairplay_receive_observed=False), indent=2))
