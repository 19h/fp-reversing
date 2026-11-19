#!/usr/bin/env python3
"""Verify current receive-right reassignment and service guard restoration."""

import argparse
import ctypes as ct
import json
from pathlib import Path
import struct
import subprocess

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_adid_ipc import reference
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_host_special_publication import windows
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES


CHECKS = (
    (0xfffffe000bd27cf0, 'orr', 'w8, w10, #0x300'),
    (0xfffffe000bd27cf4, 'str', 'w8, [x9, #0x10]'),
    (0xfffffe000bd23b08, 'bl', '#0xfffffe000bd27508'),
    (0xfffffe000bdd03bc, 'bl', '#0xfffffe000bd279a8'),
    (0xfffffe000bd279f4, 'bl', '#0xfffffe000bd27508'),
    (0xfffffe000bd27630, 'bl', '#0xfffffe000bd27828'),
    (0xfffffe000bd27910, 'tbnz', 'w8, #8, #0xfffffe000bd2791c'),
    (0xfffffe000bd2791c, 'mov', 'w9, #8'),
    (0xfffffe000bd27920, 'str', 'w9, [x1, #0x24]'),
    (0xfffffe000bd27928, 'tbnz', 'w8, #9, #0xfffffe000bd27964'),
    (0xfffffe000bd27964, 'mov', 'w9, #9'),
    (0xfffffe000bd27968, 'str', 'w9, [x1, #0x24]'),
    (0xfffffe000bd0c7e8, 'cmp', 'w24, #0x10'),
    (0xfffffe000bd0c7f8, 'bl', '#0xfffffe000bd08884'),
    (0xfffffe000bd0ee84, 'cmp', 'w24, #0x10'),
    (0xfffffe000bd0eeac, 'bl', '#0xfffffe000bd08884'),
    (0xfffffe000bd08b10, 'bl', '#0xfffffe000bd14e00'),
    (0xfffffe000bd08b2c, 'tbz', 'w9, #9, #0xfffffe000bd08b88'),
    (0xfffffe000bd08b50, 'str', 'xzr, [x8]'),
    (0xfffffe000bd08b98, 'and', 'w9, w9, #0xfffffdff'),
    (0xfffffe000bd08b9c, 'stur', 'w9, [x26, #-0x60]'),
    (0xfffffe000bd14e6c, 'str', 'x17, [x0, #0x48]'),
    (0xfffffe000bd14e80, 'cmp', 'w11, #3'),
    (0xfffffe000bd14e84, 'mov', 'w11, #5'),
    (0xfffffe000bd14e88, 'cinc', 'w11, w11, ne'),
    (0xfffffe000bd14e98, 'str', 'w9, [x0]'),
    (0xfffffe000bd14eb4, 'str', 'x17, [x0, #8]'),
    (0xfffffe000bd283f4, 'str', 'w8, [x23, #0x10]'),
    (0xfffffe000bd283f8, 'str', 'x19, [x23, #8]'),
    (0xfffffe000bd15f48, 'and', 'w8, w8, #0xfffff3ff'),
    (0xfffffe000bd15f50, 'str', 'xzr, [x20, #0x78]'),
    (0xfffffe000bd15f84, 'orr', 'w8, w8, #0x400'),
    (0xfffffe000bd0d78c, 'mov', 'x4, #0'),
    (0xfffffe000bd0d790, 'bl', '#0xfffffe000bd11bd8'),
    (0xfffffe000bd11da0, 'bl', '#0xfffffe000bd1af80'),
    (0xfffffe000bd11db8, 'bl', '#0xfffffe000bd04088'),
    (0xfffffe000bd11dbc, 'cmp', 'w20, #0x10'),
    (0xfffffe000bd11dc4, 'ldr', 'w3, [sp, #0x1c]'),
    (0xfffffe000bd11ddc, 'bl', '#0xfffffe000bd1dd18'),
    (0xfffffe000bd1afc4, 'bl', '#0xfffffe000bd05f34'),
    (0xfffffe000bd1dd98, 'cmp', 'w22, #4'),
    (0xfffffe000bd1dd9c, 'ccmp', 'w22, #2, #4, ne'),
    (0xfffffe000bd1ddac, 'cmp', 'w8, #6'),
    (0xfffffe000bd1ddcc, 'ldr', 'x26, [x2, #8]'),
    (0xfffffe000bd1ddd0, 'bl', '#0xfffffe000bdc68b8'),
    (0xfffffe000bd1ddd4, 'ldr', 'x8, [x0, #0x608]'),
    (0xfffffe000bd1ddd8, 'cbz', 'x8, #0xfffffe000bd1e0e8'),
    (0xfffffe000bd1dddc, 'ldrb', 'w8, [x8, #0x28]'),
    (0xfffffe000bd1dde0, 'tbz', 'w8, #0, #0xfffffe000bd1e0e8'),
    (0xfffffe000bd1dde4, 'ldr', 'w8, [x26, #0x10]'),
    (0xfffffe000bd1de00, 'cbz', 'w8, #0xfffffe000bd1de4c'),
    (0xfffffe000bd1de04, 'cmp', 'w3, w8'),
    (0xfffffe000bd1de10, 'orr', 'w8, w8, #0xc00'),
    (0xfffffe000bd1de14, 'str', 'w8, [x20, #0x10]'),
    (0xfffffe000bd1de18, 'ldr', 'x8, [x26, #8]'),
    (0xfffffe000bd1de1c, 'str', 'x8, [x20, #0x78]'),
    (0xfffffe000bd1deb4, 'stur', 'w3, [x8, #-0x14]'),
    (0xfffffe000bd1ded4, 'str', 'x17, [x8]'),
    (0xfffffe000bd1df54, 'orr', 'w8, w25, #0x20000'),
    (0xfffffe000bd1df58, 'str', 'w8, [x4, #8]'),
)

FUNCTIONS = {
    'receive_port_construction': 0xfffffe000bd27fac,
    'user_descriptor_copyin': 0xfffffe000bd0c2ac,
    'kernel_descriptor_copyin': 0xfffffe000bd0eacc,
    'destination_link': 0xfffffe000bd14e00,
    'destination_chain': 0xfffffe000bd08884,
    'destroy': 0xfffffe000bd15aa8,
    'descriptor_copyout': 0xfffffe000bd0d520,
    'right_copyout': 0xfffffe000bd11bd8,
    'name_lookup': 0xfffffe000bd1af80,
    'reverse_lookup': 0xfffffe000bd05f34,
    'receive_publication': 0xfffffe000bd1dd18,
    'thread_owner': 0xfffffe000bdc68b8,
    'get_attributes_core': 0xfffffe000bd27508,
    'receive_status_projection': 0xfffffe000bd27828,
}


def kernel_evidence(path):
    image = Collection(path, IDENTITIES[1])
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    bounds = compiler_ranges(image)
    pins = assert_instructions(image.read, CHECKS)
    legacy = reference('receive_name_guard_source')['kernel_functions']
    pairs = {
        'construct': 'receive_port_construction', 'link_walk': 'destination_chain',
        'descriptor_copyout': 'descriptor_copyout', 'right_copyout': 'right_copyout',
        'receive_publish': 'receive_publication',
    }
    correspondence = {}
    for before, after in pairs.items():
        start = FUNCTIONS[after]
        size = bounds[start][1] - start
        previous = legacy[before]
        original = bytes.fromhex(previous['bytes'])
        prefix = 12 if before == 'construct' else 48
        assert size == len(original) and original[:prefix] == image.read(start, prefix)
        correspondence[after] = dict(archive_start=previous['start'], installed_start=hex(start),
                                     function_bytes=size, matching_prefix_bytes=prefix)
    root = 0xfffffe0007e73b08
    assert image.pointer(0xfffffe000caff020)['target'] == hex(root)
    entry = root + 32 + (3217 - 3200) * 32
    mig = image.pointer(entry + 8)
    trap_entry = 0xfffffe0007f07750 + (40 - 77) * 24
    trap = image.pointer(trap_entry + 8)
    assert struct.unpack('<Q', image.read(trap_entry, 8)) == (0x505,)
    assert (mig['target'], trap['target']) == ('0xfffffe000bdd0358', '0xfffffe000bd23a4c')
    diagnostic = 'Service port not sent back to launchd'
    assert image.read(0xfffffe000704a544, len(diagnostic)) == diagnostic.encode()
    return dict(identity=IDENTITIES[1], checks=pins, archived_correspondence=correspondence,
                receive_status_trap_pointer=trap, receive_status_mig_pointer=mig,
                windows=windows(image.read, {
                    key: (start, bounds[start][1] - start) for key, start in FUNCTIONS.items()
                }))


def library_evidence():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    lib = Dylib(cache, LIBKERNEL)
    assert lib.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    assert lib.exports['_mach_port_get_attributes']['address'] == 0x18054b66c
    pins = assert_instructions(cache.read, (
        (0x18054b698, 'bl', '#0x180548bc4'),
        (0x180548bc4, 'mov', 'x16, #-0x28'),
        (0x180548bc8, 'svc', '#0x80'),
        (0x18054b69c, 'mov', 'w8, #3'),
        (0x18054b6a0, 'movk', 'w8, #0x1000, lsl #16'),
        (0x18054b6e0, 'b', '#0x180553aa0'),
        (0x180553b40, 'movk', 'x2, #0x2c, lsl #32'),
        (0x180553b44, 'mov', 'x4, #0xc9100000000'),
        (0x180553b50, 'bl', '#0x18055b918'),
    ))
    return dict(cache_uuid=cache.uuid, library_uuid=lib.uuid, checks=pins)


def private_control():
    source = b'''#include <mach/mach.h>
#include <stddef.h>
_Static_assert(sizeof(mach_msg_header_t) == 24, "header");
_Static_assert(sizeof(mach_msg_body_t) == 4, "body prefix");
_Static_assert(sizeof(mach_msg_port_descriptor_t) == 12, "descriptor");
_Static_assert(MACH_PORT_RECEIVE_STATUS == 2 && MACH_PORT_RECEIVE_STATUS_COUNT == 10, "query");
_Static_assert(offsetof(mach_port_status_t, mps_flags) == 36, "flags");
_Static_assert(MACH_PORT_STATUS_FLAG_TEMPOWNER == 1 && MACH_PORT_STATUS_FLAG_IMP_DONATION == 8, "masks");
_Static_assert(MACH_PORT_TEMPOWNER == 4 && KERN_INVALID_RIGHT == 17, "mark and status");
_Static_assert(MACH_MSG_TYPE_COPY_SEND == 19 && MACH_MSG_TYPE_MAKE_SEND == 20, "send dispositions");
_Static_assert(MACH_MSG_TYPE_MOVE_RECEIVE == 16 && MACH_MSG_PORT_DESCRIPTOR == 0, "receive disposition");
_Static_assert(MACH_PORT_TYPE_SEND == 0x10000 && MACH_PORT_TYPE_RECEIVE == 0x20000, "rights");
'''
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fsyntax-only', '-x', 'c', '-'],
                   input=source, check=True)
    lib = ct.CDLL(None)
    u32 = ct.c_uint32
    out = ct.POINTER(u32)
    task = u32.in_dll(lib, 'mach_task_self_').value
    for name, args in {
        'mach_port_allocate': (u32, ct.c_int, out),
        'mach_port_insert_right': (u32, u32, u32, ct.c_int),
        'mach_port_set_attributes': (u32, u32, ct.c_int, out, u32),
        'mach_port_get_attributes': (u32, u32, ct.c_int, out, out),
        'mach_port_type': (u32, u32, out),
        'mach_port_destroy': (u32, u32),
        'mach_msg': (ct.c_void_p, u32, u32, u32, u32, u32, u32),
    }.items():
        function = getattr(lib, name)
        function.argtypes = args
        function.restype = ct.c_int

    def status(name):
        result = (u32 * 10)()
        count = u32(len(result))
        code = lib.mach_port_get_attributes(task, name, 2, result, ct.byref(count))
        if code == 0:
            assert count.value == len(result)
            return code, result[9]
        return code, None

    cases = []
    for mark in (False, True):
        owned = set()

        def allocate():
            output = u32()
            assert lib.mach_port_allocate(task, 1, ct.byref(output)) == 0
            owned.add(output.value)
            assert lib.mach_port_insert_right(task, output, output, 20) == 0
            return output.value

        try:
            moved, destination = allocate(), allocate()
            assert moved != destination
            before_mark = status(moved)
            if mark:
                assert lib.mach_port_set_attributes(task, moved, 4, None, 0) == 0
            before_send = status(moved)
            assert before_mark == (0, 0) and before_send == (0, 9 if mark else 0)
            message_id = 0x414247
            message = struct.pack('<9IHBB', 0x80000013, 40, destination, 0, 0,
                                  message_id, 1, moved, 0, 0, 16, 0)
            buf = ct.create_string_buffer(message)
            assert lib.mach_msg(buf, 0x11, len(message), 0, 0, 0, 0) == 0
            right_type = u32()
            assert lib.mach_port_type(task, moved, ct.byref(right_type)) == 0
            transit_type = right_type.value
            in_transit = status(moved)
            assert transit_type == 0x10000 and in_transit == (17, None)
            received = (ct.c_uint64 * 16)()
            assert lib.mach_msg(received, 0x102, 0, ct.sizeof(received), destination, 0, 0) == 0
            bits, size, remote, local, voucher, mid, count, name, _, _, disposition, kind = (
                struct.unpack_from('<9IHBB', received))
            assert name not in (0, destination)
            owned.add(name)
            assert name == moved
            assert (bits, size, remote, local, voucher, mid, count, disposition, kind) == (
                0x80001100, 40, 0, destination, 0, message_id, 1, 16, 0)
            assert lib.mach_port_type(task, name, ct.byref(right_type)) == 0 and right_type.value == 0x30000
            after = status(name)
            assert after == (0, 8 if mark else 0)
        finally:
            destroyed = [lib.mach_port_destroy(task, name) for name in owned]
            assert all(code == 0 for code in destroyed)
        cases.append(dict(marked=mark, initial_status=before_mark, marked_status=before_send,
                          transit_right_type=transit_type, transit_receive_status=in_transit,
                          received_status=after, retained_name_reused=True, cleanup_succeeded=True,
                          descriptor=dict(disposition=disposition, type=kind, inline_bytes=size)))
    return dict(sdk_assertions=10, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    print(json.dumps(dict(build=build, kernel=kernel_evidence(args.collection),
                          library=library_evidence(), private_control=private_control(),
                          native_fairplay_reassignment_observed=False,
                          native_fairplay_guard_restoration_observed=False,
                          slot17_object_continuity_established=False), indent=2))


if __name__ == '__main__':
    main()
