#!/usr/bin/env python3
"""Verify current receive-right backup registration, emission and private copyout."""

import argparse
import ctypes as ct
import json
from pathlib import Path
import struct
import subprocess

from audit_daemon_iokit_native_registry import command, sysctl
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_fairplay_adid_ipc import ThinView, bindings
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_host_special_publication import LIBKERNEL, windows
from audit_live_iokit_mach_transport import CACHE_UUID, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_rpc700_publication import running_identity


def launchd_evidence(path):
    identity = running_identity({'pid': 1}, path, installed_slices(path))
    selected = identity['matched_slice']
    assert selected['arch'] == 'arm64e'
    assert selected['sha256'] == 'd35f01f9669f314a1058e17acca27d3141ba8be1b0ca0d9e9d5edbb787607243'
    with path.open('rb') as source:
        source.seek(selected['file_offset_bytes'])
        image = ThinView(source.read(selected['slice_size_bytes']))
    fixups = bindings(path, '-arch', 'arm64e')
    slot = 0x1000835c0 + 69 * 40 - 0x9f8
    callback = fixups[slot]
    assert callback == 'auth-rebase 0x1000498C0 (div=0x0000 ad=0 key=IA)'
    assert image.read(0x10007550e, 8) == b'req_pid\0'
    checks = assert_instructions(image.read, (
        (0x100046ef4, 'mov', 'w1, #0x45'),
        (0x100046ef8, 'bl', '#0x100045c0c'),
        (0x100045c54, 'str', 'w21, [x0, #0x10]'),
        (0x100045d40, 'mov', 'x1, x21'),
        (0x100045d44, 'mov', 'x2, x21'),
        (0x100045d48, 'mov', 'w3, #0x14'),
        (0x100045d4c, 'bl', '#0x10005e414'),
        (0x100045d5c, 'ldr', 'w4, [x8, #0xf20]'),
        (0x100045d6c, 'csel', 'w5, w9, w8, eq'),
        (0x100045d74, 'add', 'x6, sp, #4'),
        (0x100045d7c, 'mov', 'w2, #0x45'),
        (0x100045d80, 'mov', 'w3, #0'),
        (0x100045d84, 'bl', '#0x10005e444'),
        (0x100045dbc, 'bl', '#0x100045f3c'),
        (0x100045f44, 'ldr', 'w8, [x0, #0x10]'),
        (0x100049ab4, 'mov', 'w9, #0x28'),
        (0x100049ab8, 'umull', 'x8, w8, w9'),
        (0x100049abc, 'sub', 'x8, x8, #0x9f8'),
        (0x100049ac0, 'adrp', 'x9, #0x100083000'),
        (0x100049ac4, 'add', 'x9, x9, #0x5c0'),
        (0x100049adc, 'blraaz', 'x8'),
        (0x1000498d8, 'tbz', 'w8, #0x1f, #0x10004991c'),
        (0x1000498e0, 'cmp', 'w8, #1'),
        (0x1000498ec, 'cmp', 'w8, #0x28'),
        (0x1000498f4, 'ldrh', 'w8, [x0, #0x26]'),
        (0x1000498fc, 'cmp', 'w8, #0x100, lsl #12'),
        (0x100049904, 'ldr', 'w8, [x0, #0xc]'),
        (0x100049908, 'ldr', 'w1, [x0, #0x1c]'),
        (0x100049910, 'bl', '#0x100045904'),
        (0x100045904, 'adrp', 'x8, #0x10008b000'),
        (0x100045908, 'ldr', 'w8, [x8, #0x414]'),
        (0x10004590c, 'cbz', 'w8, #0x100045918'),
        (0x100045910, 'mov', 'w0, #5'),
        (0x100045924, 'mov', 'x0, x1'),
        (0x10004592c, 'bl', '#0x10005c570'),
        (0x100045934, 'ldr', 'x0, [x0, #0x18]'),
        (0x100045938, 'mov', 'w1, #0x45'),
        (0x10004593c, 'bl', '#0x10005de04'),
        (0x1000467b4, 'adrp', 'x19, #0x10008b000'),
        (0x1000467b8, 'add', 'x19, x19, #0x414'),
        (0x1000467bc, 'ldrsw', 'x2, [x19]'),
        (0x1000467c0, 'adrp', 'x1, #0x100075000'),
        (0x1000467c4, 'add', 'x1, x1, #0x50e'),
        (0x1000467c8, 'bl', '#0x10005f6b4'),
    ))
    stubs = ('_mach_port_insert_right', '_mach_port_request_notification', '_dispatch_source_merge_data')
    listing = command('otool', '-arch', 'arm64e', '-tv', str(path)).decode()
    for address, symbol in zip((0x10005e414, 0x10005e444, 0x10005de04), stubs):
        assert f'0x{address:x} ; symbol stub for: {symbol}' in listing
    return dict(identity=identity, slot=hex(slot), original_slot=image.read(slot, 8).hex(),
                callback_fixup=callback, checks=checks, windows=windows(image.read, {
                    'register': (0x100045d40, 0x84),
                    'select': (0x100049aa4, 0x3c),
                    'validate': (0x1000498c0, 0x64),
                    'dispatch': (0x100045904, 0x40),
                }))


def kernel_evidence(path):
    image = Collection(path, IDENTITIES[1])
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    trap_slot, mig_root, entry = 0xfffffe0007f07750, 0xfffffe0007e73b08, 0xfffffe0007e73cc8
    assert struct.unpack('<Q', image.read(trap_slot, 8)) == (0x707,)
    assert struct.unpack('<III', image.read(mig_root + 8, 12)) == (3200, 3243, 576)
    assert entry == mig_root + 32 + (3213 - 3200) * 0x20
    assert struct.unpack('<4I', image.read(entry + 16, 16)) == (6, 0, 1, 52)
    pointers = [image.pointer(a) for a in (trap_slot + 8, 0xfffffe000caff020, entry + 8)]
    assert tuple(int(row['target'], 16) for row in pointers) == (
        0xfffffe000bd23f44, mig_root, 0xfffffe000bdd07c4)
    assert image.read(0xfffffe000700dd38, 8) == struct.pack('<II', 69, 1)
    functions = {
        'trap': (0xfffffe000bd23f44, 0xfffffe000bd24124),
        'mig': (0xfffffe000bdd07c4, 0xfffffe000bdd094c),
        'register': (0xfffffe000bd270e0, 0xfffffe000bd2741c),
        'destroy': (0xfffffe000bd15aa8, 0xfffffe000bd16204),
        'send': (0xfffffe000bd3d4d0, 0xfffffe000bd3d5ac),
    }
    bounds = compiler_ranges(image)
    assert all(bounds[start][1] == end for start, end in functions.values())
    checks = assert_instructions(image.read, (
        (0xfffffe000bd2401c, 'bl', '#0xfffffe000bd270e0'),
        (0xfffffe000bdd08b0, 'bl', '#0xfffffe000bd270e0'),
        (0xfffffe000bd27324, 'mov', 'w3, #0x45'),
        (0xfffffe000bd27328, 'bl', '#0xfffffe000bd13f58'),
        (0xfffffe000bd27344, 'add', 'x8, x20, #0x60'),
        (0xfffffe000bd27360, 'str', 'x17, [x8]'),
        (0xfffffe000bd2738c, 'str', 'x17, [x8, #0x10]'),
        (0xfffffe000bd15b58, 'ldr', 'x16, [x8, #0x60]!'),
        (0xfffffe000bd15b6c, 'autda', 'x16, x17'),
        (0xfffffe000bd15b70, 'mov', 'x26, x16'),
        (0xfffffe000bd15b80, 'str', 'x17, [x8]'),
        (0xfffffe000bd1601c, 'mov', 'x17, x20'),
        (0xfffffe000bd1603c, 'stur', 'x17, [sp, #0x70]'),
        (0xfffffe000bd16040, 'mov', 'w8, #0x100000'),
        (0xfffffe000bd16050, 'str', 'w8, [sp, #0x4c]'),
        (0xfffffe000bd16054, 'stur', 'x26, [sp, #0x54]'),
        (0xfffffe000bd16058, 'adrp', 'x8, #0xfffffe000700d000'),
        (0xfffffe000bd1605c, 'ldr', 'd0, [x8, #0xd38]'),
        (0xfffffe000bd16060, 'stur', 'd0, [sp, #0x68]'),
        (0xfffffe000bd16068, 'mov', 'w1, #0x34'),
        (0xfffffe000bd1607c, 'bl', '#0xfffffe000bd3d4d0'),
    ))
    return dict(identity=IDENTITIES[1], trap_metadata=image.read(trap_slot, 8).hex(),
                mig_subsystem=image.read(mig_root, 32).hex(), pointers=pointers,
                mig_row=image.read(entry, 32).hex(), notification_id_and_count=[69, 1],
                checks=checks, windows=windows(image.read, {
                    name: (start, end - start) for name, (start, end) in functions.items()
                }))


def libkernel_evidence():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    lib = Dylib(cache, LIBKERNEL)
    assert lib.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    assert lib.exports['_mach_port_request_notification']['address'] == 0x18054ab18
    checks = assert_instructions(cache.read, (
        (0x18054ab50, 'bl', '#0x180548ccc'),
        (0x180548ccc, 'mov', 'x16, #-0x4d'),
        (0x180548cd0, 'svc', '#0x80'),
        (0x18054ab54, 'mov', 'w8, #3'),
        (0x18054ab58, 'movk', 'w8, #0x1000, lsl #16'),
        (0x18054ab60, 'b.ne', '#0x18054aba8'),
        (0x18054aba4, 'b', '#0x18054cd00'),
        (0x18054cd74, 'movk', 'x2, #0x3c, lsl #32'),
        (0x18054cd84, 'mov', 'x4, #0xc8d00000000'),
        (0x18054cd90, 'bl', '#0x18055b918'),
    ))
    assert struct.unpack('<II', cache.read(0x18057e6e0, 8)) == (0, 3213)
    return dict(cache_uuid=cache.uuid, library_uuid=lib.uuid, checks=checks,
                fallback_request_id=3213, fallback_request_bytes=60)


def private_control():
    constants = dict(MACH_PORT_RIGHT_SEND=0, MACH_PORT_RIGHT_RECEIVE=1,
                     MACH_MSG_TYPE_MAKE_SEND=20, MACH_MSG_TYPE_MAKE_SEND_ONCE=21,
                     MACH_MSG_TYPE_PORT_RECEIVE=16, MACH_MSG_PORT_DESCRIPTOR=0,
                     MACH_NOTIFY_PORT_DESTROYED=69, MACH_RCV_MSG=2, MACH_RCV_TIMEOUT=256,
                     MACH_PORT_TYPE_SEND=0x10000, MACH_PORT_TYPE_RECEIVE=0x20000,
                     KERN_INVALID_NAME=15, MACH_MSGH_BITS_COMPLEX=0x80000000)
    source = '#include <mach/mach.h>\n#include <mach/notify.h>\n#include <stddef.h>\n'
    source += ''.join(f'_Static_assert({name} == {value}u, "{name}");\n'
                      for name, value in constants.items())
    source += '''
_Static_assert(sizeof(mach_msg_header_t) == 24, "header");
_Static_assert(offsetof(mach_port_destroyed_notification_t, not_port) == 28, "descriptor");
_Static_assert(offsetof(mach_port_destroyed_notification_t, trailer) == 40, "inline extent");
'''
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fsyntax-only', '-x', 'c', '-'],
                   input=source.encode(), check=True)

    lib = ct.CDLL(None)
    u32 = ct.c_uint32
    out32 = ct.POINTER(u32)
    task = u32.in_dll(lib, 'mach_task_self_').value
    for name, args in {
        'mach_port_allocate': (u32, ct.c_int, out32),
        'mach_port_insert_right': (u32, u32, u32, ct.c_int),
        'mach_port_request_notification': (u32, u32, ct.c_int, u32, u32, ct.c_int, out32),
        'mach_port_mod_refs': (u32, u32, ct.c_int, ct.c_int),
        'mach_port_get_refs': (u32, u32, ct.c_int, out32),
        'mach_port_type': (u32, u32, out32),
        'mach_port_destroy': (u32, u32),
        'mach_msg': (ct.c_void_p, ct.c_int, u32, u32, u32, u32, u32),
    }.items():
        function = getattr(lib, name)
        function.argtypes = args
        function.restype = ct.c_int

    def rights(name):
        value = u32()
        status = lib.mach_port_type(task, name, ct.byref(value))
        return status, value.value

    def refs(name, right):
        value = u32()
        assert lib.mach_port_get_refs(task, name, right, ct.byref(value)) == 0
        return value.value

    cases = []
    for retain in (False, True):
        owned = set()

        def allocate():
            value = u32()
            assert lib.mach_port_allocate(task, 1, ct.byref(value)) == 0
            owned.add(value.value)
            return value.value

        try:
            old, notify = allocate(), allocate()
            assert old != notify
            if retain:
                assert lib.mach_port_insert_right(task, old, old, 20) == 0
                assert refs(old, 0) == 1
            previous = u32()
            assert lib.mach_port_request_notification(task, old, 69, 0, notify, 21, ct.byref(previous)) == 0
            assert previous.value == 0
            assert lib.mach_port_mod_refs(task, old, 1, -1) == 0
            if not retain:
                owned.remove(old)
            before = rights(old)
            before_refs = refs(old, 0) if retain else None
            assert before == ((0, 0x10000) if retain else (15, 0))
            assert before_refs == (1 if retain else None)
            buffer = (ct.c_uint64 * 16)()
            assert lib.mach_msg(buffer, 0x102, 0, ct.sizeof(buffer), notify, 0, 0) == 0
            bits, size, remote, local, voucher, message_id, count, returned, _, _, disposition, kind = (
                struct.unpack_from('<9IHBB', buffer))
            assert (bits, size, remote, local, voucher, message_id, count, disposition, kind) == (
                0x80001200, 40, 0, notify, 0, 69, 1, 16, 0)
            assert returned not in (0, notify)
            owned.add(returned)
            same = old == returned
            assert same == retain
            after = rights(returned)
            assert after == (0, 0x30000 if retain else 0x20000)
            send_refs = refs(returned, 0) if retain else None
            receive_refs = refs(returned, 1)
            assert send_refs == before_refs and receive_refs == 1
        finally:
            cleanup = [lib.mach_port_destroy(task, name) for name in owned]
            assert all(status == 0 for status in cleanup)

        cases.append(dict(retained_send=retain, previous_right_null=True, before=before,
                          before_send_refs=before_refs, returned_name_equals_old=same, after=after,
                          after_send_refs=send_refs, after_receive_refs=receive_refs,
                          header_bits=hex(bits), inline_bytes=size, message_id=message_id,
                          descriptor_count=count, descriptor_disposition=disposition,
                          descriptor_type=kind, header_local_is_notification_destination=True,
                          header_remote_null=True, cleanup_success=True))
    return dict(constants=constants, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('launchd', type=Path)
    args = parser.parse_args()
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    print(json.dumps(dict(build=build, launchd=launchd_evidence(args.launchd),
                          kernel=kernel_evidence(args.collection), libkernel=libkernel_evidence(),
                          private_control=private_control(), native_fairplay_return_observed=False,
                          launchd_fairplay_handler_delivery_observed=False,
                          same_live_host_slot_object_after_restart_established=False), indent=2))


if __name__ == '__main__':
    main()
