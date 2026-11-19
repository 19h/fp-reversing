#!/usr/bin/env python3
"""Check the installed FairPlay port-set attachment boundary and local Mach controls."""

import argparse
import ctypes as ct
import json
from pathlib import Path
import struct
import subprocess

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_host_special_lookup import check_branch
from audit_live_host_special_publication import windows
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES


def library_evidence():
    cache = Cache()
    assert cache.uuid == dyld_uuid() == CACHE_UUID
    library = Dylib(cache, LIBKERNEL)
    assert library.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    cf_path, = (r['path'] for r in cache.images if Path(r['path']).name == 'CoreFoundation')
    cf = Dylib(cache, cf_path)
    assert cf.uuid == '14db37b1-11f1-31ad-9c07-74bed59a8036'
    symbols = {
        '_mach_port_insert_member': 0x18054af50,
        '__kernelrpc_mach_port_insert_member_trap': 0x180548af8,
        '__kernelrpc_mach_port_insert_member': 0x18056ec18,
        '_mach_msg2_internal': 0x18055b918,
    }
    for name, address in symbols.items():
        assert library.exports[name]['address'] == address
    pins = assert_instructions(cache.read, (
        (0x184773be0, 'bl', '#0x184722c44'),
        (0x184773be4, 'ldr', 'w2, [x22, #0x88]'),
        (0x184773bf4, 'mov', 'x1, x23'),
        (0x184773bf8, 'bl', '#0x188085bf0'),
        (0x184773bfc, 'add', 'x0, x20, #0x10'),
        (0x188085bf0, 'adrp', 'x17, #0x1e20f3000'),
        (0x188085bf4, 'add', 'x17, x17, #0x828'),
        (0x188085bf8, 'ldr', 'x16, [x17]'),
        (0x188085bfc, 'braa', 'x16, x17'),
        (0x18054af70, 'bl', '#0x180548af8'),
        (0x18054af74, 'mov', 'w8, #3'),
        (0x18054af78, 'movk', 'w8, #0x1000, lsl #16'),
        (0x18054af7c, 'cmp', 'w0, w8'),
        (0x18054af80, 'b.ne', '#0x18054afb0'),
        (0x18054afac, 'b', '#0x18056ec18'),
        (0x180548af8, 'mov', 'x16, #-0x16'),
        (0x180548afc, 'svc', '#0x80'),
        (0x18056ec38, 'stp', 'w2, wzr, [sp, #0x24]'),
        (0x18056ec40, 'str', 'w1, [sp, #0x20]'),
        (0x18056ec80, 'mov', 'x4, #0xc9a00000000'),
        (0x18056ec8c, 'bl', '#0x18055b918'),
        (0x18056eccc, 'cmp', 'w8, #0xcfe'),
        (0x18056ece4, 'cmp', 'w8, #0x24'),
    ))
    slot = cache.pointer(0x1e20f3828)
    assert slot['authenticated'] and int(slot['target'], 16) == symbols['_mach_port_insert_member']
    constants = {}
    for address, value in ((0x18057e410, (0x1513, 40)), (0x18057e748, (0, 3226))):
        raw = cache.read(address, 8)
        assert struct.unpack('<II', raw) == value
        constants[hex(address)] = raw.hex()
    return dict(cache_uuid=cache.uuid, corefoundation_uuid=cf.uuid,
                libsystem_kernel_uuid=library.uuid, pins=pins, constants=constants,
                cf_binding={k: v for k, v in slot.items() if k != 'path'},
                functions={n: library.function(a) for n, a in symbols.items() if n != '_mach_msg2_internal'},
                cf_source_window=windows(cache.read, {'attach_member': (0x184773bd4, 0x2c)}))


def kernel_evidence(path):
    image = Collection(path, IDENTITIES[1])
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    trap = 0xfffffe0007f07018 + 22 * 24
    raw_trap = image.read(trap, 8)
    handler = image.pointer(trap + 8)
    assert raw_trap == bytes((3, 3, 0, 0, 0, 0, 0, 0))
    assert int(handler['target'], 16) == 0xfffffe000bd23bb8 and handler['auth'] == 1

    registry = image.pointer(0xfffffe000caff020)
    subsystem = int(registry['target'], 16)
    assert subsystem == 0xfffffe0007e73b08
    low, high, maximum = struct.unpack('<3I', image.read(subsystem + 8, 12))
    assert (low, high, maximum) == (3200, 3243, 576)
    routine = subsystem + 0x20 + 32 * (3226 - low)
    stub = image.pointer(routine + 8)
    assert int(stub['target'], 16) == 0xfffffe000bdcfb20 and stub['auth'] == 1
    assert struct.unpack('<4I', image.read(routine + 16, 16)) == (3, 0, 0, 44)
    for site, target, operation in (
        (0xfffffe000bd23c24, 0xfffffe000bd27dbc, 'b'),
        (0xfffffe000bdcfb68, 0xfffffe000bd27dbc, 'bl'),
        (0xfffffe000bd27e30, 0xfffffe000bd11328, 'bl'),
        (0xfffffe000bd27e48, 0xfffffe000bd0f864, 'bl'),
        (0xfffffe000bd0f89c, 0xfffffe000bdb5638, 'bl'),
        (0xfffffe000bd0fae4, 0xfffffe000bdb5758, 'bl'),
    ):
        check_branch(image, site, target, operation)
    pins = assert_instructions(image.read, (
        (0xfffffe000bd23bdc, 'ldr', 'x16, [x0, #0x318]'),
        (0xfffffe000bd23c10, 'ldr', 'w1, [x19, #8]'),
        (0xfffffe000bd23c14, 'ldr', 'w2, [x19, #0x10]'),
        (0xfffffe000bdcfb40, 'cmp', 'w8, #0x30'),
        (0xfffffe000bdcfb64, 'ldp', 'w1, w2, [x21, #8]'),
    ))
    pins += assert_instructions(image.read, (
        (0xfffffe000bd11374, 'tbnz', 'w24, #0x11, #0xfffffe000bd1138c'),
        (0xfffffe000bd11394, 'tbz', 'w24, #0x13, #0xfffffe000bd11474'),
        (0xfffffe000bd1140c, 'str', 'x22, [x21]'),
        (0xfffffe000bd11410, 'str', 'x23, [x20]'),
        (0xfffffe000bdb56a0, 'str', 'x0, [x8, #0x28]'),
        (0xfffffe000bdb56a8, 'str', 'x1, [x8]'),
        (0xfffffe000bdb56f0, 'mov', 'w0, #0xb'),
        (0xfffffe000bdb5700, 'str', 'x9, [x1, #0x10]'),
        (0xfffffe000bdb5738, 'str', 'x9, [x0, #0x10]'),
        (0xfffffe000bdb5740, 'str', 'xzr, [x2]'),
        (0xfffffe000bd0f8d4, 'ldr', 'x25, [x21]'),
    ))
    roles = {
        'trap_22': 0xfffffe000bd23bb8,
        'mig_3226': 0xfffffe000bdcfb20,
        'insert': 0xfffffe000bd27dbc,
        'resolve_names': 0xfffffe000bd11328,
        'attach_queue': 0xfffffe000bd0f864,
        'link_waitq': 0xfffffe000bdb5638,
        'mark_ready': 0xfffffe000bdb5758,
    }
    bounds = compiler_ranges(image)
    spans = {role: (address, bounds[address][1] - address) for role, address in roles.items()}
    return dict(identity=IDENTITIES[1], trap_metadata=raw_trap.hex(), trap_handler=handler,
                mig_registry=registry, mig_stub=stub, mig_record=image.read(routine, 32).hex(),
                pins=pins, bodies=windows(image.read, spans))


def local_controls():
    defines = dict(MACH_PORT_RIGHT_RECEIVE=1, MACH_PORT_RIGHT_PORT_SET=3,
                   KERN_ALREADY_IN_SET=11, KERN_NOT_IN_SET=12, MACH_SEND_INVALID_DEST=0x10000003)
    source = '#include <mach/mach.h>\n' + ''.join(
        f'_Static_assert({name} == {value}, "{name}");\n' for name, value in defines.items())
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fsyntax-only', '-x', 'c', '-'],
                   input=source.encode(), check=True)

    lib = ct.CDLL(None)
    name = ct.c_uint32
    names_ptr = ct.POINTER(name)
    task = name.in_dll(lib, 'mach_task_self_').value
    for symbol, args in {
        'mach_port_allocate': (name, name, names_ptr),
        'mach_port_insert_member': (name, name, name),
        'mach_port_extract_member': (name, name, name),
        'mach_port_destroy': (name, name),
        'mach_port_get_set_status': (name, name, ct.POINTER(names_ptr), names_ptr),
        'mach_vm_deallocate': (name, ct.c_uint64, ct.c_uint64),
    }.items():
        function = getattr(lib, symbol)
        function.argtypes = args
        function.restype = ct.c_int
    owned = {}
    steps = []

    def expect(event, status, expected_members, expected_status=0):
        assert status == expected_status, event
        result, count = names_ptr(), name()
        query = lib.mach_port_get_set_status(task, owned['set'], ct.byref(result), ct.byref(count))
        assert query == 0, event
        try:
            members = {result[i] for i in range(count.value)}
            assert members == {owned[key] for key in expected_members}
        finally:
            address = ct.cast(result, ct.c_void_p).value
            if address:
                assert lib.mach_vm_deallocate(task, address, count.value * ct.sizeof(name)) == 0
        steps.append(dict(operation=event, status=status, members=expected_members))

    try:
        for label, right in (('A', 1), ('B', 1), ('set', 3)):
            output = name()
            assert lib.mach_port_allocate(task, right, ct.byref(output)) == 0
            owned[label] = output.value
        expect('new set', 0, [])
        expect('attach A', lib.mach_port_insert_member(task, owned['A'], owned['set']), ['A'])
        expect('reattach A', lib.mach_port_insert_member(task, owned['A'], owned['set']), ['A'], 11)
        expect('attach B', lib.mach_port_insert_member(task, owned['B'], owned['set']), ['A', 'B'])
        expect('detach A', lib.mach_port_extract_member(task, owned['A'], owned['set']), ['B'])
        expect('detach absent A', lib.mach_port_extract_member(task, owned['A'], owned['set']), ['B'], 12)
        assert lib.mach_port_destroy(task, owned['B']) == 0
        del owned['B']
        expect('destroy B', 0, [])
    finally:
        for port in reversed(owned.values()):
            assert lib.mach_port_destroy(task, port) == 0
    return dict(sdk_constants=defines, task_private_steps=steps, released_all_local_objects=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    args = parser.parse_args()
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    print(json.dumps(dict(build=build, userspace=library_evidence(), kernel=kernel_evidence(args.collection),
                          local_controls=local_controls(), native_fairplay_membership_observed=False), indent=2))
