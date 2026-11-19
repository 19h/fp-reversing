#!/usr/bin/env python3
"""Recheck normal host-special publication from original images and job metadata."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import struct

from audit_daemon_iokit_native_registry import command, sysctl
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_fairplay_adid_ipc import ThinView
from audit_live_fairplay_kernel_rpc import SELECTIONS, select
from audit_live_host_special_lookup import check_branch, kernel_lookup, launchd_job
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import CS, Collection, IDENTITIES
from audit_live_kext_selector26_transfer import words
from audit_live_rpc700_publication import running_identity

LAUNCHD_UUID = '96360fc3-2fde-3eee-a403-7dfca7b44ac3'
BINDINGS = {
    0x10005e264: '_host_set_special_port',
    0x10005e344: '_mach_host_self',
    0x10005e3c4: '_mach_port_construct',
    0x10005f744: '_xpc_int64_get_value',
    0x10005f774: '_xpc_mach_send_create_with_disposition',
    0x10005f784: '_xpc_mach_send_get_right',
    0x10005d874: '__os_assumes_log',
}


def launchd(path):
    slices = installed_slices(path)
    identity = running_identity({'pid': 1}, path, slices)
    selected = identity['matched_slice']
    assert selected['uuid'] == LAUNCHD_UUID and selected['file_offset_bytes'] == 0x4000
    assert selected['sha256'] == 'd35f01f9669f314a1058e17acca27d3141ba8be1b0ca0d9e9d5edbb787607243'
    start = selected['file_offset_bytes']
    blob = path.read_bytes()[start:start + selected['slice_size_bytes']]
    assert sha256(blob).hexdigest() == selected['sha256']
    image = ThinView(blob)

    indirect = command('otool', '-arch', selected['arch'], '-Iv', str(path)).decode()
    observed = {int(pc, 16): name for pc, name in re.findall(
        r'^\s*(0x[0-9a-fA-F]+)\s+\d+\s+(\S+)\s*$', indirect, re.M)}
    assert {site: observed[site] for site in BINDINGS} == BINDINGS
    for site, target, mnemonic in (
        (0x10005c910, 0x10005f744, 'bl'),
        (0x10003053c, 0x10005e344, 'bl'),
        (0x10003054c, 0x100046c48, 'bl'),
        (0x10003055c, 0x10005e264, 'bl'),
        (0x100030594, 0x10005d874, 'bl'),
        (0x100030598, 0x100030564, 'b'),
        (0x100046c5c, 0x10005cb70, 'bl'),
        (0x100046c78, 0x10005f784, 'b'),
        (0x10005cc44, 0x10000ce68, 'bl'),
        (0x10005cc50, 0x10005f774, 'bl'),
        (0x10000cf14, 0x10000ce10, 'bl'),
        (0x10000ce28, 0x10000cdc4, 'bl'),
        (0x10000cde8, 0x10005e3c4, 'bl'),
    ):
        image.instruction(site, mnemonic, f'#{target:#x}')
    for site, mnemonic, operands in (
        (0x10005c8f8, 'adrp', 'x1, #0x100075000'),
        (0x10005c8fc, 'add', 'x1, x1, #0x9c0'),
        (0x10005c918, 'cmp', 'x0, #8'),
        (0x10005c91c, 'b.lt', '#0x10005ca98'),
        (0x10005c920, 'cmp', 'x21, #0x24'),
        (0x10005c924, 'b.hi', '#0x10005cb34'),
        (0x10005c928, 'str', 'w21, [x20, #0x54]'),
        (0x100030498, 'ldrsw', 'x21, [x19, #0x54]'),
        (0x100030550, 'mov', 'x2, x0'),
        (0x100030554, 'mov', 'x0, x20'),
        (0x100030558, 'mov', 'x1, x21'),
        (0x100030560, 'cbnz', 'w0, #0x100030590'),
        (0x100030564, 'str', 'x19, [x23, x21, lsl #3]'),
        (0x10005cc4c, 'mov', 'w1, #0x11'),
        (0x10005cc58, 'str', 'x0, [x19, #0x68]'),
    ):
        image.instruction(site, mnemonic, operands)
    key = b'HostSpecialPort\0'
    assert image.read(0x1000759c0, len(key)) == key
    return dict(pid1=identity, installed_slices=slices,
                imports={hex(pc): name for pc, name in BINDINGS.items()},
                windows=windows(image.read, {
                    'parse_slot': (0x10005c8b0, 0x80),
                    'publish': (0x100030498, 0x104),
                    'read_send_name': (0x100046c48, 0x38),
                    'endpoint_factory': (0x10005cb70, 0x108),
                    'construct_adapters': (0x10000cdc4, 0x154),
                }))


def windows(read, spans):
    result = {}
    for label, (pc, size) in spans.items():
        data = read(pc, size)
        decoded = list(CS.disasm(data, pc))
        assert len(decoded) * 4 == size, label
        result[label] = dict(start=hex(pc), bytes=data.hex(), sha256=sha256(data).hexdigest(),
                             instructions=[[hex(i.address), i.mnemonic, i.op_str] for i in decoded])
    return result


def mach_library():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    lib = Dylib(cache, LIBKERNEL)
    assert lib.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    entry, messenger = (lib.exports[name]['address']
                        for name in ('_host_set_special_port', '_mach_msg2_internal'))
    assert (entry, messenger) == (0x1805699e0, 0x18055b918)
    constants = {}
    for role, address, expected in (
        ('message_bits_and_size', 0x18057e490, (0x80001513, 52)),
        ('send_descriptor_trailer', 0x18057e4a0, (0, 0x00130000)),
        ('voucher_and_request_id', 0x18057e500, (0, 413)),
    ):
        raw = cache.read(address, 8)
        assert struct.unpack('<II', raw) == expected
        constants[role] = dict(address=hex(address), words=list(expected), bytes=raw.hex())
    for site, mnemonic, operands in (
        (0x1805699fc, 'stp', 'w20, w2, [sp, #0x20]'),
        (0x180569a14, 'str', 'x8, [sp, #0x30]'),
        (0x180569a18, 'str', 'w1, [sp, #0x38]'),
        (0x180569a2c, 'stp', 'w19, w0, [sp, #0x10]'),
        (0x180569a5c, 'mov', 'x4, #0x19d00000000'),
        (0x180569a60, 'mov', 'w6, #0x2c'),
        (0x180569a68, 'bl', f'#{messenger:#x}'),
        (0x180569aa4, 'cmp', 'w8, #0x201'),
        (0x180569abc, 'cmp', 'w8, #0x24'),
        (0x180569acc, 'ldr', 'w19, [sp, #0x28]'),
    ):
        insn, = CS.disasm(cache.read(site, 4), site)
        assert (insn.mnemonic, insn.op_str) == (mnemonic, operands)
    return dict(cache_uuid=cache.uuid, image_uuid=lib.uuid, constants=constants,
                windows=windows(cache.read, {'setter': (entry, 0x124)}))


def kernel(path):
    getter = kernel_lookup(path)
    image = Collection(path, IDENTITIES[1])
    for site, target, mnemonic in (
        (0xfffffe000bd3a2a8, 0xfffffe000bd3a2c0, 'b'),
        (0xfffffe000bd3a3a0, 0xfffffe000bd3a088, 'b'),
        (0xfffffe000bd3a1c4, image.named('_ipc_port_release_send'), 'bl'),
    ):
        check_branch(image, site, target, mnemonic)
    for site, mnemonic, operands in (
        (0xfffffe000bdcbe10, 'ldr', 'w1, [x21, #8]'),
        (0xfffffe000bd3a0e0, 'casa', 'x8, x9, [x11]'),
        (0xfffffe000bd3a0ec, 'add', 'x8, x0, #0x10'),
        (0xfffffe000bd3a0f0, 'ubfiz', 'x10, x19, #3, #0x20'),
        (0xfffffe000bd3a11c, 'autda', 'x16, x17'),
        (0xfffffe000bd3a130, 'pacda', 'x17, x16'),
        (0xfffffe000bd3a144, 'str', 'x17, [x9]'),
        (0xfffffe000bd3a158, 'casl', 'w2, wzr, [x10]'),
        (0xfffffe000a64bda4, 'csel', 'w2, w9, w8, eq'),
    ):
        image.instruction(site, mnemonic, operands)
    host, table = (int(getter[key], 16) for key in ('host_identity', 'table_base'))
    assert host + 0x10 == table
    cells = {index: getter['cells'][index] for index in (17, 31, 34)}
    for index, cell in cells.items():
        assert int(cell['unslid_cell'], 16) == table + 8 * index
    kext_lookup = {row[0]: select(image, *row) for row in SELECTIONS[:2]}
    assert int(kext_lookup['host_get_special_port']['slot']['target'], 16) == 0xfffffe000bd3a480
    spans = {
        'mig_setter': (0xfffffe000bdcbdac, 0xcc),
        'replacement_core': (0xfffffe000bd3a088, 0x19c),
        'setter_front_and_policy': (0xfffffe000bd3a224, 0x180),
        'getter_acquisition': (0xfffffe000bd3a4dc, 0xa4),
        'kext_slot_selection': (0xfffffe000a64bd94, 0xb8),
    }
    return dict(identity=getter['identity'], setter_record=getter['records'][413],
                table_base=hex(table), cells=cells, kext_lookup=kext_lookup,
                windows={role: words(image, start, size) for role, (start, size) in spans.items()})


def audit(collection, launchd_path):
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    launchd_code = launchd(launchd_path)
    started = datetime.now(timezone.utc)
    first = launchd_job('system', 'com.apple.fairplayd')
    second = launchd_job('system', 'com.apple.fairplayd')
    finished = datetime.now(timezone.utc)
    assert first == second
    for slot, name in ((17, 'com.apple.unfreed'), (31, 'com.apple.arcade.fpsd')):
        assert first['endpoints'][name] == {'active': 1, 'host_slot': slot}
    return dict(build=build, launchd=launchd_code, mach_library=mach_library(),
                kernel=kernel(collection), job_observation=first,
                observation_started_utc=started.isoformat(), observation_ended_utc=finished.isoformat(),
                live_slot_object_observed=False, native_setter_event_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('launchd', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.collection, args.launchd), indent=2))
