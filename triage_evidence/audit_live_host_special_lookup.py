#!/usr/bin/env python3
"""Recover host-special lookup paths and optionally record public queries."""

import argparse
import ctypes as ct
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_kext_selector26 import Collection, CS, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair, words

SLOTS = (17, 31, 34, 35, 36)
SUBSYSTEM = 0xfffffe0007e73228
REGISTRY_POINTER = 0xfffffe000caff030


def check_branch(image, site, destination, operation):
    (word,) = struct.unpack('<I', image.read(site, 4))
    assert word >> 26 == {'b': 0x05, 'bl': 0x25}[operation]
    displacement = ((word & 0x1ffffff) - (word & 0x2000000)) * 4
    assert site + displacement == destination == image.branch(site, operation)


def kernel_lookup(path):
    image = Collection(path, IDENTITIES[1])
    registry = image.pointer(REGISTRY_POINTER)
    assert int(registry['target'], 16) == SUBSYSTEM
    start, end, maximum = struct.unpack('<3I', image.read(SUBSYSTEM + 8, 12))
    assert (start, end, maximum) == (400, 426, 0x1034)
    metadata = {}
    for mid, stub, descriptors, reply_bytes in (
        (412, 0xfffffe000bdcbe78, 1, 52),
        (413, 0xfffffe000bdcbdac, 0, 44),
    ):
        record = SUBSYSTEM + 0x20 + (mid - start) * 0x20
        pointer = image.pointer(record + 8)
        assert int(pointer['target'], 16) == stub
        assert struct.unpack('<2I', image.read(record + 24, 8)) == (descriptors, reply_bytes)
        metadata[mid] = {'stub': pointer, 'record_bytes': image.read(record, 32).hex()}
    direct = image.named('_host_get_special_port')
    self_address = image.named('_host_priv_self')
    assert (direct, self_address) == (0xfffffe000bd3a480, 0xfffffe000bd3a6a0)
    for site, target, operation in (
        (0xfffffe000bdcbec0, 0xfffffe000bd3b240, 'bl'),
        (0xfffffe000bdcbecc, 0xfffffe000bd3a3a4, 'bl'),
        (0xfffffe000bdcbe08, 0xfffffe000bd3b240, 'bl'),
        (0xfffffe000bdcbe50, 0xfffffe000bd3a224, 'bl'),
        (0xfffffe000bd3a47c, direct, 'b'),
        (0xfffffe000bd3a56c, 0xfffffe000bd17fb0, 'bl'),
    ):
        check_branch(image, site, target, operation)
    for site, operation, operand in (
        (0xfffffe000bdcbe88, 'cmp', 'w8, #0x30'),
        (0xfffffe000bdcbeb8, 'ldr', 'x0, [x0, #8]'),
        (0xfffffe000bdcbec4, 'ldr', 'w2, [x20, #0xc]'),
        (0xfffffe000bdcbed4, 'str', 'w0, [x19, #0x28]'),
        (0xfffffe000bdcbf14, 'stur', 'x17, [x19, #0x24]'),
        (0xfffffe000bdcbf2c, 'str', 'w8, [x19, #0x20]'),
        (0xfffffe000bd3b260, 'ldr', 'x16, [x0, #0x2d0]'),
        (0xfffffe000bd3b274, 'cmp', 'x19, x16'),
        (0xfffffe000bd3b2ac, 'cmp', 'w8, #0x19'),
        (0xfffffe000bd3b288, 'mov', 'x0, #0'),
        (0xfffffe000bd3a3bc, 'mov', 'w0, #4'),
        (0xfffffe000bd3a3c0, 'cbz', 'x21, #0xfffffe000bd3a450'),
        (0xfffffe000bd3a3c8, 'sub', 'w8, w2, #0x25'),
        (0xfffffe000bd3a3cc, 'cmn', 'w8, #0x24'),
        (0xfffffe000bd3a4e4, 'ubfiz', 'x9, x22, #3, #0x20'),
        (0xfffffe000bd3a4fc, 'ldr', 'x16, [x17]'),
        (0xfffffe000bd3a53c, 'mov', 'x0, #0'),
        (0xfffffe000bd3a574, 'mov', 'w0, #0'),
        (0xfffffe000bd3a578, 'str', 'x8, [x21]'),
        (0xfffffe000bd17fc0, 'add', 'x8, x0, #1'),
        (0xfffffe000bd17fc4, 'cmp', 'x8, #2'),
        (0xfffffe000bd17fc8, 'b.lo', '#0xfffffe000bd18090'),
    ):
        image.instruction(site, operation, operand)
    host = address_pair(image, self_address + 4, 'x0')
    assert address_pair(image, 0xfffffe000bd3b2cc, 'x8') == host
    table = address_pair(image, 0xfffffe000bd3a4dc, 'x8')
    assert table == host + 0x10
    cells = {}
    for index in SLOTS:
        address = table + 8 * index
        raw = image.read(address, 8)
        assert raw == bytes(8) and image.offset(address, 8) not in image.fixups
        cells[index] = {'unslid_cell': hex(address), 'file_word': raw.hex()}
    ranges = (
        ('kernel_host_identity', self_address, 0x10),
        ('kernel_getter', direct, 0x1d0),
        ('user_getter_wrapper', 0xfffffe000bd3a3a4, 0xdc),
        ('user_host_conversion', 0xfffffe000bd3b240, 0xa0),
        ('ordinary_slot_copy', 0xfffffe000bd17fb0, 0xec),
        ('kernel_MIG_412', 0xfffffe000bdcbe78, 0xc8),
        ('kernel_MIG_413', 0xfffffe000bdcbdac, 0xcc),
    )
    return {'identity': IDENTITIES[1], 'registry_pointer': registry, 'records': metadata,
            'host_identity': hex(host), 'table_base': hex(table), 'cells': cells,
            'windows': {name: words(image, start, size) for name, start, size in ranges}}


def launchd_job(domain, label):
    domain_arg = f'gui/{os.getuid()}' if domain == 'gui' else domain
    raw = command('launchctl', 'print', f'{domain_arg}/{label}')
    state, = re.findall(rb'^\tstate = ([^\n]+)$', raw, re.M)
    block, = re.findall(rb'^\tendpoints = \{\n(.*?)^\t\}', raw, re.M | re.S)
    endpoints = {}
    for name, fields in re.findall(rb'^\t\t"([^"]+)" = \{\n(.*?)^\t\t\}', block, re.M | re.S):
        active, = re.findall(rb'^\t\t\tactive = ([01])$', fields, re.M)
        slots = re.findall(rb'^\t\t\thost-special port = (\d+)', fields, re.M)
        assert len(slots) <= 1
        endpoints[name.decode()] = {'active': int(active), 'host_slot': int(slots[0]) if slots else None}
    assert endpoints
    return {'domain': domain, 'state': state.decode(), 'endpoints': endpoints,
            'endpoint_block_sha256': hashlib.sha256(block).hexdigest()}


def user_observation():
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    started = datetime.now(timezone.utc).isoformat()
    lib = ct.CDLL(None)
    name = ct.c_uint32
    lib.mach_host_self.restype = name
    lib.mach_port_deallocate.argtypes = (name, name)
    lib.host_page_size.argtypes = (name, ct.POINTER(ct.c_size_t))
    getter = lib.host_get_special_port
    getter.argtypes = (name, ct.c_int, ct.c_int, ct.POINTER(name))
    entry = ct.cast(getter, ct.c_void_p).value
    stub_bytes = ct.string_at(entry, 0x158)
    decoded = list(CS.disasm(stub_bytes, entry))
    assert len(decoded) == len(stub_bytes) // 4
    page, load = decoded[0x44 // 4:0x4c // 4]
    assert page.mnemonic == 'adrp' and load.op_str == 'd0, [x8, #0x4f8]'
    constant = int(page.op_str.split('#')[1], 0) + 0x4f8
    assert struct.unpack('<II', ct.string_at(constant, 8)) == (0, 412)
    assert decoded[0x78 // 4].mnemonic == 'bl'
    assert decoded[0xb8 // 4].op_str == 'w8, #0x200'
    host = lib.mach_host_self()
    task = name.in_dll(lib, 'mach_task_self_').value
    page_bytes = ct.c_size_t()
    results = {}
    try:
        page_status = lib.host_page_size(host, ct.byref(page_bytes))
        for slot in SLOTS:
            result = name(0xffffffff)
            status = getter(host, -1, slot, ct.byref(result))
            release = None
            if status == 0 and result.value not in (0, 0xffffffff):
                release = lib.mach_port_deallocate(task, result.value)
            results[slot] = {'status': status, 'out_before': '0xffffffff',
                             'out_after': hex(result.value), 'returned_right_release_status': release}
    finally:
        host_release = lib.mach_port_deallocate(task, host)
    assert page_status == host_release == 0 and page_bytes.value == os.sysconf('SC_PAGE_SIZE')
    jobs = {label: launchd_job(domain, label) for domain, label in (
        ('system', 'com.apple.fairplayd'),
        ('system', 'com.apple.managedappdistributiond'),
        ('gui', 'com.apple.managedappdistributionagent'),
    )}
    return {'utc_start': started, 'utc_end': datetime.now(timezone.utc).isoformat(),
            'build': command('sw_vers', '-buildVersion').decode().strip(),
            'user_getter_text': stub_bytes.hex(), 'send_offset': '0x78', 'message_ids': [412, 512],
            'host_page_size_status': page_status, 'host_page_size_bytes': page_bytes.value,
            'host_right_release_status': host_release, 'public_host_gets': results,
            'launchd_jobs': jobs, 'native_fairplay_rpc_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--observe', action='store_true', help='also read current launchd and public host metadata')
    args = parser.parse_args()
    receipt = {'kernel': kernel_lookup(args.collection)}
    if args.observe:
        receipt['observation'] = user_observation()
    print(json.dumps(receipt, indent=2))
