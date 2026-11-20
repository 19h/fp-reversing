#!/usr/bin/env python3
"""Verify the installed direct IOKit trap boundary for FairPlayIOKit."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess

from audit_archived_iokit_open_retirement import TRACE_SHA, trace_record
from audit_live_adid_peer_entitlement import checked_instructions
from audit_live_audit_token_generation import MACH_NAMES, MACH_TABLE, table_row
from audit_live_fairplay_adid_ipc import ThinView, bindings
from audit_live_fairplay_client_entitlements import BUILD, clients, identity, process, signed_blobs
from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from audit_live_kext_selector26 import CLIENT, DRIVER, IDENTITIES, Collection
from bootpolicy_cache_reader import Cache, Dylib
from resolve_kernel_collection_interfaces import macho


IOKIT = '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
TRAP_API = re.compile(r'\b_?(?:IOConnectTrap[0-6]|iokit_user_client_trap)\b')
STRUCT_METHOD = '_IOConnectCallStructMethod'
STUB = 0x184ed9cd0
WRAPPERS = (0x184ee305c, 0x184ee3078, 0x184ee3090, 0x184ee30a4,
            0x184ee30b4, 0x184ee30c0, 0x184ee30c8)
METHOD_SLOTS = {
    'adid': (0x1002d8400, 'E258'),
    'fairplayd': (0x1010a0640, '7A6C'),
    'lskdd': (0x100e738d0, '21C3'),
}
SELECTED_CALLS = {
    'adid': ((0x10001f908, 0xc, 26),),
    'fairplayd': ((0x1002069c4, 0x10, 26), (0x100293074, 0xc, 26)),
    'lskdd': ((0x100474e38, 0x10, 19),),
}


def framework():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    iokit = Dylib(cache, IOKIT)
    assert iokit.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert iokit.exports['_iokit_user_client_trap']['address'] == STUB
    assert iokit.exports[STRUCT_METHOD]['address'] == 0x184ebedb0
    wrappers = {}
    for arity, start in enumerate(WRAPPERS):
        name = f'_IOConnectTrap{arity}'
        assert iokit.exports[name]['address'] == start
        padding = [(start + 4 * i, f'mov x{reg}, #0')
                   for i, reg in enumerate(range(arity + 2, 8))]
        wrappers[name] = checked_instructions(
            cache.read, [*padding, (start + 4 * len(padding), f'b #{STUB:#x}')])
    return {
        'cache_uuid': cache.uuid, 'iokit_uuid': iokit.uuid, 'wrappers': wrappers,
        'trap_instructions': checked_instructions(cache.read, (
            (STUB, 'mov x16, #-0x64'), (STUB + 4, 'svc #0x80'), (STUB + 8, 'ret'),
        )),
    }


def kernel(collection):
    image = Collection(collection, IDENTITIES[1])
    row = table_row(image, 100, 'iokit_user_client_trap', MACH_TABLE, MACH_NAMES, mach=True)
    assert row['handler']['target'] == '0xfffffe000c5c1dc4'
    assert bytes.fromhex(row['record_bytes'])[:3] == bytes((8, 8, 0))
    slots = {}
    base = image.named(f'__ZTV{CLIENT}') + 16
    parent_base = image.named('__ZTV12IOUserClient') + 16
    for offset, symbol, target, diversity in (
        (0x970, f'__ZN{CLIENT}26getTargetAndMethodForIndexEPP9IOServicej',
         0xfffffe000a544e60, '0xbdaa'),
        (0x980, '__ZN12IOUserClient23getExternalTrapForIndexEj',
         0xfffffe000c5b1ebc, '0xea23'),
        (0x988, '__ZN12IOUserClient24getTargetAndTrapForIndexEPP9IOServicej',
         0xfffffe000c5b1e68, '0x2bcb'),
    ):
        pointer = image.pointer(base + offset)
        assert (int(pointer['target'], 16), pointer['auth'], pointer['address_diversity'],
                pointer['key'], pointer['diversity']) == (target, 1, 1, 0, diversity)
        assert image.named(symbol) == target
        slots[hex(offset)] = {'symbol': symbol, **pointer}
        if offset in (0x980, 0x988):
            parent = image.pointer(parent_base + offset)
            assert pointer['target'] == parent['target'] and diversity == parent['diversity']
            slots[hex(offset)]['parent_slot'] = parent['slot']
    insns = checked_instructions(image.read, (
        (0xfffffe000c5c1de0, 'mov w19, #0x2c2'),
        (0xfffffe000c5c1de4, 'movk w19, #0xe000, lsl #16'),
        (0xfffffe000c5c1de8, 'ldr x20, [x0]'),
        (0xfffffe000c5c1dfc, 'mov x0, x19'),
        (0xfffffe000c5c1e7c, 'mov x0, x20'),
        (0xfffffe000c5c1e80, 'mov w1, #0x27'),
        (0xfffffe000c5c1e84, 'bl #0xfffffe000be7e528'),
        (0xfffffe000c5c1e88, 'cbz x0, #0xfffffe000c5c1dfc'),
        (0xfffffe000c5c1f2c, 'str xzr, [sp, #8]'),
        (0xfffffe000c5c1f8c, 'ldr w2, [x8, #8]'),
        (0xfffffe000c5c1f98, 'mov x17, #0x988'),
        (0xfffffe000c5c1fa4, 'add x1, sp, #8'),
        (0xfffffe000c5c1fac, 'movk x16, #0x2bcb, lsl #48'),
        (0xfffffe000c5c1fb0, 'blraa x8, x16'),
        (0xfffffe000c5c1fb4, 'ldr x9, [sp, #8]'),
        (0xfffffe000c5c1fb8, 'add w19, w19, #0x2e'),
        (0xfffffe000c5c1fbc, 'cmp x0, #0'),
        (0xfffffe000c5c1fc0, 'ccmp x9, #0, #4, ne'),
        (0xfffffe000c5c1fc4, 'b.eq #0xfffffe000c5c2084'),
        (0xfffffe000c5c2070, 'ldp x1, x2, [x23, #0x10]'),
        (0xfffffe000c5c2074, 'ldp x3, x4, [x23, #0x20]'),
        (0xfffffe000c5c2078, 'ldp x5, x6, [x23, #0x30]'),
        (0xfffffe000c5c207c, 'blraa x8, x9'),
        (0xfffffe000c5c2088, 'autda x16, x24'),
        (0xfffffe000c5c208c, 'ldr x8, [x16, #0x28]!'),
        (0xfffffe000c5c2098, 'blraa x8, x16'),
        (0xfffffe000c5c209c, 'b #0xfffffe000c5c1dfc'),
        (0xfffffe000c5b1e8c, 'mov x17, #0x980'),
        (0xfffffe000c5b1e98, 'mov x1, x2'),
        (0xfffffe000c5b1e9c, 'movk x16, #0xea23, lsl #48'),
        (0xfffffe000c5b1ea0, 'blraa x8, x16'),
        (0xfffffe000c5b1ea4, 'cbz x0, #0xfffffe000c5b1eb0'),
        (0xfffffe000c5b1ebc, 'bti c'),
        (0xfffffe000c5b1ec0, 'mov x0, #0'),
        (0xfffffe000c5b1ec4, 'ret'),
    ))
    result = 0xe00002c2 + 0x2e
    assert result == 0xe00002f0
    assertions = b"""
#include <IOKit/IOReturn.h>
_Static_assert((unsigned) kIOReturnBadArgument == 0xe00002c2u, "bad argument");
_Static_assert((unsigned) kIOReturnNotFound == 0xe00002f0u, "not found");
"""
    subprocess.run(['xcrun', '--sdk', 'macosx', 'clang', '-x', 'c', '-fsyntax-only', '-'],
                   input=assertions, check=True)
    return {'collection_sha256': image.digest, 'kernel_uuid': IDENTITIES[1][1],
            'driver_uuid': IDENTITIES[1][2], 'table_entry': row, 'vtable_slots': slots,
            'instructions': insns, 'absent_descriptor_result': hex(result)}


def svc_census(image):
    sites = []
    scanned = 0
    view = memoryview(image)
    for section in macho(image, 0, 'client')['sections']:
        if not section['flags'] & 0x80000400:
            continue
        first = section['file_offset']
        end = first + section['size']
        scanned += section['size']
        assert end <= len(image) and section['size'] % 4 == 0
        for index, (word,) in enumerate(struct.iter_unpack('<I', view[first:end])):
            if word & 0xffe0001f == 0xd4000001:
                sites.append(hex(section['address'] + 4 * index))
    assert scanned and not sites
    return {'instruction_section_bytes': scanned, 'svc_sites': sites}


def attached_executables():
    before = clients()
    assert before[0] == '0x1000002fb'
    result = []
    for child in before[1]:
        pid, name = child['pid'], child['creator']
        start, euid, path = process(pid)
        assert path.name == name
        live = identity(pid)
        _, source = signed_blobs(path, live)
        row = source['slice']
        with path.open('rb') as stream:
            stream.seek(row['file_offset_bytes'])
            image = stream.read(row['slice_size_bytes'])
        assert sha256(image).hexdigest() == row['sha256']
        imports = subprocess.check_output(['xcrun', 'dyld_info', '-imports',
                                           '-arch', 'arm64e', path], text=True)
        assert re.search(rf'\b{STRUCT_METHOD}\s+\(from IOKit\)', imports)
        assert not TRAP_API.search(imports)
        fixups = bindings(path, '-arch', 'arm64e')
        assert not any(TRAP_API.search(entry) for entry in fixups.values())
        slot, modifier = METHOD_SLOTS[name]
        entry = fixups[slot]
        assert entry == f'auth-bind IOKit/{STRUCT_METHOD} (div=0x{modifier} ad=0 key=IA)'
        view = ThinView(image)
        calls = {
            hex(pc): checked_instructions(view.read, (
                (pc - selector_distance, f'mov w1, #{selector:#x}'),
                (pc - 4, f'mov x17, #{int(modifier, 16):#x}'),
                (pc, 'blraa x8, x17'),
            ))
            for pc, selector_distance, selector in SELECTED_CALLS[name]
        }
        assert process(pid) == (start, euid, path) and identity(pid) == live
        result.append({'creator': name, 'pid': pid, 'registry_entry': child['entry'],
                       'slice_uuid': row['uuid'], 'slice_sha256': row['sha256'],
                       'struct_method_slot': hex(slot), 'binding': entry,
                       'selected_call_windows': calls,
                       'direct_trap_imports': 0, **svc_census(image)})
    assert clients() == before
    return {'service_entry': before[0], 'clients': result}


def archive(trace):
    open_exchange = trace_record(trace)
    raw = trace.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    lines = raw.decode().splitlines()
    api_refs = [i for i, line in enumerate(lines, 1) if TRAP_API.search(line)]
    assert len(lines) == 1748 and not api_refs
    request, reply = open_exchange['guest_messages'][-2:]
    return {'sha256': TRACE_SHA, 'line_count': len(lines), 'named_trap_matches': api_refs,
            'open_request_id': request['id'], 'open_reply_id': reply['id'],
            'open_connection_is_null': reply['descriptors'][0]['name'] == '0x0',
            'open_result': open_exchange['application_result'],
            'guest_send_count': len(open_exchange['guest_send_ids']),
            'guest_method_send_count': open_exchange['guest_send_ids'].count(2865)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('annotated_trace', type=Path)
    args = parser.parse_args()
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    loaded = subprocess.check_output(['kmutil', 'showloaded'], text=True)
    driver, = (line for line in loaded.splitlines() if f'{DRIVER} (' in line)
    assert IDENTITIES[1][2] in driver.lower()
    result = {'macos_build': BUILD, 'framework': framework(), 'kernel': kernel(args.collection),
              'attached_executables': attached_executables(), 'annotated_trace': archive(args.annotated_trace)}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
