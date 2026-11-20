#!/usr/bin/env python3
"""Verify the pinned registry-property calls and installed IOKit transport."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct

from audit_archived_iokit_open_retirement import GUEST_MESSAGE, TRACE_SHA
from audit_daemon_iokit_retirement import Image, fixups
from audit_live_iokit_mach_transport import (
    CACHE_UUID, CS, IOKIT, LIBKERNEL, Cache, Dylib, clean_pointer, dyld_uuid, record_windows,
)
from audit_live_iokit_registry_parent import check, daemon_evidence as parent_evidence
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map


# Request, framework stub, send site, header literal, reply ID check, user
# reply size check, user success size, kernel stub, kernel internal size.
ROUTES = (
    (2805, 0x184f5e34c, 0x184f5e424, 0x184f98960, 0x184f5e470, 0x184f5e4d0, 56,
     0xfffffe000be861dc, 64),
    (2879, 0x184ebd8dc, 0x184ebda1c, 0x184f98b70, 0x184ebda68, 0x184ebdac8, 56,
     0xfffffe000be800a4, 64),
    (2889, 0x184f62330, 0x184f62488, 0x184f98bc0, 0x184f624d4, 0x184f62534, 64,
     0xfffffe000be7f184, 72),
)


def daemon(path):
    parent = parent_evidence(path)
    image = Image(path)
    imports = fixups(path)
    bindings = {}
    for stub, slot, name in (
        (0x100e2a950, 0x1010b1bb8, 'IOKit/_IORegistryEntryCreateCFProperty'),
        (0x100e2a840, 0x1010b1bf0, 'CoreFoundation/_CFBooleanGetValue'),
        (0x100e2a870, 0x1010b1c08, 'CoreFoundation/_CFDataGetBytes'),
        (0x100e2a900, 0x1010b1c50, 'CoreFoundation/_CFRelease'),
        (0x100e2a940, 0x1010b1bb0, 'IOKit/_IOObjectRelease'),
    ):
        check(image.read, (
            (stub, 'adrp', 'x17, #0x1010b1000'),
            (stub + 4, 'add', f'x17, x17, #{slot & 0xfff:#x}'),
            (stub + 8, 'ldr', 'x16, [x17]'),
            (stub + 12, 'braa', 'x16, x17'),
        ))
        binding = imports[slot]
        assert (binding['target'], binding['kind'], binding['modifier'],
                binding['address_diversity'], binding['key']) == (name, 'auth-bind', 0, 1, 'IA')
        bindings[hex(stub)] = {'slot': hex(slot), **binding}
    assert imports[0x1010b1dc0]['target'] == 'CoreFoundation/_kCFAllocatorDefault'
    data_binding = imports[0x1010a1630]
    assert data_binding['target'] == 'IOKit/_IORegistryEntryCreateCFProperty'
    for address, name in ((0x1010b19f8, b'IOBuiltin'), (0x1010b19d8, b'IOMACAddress')):
        assert imports[address]['target'] == 'CoreFoundation/___CFConstantStringClassReference'
        literal = int(imports[address + 16]['target'], 16)
        assert image.read(literal, len(name) + 1) == name + b'\0'
        assert int.from_bytes(image.read(address + 24, 8), 'little') == len(name)
    anchors = (
        (0x10000429c, 'ldr', 'x21, [x8]'),
        (0x1000042a8, 'add', 'x23, x23, #0x9f8'),
        (0x1000042ac, 'mov', 'x0, x19'),
        (0x1000042b0, 'mov', 'x1, x23'),
        (0x1000042c8, 'bl', '#0x100e2a840'),
        (0x1000042d4, 'bl', '#0x100e2a900'),
        (0x100004300, 'add', 'x1, x1, #0x9f8'),
        (0x100004304, 'mov', 'x0, x19'),
        (0x10000431c, 'bl', '#0x100e2a840'),
        (0x100004324, 'bl', '#0x100e2a900'),
        (0x100004344, 'ldr', 'w0, [sp, #0xc]'),
        (0x10000434c, 'add', 'x1, x1, #0x9d8'),
        (0x10000435c, 'cbz', 'x0, #0x10000437c'),
        (0x100004364, 'mov', 'x1, #0'),
        (0x100004368, 'mov', 'w2, #6'),
        (0x100004370, 'bl', '#0x100e2a870'),
        (0x100004378, 'bl', '#0x100e2a900'),
        (0x100004380, 'bl', '#0x100e2a940'),
        (0x100004388, 'bl', '#0x100e2a940'),
    )
    check(image.read, anchors)
    for call in (0x1000042bc, 0x100004310, 0x100004358):
        check(image.read, ((call - 8, 'mov', 'x2, x21'), (call - 4, 'mov', 'w3, #0')))
    return {**parent, 'property_stubs': bindings, 'property_data_binding': data_binding,
            'property_data_binding_slot': '0x1010a1630',
            'property_windows': record_windows(image.read, ((0x10000425c, 0x150),))}


def framework():
    cache = Cache()
    io = Dylib(cache, IOKIT)
    libkernel = Dylib(cache, LIBKERNEL)
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    assert io.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert libkernel.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    for symbol, pc in (('_IORegistryEntryCreateCFProperty', 0x184ebd698),
                       ('_IORegistryEntrySearchCFProperty', 0x184ebd6ac),
                       ('_IOCFUnserializeWithSize', 0x184ebe578)):
        assert io.exports[symbol]['address'] == pc

    veneers = {}
    for pc, name in ((0x188076d50, '_mig_get_reply_port'), (0x188088af0, '_mach_msg2_internal'),
                     (0x18806c8c0, '_vm_deallocate')):
        code = list(CS.disasm(cache.read(pc, 16), pc))
        assert [item.mnemonic for item in code] == ['adrp', 'add', 'ldr', 'braa']
        slot = sum(int(item.op_str.split('#')[-1], 16) for item in code[:2])
        pointer = cache.pointer(slot)
        assert pointer['authenticated']
        assert name in {row['name'] for row in libkernel.symbols_at(int(pointer['target'], 16))}
        veneers[name] = clean_pointer(pointer)

    compatibility = cache.pointer(0x1e01cbf88)
    assert compatibility['target'] == '0x1eb0ede20'
    assert '__os_xbs_chrooted' in {row['name'] for row in libkernel.symbols_at(0x1eb0ede20)}
    assert cache.read(0x1eb0ede20, 1) == b'\0'
    assert cache.read(0x1eb1ee3f8, 1) == b'\x01'
    assert cache.read(0x184f889f8, 1) == b'\0'
    anchors = (
        (0x184ebd6a0, 'mov', 'x1, #0'),
        (0x184ebd6a4, 'mov', 'w4, #0'),
        (0x184ebd6a8, 'b', '#0x184ebd6ac'),
        (0x184ebd6f8, 'mov', 'w8, #0x800'),
        (0x184ebd71c, 'ldrb', 'w9, [x9, #0x3f8]'),
        (0x184ebd720, 'tbnz', 'w9, #0, #0x184ebd740'),
        (0x184ebd724, 'tbnz', 'w21, #0, #0x184ebd7cc'),
        (0x184ebd738, 'bl', '#0x184f5e34c'),
        (0x184ebd74c, 'csel', 'x1, x9, x23, eq'),
        (0x184ebd754, 'ldr', 'x9, [x9, #0xf88]'),
        (0x184ebd758, 'ldrb', 'w9, [x9]'),
        (0x184ebd75c, 'cmp', 'w9, #1'),
        (0x184ebd760, 'b.ne', '#0x184ebd7ec'),
        (0x184ebd778, 'bl', '#0x184ebd8dc'),
        (0x184ebd7ec, 'add', 'x4, sp, #0x28'),
        (0x184ebd808, 'bl', '#0x184f62330'),
        (0x184ebd81c, 'cbz', 'w21, #0x184ebd828'),
        (0x184ebd828, 'ldr', 'x0, [sp, #0x18]'),
        (0x184ebd82c, 'cbz', 'x0, #0x184ebd838'),
        (0x184ebd830, 'ldr', 'w1, [sp, #0x24]'),
        (0x184ebd838, 'ldr', 'x1, [sp, #8]'),
        (0x184ebd83c, 'add', 'x0, sp, #0x28'),
        (0x184ebd84c, 'bl', '#0x184ebe578'),
        (0x184ebd88c, 'ldr', 'w2, [sp, #0x24]'),
        (0x184ebd890, 'bl', '#0x18806c8c0'),
        (0x184f5e3e4, 'mov', 'w2, #0x1513'),
        (0x184ebd9e0, 'mov', 'w8, #0x1513'),
        (0x184f6244c, 'mov', 'w8, #0x1513'),
        (0x184f62564, 'ldur', 'x9, [sp, #0x34]'),
        (0x184f6256c, 'ldur', 'x9, [sp, #0x1c]'),
        (0x184f62574, 'str', 'w8, [x19]'),
    )
    check(cache.read, anchors)

    routes = {}
    windows = [(0x184ebd698, 0x244)]
    for request, stub, send, literal, id_check, size_check, user_size, _, _ in ROUTES:
        assert struct.unpack('<II', cache.read(literal, 8)) == (0, request)
        check(cache.read, ((send, 'bl', '#0x188088af0'),
                           (id_check, 'cmp', f'w8, #{request + 100:#x}'),
                           (size_check, 'cmp', f'w8, #{user_size:#x}')))
        routes[request] = {'stub': hex(stub), 'send': hex(send), 'reply_id': request + 100,
                           'reply_success_bytes': user_size, 'literal': hex(literal)}
        windows.append((stub, size_check + 0x48 - stub))
    return {'cache_uuid': cache.uuid, 'iokit_uuid': io.uuid, 'libkernel_uuid': libkernel.uuid,
            'routes': routes, 'veneers': veneers, 'chroot_flag_pointer': clean_pointer(compatibility),
            'on_disk_flag_bytes': {'serialization': 1, 'chrooted': 0},
            'windows': record_windows(cache.read, windows)}


def kernel(image):
    table = int(mig_map(image)['subsystem'], 16)
    stubs = {}
    windows = [(0xfffffe000c5bbf6c, 0x23c), (0xfffffe000c5bc984, 0x45c)]
    for route, argument_count, size in zip(ROUTES, (4, 6, 9), (0x168, 0x1f0, 0x200)):
        request, *_, kc_stub, kc_size = route
        slot = table + 40 + 32 * (request - 2800)
        pointer = image.pointer(slot)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (hex(kc_stub), 1, '0x3a83')
        assert struct.unpack('<4I', image.read(slot + 8, 16)) == (argument_count, 0, 1, kc_size)
        stubs[request] = {**pointer, 'reply_success_bytes': kc_size}
        windows.append((kc_stub, size))
    calls = {
        0xfffffe000be862a4: 0xfffffe000be7e18c, 0xfffffe000be862b8: 0xfffffe000c5bbf6c,
        0xfffffe000be801b4: 0xfffffe000be7e18c, 0xfffffe000be801d8: 0xfffffe000c5bc984,
        0xfffffe000be7f294: 0xfffffe000be7e18c, 0xfffffe000be7f2c0: 0xfffffe000c5bc984,
        0xfffffe000c5bc10c: 0xfffffe000be19754, 0xfffffe000c5bcca4: 0xfffffe000be19754,
        0xfffffe000c5bcc2c: 0xfffffe000bec09cc, 0xfffffe000bd0f208: 0xfffffe000bd0fbf0,
    }
    for pc, target in calls.items():
        assert image.branch(pc, 'bl') == target
    assert image.named('_copyout') == calls[0xfffffe000c5bcc2c]
    assert image.named('__ZN11OSSerialize18binaryWithCapacityEjPvS0_') == 0xfffffe000c4d7840
    anchors = (
        (0xfffffe000be7e1c4, 'cmp', 'w8, #0x28'),
        (0xfffffe000be801d0, 'mov', 'x4, #0'),
        (0xfffffe000be801d4, 'mov', 'x5, #0'),
        (0xfffffe000be86310, 'stur', 'x17, [x22, #0x24]'),
        (0xfffffe000be80260, 'stur', 'x17, [x23, #0x24]'),
        (0xfffffe000be7f348, 'stur', 'x17, [x24, #0x24]'),
        (0xfffffe000be7f364, 'str', 'x8, [x23, #8]'),
        (0xfffffe000c5bcbe4, 'cmp', 'x10, x23'),
        (0xfffffe000c5bcbec, 'b.lo', '#0xfffffe000c5bcc60'),
        (0xfffffe000c5bcbf0, 'str', 'x23, [x9]'),
        (0xfffffe000c5bcbf4, 'str', 'wzr, [x10]'),
        (0xfffffe000c5bcbfc, 'str', 'xzr, [x9]'),
        (0xfffffe000c5bcc60, 'str', 'xzr, [x9]'),
        (0xfffffe000c5bcc64, 'str', 'w21, [x10]'),
        (0xfffffe000bd3c678, 'add', 'w8, w8, #0x64'),
    )
    for pc, mnemonic, operands in anchors:
        image.instruction(pc, mnemonic, operands)
    return {'identity': IDENTITIES[1], 'stubs': stubs,
            'calls': {hex(pc): hex(target) for pc, target in calls.items()},
            'windows': record_windows(image.read, windows)}


def archive(path):
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    counts = Counter(int(match[8]) for line in raw.decode().splitlines()
                     if (match := GUEST_MESSAGE.fullmatch(line)))
    assert counts.total() == 44
    for expected in (2877, 2977, 2881, 2981, 2802, 2902):
        assert counts[expected] == 1
    selected = {ident: counts[ident] for route in ROUTES for ident in (route[0], route[0] + 100)}
    assert not any(selected.values())
    return {'sha256': TRACE_SHA, 'header_count': counts.total(),
            'property_messages': selected, 'observed_messages': dict(counts)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    print(json.dumps({'daemon': daemon(args.daemon), 'framework': framework(),
                      'kernel': kernel(Collection(args.collection, IDENTITIES[1])),
                      'archive': archive(args.trace), 'native_property_exchange_observed': False},
                     indent=2, sort_keys=True))
