#!/usr/bin/env python3
"""Verify the installed kernel's matching and iteration interfaces."""

import argparse
import ctypes
import json
import plistlib
import struct
import subprocess
from pathlib import Path

from audit_live_iokit_discovery import archived_discovery
from audit_live_iokit_mach_transport import CACHE_UUID, IOKIT, LIBKERNEL, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map

SERVICE_CLASS = 'com_apple_driver_FairPlayIOKit'
BUILD = '26C5035r'
MATCHING_IDS = (2881, 2802)


def installed_matching(image):
    subsystem = int(mig_map(image)['subsystem'], 16)
    routines = {}
    for message_id, target, fields in (
        (2881, 0xfffffe000be7fe24, (4, 0, 1, 52)),
        (2802, 0xfffffe000be8651c, (2, 0, 1, 52)),
    ):
        record = subsystem + 0x20 + (message_id - 2800) * 32
        pointer = image.pointer(record + 8)
        assert (pointer['format'], pointer['auth'], pointer['diversity']) == (8, 1, '0x3a83')
        assert int(pointer['target'], 16) == target
        assert struct.unpack('<4I', image.read(record + 16, 16)) == fields
        routines[message_id] = {'record': hex(record), 'stub': pointer, 'fields': fields}

    symbols = {}
    for name, address in (
        ('__Z16OSUnserializeXMLPKcmPP8OSString', 0xfffffe000c4d776c),
        ('__ZN12OSDictionary10gMetaClassE', 0xfffffe000cbcddf8),
        ('__ZN9IOService19getMatchingServicesEP12OSDictionary', 0xfffffe000c53bd24),
        ('__ZN14IOUserIterator10gMetaClassE', 0xfffffe000cbd77d0),
        ('__ZN10OSIterator10gMetaClassE', 0xfffffe000cbd77f8),
        ('__ZTV14IOUserIterator', 0xfffffe0007f5cd18),
    ):
        assert image.named(name) == address
        symbols[name] = hex(address)

    vtable = image.named('__ZTV14IOUserIterator') + 0x10
    slots = {}
    for offset, target, discriminator in (
        (0x28, image.named('__ZNK8OSObject7releaseEv'), '0x3a87'),
        (0xa8, 0xfffffe000c5af874, '0x4a6a'),
        (0x170, 0xfffffe000c5af550, '0xedb1'),
    ):
        pointer = image.pointer(vtable + offset)
        assert (pointer['format'], pointer['auth'], pointer['address_diversity']) == (8, 1, 1)
        assert pointer['diversity'] == discriminator and int(pointer['target'], 16) == target
        slots[hex(offset)] = pointer

    instructions = {}
    for pc, asm in (
        (0xfffffe000be7fe28, 'ldr w8, [x0]'),
        (0xfffffe000be7fe30, 'ldr w8, [x0, #4]'),
        (0xfffffe000be7fe48, 'ldr w9, [x1, #8]'),
        (0xfffffe000be7fe5c, 'and w9, w9, #0x3ffc'),
        (0xfffffe000be7fe60, 'add w9, w9, #0x2c'),
        (0xfffffe000be7fe68, 'b.eq #0xfffffe000be7fe84'),
        (0xfffffe000be7fea4, 'ldr d0, [x8, #0xe30]'),
        (0xfffffe000be7feac, 'stur d0, [x3, #0x2c]'),
        (0xfffffe000be7feb0, 'ldr x0, [x0, #8]'),
        (0xfffffe000be7feb4, 'ldr w2, [x1, #8]'),
        (0xfffffe000be7feb8, 'add x1, x1, #0xc'),
        (0xfffffe000be7fec0, 'bl #0xfffffe000c5b9628'),
        (0xfffffe000be7fee8, 'mov w1, #0x28'),
        (0xfffffe000be7feec, 'bl #0xfffffe000c5b07cc'),
        (0xfffffe000be7ff10, 'blraa x8, x16'),
        (0xfffffe000be7ff1c, 'movk x16, #0x1ab, lsl #48'),
        (0xfffffe000be7ff24, 'pacda x17, x16'),
        (0xfffffe000be7ff30, 'stur x17, [x21, #0x24]'),
        (0xfffffe000be7ff40, 'stp w8, w9, [x21]'),
        (0xfffffe000be7ff48, 'str w8, [x21, #0x20]'),
        (0xfffffe000c5b9650, 'cmp x0, x8'),
        (0xfffffe000c5b9674, 'bl #0xfffffe000c4d776c'),
        (0xfffffe000c5b96a8, 'add x8, x8, #0xdf8'),
        (0xfffffe000c5b96f8, 'blraa x8, x16'),
        (0xfffffe000c5b975c, 'blraa x8, x16'),
        (0xfffffe000c5b9764, 'bl #0xfffffe000c53bd24'),
        (0xfffffe000c5b97f0, 'str x16, [x0]'),
        (0xfffffe000c5b9824, 'blraa x8, x16'),
        (0xfffffe000c5b982c, 'str x20, [x21, #0x10]'),
        (0xfffffe000c5b9874, 'str x21, [x23]'),
        (0xfffffe000c4d77a4, 'bl #0xfffffe000c6b451c'),
        (0xfffffe000c4d77e0, 'b #0xfffffe000c4d8830'),
        (0xfffffe000be86564, 'bl #0xfffffe000be7e18c'),
        (0xfffffe000be86570, 'bl #0xfffffe000c5b9200'),
        (0xfffffe000be86598, 'blraa x8, x16'),
        (0xfffffe000be865d8, 'mov w1, #0x28'),
        (0xfffffe000be865dc, 'bl #0xfffffe000c5b07cc'),
        (0xfffffe000be86600, 'blraa x8, x16'),
        (0xfffffe000be86614, 'pacda x17, x16'),
        (0xfffffe000be86620, 'stur x17, [x21, #0x24]'),
        (0xfffffe000be86630, 'stp w8, w9, [x21]'),
        (0xfffffe000be86638, 'str w8, [x21, #0x20]'),
        (0xfffffe000be7e1c4, 'cmp w8, #0x28'),
        (0xfffffe000be7e1d0, 'ldr x16, [x17, #0x50]!'),
        (0xfffffe000be7e1d8, 'autda x16, x17'),
        (0xfffffe000c5b92bc, 'movk x16, #0xedb1, lsl #48'),
        (0xfffffe000c5b92c0, 'blraa x8, x16'),
        (0xfffffe000c5b9318, 'str x0, [x19]'),
        (0xfffffe000c5af580, 'casa x2, x8, [x10]'),
        (0xfffffe000c5af58c, 'ldr x0, [x19, #0x10]'),
        (0xfffffe000c5af5b4, 'blraa x8, x16'),
        (0xfffffe000c5af5d8, 'blraa x8, x16'),
        (0xfffffe000c5af5f0, 'casl w2, wzr, [x10]'),
        (0xfffffe000c5b08d8, 'cmp x16, x0'),
        (0xfffffe000c5b08e8, 'cmp w9, w20'),
        (0xfffffe000bd0d720, 'autda x16, x17'),
    ):
        i, = image.instructions(pc, 4)
        assert f'{i.mnemonic} {i.op_str}'.strip() == asm, hex(pc)
        instructions[hex(pc)] = {'bytes': i.bytes.hex(), 'instruction': asm}

    signature = image.read(0xfffffe000704562c, 4)
    trailer = image.read(0xfffffe000700de30, 8)
    assert signature == bytes.fromhex('d3000000')
    assert trailer == bytes.fromhex('0000110000000000')
    return {
        'identities': IDENTITIES[1], 'routines': routines, 'symbols': symbols,
        'iterator_vtable': slots, 'instructions': instructions,
        'binary_signature': signature.hex(), 'expanded_descriptor_suffix': trailer.hex(),
    }


def live_observation():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    kernel_extensions = subprocess.check_output(['kmutil', 'showloaded'], text=True)
    driver, = (line for line in kernel_extensions.splitlines()
               if 'com.apple.driver.FairPlayIOKit (' in line)
    assert IDENTITIES[1][2] in driver.lower()
    registry = plistlib.loads(subprocess.check_output(
        ['ioreg', '-a', '-r', '-c', SERVICE_CLASS, '-d', '1']))
    registry_by_id = {entry['IORegistryEntryID']: entry for entry in registry}

    io, kernel = ctypes.CDLL(IOKIT), ctypes.CDLL(LIBKERNEL)
    u32, u64 = ctypes.c_uint32, ctypes.c_uint64
    u32_out = ctypes.POINTER(u32)
    status = ctypes.c_int

    def bind(lib, name, result, *args):
        function = getattr(lib, name)
        function.restype = result
        function.argtypes = args
        return function

    task = u32.in_dll(kernel, 'mach_task_self_').value
    main_port = bind(io, 'IOMainPort', status, u32, u32_out)
    matching = bind(io, 'IOServiceMatching', ctypes.c_void_p, ctypes.c_char_p)
    match = bind(io, 'IOServiceGetMatchingServices', status, u32, ctypes.c_void_p, u32_out)
    next_service = bind(io, 'IOIteratorNext', u32, u32)
    get_id = bind(io, 'IORegistryEntryGetRegistryEntryID', status, u32, ctypes.POINTER(u64))
    get_class = bind(io, 'IOObjectGetClass', status, u32, ctypes.POINTER(ctypes.c_char))
    release = bind(io, 'IOObjectRelease', status, u32)
    deallocate = bind(kernel, 'mach_port_deallocate', status, u32, u32)
    port_type = bind(kernel, 'mach_port_type', status, u32, u32, u32_out)
    get_refs = bind(kernel, 'mach_port_get_refs', status, u32, u32, status, u32_out)

    def describe(name):
        types, count = u32(), u32()
        assert port_type(task, name, ctypes.byref(types)) == 0
        assert get_refs(task, name, 0, ctypes.byref(count)) == 0
        assert types.value & 0x10000 and count.value > 0
        return {'name': hex(name), 'type_bits': hex(types.value), 'send_user_refs': count.value}

    main, iterator = u32(), u32()
    assert main_port(0, ctypes.byref(main)) == 0 and main.value
    services = []
    try:
        dictionary = matching(SERVICE_CLASS.encode())
        assert dictionary
        assert match(main.value, dictionary, ctypes.byref(iterator)) == 0 and iterator.value
        try:
            main_right, iterator_right = describe(main.value), describe(iterator.value)
            while service := next_service(iterator.value):
                try:
                    entry, name = u64(), ctypes.create_string_buffer(128)
                    assert get_id(service, ctypes.byref(entry)) == 0
                    assert get_class(service, name) == 0 and name.value.decode() == SERVICE_CLASS
                    properties = registry_by_id[entry.value]
                    assert properties['CFBundleIdentifier'] == 'com.apple.driver.FairPlayIOKit'
                    selected = {key: properties[key] for key in (
                        'CFBundleIdentifier', 'IOClass', 'IOProviderClass', 'IOUserClientClass',
                    )}
                    assert selected['IOClass'] == SERVICE_CLASS
                    services.append({
                        'right': describe(service), 'registry_id': hex(entry.value),
                        'properties': selected,
                    })
                finally:
                    release_status = release(service)
                    assert release_status == 0
        finally:
            release_status = release(iterator.value)
            assert release_status == 0
    finally:
        release_status = deallocate(task, main.value)
        assert release_status == 0
    assert services
    return {
        'build': BUILD, 'cache_uuid': CACHE_UUID, 'main': main_right, 'iterator': iterator_right,
        'services': services, 'caller': 'Read-only verifier process',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    kernel = installed_matching(Collection(args.collection, IDENTITIES[1]))
    trace = archived_discovery(args.trace)
    pairs = []
    for row in trace['transactions']:
        request = bytes.fromhex(row['send_hex'])
        if int.from_bytes(request[20:24], 'little') in MATCHING_IDS:
            pairs.append(row)
        if row['send_line'] == 1699:
            assert request[36:40].hex() == kernel['binary_signature']
    assert len(pairs) == 2
    result = {'kernel': kernel, 'archived': {'sha256': trace['trace_sha256'], 'pairs': pairs}}
    if args.observe:
        result['current_observation'] = live_observation()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
