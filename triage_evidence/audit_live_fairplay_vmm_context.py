#!/usr/bin/env python3
"""Verify the environmental query used by fairplayd's IOKit class selection."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess

from audit_live_iokit_discovery import archived_discovery
from audit_live_iokit_mach_transport import record_windows
from audit_live_iokit_main_port import BUILD
from audit_live_kext_selector26 import CS, Collection, IDENTITIES
from resolve_kernel_collection_interfaces import macho

NAME = 'kern.hv_vmm_present'
PROPERTY = 'vmm-present'
DAEMON_DIGEST = '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
DAEMON_UUID = '204741e9-b89f-32b4-9321-51f3975c7cac'


def installed(image):
    oid = 0xfffffe0007f2fd08
    number, kind = struct.unpack('<iI', image.read(oid + 16, 8))
    assert (number, kind) == (-1, 0x11e00002)
    assert image.read(oid + 24, 16) == b'\0' * 16
    bindings = {}
    for field, offset, target in (
        ('parent', 0, image.named('_sysctl__kern_children')),
        ('name', 40, 0xfffffe00070c0b92),
        ('handler', 48, 0xfffffe000c3c5ff4),
        ('format', 56, 0xfffffe00070ec63d),
    ):
        pointer = image.pointer(oid + offset)
        assert int(pointer['target'], 16) == target
        bindings[field] = pointer
    assert (bindings['handler']['auth'], bindings['handler']['diversity']) == (1, '0xe2e')
    for address, value in ((0xfffffe00070c0b92, 'hv_vmm_present'),
                           (0xfffffe00070ec63d, 'I'), (0xfffffe00070c0bb2, PROPERTY),
                           (0xfffffe00070eb914, '/defaults')):
        assert image.read(address, len(value) + 1) == value.encode() + b'\0'
    assert image.named('_gIODTPlane') == 0xfffffe000cbd8450
    assert image.named('__ZN6OSData10gMetaClassE') == 0xfffffe000cbcddd0
    for cls, slot, symbol, diversity in (
        ('15IORegistryEntry', 0x2d8, '__ZNK15IORegistryEntry11getPropertyEPKc', '0x37a5'),
        ('6OSData', 0x160, '__ZNK6OSData9getLengthEv', '0xbb9b'),
        ('6OSData', 0x198, '__ZNK6OSData14getBytesNoCopyEv', '0xd240'),
    ):
        pointer = image.pointer(image.named('__ZTV' + cls) + 16 + slot)
        assert (pointer['target'], pointer['auth'], pointer['diversity']) == (
            hex(image.named(symbol)), 1, diversity)
        bindings[symbol] = pointer
    instructions = (
        (0xfffffe000c3c600c, 'str', 'wzr, [sp, #0xc]'),
        (0xfffffe000c3c6014, 'add', 'x0, x0, #0xbb2'),
        (0xfffffe000c3c601c, 'mov', 'w2, #4'),
        (0xfffffe000c3c6020, 'bl', '#0xfffffe000c50f4f8'),
        (0xfffffe000c3c6024, 'ldr', 'w8, [sp, #0xc]'),
        (0xfffffe000c3c602c, 'cset', 'w8, ne'),
        (0xfffffe000c3c6034, 'ldr', 'x8, [x19, #0x28]'),
        (0xfffffe000c3c6040, 'mov', 'w2, #4'),
        (0xfffffe000c3c6048, 'blraa', 'x8, x17'),
        (0xfffffe000c50f524, 'ldr', 'x1, [x8, #0x450]'),
        (0xfffffe000c50f52c, 'add', 'x0, x0, #0x914'),
        (0xfffffe000c50f53c, 'bl', '#0xfffffe000c5122e0'),
        (0xfffffe000c50f574, 'blraa', 'x8, x16'),
        (0xfffffe000c50f5a8, 'add', 'x8, x8, #0xdd0'),
        (0xfffffe000c50f5b0, 'b.eq', '#0xfffffe000c50f5c8'),
        (0xfffffe000c50f5e4, 'blraa', 'x8, x16'),
        (0xfffffe000c50f5e8, 'cmp', 'w0, w21'),
        (0xfffffe000c50f5ec, 'b.ls', '#0xfffffe000c50f628'),
        (0xfffffe000c50f648, 'blraa', 'x8, x16'),
        (0xfffffe000c50f650, 'mov', 'w2, w23'),
        (0xfffffe000c50f658, 'bl', '#0xfffffe000c697810'),
    )
    for pc, op, args in instructions:
        image.instruction(pc, op, args)
    return {'identity': IDENTITIES[1], 'oid': hex(oid), 'kind': hex(kind), 'compiled_number': number,
            'bindings': bindings, 'instruction_assertions': len(instructions),
            'windows': record_windows(image.read, ((0xfffffe000c3c5ff4, 0x68), (0xfffffe000c50f4f8, 0x16c)))}


def daemon_image(path):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DAEMON_DIGEST
    image = macho(raw, 0, 'daemon')
    assert image['uuid'] == DAEMON_UUID

    def read(address, size):
        seg = next(s for s in image['segments'] if s['address'] <= address and
                   address + size <= s['address'] + s['file_size'])
        offset = seg['file_offset'] + address - seg['address']
        return raw[offset:offset + size]

    literal = 0x100ecc5c0
    assert read(literal, len(NAME) + 1) == NAME.encode() + b'\0'
    for pc, op, args in (
        (0x10043df7c, 'mov', 'x3, #0'), (0x10043df80, 'mov', 'x4, #0'),
        (0x10043df88, 'blraa', 'x8, x17'), (0x100130b30, 'strb', 'w10, [x8]'),
        (0x1003609bc, 'strb', 'w8, [x19]'),
    ):
        instruction, = CS.disasm(read(pc, 4), pc)
        assert (instruction.mnemonic, instruction.op_str) == (op, args)
    return {'uuid': DAEMON_UUID, 'sha256': DAEMON_DIGEST, 'query_name_address': hex(literal),
            'file_backed_end': hex(max(s['address'] + s['file_size'] for s in image['segments'])),
            'windows': record_windows(read, ((0x10043df70, 0x24), (0x100130b20, 0x28), (0x1003609a4, 0x20)))}


def archived(path, daemon):
    evidence = archived_discovery(path)
    lines = path.read_text().splitlines()
    calls = []
    for line_number, line in enumerate(lines, 1):
        match = re.search(r'pc=(0x[0-9a-f]+) sysctl\(([^)]+)\) = ([-0-9]+)$', line)
        if match:
            calls.append((line_number, int(match[1], 16),
                          [int(item, 0) for item in match[2].split(', ')], int(match[3])))
    assert len(calls) == 15
    assert all(row[2][4] != int(daemon['query_name_address'], 16) for row in calls)
    first, = (row for row in calls if row[2][-1] == len(NAME) + 1)
    second, = (row for row in calls if row[0] == first[0] + 1)
    assert (first[0], second[0]) == (552, 553)
    assert first[1] == second[1] == 0x1010e64d4
    assert first[2][2] == second[2][0] and (first[2][1], second[2][1]) == (2, 4)
    assert first[3] == second[3] == 0
    assert int(daemon['file_backed_end'], 16) < first[2][4]
    assert not any('sysctlbyname(' in line for line in lines)
    return {'sha256': evidence['trace_sha256'], 'numeric_sysctl_count': len(calls),
            'name_length_candidate': {'line': first[0], 'trap_pc': hex(first[1]),
                                      'input_pointer': hex(first[2][4]), 'input_size_bytes': first[2][5],
                                      'following_line': second[0], 'following_mib_count': second[2][1]},
            'match': evidence['transactions'][2]}


def observe():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    lib = ctypes.CDLL(None)
    n, u = ctypes.c_int, ctypes.c_size_t
    lib.sysctlnametomib.argtypes = [ctypes.c_char_p, ctypes.POINTER(n), ctypes.POINTER(u)]
    lib.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(u), ctypes.c_void_p, u]
    lib.sysctl.argtypes = [ctypes.POINTER(n), ctypes.c_uint, ctypes.c_void_p,
                           ctypes.POINTER(u), ctypes.c_void_p, u]
    mib, count = (n * 12)(), u(12)
    name = NAME.encode()
    assert lib.sysctlnametomib(name, mib, ctypes.byref(count)) == 0
    assert mib[:count.value] == [1, 295]
    a, b = n(-1), n(-1)
    len_a, len_b = u(ctypes.sizeof(a)), u(ctypes.sizeof(b))
    assert lib.sysctlbyname(name, ctypes.byref(a), ctypes.byref(len_a), None, 0) == 0
    assert lib.sysctl(mib, count.value, ctypes.byref(b), ctypes.byref(len_b), None, 0) == 0
    assert (a.value, b.value, len_a.value, len_b.value) == (0, 0, 4, 4)
    # CTL_SYSCTL / OIDFMT returns the registered kind followed by the format string.
    format_mib = (n * 4)(0, 4, *mib[:count.value])
    metadata = ctypes.create_string_buffer(16)
    metadata_size = u(ctypes.sizeof(metadata))
    assert lib.sysctl(format_mib, len(format_mib), metadata, ctypes.byref(metadata_size), None, 0) == 0
    kind, fmt = struct.unpack('<I2s', metadata.raw[:metadata_size.value])
    assert (kind, fmt) == (0x11e00002, b'I\0')
    output = subprocess.check_output(['ioreg', '-a', '-l', '-p', 'IODeviceTree', '-r', '-n', 'defaults', '-d', '1'])
    node, = plistlib.loads(output)
    assert node['IORegistryEntryName'] == 'defaults' and PROPERTY not in node
    return {'mib': mib[:count.value], 'named_value': a.value, 'numeric_value': b.value,
            'registered_kind': hex(kind), 'registered_format': 'I', 'result_size_bytes': len_a.value, 'property_visible_at_defaults': PROPERTY in node}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('collection', 'daemon', 'trace'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    daemon = daemon_image(args.daemon)
    result = {'installed': installed(Collection(args.collection, IDENTITIES[1])), 'daemon': daemon,
              'archive': archived(args.trace, daemon), 'native_query': observe()}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
