#!/usr/bin/env python3
"""Verify the Arcade registration and subscription handoff in the current fileset."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

from audit_archived_iokit_open_retirement import GUEST_MESSAGE, THIN_SHA, TRACE_SHA
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_fairplay_adid_ipc import ThinView
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair, words

SUBSYSTEM = 0xfffffe0007e748d8
REGISTRY_SLOT = 0xfffffe000caff0a0
REGISTRATION_OBJECT = 0xfffffe0007e68540
PENDING = 0xfffffe000cbdbe10
ENDPOINT = 0xfffffe000cbdbe18
HOST_SLOT = 0xfffffe000cb4c340
ARCADE_RECEIVER = 0x1000053c8
SUBSCRIPTION_RECEIVER = 0x1000054d8
REGISTRATION_CLIENT = 0x1000043b4
INITIALIZER = 0xfffffe000c679074
SUBSCRIPTION = 0xfffffe000bdda298
REGISTER = 0xfffffe000bd29758
HANDOFF = 0xfffffe000bd29958
EVENT = 0xfffffe000bd29e80
SEND = 0xfffffe000bd3d4d0


def kernel_audit(image, previous):
    bounds = compiler_ranges(image)
    lookup = image.pointer(SUBSYSTEM)
    stub = image.pointer(SUBSYSTEM + 40)
    registry = image.pointer(REGISTRY_SLOT)
    assert (int(lookup['target'], 0), int(stub['target'], 0)) == (0xfffffe000bdda4f4, 0xfffffe000bdda404)
    assert (lookup['auth'], lookup['key'], lookup['diversity']) == (1, 0, '0x423')
    assert (stub['auth'], stub['key'], stub['diversity']) == (1, 0, '0x3a83')
    assert int(registry['target'], 0) == SUBSYSTEM and registry['auth'] == 0
    table = image.read(SUBSYSTEM, 64)
    assert struct.unpack_from('<III', table, 8) == (51471, 51472, 44)
    needle = struct.pack('<II', 51471, 51472)
    offset = image.data.find(needle)
    assert offset == image.offset(SUBSYSTEM + 8, len(needle))
    assert image.data.find(needle, offset + 1) == -1

    for address, size in ((REGISTRATION_OBJECT, 8), (PENDING, 4), (ENDPOINT, 8), (HOST_SLOT, 8)):
        assert image.read(address, size) == bytes(size)
    assert address_pair(image, 0xfffffe000c679120, 'x19') == REGISTRATION_OBJECT
    assert address_pair(image, 0xfffffe000bd29ac8, 'x0') + 16 + 8 * 31 == HOST_SLOT
    assert address_pair(image, 0xfffffe000bd29ac8, 'x0') == address_pair(
        image, image.named('_host_priv_self') + 4, 'x0')
    assert address_pair(image, 0xfffffe000bd29b80, 'x2') == ENDPOINT
    assert address_pair(image, 0xfffffe000bd29870, 'x1') == ENDPOINT
    assert address_pair(image, 0xfffffe000bd29a10, 'x11') == PENDING - 8

    picks = (
        (0xfffffe000bd29ee4, 'ldr', 'w10, [x19, #0x43c]'),
        (0xfffffe000bd29ee8, 'orr', 'w8, w8, w10'),
        (0xfffffe000bd29f1c, 'tbnz', 'w21, #0xb, #0xfffffe000bd29f78'),
        (0xfffffe000bd29f80, 'ldclr', 'w9, w8, [x8]'),
        (0xfffffe000bd29f7c, 'mov', 'w9, #0x800'),
        (0xfffffe000bd29a88, 'ldr', 'x0, [x22, #0xe18]'),
        (0xfffffe000bd29aa8, 'str', 'w25, [x23, #0xe10]'),
        (0xfffffe000bd29ad0, 'mov', 'w2, #0x1f'),
        (0xfffffe000bd3a4e4, 'ubfiz', 'x9, x22, #3, #0x20'),
        (0xfffffe000bd3a4fc, 'ldr', 'x16, [x17]'),
        (0xfffffe000bd3a578, 'str', 'x8, [x21]'),
        (0xfffffe000bd29af8, 'ldr', 'x17, [x8, #0x540]'),
        (0xfffffe000bd29b10, 'str', 'w25, [sp, #0x5c]'),
        (0xfffffe000bd29b20, 'stur', 'x17, [sp, #0x60]'),
        (0xfffffe000bd29b24, 'mov', 'w8, #0x130000'),
        (0xfffffe000bd29b28, 'str', 'w8, [sp, #0x68]'),
        (0xfffffe000bd29b38, 'stur', 'x27, [sp, #0x44]'),
        (0xfffffe000bd29b3c, 'mov', 'w8, #0xa1ff'),
        (0xfffffe000bd29b48, 'mov', 'w1, #0x34'),
        (0xfffffe000bd29b50, 'movk', 'w2, #5, lsl #16'),
        (0xfffffe000bd29ba0, 'str', 'wzr, [x23, #0xe10]'),
        (0xfffffe000c67912c, 'mov', 'w1, #0x12b'),
        (0xfffffe000c67913c, 'stlr', 'x0, [x19]'),
        (0xfffffe000bd3c9c4, 'and', 'x8, x20, #0xff'),
        (0xfffffe000bd3c9cc, 'eor', 'x8, x8, x9'),
        (0xfffffe000bd3c9d8, 'str', 'x17, [x19, #0x50]'),
        (0xfffffe000bdda4f8, 'ldr', 'w8, [x0, #0x1c]'),
        (0xfffffe000bdda4fc, 'mov', 'w9, #0xc90f'),
        (0xfffffe000bdda508, 'add', 'x16, x16, #0x404'),
        (0xfffffe000bdda420, 'cmp', 'w8, #0x34'),
        (0xfffffe000bdda4d8, 'cmp', 'w8, #0x2b'),
        (0xfffffe000bdda4e4, 'movk', 'x17, #0x71, lsl #48'),
        (0xfffffe000bdda4a8, 'str', 'w0, [x19, #8]'),
        (0xfffffe000bd29828, 'ldr', 'w8, [x8, #0xe10]'),
        (0xfffffe000bd29848, 'str', 'x20, [x23, #0xe18]'),
        (0xfffffe000bd298ec, 'mov', 'w0, #0'),
        (0xfffffe000bd29c5c, 'mov', 'w3, #0x1000'),
        (0xfffffe000bd29cac, 'mov', 'w2, #0x1000'),
        (0xfffffe000bdda2f0, 'stp', 'w8, w2, [sp, #0x2c]'),
        (0xfffffe000bdda300, 'str', 'w2, [sp, #0x3c]'),
        (0xfffffe000bdda304, 'str', 'x3, [sp, #0x40]'),
        (0xfffffe000bdda328, 'mov', 'w1, #0x48'),
        (0xfffffe000bdda32c, 'mov', 'w2, #0x38'),
        (0xfffffe000bdda350, 'mov', 'w9, #0xf083'),
        (0xfffffe000bdda3f8, 'str', 'w8, [x19]'),
    )
    for address, mnemonic, operands in picks:
        image.instruction(address, mnemonic, operands)
    calls = {
        0xfffffe000bd29f84: HANDOFF,
        0xfffffe000bd29ad4: image.named('_host_get_special_port'),
        0xfffffe000bd29b5c: SEND,
        0xfffffe000bd3d578: 0xfffffe000bd0effc,
        0xfffffe000bd29b68: image.named('_ipc_port_release_send'),
        0xfffffe000bd29b90: image.named('_lck_mtx_sleep_deadline'),
        0xfffffe000c679138: 0xfffffe000bd3c950,
        0xfffffe000bdda4a4: REGISTER,
        0xfffffe000bd29844: image.named('_ipc_port_release_send'),
        0xfffffe000bd298e8: 0xfffffe000bdb6120,
        0xfffffe000bd29cb0: SUBSCRIPTION,
        0xfffffe000bdda33c: 0xfffffe000bd3d8d4,
        0xfffffe000bd3da9c: 0xfffffe000bd0effc,
        0xfffffe000bd29ce0: image.named('_ipc_port_release_send'),
    }
    for pc, target in calls.items():
        assert image.branch(pc, 'bl') == target
    assert image.read(0xfffffe000700dc10, 8) == struct.pack('<II', 0x80001513, 0)
    assert image.read(0xfffffe000700dee0, 8) == struct.pack('<II', 0, 61471)
    literals = {0xfffffe000704a930: 'com.apple.arcade.fpsd',
                0xfffffe00070eea57: 'arcade: received register request',
                0xfffffe00070eea79: 'arcade: subscription validation upcall returned %#x'}
    for address, value in literals.items():
        assert image.read(address, len(value) + 1) == value.encode() + b'\0'
    functions = {}
    for address in (REGISTER, HANDOFF, EVENT, SUBSCRIPTION, INITIALIZER, SEND, 0xfffffe000bd3a480,
                    0xfffffe000bdda4f4, 0xfffffe000bdda404):
        ordinal, end = bounds[address]
        data = image.read(address, end - address)
        functions[hex(address)] = {'ordinal': ordinal, 'end': hex(end), 'sha256': sha256(data).hexdigest(),
                                   'instructions': words(image, address, len(data))}

    old_ranges = {int(row['start'], 16): row for row in previous['kernel']['ranges']}
    correspondence = {}
    for base in (REGISTER, HANDOFF, SUBSCRIPTION, 0xfffffe000bdda4f4, 0xfffffe000bdda404):
        older = old_ranges[base - 0x47ef4]
        new = functions[hex(base)]
        assert len(older['instructions']) == len(new['instructions'])
        matches = sum(left['mnemonic'] == right['mnemonic']
                      for left, right in zip(older['instructions'], new['instructions'], strict=True))
        assert matches == len(new['instructions'])
        correspondence[hex(base)] = {'earlier_start': older['start'], 'earlier_sha256': older['sha256'],
                                     'same_mnemonic_count': matches, 'instruction_count': len(new['instructions'])}
    return {'collection': IDENTITIES[1], 'compiler_functions': functions, 'instruction_assertions': len(picks),
            'call_edges': {hex(pc): hex(target) for pc, target in calls.items()}, 'literals': literals,
            'subsystem_data': table.hex(), 'subsystem_file_offset': hex(offset - 8),
            'subsystem_fixups': [registry, lookup, stub], 'earlier_range_comparison': correspondence,
            'initial_data': {hex(addr): image.read(addr, size).hex() for addr, size in
                             ((REGISTRATION_OBJECT, 8), (PENDING, 4), (ENDPOINT, 8), (HOST_SLOT, 8))}}


def daemon_audit(installed, reference, previous):
    old_blob = reference.read_bytes()
    assert sha256(old_blob).hexdigest() == THIN_SHA
    selected, = (row for row in installed_slices(installed) if row['arch'] == 'arm64e')
    assert selected['uuid'] == '204741e9-b89f-32b4-9321-51f3975c7cac'
    offset = selected['file_offset_bytes']
    blob = installed.read_bytes()[offset:offset + selected['slice_size_bytes']]
    assert sha256(blob).hexdigest() == selected['sha256']
    current, old = ThinView(blob), ThinView(old_blob)
    checked = []
    for row in previous['ranges']:
        start, end = int(row['start'], 16), int(row['end'], 16)
        raw = current.read(start, end - start)
        assert raw == old.read(start, len(raw)) == bytes.fromhex(row['bytes'])
        assert sha256(raw).hexdigest() == row['sha256']
        checked.append({'start': hex(start), 'end': hex(end), 'sha256': row['sha256']})
    assert {ARCADE_RECEIVER, SUBSCRIPTION_RECEIVER, REGISTRATION_CLIENT} <= {int(row['start'], 16) for row in checked}
    for row in previous['native_instruction_checks']:
        assert current.read(int(row['address'], 16), 4).hex() == row['bytes']
    return {'selected_slice': selected, 'reference_sha256': THIN_SHA, 'range_matches': checked,
            'instruction_matches': len(previous['native_instruction_checks'])}


def archive_audit(path):
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == TRACE_SHA
    ids = [int(match[8]) for line in raw.decode().splitlines() if (match := GUEST_MESSAGE.fullmatch(line))]
    assert len(ids) == 44 and not set(ids).intersection({41471, 41571, 51471, 51571, 61471, 61571})
    return {'trace_sha256': TRACE_SHA, 'messages_checked': len(ids), 'arcade_message_matches': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('collection', 'installed_daemon', 'reference_daemon', 'annotated_trace'):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    path = Path(__file__).with_name('created_port_contracts.json.zst')
    older = subprocess.check_output(['zstd', '-dcq', path])
    previous = json.loads(older)
    assert previous['kernel']['uuid'] == IDENTITIES[0][1]
    image = Collection(args.collection, IDENTITIES[1])
    print(json.dumps({'previous_audit_sha256': sha256(older).hexdigest(), 'kernel': kernel_audit(image, previous),
                      'daemon': daemon_audit(args.installed_daemon, args.reference_daemon, previous),
                      'archive': archive_audit(args.annotated_trace)}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
