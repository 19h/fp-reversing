#!/usr/bin/env python3
"""Verify FPDI byte-table producers and conditional selector 26 caller edges."""

import argparse
import json
from pathlib import Path
import struct

from audit_live_fpdi_selector26_route import (
    POOL, SHA256, TABLE, UUID, ThinView, bindings, daemon_slices, digest,
    negative_adjust, selected_identity, selection, window,
)
from resolve_kernel_collection_interfaces import commands

BANK_WRITES = (
    (0x100074a28, 0x14b8, -0xef57, 0x9910, 0x128, 0x1005b1b40),
    (0x100074a3c, 0x378, -0xb0ff, 0xa2b3, 0x120, 0x1005bc230),
)
WINDOWS = {
    'upstream_dispatch': (0x100204aa0, 0x100204b0c),
    'bank_producer': (0x1000748fc, 0x100074a64),
    'same_cells_reversed': (0x1000f1718, 0x1000f1778),
    'nonnull_initialization': (0x1001523f8, 0x10015245c),
    'nonnull_comparison': (0x100147ce8, 0x100147d80),
    'state_forwarding': (0x10007c2a8, 0x10007c340),
    'second_helper': (0x100072a88, 0x100072b60),
    'third_helper': (0x100012da8, 0x100012eb8),
    'next_record_consumer': (0x100017b8c, 0x100017c3c),
    'table_restore': (0x100054cac, 0x100054d1c),
    'immediate_dispatch_candidate': (0x1001286d8, 0x100128748),
    'record_call_and_return': (0x1000503c4, 0x1000504b8),
    'result_comparison': (0x100152828, 0x1001528a8),
}


def section_const(thin):
    for start, command, _ in commands(thin, 0):
        if command != 0x19:
            continue
        count = struct.unpack_from('<I', thin, start + 64)[0]
        for offset in range(start + 72, start + 72 + 80 * count, 80):
            name, segment, address, size, file_offset = struct.unpack_from(
                '<16s16sQQI', thin, offset)
            if (name.rstrip(b'\0'), segment.rstrip(b'\0')) == (b'__const', b'__TEXT'):
                return address, thin[file_offset:file_offset + size]
    raise ValueError('missing __TEXT,__const')


def bank_catalog(start, data):
    """Index every contiguous 256 B permutation, including unaligned windows."""
    counts = [0] * 256
    for value in data[:255]:
        counts[value] += 1
    unique = sum(count > 0 for count in counts)
    catalog = {}
    for end in range(255, len(data)):
        value = data[end]
        unique += counts[value] == 0
        counts[value] += 1
        begin = end - 255
        if unique == 256:
            catalog.setdefault(data[begin:end + 1], []).append(start + begin)
        value = data[begin]
        counts[value] -= 1
        unique -= counts[value] == 0
    return catalog


def slot_record(image, fixups, index, modifier, target):
    slot = TABLE + 8 * index
    binding = fixups[slot]
    assert binding == f'auth-rebase 0x{target:X} (div=0x{modifier:04X} ad=0 key=IA)'
    return {'index': hex(index), 'slot': hex(slot), 'word': image.read(slot, 8).hex(),
            'binding': binding}


def inspect(daemon):
    _, _, thin = next(row for row in daemon_slices(daemon.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == UUID and digest(thin) == SHA256
    image = ThinView(thin)
    fixups = bindings(daemon, '-arch', 'arm64e')
    check = image.instruction
    check(0x10007492c, 'adrp', 'x21, #0x1005e7000')
    check(0x100074930, 'add', 'x21, x21, #0xc80')
    writes = []
    for pc, offset, low, high, cell, bank in BANK_WRITES:
        check(pc, 'ldr', f'x9, [x21, #{offset:#x}]')
        check(pc + 4, 'mov', f'x10, #{low:#x}')
        check(pc + 8, 'movk', f'x10, #{high:#x}, lsl #16')
        check(pc + 12, 'add', 'x9, x9, x10')
        check(pc + 16, 'str', f'x9, [sp, #{cell:#x}]')
        slot = 0x1005e7c80 + offset
        kind, encoded = fixups[slot].split()
        assert kind == 'rebase'
        adjust = negative_adjust(low, high)
        assert int(encoded, 16) + adjust == bank
        writes.append({'store': hex(pc + 16), 'sp_offset_bytes': cell, 'bank': hex(bank),
                       'slot': hex(slot), 'rebase': encoded, 'adjustment': adjust})
    checks = (
        (0x100074994, 'stur', 'x12, [x29, #-0xc8]'),
        (0x100050468, 'ldr', 'x11, [sp, #0x128]'),
        (0x100050474, 'mov', 'w12, #0xd6'),
        (0x10005047c, 'ldr', 'x12, [sp, #0x120]'),
        (0x10005048c, 'mov', 'w9, #0x4d3f'),
        (0x100050494, 'ldr', 'x8, [x26, w8, uxtw #3]'),
        (0x1000504a0, 'blraa', 'x8, x17'),
        (0x1000504a8, 'ldur', 'w21, [x29, #-0x7c]'),
        (0x1000504ac, 'ldr', 'x8, [x16, w20, sxtw #3]'),
        (0x100054d00, 'ldur', 'x26, [x29, #-0xc8]'),
        (0x100128734, 'ldr', 'x8, [x26, w8, sxtw #3]'),
        (0x100128744, 'braa', 'x8, x17'),
    )
    for pc, mnemonic, operands in checks:
        check(pc, mnemonic, operands)
    check(0x1000f1758, 'str', 'x8, [sp, #0x120]')
    check(0x1000f176c, 'str', 'x8, [sp, #0x128]')
    check(0x100074990, 'mov', 'w0, #0x10')
    check(0x100072af8, 'mov', 'w0, #0x20')
    check(0x100012e88, 'str', 'x0, [x25, #0x18]')
    check(0x100017b90, 'ldr', 'x17, [x7, #0x18]')

    banks = tuple(row[-1] for row in BANK_WRITES)
    selections = {
        'adapter': selection(image, fixups, banks, 0xd6, 0x4d3f, TABLE, 0x1001f7e68),
        'reversed_order': selection(
            image, fixups, banks[::-1], 0xd6, 0x4d3f, TABLE, 0x100201afc),
        '16B_helper': selection(
            image, fixups, (0x1005b1a40, 0x1005bc030), 0x2e, 0x4c3d, TABLE, 0x10020b5f0),
        '32B_helper': selection(
            image, fixups, (0x10057a1e0, 0x1005a5e90), 0xdb, 0x4cae, TABLE, 0x10020b5f0),
        'third_helper': selection(image, fixups, banks, 5, 0x4c35, TABLE, 0x10020b5f0),
    }
    assert selections['adapter']['binding'].endswith('(div=0x132E ad=0 key=IA)')
    assert selections['reversed_order']['binding'].endswith('(div=0xAA88 ad=0 key=IA)')
    for name in ('16B_helper', '32B_helper', 'third_helper'):
        assert selections[name]['binding'].endswith('(div=0xD2EA ad=0 key=IA)')
    start, data = section_const(thin)
    catalog = bank_catalog(start, data)
    compatible = {slot: row for slot, row in fixups.items()
                  if row.endswith('(div=0x132E ad=0 key=IA)')
                  and 0x4d3f <= (slot - TABLE) // 8 <= 0x4e3e}
    assert sorted(compatible) == [0x1005e7990, 0x1005e7a38, 0x1005e7a50, 0x1005e7a70]
    matches = []
    for slot in sorted(compatible):
        constant = (slot - TABLE) // 8 - 0x4d3f
        for left, starts in catalog.items():
            required = bytearray(256)
            for value, mapped in enumerate(left):
                required[mapped ^ 0xd6] = value ^ constant
            for left_start in starts:
                for right_start in catalog.get(bytes(required), ()):
                    matches.append((slot, left_start, right_start))
    assert matches == [(0x1005e7990, *banks)]
    windows = {name: window(image, start, stop) for name, (start, stop) in WINDOWS.items()}
    return {
        'uuid': UUID, 'sha256': SHA256, 'bank_writes': writes, 'selections': selections,
        'constant_section': {'start': hex(start), 'size_bytes': len(data),
                             'windows_tested': len(data) - 255,
                             'permutation_windows': sum(map(len, catalog.values())),
                             'matches': [list(map(hex, row)) for row in matches]},
        'compatible_slots': {hex(slot): row for slot, row in compatible.items()},
        'windows': windows, 'instruction_count': sum(map(len, windows.values())),
        'conditional_edges': conditional_edges(image, fixups),
        'native_request_observed': False,
    }


def conditional_edges(image, fixups):
    # State at the producer and ordinary nonnull returns through the three helper calls.
    w19 = 0x1410
    w20 = (w19 - 0x11f6) | 0x400
    w22 = w19 - 0x12d7
    produced = w19 ^ ((w20 - 0x50f) ^ w22)
    w8 = (w20 ^ 0x61f) * 0x6f1
    w9 = (w8 ^ 0x22b0) * 0x679
    w23 = (w9 + 0x7b96dd5e) & 0x84692a6f
    word = w23 ^ ((0x39164ac9 - 0x574) ^ (0x39166d7e - 4))
    assert word == 4
    index = w9 ^ ((w9 ^ 0x96fcf98b) ^ (0x96fcc1ac + 0xfb1))
    w20_32 = (w23 - 0x576) ^ 0x6827
    third_state = 3 * (w20_32 ^ 0x4b05)
    # Separate immediate caller candidate and the adapter result continuation.
    caller_state = (0xc0d + 0xe6d3392) & 0xf192fdeb
    assert caller_state + 0x202 == 0x3f8d
    assert (caller_state << 4) ^ 0x3cca0 == w19
    assert (0xc1a + 0xe6d3392) & 0xf192fdeb == 0x3da8
    assert 0xc0d ^ 0x17 == 0xc1a
    expected_result = (0x965c5dd5 + ((w19 + 0x917499a9) & 0x6e8b537f) - 0x139)
    assert expected_result == 0x965c5dd5
    edges = (
        (0x100074a60, w19, 0x1210, 0x10011e544),
        (0x100074a60, produced, 0x1210, 0x1001523f8),
        (0x100152458, w20, 0x50e7, 0x100147ce8),
        (0x100147d7c, w8 - 0xee6, 0x30f7, 0x10007c2a8),
        (0x10007c33c, index, 0x681d, 0x100072a88),
        (0x100072b5c, w23 ^ (w20_32 - 0x4a7c), 0xdb4e, 0x100012da8),
        (0x100012eb4, w20_32, 0x73bf, 0x1000c70b0),
        (0x1000c71e8, third_state + 0x2d99, 0x00e4, 0x100017b8c),
        (0x100054d18, 0x2a4c, 0xc52f, 0x1001286d8),
        (0x100128744, 0xc0d, 0x20cd, 0x1000503c4),
        (0x100128744, 0xc1a, 0x20cd, 0x100146cdc),
        (0x1000504b4, caller_state, 0xae07, 0x100152828),
        (0x1001528a4, w19, 0x1210, 0x10011e544),
        (0x1001528a4, w19 ^ 0x557e, 0x1210, 0x1000304f4),
    )
    records = []
    for pc, index, modifier, target in edges:
        image.instruction(pc - 4, 'mov', f'x17, #{modifier:#x}')
        records.append({'branch': hex(pc), **slot_record(image, fixups, index, modifier, target)})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.daemon), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
