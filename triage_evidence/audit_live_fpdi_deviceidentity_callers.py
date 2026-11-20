#!/usr/bin/env python3
"""Corroborate the protected, output-bearing DeviceIdentity call sites."""

import argparse
from bisect import bisect_right
import json
from pathlib import Path
from struct import iter_unpack, unpack_from

from audit_live_fpdi_selector26_caller import bank_catalog, section_const, slot_record
from audit_live_fpdi_selector26_route import TABLE
from audit_live_fpdi_startup import (
    SHA256, UUID, ThinView, bindings, commands, daemon_slices, digest, selected_identity, window,
)

CALLS = (
    (0x1000c8eb0, 0x4d61, 0xd6, 'x12', (0x480, 0x220, 0x204, 0x178, 0x474),
     ((0x1005b1b40, 0x1005bc230),)),
    (0x100174364, 0x4dd6, 0xdb, 'x1', (0x248, 0x3a0, 0x444, 0x278, 0x3b0),
     ((0x10057a1e0, 0x1005a5e90), (0x1005b3cf0, 0x1005542d0))),
)
TARGET = 0x100001130
INDEX = 0x4e04
MODIFIER = 0xf447
CHECKS = (
    (0x1000c8e5c, 'ldr', 'x20, [sp, #0x138]'),
    (0x1000c8e64, 'ldrb', 'w10, [x10]'),
    (0x1000c8e68, 'mov', 'w11, #0xd6'),
    (0x1000c8e6c, 'eor', 'w10, w10, w11'),
    (0x1000c8e74, 'ldr', 'x13, [sp, #0xb8]'),
    (0x1000c8e78, 'ldrb', 'w10, [x13, w10, uxtw]'),
    (0x1000c8e84, 'eor', 'w8, w9, w10'),
    (0x1000c8ea8, 'mov', 'w0, #0'),
    (0x1000c8eb4, 'ldr', 'x30, [sp, #0x168]'),
    (0x1000c8ec0, 'and', 'w8, w8, w0, lsl #1'),
    (0x1000c8ecc, 'sub', 'w8, w0, w8'),
    (0x1000c8ed0, 'add', 'w22, w8, w9'),
    (0x1000c8eec, 'mov', 'w9, #0x5091'),
    (0x1000c8ef8, 'eor', 'w8, w8, w25'),
    (0x1000c8efc, 'ldr', 'x8, [x30, w8, sxtw #3]'),
    (0x1000c8f00, 'mov', 'x17, #0xf330'),
    (0x1000c8f04, 'braa', 'x8, x17'),
    (0x100174310, 'add', 'x10, x24, w9, uxtb'),
    (0x100174314, 'ldrb', 'w10, [x10]'),
    (0x100174318, 'mov', 'w11, #0xdb'),
    (0x10017431c, 'eor', 'w10, w10, w11'),
    (0x100174320, 'ldrb', 'w10, [x20, w10, uxtw]'),
    (0x100174330, 'eor', 'w8, w9, w10'),
    (0x100174358, 'mov', 'w0, #0'),
    (0x10017436c, 'ldp', 'x5, x1, [sp, #0x160]'),
    (0x100174394, 'add', 'w9, w23, w9'),
    (0x100174398, 'lsl', 'w9, w0, w9'),
    (0x1001743a4, 'and', 'w9, w9, w10'),
    (0x1001743a8, 'subs', 'w9, w0, w9'),
    (0x1001743b0, 'cset', 'w9, eq'),
    (0x1001743bc, 'eor', 'w9, w9, w23'),
    (0x1001743c0, 'ldr', 'x9, [x1, w9, sxtw #3]'),
    (0x1001743c4, 'mov', 'x17, #0x3530'),
    (0x1001743c8, 'braa', 'x9, x17'),
    (0x1000106b4, 'add', 'x9, sp, #0x1f8'),
    (0x1000106b8, 'str', 'xzr, [x9, #0x288]'),
    (0x1000106bc, 'str', 'xzr, [x9, #0x28]'),
    (0x1000106c0, 'str', 'wzr, [sp, #0x204]'),
    (0x1000106c4, 'str', 'xzr, [sp, #0x178]'),
    (0x1000106c8, 'str', 'wzr, [sp, #0x474]'),
    (0x100152908, 'add', 'x11, sp, #0x1f8'),
    (0x10015290c, 'str', 'xzr, [x11, #0x50]'),
    (0x100152910, 'str', 'xzr, [x11, #0x1a8]'),
    (0x100152914, 'str', 'wzr, [sp, #0x444]'),
    (0x100152918, 'str', 'xzr, [x11, #0x80]'),
    (0x10015291c, 'str', 'wzr, [sp, #0x3b0]'),
    (0x100221018, 'add', 'x12, sp, #0x1f8'),
    (0x10022101c, 'ldr', 'x13, [x12, #0x288]'),
    (0x100221020, 'ldr', 'x8, [x12, #0x28]'),
    (0x100221028, 'ldr', 'w9, [sp, #0x204]'),
    (0x100221050, 'ldr', 'x9, [sp, #0x178]'),
    (0x100221058, 'ldr', 'w10, [sp, #0x474]'),
    (0x1002210e4, 'cmp', 'x13, #0'),
    (0x1002210e8, 'ccmp', 'x8, #0, #4, ne'),
    (0x1002210ec, 'ccmp', 'x9, #0, #4, ne'),
    (0x10022c444, 'add', 'x19, sp, #0x1f8'),
    (0x10022c448, 'ldr', 'x11, [x19, #0x50]'),
    (0x10022c44c, 'ldr', 'x12, [x19, #0x1a8]'),
    (0x10022c450, 'ldr', 'w13, [sp, #0x444]'),
)
WINDOWS = {
    'compiler_entry': (0x100002784, 0x100002848),
    'first_call_and_status': (0x1000c8e20, 0x1000c8f08),
    'second_call_and_status': (0x1001742e0, 0x1001743cc),
    'first_output_initializer': (0x1000106a4, 0x100010704),
    'second_output_initializer': (0x1001528ec, 0x100152960),
    'first_candidate_consumer': (0x100220ff8, 0x100221114),
    'second_candidate_consumer': (0x10022c3dc, 0x10022c554),
}


def function_starts(thin):
    location, = (offset for offset, kind, _ in commands(thin, 0) if kind == 0x26)
    offset, size = unpack_from('<II', thin, location + 8)
    starts = []
    address, delta, shift = 0x100000000, 0, 0
    for byte in thin[offset:offset + size]:
        delta |= (byte & 127) << shift
        if byte & 128:
            shift += 7
        elif delta:
            address += delta
            starts.append(address)
            delta, shift = 0, 0
        else:
            break
    return starts


def text_modifier_sites(thin):
    """Census unshifted MOVZ X17, #0xf447 immediately before BLRAA X8, X17."""
    for offset, kind, _ in commands(thin, 0):
        if kind != 0x19:
            continue
        count, = unpack_from('<I', thin, offset + 64)
        for section in range(offset + 72, offset + 72 + count * 80, 80):
            if thin[section:section + 32] != b'__text'.ljust(16, b'\0') + b'__TEXT'.ljust(16, b'\0'):
                continue
            base, size, file_offset = unpack_from('<QQI', thin, section + 32)
            words = iter_unpack('<I', memoryview(thin)[file_offset:file_offset + size])
            last = 0
            for index, (word,) in enumerate(words):
                if last == 0xd29e88f1 and word == 0xd73f0911:
                    yield base + 4 * index
                last = word


def matching_tables(catalog, key, constant):
    for left, starts in catalog.items():
        right = bytearray(256)
        for byte, mapped in enumerate(left):
            right[mapped ^ key] = byte ^ constant
        for first in starts:
            for second in catalog.get(bytes(right), ()):
                yield first, second


def candidate_return_edges():
    mask = (1 << 32) - 1
    first_state, second_state = 0x3b29, 0x3ba3
    compare_word = (((first_state - 0x2b51) & mask) | 0x2b49) ^ 0x965c769e
    encoded = [(status - ((status << 1) & 0x2cb8bbaa) + 0x965c5dd5) & mask
               for status in range(5)]
    assert compare_word not in encoded
    shift = (second_state - 0x1ab0) & 31
    residuals = [(status - ((status << shift) & 0x2cb8bbaa)) & mask
                 for status in range(5)]
    assert residuals[0] == 0 and all(residuals[1:])
    return {
        'first': {'w25': hex(first_state), 'encoded_statuses': list(map(hex, encoded)),
                  'compare_word': hex(compare_word), 'index': hex(first_state)},
        'second': {'w23': hex(second_state), 'shift': shift, 'residuals': list(map(hex, residuals)),
                   'index_for_status_1_through_4': hex(second_state)},
    }


def inspect(daemon):
    _, _, thin = next(row for row in daemon_slices(daemon.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == UUID and digest(thin) == SHA256
    image, fixups = ThinView(thin), bindings(daemon, '-arch', 'arm64e')
    for pc, mnemonic, operands in CHECKS:
        image.instruction(pc, mnemonic, operands)
    starts = function_starts(thin)
    modifier_sites = list(text_modifier_sites(thin))
    assert modifier_sites == [
        0x10002e7d8, 0x1000c8eb0, 0x100174364, 0x1001978b0, 0x100206378, 0x1002b41ec,
        0x1003b0274, 0x100535164, 0x10053a818, 0x10053a9c8,
    ]
    start, const = section_const(thin)
    catalog = bank_catalog(start, const)
    target_slot = TABLE + 8 * INDEX
    target = slot_record(image, fixups, INDEX, MODIFIER, TARGET)
    calls = {}
    for pc, bias, key, base_register, offsets, tables in CALLS:
        load = 0x1000c8e90 if pc == 0x1000c8eb0 else 0x10017433c
        image.instruction(load - 8, 'mov', f'w9, #{bias:#x}')
        image.instruction(load - 4, 'add', 'w8, w9, w8, uxtb')
        image.instruction(load, 'ldr', f'x8, [{base_register}, w8, uxtw #3]')
        for arg, offset in enumerate(offsets, 1):
            image.instruction(load + 4 * arg, 'add', f'x{arg}, sp, #{offset:#x}')
        image.instruction(pc - 4, 'mov', 'x17, #0xf447')
        image.instruction(pc, 'blraa', 'x8, x17')
        owner = bisect_right(starts, pc) - 1
        assert starts[owner:owner + 2] == [0x100002784, 0x1001f40fc]
        compatible = {
            slot: binding for slot, binding in sorted(fixups.items())
            if binding.endswith('(div=0xF447 ad=0 key=IA)')
            and bias <= (slot - TABLE) // 8 < bias + 256
        }
        matches = [
            (slot, left, right)
            for slot in compatible
            for left, right in matching_tables(catalog, key, (slot - TABLE) // 8 - bias)
        ]
        assert matches == [(target_slot, *pair) for pair in tables]
        for left, right in tables:
            a, b = image.read(left, 256), image.read(right, 256)
            assert {bias + (value ^ b[a[value] ^ key]) for value in range(256)} == {INDEX}
        calls[hex(pc)] = {
            'mode': 0, 'output_sp_offsets_bytes': offsets, 'table_base_register': base_register,
            'lookup_key': hex(key), 'index_bias': hex(bias),
            'compatible_fixups': {hex(slot): binding for slot, binding in compatible.items()},
            'fixed_slot_matches': [[hex(value) for value in match] for match in matches],
        }

    associated_slots = {
        'first_entry': slot_record(image, fixups, 0x4581, 0x121e, 0x1000c8e20),
        'second_entry': slot_record(image, fixups, 0x48b2, 0x67ce, 0x1001742e0),
        'first_initializer': slot_record(image, fixups, 0x827, 0x8ad9, 0x1000106a4),
        'second_initializer': slot_record(image, fixups, 0x2978, 0x406e, 0x1001528ec),
        'first_candidate_consumer': slot_record(image, fixups, 0x3b29, 0xf330, 0x100220ff8),
        'second_candidate_consumer': slot_record(image, fixups, 0x3ba3, 0x3530, 0x10022c3dc),
    }
    windows = {name: window(image, lo, hi) for name, (lo, hi) in WINDOWS.items()}
    return {
        'uuid': UUID, 'sha256': SHA256, 'anchor_checks': len(CHECKS),
        'modifier_sites': [hex(pc) for pc in modifier_sites],
        'const_bytes': len(const), 'permutation_windows': sum(map(len, catalog.values())),
        'compiler_starts': len(starts), 'shared_compiler_range': ['0x100002784', '0x1001f40fc'],
        'calls': calls, 'target': target, 'associated_slots': associated_slots,
        'candidate_return_edges': candidate_return_edges(),
        'windows': windows, 'instruction_count': sum(map(len, windows.values())),
        'native_dispatch_observed': False, 'continuous_path_verified': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.daemon), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
