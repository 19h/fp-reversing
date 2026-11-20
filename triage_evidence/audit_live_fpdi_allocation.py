#!/usr/bin/env python3
"""Resolve FPDI's allocation wrapper and selected imported calls from installed bytes."""

import argparse
import json
from pathlib import Path

from audit_live_fpdi_selector26_route import (
    POOL, SHA256, TABLE, UUID, ThinView, bindings, daemon_slices, digest,
    negative_adjust, selected_identity, selection, window,
)

BANKS = {
    'direct': (0x1005b1a40, 0x1005bc030),
    'first': (0x10057a0e0, 0x1005a5d90),
    'second': (0x1005bc130, 0x10057a2e0),
    'third': (0x1005b1b40, 0x1005bc230),
    'fourth': (0x10057a1e0, 0x1005a5e90),
}
SELECTIONS = (
    ('outer_global', 'direct', 0x2d, 0x18c, POOL, 0x1005ec218, (-0x1b3f, 0xad6d)),
    ('outer_state', 'first', 0x67, 0x139, POOL, 0x1005ec0a8, (-0x916f, 0xc066)),
    ('outer_null_gate', 'first', 0xfd, 0x1b5, POOL, 0x1005eddb0, (-0x878a, 0xaa44)),
    ('outer_stack_word', 'first', 0x6d, 0x2b, POOL, 0x1005ec0f8, (-0x4d6b, 0xc3ee)),
    ('dispatch_base', 'direct', 0x2d, 0xe0, POOL, TABLE, (-0x502b, 0xdde1)),
    ('outer_call', 'second', 0xda, 0x4ce0, TABLE, 0x10053c3ec, None),
    ('middle_state_one', 'third', 5, 0x153, POOL, 0x1005ed910, (-0x39ea, 0x95ae)),
    ('middle_state_two', 'second', 0x75, 0x143, POOL, 0x1005ec0a8, (-0x916f, 0xc066)),
    ('middle_stack_word', 'first', 0x67, 0x1f, POOL, 0x1005ec0f8, (-0x4d6b, 0xc3ee)),
    ('middle_call', 'fourth', 0x9f, 0x4d33, TABLE, 0x100539d2c, None),
    ('allocator_state_one', 'fourth', 0x9f, 0xc5, POOL, 0x1005ed0a0, (-0xed2b, 0xfb25)),
    ('allocator_state_two', 'second', 0xda, 0x13b, POOL, 0x1005ec0a8, (-0x916f, 0xc066)),
    ('arena_cells', 'third', 0xd6, 0x198, POOL, 0x1005edd60, (-0xde7b, 0xd8f4)),
    ('allocator_dispatch_base', 'second', 0xda, 0x161, POOL, TABLE, (-0x502b, 0xdde1)),
    ('contention_call', 'third', 0x9d, 0x4c31, TABLE, 'libSystem/_sched_yield', None),
    ('mapping_call', 'direct', 0x2d, 0x4d5a, TABLE, 'libSystem/_mmap', None),
)
CHECKS = (
    (0x10020b740, 'cbz', 'x1, #0x10020b85c'),
    (0x10020b79c, 'str', 'x1, [sp]'),
    (0x10020b83c, 'mov', 'x1, sp'),
    (0x10020b840, 'mov', 'x17, #0x7c87'),
    (0x10020b844, 'blraa', 'x8, x17'),
    (0x10020b854, 'mov', 'sp, x8'),
    (0x10020b85c, 'mov', 'x0, #0'),
    (0x10053c50c, 'ldr', 'x21, [x19]'),
    (0x10053c594, 'str', 'x15, [x20]'),
    (0x10053c64c, 'mov', 'x1, x20'),
    (0x10053c650, 'mov', 'x17, #0xe204'),
    (0x10053c654, 'blraa', 'x8, x17'),
    (0x10053c660, 'ubfiz', 'x8, x8, #4, #0x10'),
    (0x10053c664, 'str', 'x8, [x19]'),
    (0x100539d50, 'mov', 'x19, x0'),
    (0x100539e5c, 'add', 'x12, x12, #0xe0'),
    (0x100539e60, 'str', 'x12, [x1]'),
    (0x100539fb0, 'cbz', 'x21, #0x10053a1f0'),
    (0x10053a0a0, 'swpal', 'w20, w8, [x28]'),
    (0x10053a110, 'mov', 'x17, #0x41e2'),
    (0x10053a114, 'blraa', 'x8, x17'),
    (0x10053a170, 'cmp', 'x19, #0xe0'),
    (0x10053a17c, 'and', 'x8, x8, #0x1f0'),
    (0x10053a188, 'csel', 'x8, x9, x8, lo'),
    (0x10053a31c, 'str', 'x10, [x8, #8]'),
    (0x10053a8ec, 'add', 'x0, x8, #0x10'),
    (0x10053a8fc, 'stlr', 'wzr, [x8]'),
    (0x10053a9c4, 'mov', 'x17, #0xf447'),
    (0x10053a9c8, 'blraa', 'x8, x17'),
    (0x10053a9d8, 'cmn', 'x0, #1'),
)
WINDOWS = {
    'outer_wrapper': (0x10020b5f0, 0x10020b86c),
    'middle_wrapper': (0x10053c3ec, 0x10053c67c),
    'allocator_prologue_and_small_bins': (0x100539d2c, 0x10053a1f8),
    'small_bin_success': (0x10053a304, 0x10053a340),
    'return_and_mapping_request': (0x10053a8ec, 0x10053aa04),
}


def inspect(daemon):
    _, _, thin = next(row for row in daemon_slices(daemon.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == UUID and digest(thin) == SHA256
    image = ThinView(thin)
    fixups = bindings(daemon, '-arch', 'arm64e')
    for pc, mnemonic, operands in CHECKS:
        image.instruction(pc, mnemonic, operands)

    results = {}
    for name, bank, key, bias, base, expected, adjust in SELECTIONS:
        results[name] = selection(image, fixups, BANKS[bank], key, bias, base, expected,
                                  negative_adjust(*adjust) if adjust else 0)
    for name, modifier in (('outer_call', 0x7c87), ('middle_call', 0xe204),
                           ('contention_call', 0x41e2), ('mapping_call', 0xf447)):
        assert results[name]['binding'].endswith(f'(div=0x{modifier:04X} ad=0 key=IA)')

    # The innermost entry restores the 64-bit word forwarded by the middle wrapper.
    mask = (1 << 64) - 1
    stack_deltas = set()
    for high_nibble in range(16):
        word = high_nibble << 60
        delta = ((((word * 0x2ebd + 1) & mask) >> 60) * 16 + 31) & 0x1f0
        assert delta % 16 == 0
        stack_deltas.add(delta)
    for edge_value in (0, 1, 0xdf, 0xe0, mask):
        assert (((edge_value - 0xe0) & mask) + 0xe0) & mask == edge_value
    assert stack_deltas == set(range(16, 257, 16))
    small_requests = (16, 32, 128)
    size_classes = [(size + 31) & 0x1f0 for size in small_requests]
    assert size_classes == [32, 48, 144]

    windows = {name: window(image, start, end) for name, (start, end) in WINDOWS.items()}
    return {
        'uuid': UUID, 'sha256': SHA256, 'selections': results,
        'checks': len(CHECKS), 'windows': windows,
        'instruction_count': sum(map(len, windows.values())),
        'stack_deltas_bytes': sorted(stack_deltas),
        'selected_small_request_classes_bytes': dict(zip(small_requests, size_classes)),
        'gate_file_initial_bytes': image.read(0x1005eddb0, 8).hex(),
        'native_allocation_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.daemon), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
