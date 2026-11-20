#!/usr/bin/env python3
"""Audit the installed selector 19 call-site return dispatch."""

import argparse
import json
from pathlib import Path

from audit_live_lskdd_selector19_binding import (
    SHA, TABLE, ThinView, bindings, daemon_slices, selected_identity, window,
)

DISPATCH = {
    0x100474cc4: (0xe28d, 0x100474d34),
    0x100474d34: (0x25d2, 0x100474e6c),
    0x1003b483c: (0x533b, 0x1003b4884),
    0x100474944: (0xd5f8, 0x1004749a4),
    0x10098cbe0: (0x25d2, 0x10098cc44),
    0x100425608: (0xd438, 0x100425690),
    0x10072cb44: (0x0557, 0x10072cb64),
    0x1001fac74: (0x564b, 0x1001fad04),
}


def u32(value):
    return value & 0xffffffff


def signed_index(value):
    return ((value + 0x80000000) & 0xffffffff) - 0x80000000


def slot(index):
    return TABLE + 8 * signed_index(index)


def edge(fixups, index, modifier, target):
    address = slot(index)
    expected = f'auth-rebase 0x{target:X} (div=0x{modifier:04X} ad=0 key=IA)'
    assert fixups[address] == expected, (hex(address), fixups[address])
    return {'index': hex(index), 'slot': hex(address), 'fixup': expected}


def audit(path):
    thin, = [blob for cpu, subtype, blob in daemon_slices(path.read_bytes())
             if (cpu, subtype) == (0x0100000c, 0x80000002)]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    assert identity['uuid'] == '28d510e5-3b91-3916-97ab-b765a3a7ba21'
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    windows = {hex(start): window(image, start, end)
               for start, (_, end) in DISPATCH.items()}

    # The entry writes W8 = W21 ^ 0x4eee and W9 = W8 << 5.
    # The method block computes W23 = W9 - W8 before either call.
    candidates = {
        (address - TABLE) // 8
        for address, description in fixups.items()
        if (address - TABLE) % 8 == 0
        and description.startswith('auth-rebase ')
        and description.endswith('(div=0x25D2 ad=0 key=IA)')
        and -(1 << 31) <= (address - TABLE) // 8 < (1 << 31)
    }
    pairs = []
    for nonzero_index in sorted(candidates):
        state = u32(nonzero_index)
        w23 = u32(31 * (state ^ 0x4eee))
        zero_index = u32(state ^ u32(w23 - 0x287d))
        if signed_index(zero_index) in candidates:
            pairs.append((state, zero_index, w23))
    assert len(candidates) == 8
    assert pairs == [(0x4fbf, 0x4fed, 0x28cf)]
    state, zero_index, w23 = pairs[0]

    # First return branch after IOConnectCallStructMethod.
    nonzero = [edge(fixups, state, 0x25d2, 0x1003b483c),
               edge(fixups, w23, 0x533b, 0x100474944)]
    w23_after_error = w23 ^ 0x23d1
    error_state = w23_after_error ^ 0x4ea7
    assert error_state == 0x45b9
    nonzero.append(edge(fixups, u32(error_state - 0x3567) ^ w23_after_error,
                        0xd5f8, 0x10096bb98))
    zero = edge(fixups, zero_index, 0x25d2, 0x10098cbe0)

    # Zero-status path's unsigned field test at output +8 B.
    w22 = u32(state - 0x493d) | 0x148
    w23 = u32(state - 0x26f0)
    mask = w22 ^ (w23 ^ 0x1bd0)
    in_range = state ^ mask
    length_paths = {
        'length_at_least_3072': edge(fixups, state, 0x25d2, 0x1003b483c),
        'length_below_3072': edge(fixups, in_range, 0x25d2, 0x100425608),
    }
    w23 = u32(w22 + 0x396e) | 0x481
    short = [
        edge(fixups, u32(w22 - 0x33b8 + w23), 0xd438, 0x10072cb44),
        edge(fixups, u32(w23 - 0x2b09), 0x0557, 0x1001fac74),
    ]

    # The two constant pairs cancel in the endpoint comparison.
    mask64 = (1 << 64) - 1
    assert (0x4467300b1fd1460e + 0xbb98cff4e02eb9f2) & mask64 == 0
    assert (0x0fbbe16f29c3dd9f + 0xf0441e90d63c2261) & mask64 == 0
    w13 = u32(w23 - 0x19b4)
    w14 = u32(w13 + 0x5411) | 0x829
    endpoint_paths = {
        'source_payload_pointer_at_most_destination_pointer':
            edge(fixups, w13, 0x564b, 0x10055d898),
        'source_payload_pointer_greater_than_destination_pointer':
            edge(fixups, w13 ^ (w14 ^ 0x8831), 0x564b, 0x10044fd30),
    }
    return {
        'arm64e_sha256': identity['sha256'],
        'arm64e_uuid': identity['uuid'],
        'entry': edge(fixups, 0x1839, 0xe28d, 0x100474cc4),
        'candidate_count': len(candidates),
        'entry_w21': hex(state),
        'nonzero_return': nonzero,
        'zero_return': zero,
        'zero_return_length_paths': length_paths,
        'below_3072_continuation': short,
        'short_length_pointer_order': endpoint_paths,
        'windows': windows,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.image), indent=2, sort_keys=True))
