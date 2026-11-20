#!/usr/bin/env python3
"""Verify fixed-frame predecessor calculations for lskdd selector 19."""

import argparse
import json
from pathlib import Path

from audit_live_lskdd_selector19_binding import (
    SHA, ThinView, bindings, daemon_slices, selected_identity, window,
)
from audit_live_lskdd_selector19_reply import edge, u32

ENTRY = 0x100474cc4
BRANCH_MODIFIER = 0xe28d
FRAME_STATE = 0x45b9
MATCHING_STATUS = 0x2ee02eab
SPANS = (
    (0x1008eda8c, 0x1008edaec),
    (0x100b5c91c, 0x100b5c950),
    (0x1006eb420, 0x1006eb450),
    (0x100ac2654, 0x100ac2688),
    (0x100a35c84, 0x100a35ca0),
    (0x100474cc4, 0x100474e3c),
)


def audit(path):
    thin, = [blob for cpu, subtype, blob in daemon_slices(path.read_bytes())
             if (cpu, subtype) == (0x0100000c, 0x80000002)]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    assert identity['uuid'] == '28d510e5-3b91-3916-97ab-b765a3a7ba21'
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')

    state = FRAME_STATE
    entry_w21 = u32(5 * ((u32(state - 0x3db8) | 0x20ce) ^ 0x273c))
    base = u32(state - 0x2da4)
    match_index = base ^ u32(entry_w21 - 0x4f93)
    assert entry_w21 == 0x4fbf
    assert match_index == 0x1839

    # A different predecessor reaches the same target with live-in W21.
    direct_state = u32(match_index + 0x2d6e)
    alternate_state = u32((match_index ^ 0x189a) + 0x44e8)
    assert (direct_state, alternate_state) == (0x45a7, 0x458b)
    assert fixups[0x100e77350] == 'rebase 0x100E82AF8'
    return {
        'arm64e_sha256': identity['sha256'],
        'arm64e_uuid': identity['uuid'],
        'entry_state_producer': {
            'entry_fixup': edge(fixups, 0x263, 0xb9a3, 0x1008eda8c),
            'frame_state': hex(state),
            'required_status': hex(MATCHING_STATUS),
            'entry_w21': hex(entry_w21),
            'matching_edge': edge(fixups, match_index, BRANCH_MODIFIER, ENTRY),
            'nonmatching_edge': edge(fixups, base, BRANCH_MODIFIER, 0x1004decf4),
        },
        'other_entry_inputs': {
            '0x100b5c91c': {'sp_plus_0x5b94': hex(direct_state)},
            '0x1006eb420': {'sp_plus_0x3840': hex(match_index)},
            '0x100ac2654': {'sp_plus_0x5b94': hex(alternate_state)},
        },
        'selector18_connection_fixup': fixups[0x100e77350],
        'windows': {hex(start): window(image, start, end) for start, end in SPANS},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.image), indent=2, sort_keys=True))
