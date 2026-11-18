#!/usr/bin/env python3
"""Verify second-child stores and owner links on both readback continuations."""

import json
import subprocess

from audit_daemon_selector26_allocation_prefix import WRITES
from audit_daemon_selector26_readback_continuations import READ_SITES, walk
from audit_daemon_selector26_record_consumer import (
    FRONTIER, NEXT_BLOCK, REPLAY, SOURCE, number, sections, sha,
)
from audit_daemon_selector26_second_child import CHILD, OWNER, check_return
from daemon_receive_tools import verify_original_fixups


def check_writes(fixture, data, profiles, equal):
    frame, original_owner, _ = check_return(fixture, data, profiles, equal)
    sp = number(frame.read('sp'))
    original_child = number(frame.get(original_owner + 0x18, 8))
    store_start, load_start = len(frame.stores), len(frame.loads)
    prefix = [(pc, CHILD + offset, 1) for offset, pc in enumerate(WRITES)]
    if equal:
        extent = 26
        tail = [(0x100646ccc, CHILD + offset, 1) for offset in range(25, 9, -1)]
        first_edge = (0x100652184, 0x101043818, 0x1009de2d4)
        link_sites = (0x10063f69c, 0x10063f6a4)
        next_call, edge_count = 0x100a21528, 44
        tail_source = number(frame.get(sp + 0x420, 8))
    else:
        extent = 14
        tail = [(pc, CHILD + offset, 1) for offset, pc in enumerate(WRITES[:4], start=10)]
        first_edge = (0x100652184, 0x1010435a8, 0x1006d4db0)
        link_sites = (0x1006527b8, 0x1006527c0)
        next_call, edge_count = 0x100a17948, 38
    edges, calls = [], []
    assert walk(frame, NEXT_BLOCK + 8, edges, calls) == next_call
    assert len(edges) == edge_count and edges[0] == first_edge
    assert calls == [(next_call, 'libSystem/_malloc', 32)]
    assert (0x1009d131c, 0x1010737e8, 0x100641ec4) in edges
    stores = frame.stores[store_start:]
    loads = frame.loads[load_start:]
    assert [(pc, at, n) for pc, at, n, _ in stores if at < CHILD + extent and CHILD < at + n] == prefix + tail
    assert all(CHILD + offset in frame.ram for offset in range(extent))
    assert not any(at < CHILD + extent and CHILD < at + n for _, at, n in loads)
    assert [(pc, at, n) for pc, at, n in loads if at < original_child + 14 and original_child < at + n] == [
        (pc, original_child + offset, 1) for offset, pc in enumerate(READ_SITES)
    ]
    assert not any(at < original_child + 14 and original_child < at + n for _, at, n, _ in stores)
    assert [(pc, at, n, number(value)) for pc, at, n, value in stores if pc in link_sites] == [
        (link_sites[0], original_owner, 8, OWNER), (link_sites[1], OWNER + 8, 8, original_owner),
    ]
    assert number(frame.get(original_owner, 8)) == OWNER
    assert number(frame.get(OWNER + 8, 8)) == original_owner
    assert number(frame.get(original_owner + 0x18, 8)) == original_child
    assert number(frame.get(OWNER + 0x18, 8)) == CHILD
    if equal:
        assert [(at, n) for pc, at, n in loads if pc == 0x100646c90] == [
            (tail_source + offset, 1) for offset in range(15, -1, -1)
        ]
        assert [slot for pc, slot, _ in edges if pc == 0x100646ce8] == [0x10104ad98] * 15 + [0x10109dc30]
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    slots = set()
    for equal in (False, True):
        first = check_writes(0x98, data, profiles, equal)
        assert check_writes(0x99, data, profiles, equal) == first
        slots.update(slot for _, slot, _ in first)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(f'4 cases, complete 14 B and 26 B writes, owner links, {len(slots)} chained fixups')


if __name__ == '__main__':
    main()
