#!/usr/bin/env python3
"""Verify the selector 26 aggregate buffer's sources, stores and first calls."""

import json
import subprocess

import z3

from audit_daemon_selector26_postrelease import (
    MALLOC, check_nonnull, check_prefix, check_retirement, return_from_call, walk,
)
from audit_daemon_selector26_record_consumer import FRONTIER, REPLAY, SOURCE, number, sections, sha
from daemon_receive_tools import verify_original_fixups

BUFFER = 0x37000
ALLOC = 0x1006b09e0
HELPER = 0x100444dfc
FIRST_HELPER = 0x100a3826c
SECOND_HELPER = 0x10064b5bc
LOOP_LOAD = 0x10070b900
LOOP_STORE = 0x10070bc30
TRAILER_HEAD = (0x100a0b1cc, 0x100a0b41c, 0x100a0b5d8, 0x100a0b7f8)


def trace(frame, pc, result, expected, count):
    return_from_call(frame, pc + 4, result)
    edges, calls = [], []
    assert walk(frame, pc + 4, edges, calls, limit=42000) == expected[0]
    assert calls == [expected], calls
    assert len(edges) == count, (hex(pc), len(edges))
    return edges


def buffers_equal(frame, snapshot):
    for offset, expected in enumerate(snapshot):
        assert z3.is_true(z3.simplify(frame.get(BUFFER + offset, 1) == expected)), offset


def check_aggregate(fixture, data, profiles, equal):
    owners = (0x2f000, 0x2b000, 0x2d000) if equal else (0x31000, 0x2b000, 0x2d000, 0x2f000)
    extents = [14, 26, 42] if equal else [14, 14, 26, 42]
    total, capacity = sum(extents), 96 if equal else 112
    frame, _ = check_retirement(fixture, data, profiles, equal)
    check_prefix(frame)
    check_nonnull(frame, owners, extents)
    assert number(frame.read('x0')) == capacity

    tags, payload_loads, payload_stores = [], [], []
    for owner, extent in zip(owners, extents, strict=True):
        child = number(frame.get(owner + 0x18, 8))
        base = len(tags)
        for offset in range(extent):
            tag = z3.BitVec(f'child_{owner:x}_byte_{offset}', 8)
            frame.put(child + offset, 1, tag)
            tags.append(tag)
        payload_loads.extend((LOOP_LOAD, child + i, 1) for i in reversed(range(extent)))
        payload_stores.extend((LOOP_STORE, BUFFER + base + i, 1) for i in reversed(range(extent)))

    first_load, first_store = len(frame.loads), len(frame.stores)
    argument = number(frame.read('x29')) - 0xa0
    edges = trace(frame, ALLOC, BUFFER, (FIRST_HELPER, HELPER, argument), 109 if equal else 129)
    loads = frame.loads[first_load:]
    assert [event for event in loads if event[0] == LOOP_LOAD] == payload_loads
    assert [event for event in loads if event[0] in (0x10063eb74, 0x10087695c, 0x10093b8f0, 0x1006c078c)] == [
        event for owner in owners for event in (
            (0x10063eb74, owner + 0x10, 4), (0x10087695c, owner + 0x18, 8),
            (0x10093b8f0, owner + 0x10, 4), (0x1006c078c, owner, 8),
        )
    ]
    assert not any(at < BUFFER + capacity and BUFFER < at + n for _, at, n in loads)

    trailer_sites = TRAILER_HEAD + (0x1006d36d4, 0x1006d36d8) + TRAILER_HEAD
    trailer = [(pc, BUFFER + total + i, 1) for i, pc in enumerate(trailer_sites)]
    trailer.extend((0x10090b374, BUFFER + i, 1) for i in range(capacity - 1, total + 9, -1))
    assert [(pc, at, width) for pc, at, width, _ in frame.stores[first_store:]
            if at < BUFFER + capacity and BUFFER < at + width] == payload_stores + trailer
    snapshot = [frame.get(BUFFER + i, 1) for i in range(capacity)]
    assert all(z3.is_bv_value(z3.simplify(out ^ tag))
               for out, tag in zip(snapshot[:total], tags, strict=True))

    first_load, first_store = len(frame.loads), len(frame.stores)
    frame.put(argument + 8, 8, z3.FreshConst(z3.BitVecSort(64), 'aggregate_helper_result'))
    edges.extend(trace(frame, FIRST_HELPER, None, (SECOND_HELPER, HELPER, argument), 10))
    frame.put(argument + 8, 8, z3.FreshConst(z3.BitVecSort(64), 'aggregate_helper_result'))
    edges.extend(trace(frame, SECOND_HELPER, None, (0x100948dd0, MALLOC, 32), 15))
    assert not any(at < BUFFER + capacity and BUFFER < at + n for _, at, n in frame.loads[first_load:])
    assert not any(at < BUFFER + capacity and BUFFER < at + n for _, at, n, _ in frame.stores[first_store:])
    buffers_equal(frame, snapshot)
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    slots = set()
    for equal in (False, True):
        first = check_aggregate(0x98, data, profiles, equal)
        assert check_aggregate(0x99, data, profiles, equal) == first
        slots.update(slot for _, slot, _ in first)
        print(f'equal={equal} edges={len(first)}', flush=True)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(f'4 replay cases, 96 and 82 source bytes, complete buffer writes, {len(slots)} chained fixups')


if __name__ == '__main__':
    main()
