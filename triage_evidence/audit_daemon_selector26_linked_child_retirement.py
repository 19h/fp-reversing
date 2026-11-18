#!/usr/bin/env python3
"""Verify the selector 26 owner chain through the first child release call."""

import json
import subprocess

from audit_daemon_selector26_allocation_prefix import WRITES
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_readback_continuations import walk
from audit_daemon_selector26_record_consumer import FRONTIER, REPLAY, SOURCE, number, sections, sha
from audit_daemon_selector26_second_child_writes import OWNER, check_writes
from daemon_receive_tools import verify_original_fixups

ORIGINAL_OWNER = 0x29000
TAIL = 0x27008
MALLOC = 'libSystem/_malloc'
FREE = 'libSystem/_free'


def trace_return(frame, call, result, next_call, expected_edges):
    return_from_call(frame, call + 4, result)
    edges, calls = [], []
    assert walk(frame, call + 4, edges, calls, limit=18000) == next_call[0]
    assert calls == [next_call], calls
    assert len(edges) == expected_edges, (hex(call), len(edges))
    return edges


def check_child(frame, owner, child, extent, store_start, writer):
    assert number(frame.get(owner + 0x10, 4)) == extent
    assert number(frame.get(owner + 0x18, 8)) == child
    expected = [(pc, child + offset, 1) for offset, pc in enumerate(WRITES)]
    if writer is None:
        expected.extend((pc, child + offset, 1) for offset, pc in enumerate(WRITES[:4], start=10))
    else:
        expected.extend((writer, child + offset, 1) for offset in range(extent - 1, 9, -1))
    actual = [(pc, at, size) for pc, at, size, _ in frame.stores[store_start:]
              if at < child + extent and child < at + size]
    assert actual == expected, (extent, actual)
    assert all(child + offset in frame.ram for offset in range(extent))


def check_links(frame, previous, owner, store_start, link_sites):
    actual = [(pc, at, size, number(value)) for pc, at, size, value in frame.stores[store_start:]
              if pc in link_sites]
    assert actual == [
        (link_sites[0], previous, 8, owner),
        (link_sites[1], owner + 8, 8, previous),
        (link_sites[2], TAIL, 8, owner),
    ], actual


def check_retirement(fixture, data, profiles, equal):
    frame, _ = check_writes(fixture, data, profiles, equal)
    original_child = number(frame.get(ORIGINAL_OWNER + 0x18, 8))
    assert original_child == 0x2a000
    assert number(frame.get(ORIGINAL_OWNER, 8)) == OWNER
    first_store = len(frame.stores)
    allocations = iter(range(0x2d000, 0x33000, 0x1000))
    edges = []
    previous = OWNER
    stages = []
    if not equal:
        stages.append((0x100a17948, 0x100a5dcec, 26, 0x100a21528, 53,
                       0x100646ccc, (0x10063f69c, 0x10063f6a4, 0x10063f6a8)))
    stages.append((0x100a21528, 0x1006443cc, 42, 0x100948dd0, 73 if equal else 79,
                   0x10064d9f8, (0x1006436f0, 0x1006436f8, 0x1006436fc)))
    stages.append((0x100948dd0, 0x100a2fc00, 14, 0x100643c5c, 37, None, ()))
    for owner_call, child_call, extent, next_pc, edge_count, writer, links in stages:
        owner, child = next(allocations), next(allocations)
        edges.extend(trace_return(frame, owner_call, owner, (child_call, MALLOC, extent), 2))
        store_start = len(frame.stores)
        next_call = (next_pc, MALLOC, 32) if links else (next_pc, FREE, original_child)
        edges.extend(trace_return(frame, child_call, child, next_call, edge_count))
        check_child(frame, owner, child, extent, store_start, writer)
        if links:
            check_links(frame, previous, owner, store_start, links)
        previous = owner
    assert not any(at < original_child + 14 and original_child < at + size
                   for _, at, size, _ in frame.stores[first_store:])
    assert edges[-1] == (0x100643c5c, 0x10109ff30, FREE)
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    slots = set()
    for equal in (False, True):
        first = check_retirement(0x98, data, profiles, equal)
        assert check_retirement(0x99, data, profiles, equal) == first
        slots.update(slot for _, slot, _ in first)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(f'4 cases, 175 mismatch and 114 equality edges, {len(slots)} chained fixups, first free at 0x100643c5c')


if __name__ == '__main__':
    main()
