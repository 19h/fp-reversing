#!/usr/bin/env python3
"""Audit selector 26 cleanup and the next list-dependent allocation."""

import json
import subprocess

import z3

from audit_daemon_selector26_class_retry import F, R, REJECTED
from audit_daemon_selector26_linked_child_retirement import (
    FREE, MALLOC, ORIGINAL_OWNER, check_retirement, return_from_call, walk,
)
from audit_daemon_selector26_record_consumer import FRONTIER, REPLAY, SOURCE, number, sections, sha
from daemon_receive_tools import verify_original_fixups
from probe_daemon_frame_entry import Fill

BYTE_FILL = 0x10046faf8
GUARD = 0x1009e572c
FIRST_FREE = 0x100643c5c
OWNER_FREE = 0x10094caf4
FIRST_FILL = 0x100640a84
SECOND_FILL = 0x100640adc
NEXT_ALLOC = 0x100a05060
FIRST_BUFFER, SECOND_BUFFER = 0x33000, 0x34000


def advance(frame, pc, result, expected, edge_count, *, stop=None):
    return_from_call(frame, pc + 4, result)
    edges, calls = [], []
    assert walk(frame, pc + 4, edges, calls, limit=18000, stop=stop) == (
        stop if stop is not None else expected[0]
    )
    assert calls == ([] if expected is None else [expected]), calls
    assert len(edges) == edge_count, (hex(pc), len(edges))
    return edges


def zero_fill(frame, offset, size):
    destination, byte, length = (number(frame.read(r)) for r in ('x0', 'w1', 'x2'))
    assert destination == number(frame.read('sp')) + offset
    assert (byte, length) == (0, size)
    frame.put(destination, size, 0)
    return destination + size


def check_prefix(frame):
    start = len(frame.stores)
    edges = advance(frame, FIRST_FREE, None, (OWNER_FREE, FREE, ORIGINAL_OWNER), 2)
    assert [(pc, address, width, number(value)) for pc, address, width, value in frame.stores[start:]
            if ORIGINAL_OWNER <= address < ORIGINAL_OWNER + 32] == [
        (0x100643c68, ORIGINAL_OWNER + 0x18, 8, 0),
    ]
    sp = number(frame.read('sp'))
    edges.extend(advance(frame, OWNER_FREE, None, (FIRST_FILL, BYTE_FILL, sp + 0xae0), 9))
    dest = zero_fill(frame, 0xae0, 16)
    edges.extend(advance(frame, FIRST_FILL, dest, (SECOND_FILL, BYTE_FILL, sp + 0xaf0), 1))
    dest = zero_fill(frame, 0xaf0, 32)
    edges.extend(advance(frame, SECOND_FILL, dest, (NEXT_ALLOC, MALLOC, 16), 6))
    return edges


def check_null(frame, owners):
    child_free, node_free = 0x100942a64, 0x100a35f0c
    pc, result, edges = NEXT_ALLOC, 0, []
    for index, owner in enumerate(owners):
        child = owner + 0x1000
        loads = len(frame.loads)
        edges.extend(advance(frame, pc, result, (child_free, FREE, child), 21 if index == 0 else 3))
        assert [event for event in frame.loads[loads:] if event[0] in (0x10063f7e4, 0x10063f7e8)] == [
            (0x10063f7e4, owner, 8), (0x10063f7e8, owner + 0x18, 8),
        ]
        stores = len(frame.stores)
        edges.extend(advance(frame, child_free, None, (node_free, FREE, owner), 2))
        assert [(site, address, width, number(value))
                for site, address, width, value in frame.stores[stores:] if site == 0x100942a6c] == [
            (0x100942a6c, owner + 0x18, 8, 0),
        ]
        pc, result = node_free, None
    for next_pc, argument, count in (
        (0x100945d50, 0x27000, 2), (0x100945d50, 0x28000, 8),
        (0x100902cbc, 0x25000, 3), (0x100a86f0c, 0x24000, 8),
        (0x100a2fe70, 0x23000, 14),
    ):
        edges.extend(advance(frame, pc, None, (next_pc, FREE, argument), count))
        pc = next_pc
    edges.extend(advance(frame, pc, None, None, 7, stop=GUARD))
    assert z3.is_false(z3.simplify(frame.condition('ne')))
    assert number(frame.get(R + 8, 4)) == 0x74c29d85
    frame.step(0x1009e5730, 0x1009e5754)
    assert frame.return_pc == 0x1009e5750
    assert number(frame.read('x30')) == 0x100902ae0
    frame.step(0x100902ae0, 0x100902b04)
    assert frame.return_pc == 0x100902b00
    assert number(frame.read('x30')) == 0x10028a8b4
    assert number(frame.read('sp')) == F and number(frame.get(F + 0x80, 8)) == 0
    calls = []
    assert walk(frame, 0x10028a8b4, edges, calls, stop=REJECTED) == REJECTED
    assert not calls
    return edges


def check_nonnull(frame, owners, extents):
    since_stores = len(frame.stores)
    edges = advance(frame, NEXT_ALLOC, FIRST_BUFFER, (0x100723080, MALLOC, 16), 14)
    writes = [(at, width) for _, at, width, _ in frame.stores[since_stores:]
              if FIRST_BUFFER <= at < FIRST_BUFFER + 16]
    assert writes == [(FIRST_BUFFER + i, 1) for i in range(16)]
    since_loads = len(frame.loads)
    edges.extend(advance(frame, 0x100723080, SECOND_BUFFER, (0x1006fd704, FREE, FIRST_BUFFER), 16))
    reads = [(at, width) for _, at, width in frame.loads[since_loads:]
             if FIRST_BUFFER <= at < FIRST_BUFFER + 16]
    assert reads == [(FIRST_BUFFER + i, 1) for i in (*range(6, 10), *range(6))]
    edges.extend(advance(frame, 0x1006fd704, None, (0x100948dd0, MALLOC, 32), 8))
    edges.extend(advance(frame, 0x100948dd0, 0x35000, (0x100a2fc00, MALLOC, 14), 2))
    since_loads = len(frame.loads)
    size = 112 if len(owners) == 4 else 96
    edges.extend(advance(frame, 0x100a2fc00, 0x36000, (0x1006b09e0, MALLOC, size),
                         43 if len(owners) == 4 else 41))
    assert [event for event in frame.loads[since_loads:] if event[0] in (0x10063f484, 0x10074b150)] == [
        event for owner in owners for event in ((0x10063f484, owner + 0x10, 4), (0x10074b150, owner, 8))
    ]
    assert [number(frame.get(owner + 0x10, 4)) for owner in owners] == extents
    return edges


def check_case(fixture, data, profiles, equal, null):
    frame, _ = check_retirement(fixture, data, profiles, equal)
    owners = (0x2f000, 0x2b000, 0x2d000) if equal else (0x31000, 0x2b000, 0x2d000, 0x2f000)
    extents = [14, 26, 42] if equal else [14, 14, 26, 42]
    edges = check_prefix(frame)
    edges.extend(check_null(frame, owners) if null else check_nonnull(frame, owners, extents))
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    for length in (16, 32):
        result = Fill({'alignment': 0, 'length': length, 'byte': 0}).run()
        assert int(result['result_X0'], 16) == int(result['destination'], 16) + length
        assert result['bytes_hex'] == '00' * length
    slots = set()
    for equal in (False, True):
        for null in (False, True):
            first = check_case(0x98, data, profiles, equal, null)
            assert check_case(0x99, data, profiles, equal, null) == first
            slots.update(slot for _, slot, _ in first)
            print(f'equal={equal} null={null} edges={len(first)}', flush=True)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(f'8 replay cases, 2 isolated fill controls, {len(slots)} chained fixups')


if __name__ == '__main__':
    main()
