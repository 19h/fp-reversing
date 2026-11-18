#!/usr/bin/env python3
"""Identify the next consumer and release of the rewritten selector 26 aggregate."""

import json
import subprocess

import z3

from audit_daemon_selector26_aggregate_writeback import check_writeback
from audit_daemon_selector26_aggregate_reads import BUFFER, walk
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_record_consumer import (
    FRONTIER, REPLAY, SOURCE, number, sections, sha,
)
from daemon_receive_tools import verify_original_fixups

ALLOCATE = 'libSystem/_malloc'
FREE = 'libSystem/_free'
AGGREGATE_FREE = 0x1009b5494
LOAD = 0x100646190
STORE = 0x100646310
PAYLOAD_OFFSET = 10
ALLOCATION_BASE = 0x3a000


def check_consumer(fixture, data, profiles, equal, seed, constant):
    (_, _, pc, _), previous, frame = check_writeback(fixture, data, profiles, equal, (0, 0), seed, constant)
    assert pc == 0x100640d30
    capacity = len(previous)
    edges, calls = [], []
    first_load, first_store = len(frame.loads), len(frame.stores)
    allocations = {}
    copy_reads, copy_writes = [], []
    original_load, original_store = frame.load, frame.store

    def load(address, width):
        value = original_load(address, width)
        if frame.pc == LOAD and BUFFER <= number(address) < BUFFER + capacity:
            at = number(address)
            assert width == 1 and number(value) == previous[at - BUFFER]
            offset = at - BUFFER
            tag = z3.BitVec(f'aggregate_consumer_{offset}', 8)
            copy_reads.append((offset, number(frame.read('x8')), tag))
            return tag
        return value

    def store(address, width, value, site):
        at = number(address)
        if site == STORE and copy_reads and len(copy_writes) < len(copy_reads):
            offset, base, tag = copy_reads[-1]
            assert width == 1 and at == base + PAYLOAD_OFFSET + offset, (at - base, offset)
            byte = z3.Extract(7, 0, value)
            mask = number(z3.simplify(byte ^ tag))
            copy_writes.append((base, offset, mask))
            value = previous[offset] ^ mask
        original_store(address, width, value, site)

    frame.load, frame.store = load, store
    for _ in range(24):
        before = len(calls)
        boundary = walk(frame, pc, edges, calls, limit=35000)
        assert len(calls) == before + 1
        site, target, argument = calls[-1]
        assert site == boundary
        if target == ALLOCATE:
            allocated = ALLOCATION_BASE + 0x1000 * len(allocations)
            assert 0 < argument < 0x1000
            assert not any(allocated <= at < allocated + argument for at in frame.ram)
            allocations[allocated] = argument
            return_from_call(frame, site + 4, allocated)
        else:
            assert target == FREE
            if argument == BUFFER:
                assert site == AGGREGATE_FREE
                break
            return_from_call(frame, site + 4)
        pc = site + 4
    else:
        raise AssertionError('aggregate release was not reached')

    loads = frame.loads[first_load:]
    stores = frame.stores[first_store:]
    assert [(site, at - BUFFER, width) for site, at, width in loads
            if BUFFER <= at < BUFFER + capacity] == [
                (LOAD, offset, 1) for offset in range(capacity - 1, -1, -1)]
    assert not any(at < BUFFER + capacity and BUFFER < at + width for _, at, width, _ in stores)
    assert bytes(number(frame.get(BUFFER + i, 1)) for i in range(capacity)) == previous

    _, first_child, _, aggregate_child, final_buffer = allocations
    assert calls[:5] == [(0x100948dd0, ALLOCATE, 32), (0x100a2fc00, ALLOCATE, 42),
                         (0x100948dd0, ALLOCATE, 32), (0x100a2fc00, ALLOCATE, capacity + 10),
                         (0x100a05060, ALLOCATE, capacity + 112)]
    assert len(copy_reads) == len(copy_writes) == capacity
    assert [(base, offset) for base, offset, _ in copy_writes] == [
        (aggregate_child, offset) for offset in range(capacity - 1, -1, -1)]
    assert [(site, at, width) for site, at, width, _ in stores
            if at < aggregate_child + capacity + PAYLOAD_OFFSET and aggregate_child + PAYLOAD_OFFSET < at + width] == [
                (STORE, aggregate_child + PAYLOAD_OFFSET + offset, 1) for offset in range(capacity - 1, -1, -1)]
    assert len(calls) == 15 and all(target == FREE for _, target, _ in calls[5:])
    assert [(site, arg) for site, _, arg in calls if arg in (first_child, aggregate_child, final_buffer)] == [
        (0x100942a64, first_child), (0x100942a64, aggregate_child)]
    print(hex(fixture), equal, seed, 'source bytes', capacity, 'child size', allocations[aggregate_child],
          'further buffer size', allocations[final_buffer], 'authenticated edges', len(edges), flush=True)
    return {slot for _, slot, _ in edges}


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    image_sections = sections()
    data = [row for row in image_sections if row['segment'] == '__DATA']
    constant, = [row for row in image_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = set()
    for equal in (False, True):
        for fixture, seed in ((0x98, 0), (0x99, 17)):
            slots.update(check_consumer(fixture, data, profiles, equal, seed, constant))
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words')


if __name__ == '__main__':
    main()
