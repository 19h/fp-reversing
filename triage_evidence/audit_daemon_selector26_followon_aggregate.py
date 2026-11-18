#!/usr/bin/env python3
"""Follow the selector 26 postrelease aggregate to its next private call."""

import json
import subprocess

import z3

from audit_daemon_selector26_aggregate_consumer import (
    AGGREGATE_FREE, ALLOCATE, FREE, LOAD, PAYLOAD_OFFSET, STORE, check_consumer,
)
from audit_daemon_selector26_aggregate_reads import walk
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha,
)
from daemon_receive_tools import verify_original_fixups

CALL = 0x10064be84
CALLEE = 0x10043fe84
CALLEE_SLOT = 0x1010a0fb8
FOLLOWON_BASE = 0x41000


def overlaps(address, width, base, size):
    return address < base + size and base < address + width


def check_followon(fixture, data, profiles, equal, seed, constant):
    _, frame, source, extent = check_consumer(fixture, data, profiles, equal, seed, constant)
    assert extent == (208 if equal else 224)
    assert not any(overlaps(address, width, source, extent) for _, address, width in frame.loads)
    previous = bytes(number(frame.get(source + offset, 1)) for offset in range(extent))
    first_load, first_store = len(frame.loads), len(frame.stores)
    caller_sp, caller_fp = (number(frame.read(reg)) for reg in ('sp', 'x29'))
    edges, calls, allocations, copy = [], [], {}, []
    original_load, original_store = frame.load, frame.store
    pending = None

    def load(address, width):
        nonlocal pending
        value = original_load(address, width)
        at = number(address)
        if overlaps(at, width, source, extent):
            assert pending is None and frame.pc == LOAD and width == 1
            offset = at - source
            assert number(value) == previous[offset]
            tag = z3.BitVec(f'followon_aggregate_{offset}', 8)
            pending = offset, number(frame.read('x8')), tag
            return tag
        return value

    def store(address, width, value, site):
        nonlocal pending
        if site == STORE and pending is not None:
            offset, base, tag = pending
            assert width == 1 and number(address) == base + PAYLOAD_OFFSET + offset
            mask = number(z3.simplify(z3.Extract(7, 0, value) ^ tag))
            copy.append((offset, base))
            pending = None
            value = previous[offset] ^ mask
        original_store(address, width, value, site)

    frame.load, frame.store = load, store
    pc = AGGREGATE_FREE + 4
    return_from_call(frame, pc)
    for _ in range(32):
        site = walk(frame, pc, edges, calls, limit=50000)
        _, target, argument = calls[-1]
        pc = site + 4
        if target == FREE:
            assert not source <= argument < source + extent
            return_from_call(frame, pc)
        elif target == ALLOCATE:
            base = FOLLOWON_BASE + 0x1000 * len(allocations)
            assert 0 < argument < 0x1000
            assert not any(overlaps(address, 1, base, argument) for address in frame.ram)
            allocations[base] = argument
            return_from_call(frame, pc, base)
        else:
            assert (site, target, argument) == (CALL, CALLEE, caller_fp - 0xa0)
            break
    else:
        raise AssertionError('private call was not reached')

    _, _, _, owner, destination = allocations
    assert edges[-1] == (CALL, CALLEE_SLOT, CALLEE)
    free_count = 9 if equal else 11
    assert all(target == FREE for _, target, _ in calls[:free_count])
    assert calls[free_count:-1] == [
        (0x1006470e4, ALLOCATE, 16), (0x100948dd0, ALLOCATE, 32),
        (0x100a2fc00, ALLOCATE, 14), (0x100948dd0, ALLOCATE, 32),
        (0x100a2fc00, ALLOCATE, extent + PAYLOAD_OFFSET),
    ]
    assert copy == [(offset, destination) for offset in range(extent - 1, -1, -1)] and pending is None
    assert [(site, at - source, width) for site, at, width in frame.loads[first_load:]
            if overlaps(at, width, source, extent)] == [
                (LOAD, offset, 1) for offset in range(extent - 1, -1, -1)]
    stores = frame.stores[first_store:]
    assert not any(overlaps(at, width, source, extent) for _, at, width, _ in stores)
    assert [(site, at, width) for site, at, width, _ in stores
            if overlaps(at, width, destination + PAYLOAD_OFFSET, extent)] == [
                (STORE, destination + PAYLOAD_OFFSET + offset, 1) for offset in range(extent - 1, -1, -1)]
    assert number(frame.get(owner + 0x18, 8)) == destination
    assert [(site, width, number(value)) for site, at, width, value in stores
            if overlaps(at, width, owner + 0x18, 8)] == [(0x100a2fc08, 8, destination)]
    assert [(site, at - argument, width, number(value)) for site, at, width, value in stores
            if overlaps(at, width, argument, 0x30)] == [
                (0x10064be1c, 0, 4, 0x80f63fa2),
                (0x10064be24, 8, 8, caller_sp + 0xbaf),
    ]
    assert number(frame.get(argument, 4)) == 0x80f63fa2
    assert number(frame.get(argument + 8, 8)) == caller_sp + 0xbaf

    assert number(frame.read('sp')) == caller_sp
    assert next(CS.disasm(IMAGE.read(CALLEE, 4), CALLEE)).mnemonic == 'pacibsp'
    frame.seed('x30', CALL + 4)
    count = len(edges), len(calls)
    assert walk(frame, CALLEE + 4, edges, calls, stop=0x10043fea8) == 0x10043fea8
    assert (len(edges), len(calls)) == count
    assert number(frame.read('sp')) == caller_sp - 0x60
    assert number(frame.read('x19')) == argument
    assert number(frame.get(caller_sp - 8, 8)) == CALL + 4
    print(hex(fixture), equal, seed, 'bytes transferred', extent, 'cleanup calls', free_count,
          'authenticated edges', len(edges), flush=True)
    return {slot for _, slot, _ in edges}


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    original_sections = sections()
    data = [row for row in original_sections if row['segment'] == '__DATA']
    constant, = [row for row in original_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = set()
    for equal in (False, True):
        for fixture, seed in ((0x98, 0), (0x99, 17)):
            slots.update(check_followon(fixture, data, profiles, equal, seed, constant))
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words')


if __name__ == '__main__':
    main()
