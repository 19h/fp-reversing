#!/usr/bin/env python3
"""Audit ownership and result propagation after the process-path selector 26 gate."""

import json
import subprocess

import z3

from audit_daemon_selector26_aggregate_reads import walk
from audit_daemon_selector26_class_retry import F, FALLBACK, FINAL, R, REJECTED, RELEASE
from audit_daemon_selector26_followon_aggregate import FOLLOWON_BASE, overlaps
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_pidpath_paths import (
    AGGREGATE, ALLOCATE, ALLOCATION_BASE, DESCRIPTOR, DIRECT, FREE, GUARD, PATH_CHILD, PATH_NODE, check_positive,
)
from audit_daemon_selector26_pidpath_returns import FIXTURE_PATH, profiles_for, replay_return
from audit_daemon_selector26_record_consumer import FRONTIER, REPLAY, SOURCE, number, sections, sha
from audit_daemon_selector26_self_pidpath import check_pidpath
from daemon_receive_tools import verify_original_fixups

STATUS_STORE = 0x10065f458
CORE_RETURN = 0x1009e5750
OUTER_ENTRY = 0x10028a8b4
ALLOCATE_LIST = 0x100723080
FREE_AGGREGATE = 0x10072a488
NEW_LIST = 0x4c000
NEXT_OWNER = 0x100948dd0
RELEASE_ORDER = (
    (0x100a86f0c, 0x24000),
    (0x100942a64, FOLLOWON_BASE + 0x2000), (0x100a35f0c, FOLLOWON_BASE + 0x1000),
    (0x100942a64, FOLLOWON_BASE + 0x4000), (0x100a35f0c, FOLLOWON_BASE + 0x3000),
    (0x100942a64, PATH_CHILD), (0x100a35f0c, PATH_NODE),
    (0x100945d50, FOLLOWON_BASE), (0x100a2fe70, 0x23000),
    (0x10070f118, ALLOCATION_BASE + 0x4000), (FREE_AGGREGATE, AGGREGATE),
)


def no_aggregate_access(frame, extent, loads, stores):
    assert not any(overlaps(at, width, AGGREGATE, extent) for _, at, width in frame.loads[loads:])
    assert not any(overlaps(at, width, AGGREGATE, extent) for _, at, width, _ in frame.stores[stores:])


def finish_rejection(frame, pc, extent, expected, edges, fixture):
    start_load, start_store = len(frame.loads), len(frame.stores)
    calls = []
    for site, pointer in RELEASE_ORDER:
        assert walk(frame, pc, edges, calls, stop=GUARD) == site, calls
        assert calls[-1] == (site, FREE, pointer)
        pc = site + 4
        return_from_call(frame, pc)
    assert walk(frame, pc, edges, calls, stop=GUARD) == GUARD and len(calls) == len(RELEASE_ORDER)
    assert z3.is_false(z3.simplify(frame.condition('ne')))
    assert [(site, number(value)) for site, at, width, value in frame.stores[start_store:]
            if at == R + 8 and width == 4] == [(0x1009e5714, expected)]
    for first, last, link in ((GUARD + 4, CORE_RETURN, 0x100902ae0), (0x100902ae0, 0x100902b00, OUTER_ENTRY)):
        for pc in range(first, last + 4, 4):
            frame.step(pc, pc + 4)
        assert frame.return_pc == last and number(frame.read('x30')) == link
    assert number(frame.read('sp')) == F and number(frame.get(F + 0x80, 8)) == 0
    assert walk(frame, OUTER_ENTRY, edges, calls, stop=REJECTED) == REJECTED and len(calls) == len(RELEASE_ORDER)
    no_aggregate_access(frame, extent, start_load, start_store)
    check_port_releases(frame, edges, fixture)


def check_port_releases(frame, edges, fixture):
    service, iterator = (number(frame.get(F + offset, 4)) for offset in (0xc, 0x78))
    context = number(frame.get(R + 0x10, 8))
    connection = number(frame.get(context + 4, 4))
    assert (service, iterator, connection) == (0x517, 0x217, 0x417)
    calls = []
    pc = REJECTED
    for site, name in ((0x1001dcab8, service), (0x100205980, iterator)):
        assert walk(frame, pc, edges, calls) == site, calls
        assert calls[-1] == (site, RELEASE, name)
        pc = site + 4
        return_from_call(frame, pc, 1)
    dest = FALLBACK if fixture == 0x98 else FINAL
    assert walk(frame, pc, edges, calls, stop=dest) == dest and len(calls) == 2
    assert number(frame.get(context + 4, 4)) == connection


def follow_success(frame, pc, extent, edges, allocated, fixture):
    loads, stores = len(frame.loads), len(frame.stores)
    calls = []
    assert walk(frame, pc, edges, calls) == ALLOCATE_LIST
    assert calls == [(ALLOCATE_LIST, ALLOCATE, 16)]
    no_aggregate_access(frame, extent, loads, stores)
    pc = ALLOCATE_LIST + 4
    return_from_call(frame, pc, allocated)
    if allocated == 0:
        finish_rejection(frame, pc, extent, 0x74c29d85, edges, fixture)
        return
    assert walk(frame, pc, edges, calls) == NEXT_OWNER
    assert calls == [(ALLOCATE_LIST, ALLOCATE, 16), (NEXT_OWNER, ALLOCATE, 32)]
    reads = [(site, at - AGGREGATE, width) for site, at, width in frame.loads[loads:]
             if overlaps(at, width, AGGREGATE, extent)]
    assert len(reads) == 14
    assert not any(overlaps(at, width, AGGREGATE, extent) for _, at, width, _ in frame.stores[stores:])
    print('aggregate reads', [(hex(site), offset, width) for site, offset, width in reads], flush=True)


def check_history(fixture, equal, data, profiles, constant):
    seed, pid, abi = (0, 11747, DIRECT) if fixture == 0x98 else (17, 501, DESCRIPTOR)
    _, routes, state = check_pidpath(fixture, data, profiles, equal, seed, pid, constant)
    frame, record, *_ = state
    _, extent = check_positive(state, routes[0], FIXTURE_PATH, abi)
    regs, ram = frame.regs.copy(), frame.ram.copy()
    loads, stores = len(frame.loads), len(frame.stores)
    slots = set()
    for profile in profiles_for(abi, extent):
        label, *controls = profile
        allocations = (0, NEW_LIST) if label == 'success' else (None,)
        for allocated in allocations:
            frame.regs, frame.ram = regs.copy(), ram.copy()
            del frame.loads[loads:]
            del frame.stores[stores:]
            status, _, pc, edges = replay_return(frame, record, abi, extent, *controls)
            if allocated is None:
                assert pc == 0x10065f430
                sp = number(frame.read('sp'))
                finish_rejection(frame, pc, extent, status, edges, fixture)
                assert [(site, number(value)) for site, at, width, value in frame.stores[stores:]
                        if at == sp + 0x764 and width == 4] == [(STATUS_STORE, status)]
            else:
                assert pc == 0x1009d9118
                follow_success(frame, pc, extent, edges, allocated, fixture)
            slots.update(slot for _, slot, _ in edges)
            print(f'{fixture:#x} {extent} B {label}: {status:#x} allocation {allocated}', flush=True)
    return slots


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    original_sections = sections()
    data = [row for row in original_sections if row['segment'] == '__DATA']
    constant, = [row for row in original_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = set()
    for equal in (False, True):
        for fixture in (0x98, 0x99):
            slots.update(check_history(fixture, equal, data, profiles, constant))
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words', flush=True)


if __name__ == '__main__':
    main()
