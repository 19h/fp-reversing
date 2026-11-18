#!/usr/bin/env python3
"""Replay IOKit returns in the process-path selector 26 caller frame."""

import json
import subprocess

from audit_daemon_selector26_aggregate_reads import walk
from audit_daemon_selector26_followon_aggregate import overlaps
from audit_daemon_selector26_helper_consumers import authenticated_edge, return_from_call
from audit_daemon_selector26_pidpath_paths import AGGREGATE, DESCRIPTOR, DIRECT, check_positive
from audit_daemon_selector26_record_consumer import CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha
from audit_daemon_selector26_return import BAD_SHAPE, KEY
from audit_daemon_selector26_self_pidpath import check_pidpath
from daemon_receive_tools import verify_original_fixups

DIRECT_STORE, DESCRIPTOR_STORE = 0x10020e6b0, 0x1001f48bc
GATE, GATE_BRANCH = 0x100873c28, 0x100873c5c
API_ERROR = 0xffff5bbc
FIXTURE_PATH = b'/' + b'fixture/fairplayd'


def replay_return(frame, record, abi, extent, status, public_size, returned_extent, malformed):
    caller, _, _, method = abi
    direct = abi == DIRECT
    sp = number(frame.read('sp'))
    descriptor = sp + 8
    frame.put(sp, 8, public_size)
    if not direct:
        frame.put(descriptor + 8, 4, returned_extent)
    return_from_call(frame, method + 4, status)
    load_start, store_start = len(frame.loads), len(frame.stores)
    payload = tuple(number(frame.get(AGGREGATE + i, 1)) for i in range(extent))
    edges, calls = [], []
    store = DIRECT_STORE if direct else DESCRIPTOR_STORE
    assert walk(frame, method + 4, edges, calls, stop=store, limit=20000) == store
    epilogue = store + (0x18 if direct else 0x1c)
    for pc in range(store, epilogue + 4, 4):
        frame.step(pc, pc + 4)
    assert frame.return_pc == epilogue and number(frame.read('x30')) == caller + 4
    assert number(frame.read('sp')) == sp + (0x50 if direct else 0x70)
    result_offset = 24 if direct else 8
    result = BAD_SHAPE if malformed else status ^ KEY
    assert number(frame.get(record + result_offset, 4)) == result
    assert [(pc, number(value)) for pc, at, width, value in frame.stores[store_start:]
            if (at, width) == (record + result_offset, 4)] == [(store, result)]
    expected_copy = [] if direct or malformed else [(AGGREGATE + offset, 1) for offset in reversed(range(extent))]
    assert [(at, width) for _, at, width in frame.loads[load_start:]
            if overlaps(at, width, AGGREGATE, extent)] == expected_copy
    assert [(at, width) for _, at, width, _ in frame.stores[store_start:]
            if overlaps(at, width, AGGREGATE, extent)] == expected_copy
    assert tuple(number(frame.get(AGGREGATE + i, 1)) for i in range(extent)) == payload
    assert [(at, width) for _, at, width in frame.loads[load_start:] if at == sp] == (
        [] if direct and status else [(sp, 8)])
    assert not calls

    for pc in range(caller + 4, caller + 20, 4):
        frame.step(pc, pc + 4)
    branch_pc = caller + 20
    instruction = next(CS.disasm(IMAGE.read(branch_pc, 4), branch_pc))
    slot, destination = authenticated_edge(frame, instruction)
    assert number(frame.read('w5')) == result
    assert (caller + 8, record + result_offset, 4) in frame.loads[load_start:]
    edges.append((branch_pc, slot, destination))
    assert destination == GATE

    for pc in range(GATE, GATE_BRANCH, 4):
        frame.step(pc, pc + 4)
    instruction = next(CS.disasm(IMAGE.read(GATE_BRANCH, 4), GATE_BRANCH))
    slot, destination = authenticated_edge(frame, instruction)
    assert number(frame.read('w22')) == (((KEY - 0x8b3d3ac9) ^ 0x9e12) + 0x5b9)
    edges.append((GATE_BRANCH, slot, destination))
    return result, slot, destination, edges


def profiles_for(abi, extent):
    if abi == DIRECT:
        return (
            ('success', 0, extent, 0, False),
            ('short-success', 0, extent - 1, 0, True),
            ('short-error', API_ERROR, extent - 1, 0, False),
        )
    return (
        ('success', 0, 16, extent, False),
        ('error', API_ERROR, 16, extent, False),
        ('wrong-public-size', 0, 0x100000010, extent, True),
        ('wrong-inner-extent', 0, 16, extent - 1, True),
    )


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    original_sections = sections()
    data = [row for row in original_sections if row['segment'] == '__DATA']
    constant, = [row for row in original_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = set()
    for equal in (False, True):
        for fixture, seed, pid, abi in ((0x98, 0, 11747, DIRECT), (0x99, 17, 501, DESCRIPTOR)):
            _, routes, state = check_pidpath(fixture, data, profiles, equal, seed, pid, constant)
            frame, record, *_ = state
            _, extent = check_positive(state, routes[0], FIXTURE_PATH, abi)
            regs, ram = frame.regs.copy(), frame.ram.copy()
            loads, stores = len(frame.loads), len(frame.stores)
            for label, status, public_size, returned_extent, malformed in profiles_for(abi, extent):
                frame.regs, frame.ram = regs.copy(), ram.copy()
                del frame.loads[loads:]
                del frame.stores[stores:]
                result, slot, destination, edges = replay_return(
                    frame, record, abi, extent, status, public_size, returned_extent, malformed)
                slots.update(slot for _, slot, _ in edges)
                print(f'{fixture:#x} {extent} B {label}: {result:#x} via {slot:#x} -> {destination:#x}', flush=True)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words', flush=True)


if __name__ == '__main__':
    main()
