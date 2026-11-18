#!/usr/bin/env python3
"""Trace the first fourteen aggregate bytes into the daemon's post-call record."""

import json
import subprocess

import z3
from z3.z3util import get_vars

from audit_daemon_selector26_aggregate_reads import walk
from audit_daemon_selector26_helper_consumers import return_from_call
from audit_daemon_selector26_pidpath_ownership import ALLOCATE_LIST, NEW_LIST, NEXT_OWNER
from audit_daemon_selector26_pidpath_paths import AGGREGATE, ALLOCATE, DESCRIPTOR, DIRECT, check_positive
from audit_daemon_selector26_pidpath_returns import FIXTURE_PATH, profiles_for, replay_return
from audit_daemon_selector26_record_consumer import CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha
from audit_daemon_selector26_return import KEY
from audit_daemon_selector26_self_pidpath import check_pidpath
from daemon_receive_tools import FIXUPS, verify_original_fixups

END_COMPARE = 0x100908f8c
FIELDS = ((0x9e8, 4), (0x9ee, 2), (0x9f0, 4), (0x9f4, 4), (0x9f8, 8), (0xa00, 8))


def prove(proposition, *conditions):
    solver = z3.Solver()
    solver.add(*conditions, z3.Not(proposition))
    assert solver.check() == z3.unsat, proposition


def inspect_fields(frame, pc, extent, edges):
    calls = []
    assert walk(frame, pc, edges, calls) == ALLOCATE_LIST
    return_from_call(frame, ALLOCATE_LIST + 4, NEW_LIST)
    sp = number(frame.read('sp'))
    fixture = [number(frame.get(AGGREGATE + i, 1)) for i in range(14)]
    data = tuple(z3.BitVec(f'aggregate_byte_{i}', 8) for i in range(14))
    concrete = tuple((tag, z3.BitVecVal(byte, 8)) for tag, byte in zip(data, fixture, strict=True))
    for i, tag in enumerate(data):
        frame.put(AGGREGATE + i, 1, tag)
    old_load, old_step = frame.load, frame.step
    allowed, slots = [], set()

    def load(address, width):
        address = z3.simplify(address)
        if z3.is_bv_value(address):
            return old_load(address, width)
        words = list(CS.disasm(IMAGE.read(frame.pc, 32), frame.pc))
        assert width == 8 and words[0].mnemonic == 'ldr', hex(frame.pc)
        destination = words[0].operands[0].reg
        branch = next(i for i in words[1:] if i.mnemonic in ('braa', 'blraa'))
        assert branch.operands[0].reg == destination
        slot = number(z3.substitute(address, *concrete))
        solver = z3.Solver()
        for condition in allowed:
            solver.add(condition)
        solver.add(address != slot)
        if solver.check() == z3.unsat:
            return old_load(z3.BitVecVal(slot, 64), width)
        assert solver.check() == z3.sat
        other = number(solver.model().eval(address))
        solver.add(address != other)
        assert solver.check() == z3.unsat
        assert all(isinstance(FIXUPS[entry]['target'], int) for entry in (slot, other))
        slots.update((slot, other))
        allowed.append(address == slot)
        print(f'branch {frame.pc:#x}: {slot:#x} -> {FIXUPS[slot]["target"]:#x}, '
              f'{other:#x} -> {FIXUPS[other]["target"]:#x}', flush=True)
        return old_load(z3.BitVecVal(slot, 64), width)

    def step(start, end):
        if start == END_COMPARE:
            left, right = (z3.simplify(frame.read(reg)) for reg in ('x11', 'x9'))
            offset = number(frame.read('x8'))
            assert offset == 0 and number(right) == extent
            prove(left == z3.ZeroExt(32, z3.Concat(*data[6:10])) + offset + 10)
        return old_step(start, end)

    frame.load, frame.step = load, step
    assert walk(frame, ALLOCATE_LIST + 4, edges, calls) == NEXT_OWNER
    assert calls == [(ALLOCATE_LIST, ALLOCATE, 16), (NEXT_OWNER, ALLOCATE, 32)]
    assert len(allowed) >= 2
    for offset, width in FIELDS:
        expression = z3.simplify(frame.get(sp + offset, width))
        vars_ = get_vars(expression)
        print('field', f'{offset:#x}', width, [item.decl().name() for item in vars_],
              f'{number(z3.substitute(expression, *concrete)):#x}', flush=True)
    for offset, source in ((0x9e8, data[:4]), (0x9f4, data[10:14])):
        prove(frame.get(sp + offset, 4) == (z3.Concat(*source) ^ KEY), *allowed)
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
        for fixture, seed, pid, abi in ((0x98, 0, 11747, DIRECT), (0x99, 17, 501, DESCRIPTOR)):
            _, routes, state = check_pidpath(fixture, data, profiles, equal, seed, pid, constant)
            frame, record, *_ = state
            _, extent = check_positive(state, routes[0], FIXTURE_PATH, abi)
            _, _, pc, edges = replay_return(frame, record, abi, extent, *profiles_for(abi, extent)[0][1:])
            slots.update(inspect_fields(frame, pc, extent, edges))
            slots.update(slot for _, slot, _ in edges)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(len(slots), 'original fixup words', flush=True)


if __name__ == '__main__':
    main()
