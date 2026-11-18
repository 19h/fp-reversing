#!/usr/bin/env python3
"""Trace selector 26 aggregate writeback and its private record result."""

import json
import subprocess

import z3
from z3.z3util import get_vars

from audit_daemon_selector26_aggregate_handoff import CALL, check_handoff
from audit_daemon_selector26_aggregate_reads import BUFFER, STOP, replay_callee, walk
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha,
)
from audit_daemon_selector26_postprocess import authenticated_edge
from daemon_receive_tools import verify_original_fixups

STATUS = 0x10031615c
RETURN = 0x100316194
NEXT = 0x10072c334
READ_ORDER = (2, 8, 1, 9, 5, 10, 13, 12, 6, 14, 3, 4, 0, 11, 7, 15)
WRITE_ORDER = (0, 6, 11, 2, 5, 3, 15, 9, 8, 10, 4, 1, 12, 13, 14, 7)
LOOP_EDGES = ((0x1004a7a2c, 0x10107da70, 0x100609fec),
              (0x10060a05c, 0x10105a1c0, 0x1004a55b0))
EXIT_EDGES = ((0x1004a7a2c, 0x101075cb8, 0x1004a51dc),
              (0x1004a520c, 0x10106e080, STATUS))


def check_writeback(fixture, data, profiles, equal, outputs, seed, constant):
    frame, _ = check_handoff(fixture, data, profiles, equal)
    record = number(frame.get(number(frame.read('sp')), 8))
    caller_sp = number(frame.read('sp')) + 0x240
    scratch = number(frame.read('x8'))
    capacity = 96 if equal else 112
    helpers = [get_vars(z3.simplify(frame.get(scratch + offset, 8)))[0] for offset in (0, 8)]
    substitutions = [(symbol, z3.BitVecVal(value, 64))
                     for symbol, value in zip(helpers, outputs, strict=True)]
    children = {var for offset in range(capacity)
                for var in get_vars(frame.get(BUFFER + offset, 1))
                if var.decl().name().startswith('child_')}
    assert len(children) == (82 if equal else 96)
    for symbol in children:
        offset = int(symbol.decl().name().rsplit('_', 1)[1])
        substitutions.append((symbol, z3.BitVecVal((seed * (offset + 1)) & 255, 8)))

    def concrete(value):
        if isinstance(value, z3.ExprRef):
            return z3.simplify(z3.substitute(value, *substitutions))
        return value

    original_load = frame.load
    aggregate_before = bytes(number(concrete(frame.get(BUFFER + i, 1))) for i in range(capacity))
    _, _, prefix, _ = replay_callee(frame, equal, outputs, constant)
    assert tuple(offset for _, offset in prefix) == READ_ORDER
    for register, value in frame.regs.items():
        frame.regs[register] = concrete(value)

    def load(address, width):
        return concrete(original_load(concrete(address), width))

    frame.load = load
    first_load, first_store = len(frame.loads), len(frame.stores)
    edges, calls = [], []
    assert walk(frame, STOP, edges, calls, limit=35000, stop=STATUS) == STATUS
    assert edges == list(LOOP_EDGES) * (capacity // 16 - 1) + list(EXIT_EDGES) and not calls
    loads, stores = frame.loads[first_load:], frame.stores[first_store:]
    writes = [(pc, at - BUFFER, width) for pc, at, width, _ in stores
              if BUFFER <= at < BUFFER + capacity]
    expected_reads = [block + offset for block in range(16, capacity, 16) for offset in READ_ORDER]
    expected_writes = [block + offset for block in range(0, capacity, 16) for offset in WRITE_ORDER]
    assert [(at - BUFFER, width) for _, at, width in loads if BUFFER <= at < BUFFER + capacity] == [
        (offset, 1) for offset in expected_reads]
    assert [(at, width) for _, at, width in writes] == [(offset, 1) for offset in expected_writes]
    callee_sp = number(frame.read('sp'))
    assert all(callee_sp <= at and at + width <= caller_sp or
               BUFFER <= at and at + width <= BUFFER + capacity for _, at, width, _ in stores)
    store_sites = tuple(pc for pc, _, _ in writes[:16])
    assert [pc for pc, _, _ in writes] == list(store_sites) * (capacity // 16)
    aggregate_after = bytes(number(frame.get(BUFFER + i, 1)) for i in range(capacity))
    assert aggregate_after != aggregate_before

    assert number(frame.read('x0')) == record
    result = number(frame.read('w8'))
    frame.step(STATUS, STATUS + 4)
    assert frame.stores[-1][:3] == (STATUS, record + 0x1c, 4)
    assert number(frame.get(record + 0x1c, 4)) == result

    for pc in range(STATUS + 4, 0x100316174, 4):
        frame.step(pc, pc + 4)
    assert number(frame.read('x8')) == number(frame.read('x9'))
    assert next(CS.disasm(IMAGE.read(RETURN, 4), RETURN)).mnemonic == 'retab'
    for pc in range(0x100316178, RETURN, 4):
        frame.step(pc, pc + 4)
    assert number(frame.read('sp')) == caller_sp and number(frame.read('x30')) == CALL + 4
    assert number(frame.read('x29')) - 0xa0 == record
    assert walk(frame, CALL + 4, [], [], stop=NEXT) == NEXT
    assert number(frame.read('w5')) == result
    slot, target = authenticated_edge(frame, next(CS.disasm(IMAGE.read(NEXT, 4), NEXT)))
    return (result, slot, target, store_sites), aggregate_after


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    image_sections = sections()
    data = [row for row in image_sections if row['segment'] == '__DATA']
    constant, = [row for row in image_sections if (row['segment'], row['section']) == ('__TEXT', '__const')]
    slots = {slot for _, slot, _ in LOOP_EDGES + EXIT_EDGES}
    for equal in (False, True):
        for fixture in (0x98, 0x99):
            results = [check_writeback(fixture, data, profiles, equal, (0, 0), seed, constant)
                       for seed in (0, 17)]
            (first_result, first_aggregate), (second_result, second_aggregate) = results
            assert first_result == second_result
            assert first_aggregate != second_aggregate
            for (result, slot, target, sites), _ in results:
                slots.add(slot)
                print(hex(fixture), equal, hex(result), hex(slot), hex(target),
                      ' '.join(map(hex, sites)), flush=True)
    assert len(verify_original_fixups(slots)['records']) == len(slots)


if __name__ == '__main__':
    main()
