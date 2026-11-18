#!/usr/bin/env python3
"""Trace the aggregate pointer from the caller into the next private helper."""

import json
import subprocess

import z3

from audit_daemon_selector26_aggregate import BUFFER, MALLOC, check_aggregate, trace, walk
from audit_daemon_selector26_record_consumer import CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha
from daemon_receive_tools import verify_original_fixups

CALL = 0x10072c304
CALLEE = 0x100457e28
TABLE_LOAD = 0x1003cc84c
CALLEE_EDGES = (
    (0x100458014, 0x10107afa0, 0x1005142f4),
    (0x10051432c, 0x101087e18, 0x100467788),
    (0x1004677d4, 0x10108b7b0, 0x1003ce340),
    (0x1003ce390, 0x101075b10, 0x10040e378),
    (0x10040e530, 0x10107fe90, 0x1003cc7b0),
)
RECORD_READS = (
    (0x100457f7c, 8, 4), (0x100457f80, 0x18, 4), (0x1005142f8, 0x20, 8),
    (0x10046778c, 0xc, 4), (0x10046779c, 0x28, 8), (0x1003ce340, 0, 8),
)


def check_handoff(fixture, data, profiles, equal):
    frame, _ = check_aggregate(fixture, data, profiles, equal)
    sp = number(frame.read('sp'))
    arg = number(frame.read('x29')) - 0xa0
    stores = len(frame.stores)
    edges = trace(frame, 0x100948dd0, 0x38000, (0x100a2fc00, MALLOC, 26), 2)
    edges.extend(trace(frame, 0x100a2fc00, 0x39000, (CALL, CALLEE, arg), 53))
    assert edges[-1] == (CALL, 0x1010a0208, CALLEE)
    assert number(frame.read('sp')) == sp
    assert [(offset, number(frame.get(arg + offset, 8))) for offset in (0, 0x10, 0x20, 0x28)] == [
        (0, BUFFER), (0x10, sp + 0xaf0), (0x20, sp + 0xae0), (0x28, BUFFER),
    ]
    for offset, writer in ((0, 0x10072c278), (0x28, 0x10072c2a8)):
        last_store = next(row for row in reversed(frame.stores[stores:])
                          if row[1] <= arg + offset < row[1] + row[2])
        assert last_store[1:3] == (arg + offset, 8)
        assert number(last_store[3]) == BUFFER
        assert last_store[0] == writer

    first_load = len(frame.loads)
    frame.seed('x30', CALL + 4)
    # Model the authenticated return address as the logical link at entry.
    assert next(CS.disasm(IMAGE.read(CALLEE, 4), CALLEE)).mnemonic == 'pacibsp'
    frame.step(CALLEE + 4, 0x100457e5c)
    frame.step(0x100457e5c, 0x100457ea4)
    callee_edges, calls = [], []
    assert walk(frame, 0x100457ea4, callee_edges, calls, stop=TABLE_LOAD) == TABLE_LOAD
    assert tuple(callee_edges) == CALLEE_EDGES and not calls
    assert [(pc, at - arg, width) for pc, at, width in frame.loads[first_load:]
            if at < arg + 0x30 and arg < at + width] == list(RECORD_READS)
    capacity = 96 if equal else 112
    assert not any(at < BUFFER + capacity and BUFFER < at + width
                   for _, at, width in frame.loads[first_load:])
    assert [(ins.mnemonic, ins.op_str) for ins in CS.disasm(IMAGE.read(TABLE_LOAD, 8), TABLE_LOAD)] == [
        ('ldrb', 'w10, [x10]'), ('ldrb', 'w14, [x8, #3]'),
    ]
    assert number(frame.read('x8')) == sp + 0xae0
    address = frame.read('x10')
    for relation in (address == 0x100e786ed, address != 0x100e786ed):
        solver = z3.Solver()
        solver.add(relation)
        assert solver.check() == z3.sat
    return frame, edges + callee_edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    slots = set()
    for equal in (False, True):
        _, first = check_handoff(0x98, data, profiles, equal)
        _, second = check_handoff(0x99, data, profiles, equal)
        assert second == first
        slots.update(slot for _, slot, _ in first)
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(f'4 replay cases, 60 handoff edges, {len(slots)} chained fixups')


if __name__ == '__main__':
    main()
