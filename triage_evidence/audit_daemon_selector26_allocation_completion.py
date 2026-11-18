#!/usr/bin/env python3
"""Check the final four byte stores and the next missing frame input."""

import json
import subprocess

import z3
from capstone.arm64_const import ARM64_EXT_SXTH

from audit_daemon_selector26_allocation_prefix import WRITES, check_prefix
from audit_daemon_selector26_helper_consumers import authenticated_edge
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, NEXT_BLOCK, REPLAY, SOURCE, number, overlapping_stores,
    replay_to_frontier, sections, sha,
)
from daemon_receive_tools import FIXUPS, TABLE, verify_original_fixups

COMPARE = 0x10070c470
COMPARE_BRANCH = 0x10070c498
WRITER_ENTRY_BRANCH = 0x100a18e20
WRITER_EXIT_BRANCH = 0x100652184
END = 0x10064633c
ALTERNATE = 0x1010892d8
EXPECTED_PREFIX = (
    (COMPARE_BRANCH, 0x1010894f0, 0x10092e844),
    (0x10092e880, 0x10105d198, 0x100902b04),
    (0x100902b48, 0x101075830, 0x10068fb70),
    (0x10068fbdc, 0x10104f740, 0x100a18e10),
    (WRITER_ENTRY_BRANCH, 0x101055670, NEXT_BLOCK),
    (WRITER_EXIT_BRANCH, 0x1010436c8, 0x1009a9d1c),
)


def enable_sxth(frame):
    original = frame.operand

    def operand(instruction, field, width):
        if field.ext == ARM64_EXT_SXTH:
            value = frame.read(instruction.reg_name(field.reg))
            return z3.SignExt(width - 16, z3.Extract(15, 0, value))
        return original(instruction, field, width)

    frame.operand = operand


def check_comparison(frame, sp):
    assert [number(frame.get(sp + off, 4)) for off in (0x1f8, 0x1c0, 0x1b8, 0x1c8)] == [
        0xffff86b4, 0x9546, 0xbd, 0x9e7d,
    ]
    frame.step(COMPARE, COMPARE_BRANCH - 8)
    assert number(frame.read('w11')) == (0x9e7d ^ 0xbd)

    original_half = frame.get(sp + 0x1f8, 4)
    half = z3.BitVec('signed_gate_halfword', 16)
    frame.put(sp + 0x1f8, 4, z3.SignExt(16, half))
    frame.step(COMPARE, COMPARE_BRANCH - 8)
    expected = z3.If(half < z3.BitVecVal(0x9546, 16), z3.BitVecVal(0x9ec0, 32),
                     z3.BitVecVal(0x9e7d, 32))
    solver = z3.Solver()
    solver.add(frame.read('w11') != expected)
    assert solver.check() == z3.unsat
    frame.put(sp + 0x1f8, 4, original_half)
    assert TABLE + 8 * 0x9e7d == ALTERNATE
    assert FIXUPS[ALTERNATE]['target'] == 0x1008781e8
    assert FIXUPS[ALTERNATE]['annotation'] == '(div=0xC2FE ad=0 key=IA)'


def walk_to_missing_input(frame, sp, base, field):
    pc = COMPARE
    edges = []
    for _ in range(8000):
        if pc == END:
            break
        instruction = next(CS.disasm(IMAGE.read(pc, 4), pc))
        op = instruction.mnemonic
        if op == 'braa':
            slot, target = authenticated_edge(frame, instruction)
            edges.append((pc, slot, target))
            assert isinstance(target, int)
            if pc == WRITER_ENTRY_BRANCH:
                assert number(frame.read('x16')) == field
                assert number(frame.read('x11')) == 0x71134a47fbd9f0c1
                assert z3.is_true(z3.simplify(frame.read('w28') == frame.get(sp + 0x178, 4)))
            pc = target
            continue
        assert op not in {'bl', 'blr', 'blraa', 'ret', 'retab'}
        assert not op.startswith(('b.', 'cb', 'tb')) and op != 'b'
        frame.step(pc, pc + 4)
        pc += 4
    assert pc == END
    assert tuple(edges[:len(EXPECTED_PREFIX)]) == EXPECTED_PREFIX
    assert edges[-1] == (0x10063ddb8, 0x10104c798, 0x100646334)
    assert number(frame.read('sp')) == sp
    assert overlapping_stores(frame, base, 14) == [
        (site, base + off, 1) for off, site in enumerate(WRITES + WRITES[:4])
    ]
    assert all(base + offset in frame.ram for offset in range(14))
    missing = next(CS.disasm(IMAGE.read(END, 4), END))
    assert (missing.mnemonic, missing.op_str) == ('ldr', 'x15, [sp, #0x938]')
    assert not overlapping_stores(frame, sp + 0x938, 8)
    assert all(sp + 0x938 + offset not in frame.ram for offset in range(8))
    return edges


def check_completion(frame):
    sp = number(frame.read('sp'))
    check_prefix(frame, sp)
    field = number(frame.get(sp + 0x250, 8))
    base = number(frame.get(field, 8))
    first_load = len(frame.loads)
    enable_sxth(frame)
    check_comparison(frame, sp)
    assert number(frame.get(sp + 0x188, 4)) == 0x8b3dc655
    edges = walk_to_missing_input(frame, sp, base, field)
    assert [(pc, address, width) for pc, address, width in frame.loads[first_load:]
            if address < base + 14 and base < address + width] == []
    field_loads = [(pc, address, width) for pc, address, width in frame.loads[first_load:]
                   if address == field]
    assert field_loads == [(0x100651b20, field, 8), (0x10063dd8c, field, 8)]
    assert number(frame.read('x14')) == base
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data_sections = [section for section in sections() if section['segment'] == '__DATA']
    traces = [check_completion(replay_to_frontier(fixture, data_sections, profiles))
              for fixture in (0x98, 0x99)]
    assert traces[0] == traces[1]
    slots = {slot for _, slot, _ in traces[0]} | {ALTERNATE}
    assert len(verify_original_fixups(slots)['records']) == len(slots)
    print(f'2 matched class paths, 14 byte writes each, {len(traces[0])} edges, {len(slots)} fixups')


if __name__ == '__main__':
    main()
