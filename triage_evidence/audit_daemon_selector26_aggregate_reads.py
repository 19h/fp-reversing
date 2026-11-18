#!/usr/bin/env python3
"""Trace the pinned selector 26 callee from its first table lookup."""

import json
import subprocess

import z3
from z3.z3util import get_vars

from audit_daemon_selector26_aggregate_handoff import BUFFER, TABLE_LOAD, check_handoff, walk
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, sections, sha,
)
from daemon_receive_tools import verify_original_fixups

STOP = 0x1004a6210
EDGE = (0x1003ccd3c, 0x10105a1c0, 0x1004a55b0)
BANK_BASE = {
    0x1004a5db0: 'x27', 0x1004a5dec: 'x8', 0x1004a5e18: 'x26', 0x1004a5e84: 'x26',
    0x1004a5ef0: 'x26', 0x1004a5f14: 'x27', 0x1004a5f74: 'x26', 0x1004a5f94: 'x8',
    0x1004a5fe4: 'x27', 0x1004a602c: 'x27', 0x1004a6070: 'x30', 0x1004a60b4: 'x8',
    0x1004a60f0: 'x8', 0x1004a6168: 'x30', 0x1004a61b4: 'x30', 0x1004a620c: 'x30',
}


def assert_equal(left, right):
    solver = z3.Solver()
    solver.add(left != right)
    assert solver.check() == z3.unsat


def table_byte(table, index):
    values = [z3.BitVecVal(byte, 8) for byte in table]
    for bit in range(8):
        high = z3.Extract(bit, bit, index) == 1
        values = [z3.If(high, values[i + 1], values[i]) for i in range(0, len(values), 2)]
    return z3.simplify(values[0])


def replay_callee(frame, equal, outputs, constant):
    scratch = number(frame.read('x8'))
    words = [z3.simplify(frame.get(scratch + offset, 8)) for offset in (0, 8)]
    for offset, pc in ((0, 0x10098b9b4), (8, 0x10082aff8)):
        for address in range(scratch + offset, scratch + offset + 8):
            store = next(row for row in reversed(frame.stores) if row[1] <= address < row[1] + row[2])
            assert store[:3] == (pc, address, 1), store[:3]
    symbols = [get_vars(word) for word in words]
    assert all(len(row) == 1 and row[0].size() == 64
               and row[0].decl().name().startswith('aggregate_helper_result!') for row in symbols)
    assert not symbols[0][0].eq(symbols[1][0])
    substitutions = tuple((row[0], z3.BitVecVal(value, 64))
                          for row, value in zip(symbols, outputs, strict=True))

    def fix_outputs(value):
        if isinstance(value, z3.ExprRef):
            return z3.simplify(z3.substitute(value, *substitutions))
        return value

    for register, value in frame.regs.items():
        frame.regs[register] = fix_outputs(value)
    previous_load, previous_step = frame.load, frame.step
    first_load, first_store = len(frame.loads), len(frame.stores)
    initial_address = number(frame.read('x10'))
    assert constant['start'] <= initial_address < constant['start'] + constant['size_bytes']
    capacity = 96 if equal else 112
    payload, banks = [], []

    def load(address, width):
        address = fix_outputs(address)
        if frame.pc in BANK_BASE:
            assert width == 1
            _, offset, byte = payload[-1]
            base = number(frame.read(BANK_BASE[frame.pc]))
            index = z3.Extract(7, 0, address - base)
            assert_equal(address, base + z3.ZeroExt(56, index))
            assert constant['start'] <= base and base + 256 <= constant['start'] + constant['size_bytes']
            if frame.pc == 0x1004a5db0:
                assert_equal(index, byte ^ 0x16)
            sources, inputs = get_vars(byte), get_vars(index)
            assert inputs and all(any(var.eq(source) for source in sources) for var in inputs)
            banks.append((frame.pc, offset, base))
            return table_byte(IMAGE.read(base, 256), index)
        at = number(address)
        value = fix_outputs(previous_load(address, width))
        if at < BUFFER + capacity and BUFFER < at + width:
            assert width == 1 and BUFFER <= at and frame.pc >= 0x1004a5da0
            assert number(frame.read('x9')) == BUFFER
            assert_equal(value, frame.get(at, 1))
            assert get_vars(value), (hex(frame.pc), at - BUFFER)
            payload.append((frame.pc, at - BUFFER, value))
        return value

    def step(start, end):
        assert end == start + 4
        instruction = next(CS.disasm(IMAGE.read(start, 4), start))
        if instruction.mnemonic != 'extr':
            return previous_step(start, end)
        frame.pc = start
        destination, high, low = (instruction.reg_name(op.reg) for op in instruction.operands[:3])
        width = frame.width(destination)
        shift = instruction.operands[3].imm
        word = z3.Concat(frame.read(high), frame.read(low))
        frame.write(destination, z3.Extract(shift + width - 1, shift, word))

    frame.load, frame.step = load, step
    edges, calls = [], []
    assert walk(frame, TABLE_LOAD, edges, calls, limit=2000, stop=STOP) == STOP
    assert edges == [EDGE] and not calls
    loads = frame.loads[first_load:]
    assert (0x1004a55e4, number(frame.read('sp')) + 0x38, 8) in loads
    assert not any(at < BUFFER + capacity and BUFFER < at + width
                   for _, at, width, _ in frame.stores[first_store:])
    assert loads[0] == (TABLE_LOAD, initial_address, 1)
    scratch_reads = [(pc, at - scratch) for pc, at, width in loads if scratch <= at < scratch + 16 and width == 1]
    unique_payload = [(pc, offset) for pc, offset, _ in payload]
    assert len(payload) == len(banks) == 16
    return initial_address, scratch_reads, unique_payload, banks


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    image_sections = sections()
    data = [row for row in image_sections if row['segment'] == '__DATA']
    constant, = [row for row in image_sections if row['segment'] == '__TEXT' and row['section'] == '__const']
    reference = None
    output_fixtures = (((0, 0), 0x100e786ed), ((0x0102030405060708, 0x1112131415161718), 0x100e786ef))
    for outputs, expected_lookup in output_fixtures:
        for equal in (False, True):
            for fixture in (0x98, 0x99):
                frame, _ = check_handoff(fixture, data, profiles, equal)
                lookup, scratch, payload, banks = replay_callee(frame, equal, outputs, constant)
                assert lookup == expected_lookup
                assert sorted(offset for _, offset in scratch) == [i for i in range(16) if i != 6]
                assert [offset for _, offset in payload] == [2, 8, 1, 9, 5, 10, 13, 12, 6, 14, 3, 4, 0, 11, 7, 15]
                if reference is None:
                    reference = scratch, payload, banks
                assert reference == (scratch, payload, banks), (fixture, equal, outputs, banks)
    assert len(verify_original_fixups({EDGE[1]})['records']) == 1
    print('8 replay cases, 2 initial lookup addresses, 16 aggregate byte reads, 16 following table reads')


if __name__ == '__main__':
    main()
