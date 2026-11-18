#!/usr/bin/env python3
"""Audit selector 26's private record consumer with the unobserved fields symbolic."""

import json
import subprocess

import z3

from audit_daemon_selector26_helper_consumers import (
    ADAPTER, CS, FALLBACK, IMAGE, SHARED, SOURCE, continuation, initial_attempt,
    input_model, lookup, number, primary_check, retire, sections, sha, walk,
)
from audit_daemon_selector26_stack_producer import select_fragment
from daemon_receive_tools import ROOT, TABLE, verify_original_fixups

REPLAY = ROOT / 'daemon_selector26_helper_consumers_audit.json.zst'
FRONTIER = 0x10094326c
MISSING = ((0x910, 4), (0x916, 2), (0x918, 4), (0x91c, 4))
KNOWN = ((0x9ee, 2, 0x1009b83b4), (0x9f0, 4, 0x1009b83b8),
         (0x9f4, 4, 0x1009b83bc), (0x26c, 4, 0x100a6305c))
TAIL = (
    {'pc': '0x100a2fc30', 'slot': '0x10107ec68', 'target': '0x1009d0ac0'},
    {'pc': '0x1009d0af8', 'slot': '0x101048cd0', 'target': '0x100943260'},
)
NEXT_SLOT = 0x101055670
NEXT_BLOCK = 0x100651b1c
DEFERRED_SLOT = TABLE + 8 * 0x12d7


def replay_to_frontier(byte, data_sections, saved_profiles):
    frame, entry, _ = initial_attempt(byte, 0x70)
    if entry == FALLBACK:
        entry = primary_check(frame, True)
    row, after = lookup(frame, entry, 'success bit clear', 0)
    assert retire(frame, row, after) == ADAPTER
    input_model(frame, data_sections)
    assert walk(frame, (0x23000, 0x24000))[0] == SHARED
    allocations = tuple(range(0x25000, 0x2b000, 0x1000))
    result = continuation(frame, number(frame.read('x0')), allocations)
    frontier, helper_calls, _, calls, edges, returns, width = result
    assert (frontier, width) == (FRONTIER, 2)
    saved = saved_profiles[row['class']]
    assert saved['allocations'] == list(allocations)
    assert saved['authenticated_edges'] == edges and tuple(edges[-2:]) == TAIL
    assert saved['helper_calls'] == list(map(hex, helper_calls))
    assert saved['calls'] == calls and saved['returns'] == returns
    assert [(register, number(frame.read(register))) for register in ('x30', 'w26', 'w22')] == [
        ('x30', TABLE), ('w26', 0x12d7), ('w22', 0xb22f),
    ]
    return frame


def overlapping_stores(frame, address, width):
    return [(pc, start, size) for pc, start, size, _ in frame.stores
            if start < address + width and address < start + size]


def check_prior_writes(frame, sp):
    for offset, width in MISSING + ((0x86c, 4), (0x872, 2), (0x874, 4)):
        address = sp + offset
        assert not overlapping_stores(frame, address, width)
        assert all(address + i not in frame.ram for i in range(width))
    for offset, width, pc in KNOWN:
        address = sp + offset
        assert overlapping_stores(frame, address, width) == [(pc, address, width)]
        assert all(address + i in frame.ram for i in range(width))
    assert number(frame.get(sp + 0x26c, 4)) == 0xb22f


def check_consumer(frame, sp):
    half = z3.BitVec('record_halfword', 16)
    word, aux = z3.BitVecs('record_word record_aux', 32)
    for offset, width, value in ((0x916, 2, half), (0x918, 4, word), (0x91c, 4, aux)):
        frame.put(sp + offset, width, value)

    pointer_pairs = ((0x478, 0x248), (0x2d0, 0x250), (0x300, 0x240), (0x5b8, 0x228))
    pointer_inputs = {}
    absent = []
    for source, destination in pointer_pairs:
        for i in range(8):
            address = sp + source + i
            if address not in frame.ram:
                frame.put(address, 1, z3.BitVec(f'pointer_byte_{source:x}_{i}', 8))
                absent.append(source + i)
        pointer_inputs[destination] = frame.get(sp + source, 8)
    assert absent == [offset + i for offset in (0x478, 0x300, 0x5b8) for i in range(8)]

    other_half = frame.get(sp + 0x9ee, 2)
    other_word = frame.get(sp + 0x9f0, 4)
    other_aux = frame.get(sp + 0x9f4, 4)
    mask = 0x01263f51
    previous_step = frame.step

    def step(start, end):
        for insn in CS.disasm(IMAGE.read(start, end - start), start):
            if insn.address in (0x10094326c, 0x1009432d0):
                assert insn.mnemonic == 'ldrsh' and insn.op_str.startswith('w12, [sp,')
                frame.pc = insn.address
                value = frame.load(frame.address(insn, insn.operands[1]), 2)
                frame.write('w12', z3.SignExt(16, value))
            else:
                previous_step(insn.address, insn.address + 4)

    frame.step = step
    select_fragment(frame, FRONTIER, 0x1009434b4, NEXT_BLOCK, NEXT_SLOT)
    frame.step = previous_step
    assert number(frame.read('sp')) == sp
    assert [(pc, at - sp, width) for pc, at, width in frame.loads
            if FRONTIER <= pc < 0x1009434b0 and sp <= at < sp + 0x1000] == [
        (0x10094326c, 0x916, 2), (0x100943278, 0x918, 4),
        (0x100943294, 0x478, 8), (0x1009432a0, 0x91c, 4),
        (0x1009432c4, 0x2d0, 8), (0x1009432d0, 0x9ee, 2),
        (0x1009432e4, 0x9f4, 4), (0x1009432f0, 0x300, 8),
        (0x1009432fc, 0x5b8, 8), (0x100943308, 0x9f0, 4),
        (0x100943338, 0x26c, 4),
    ]
    signed_half = z3.SignExt(16, half)
    signed_other = z3.SignExt(16, other_half)
    equals = z3.If(word == 0x8b3dc655, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    expected = {
        0x180: equals, 0x170: aux ^ mask, 0x1fc: signed_half,
        0x1f4: signed_half ^ 0xffffcbf9, 0x1e0: word ^ mask,
        0x1f8: signed_other, 0x1e8: signed_other ^ 0xffff9da3,
        0x178: other_aux ^ mask, 0x188: other_word, 0x1d8: other_word ^ mask,
    }
    solver = z3.Solver()
    mismatches = [frame.get(sp + offset, 4) != value for offset, value in expected.items()]
    mismatches.extend(frame.get(sp + offset, 8) != value + 0x18
                      for offset, value in pointer_inputs.items())
    solver.add(z3.Or(*mismatches))
    assert solver.check() == z3.unsat
    assert number(frame.read('x24')) == NEXT_BLOCK

    published = number(frame.read('x16'))
    assert overlapping_stores(frame, published, 8)[-1] == (0x100a2fc08, published, 8)
    frame.step(NEXT_BLOCK, NEXT_BLOCK + 8)
    assert frame.loads[-2:] == [(NEXT_BLOCK, DEFERRED_SLOT, 8), (NEXT_BLOCK + 4, published, 8)]
    assert number(frame.read('x17')) == 0x2a000


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {p['class']: p for p in saved['profiles'] if p['outcome']['frontier'] == hex(FRONTIER)}
    assert set(profiles) == {'AvpFairPlayDriver', 'com_apple_driver_FairPlayIOKit'}
    data_sections = [section for section in sections() if section['segment'] == '__DATA']
    for byte in (0x98, 0x99):
        frame = replay_to_frontier(byte, data_sections, profiles)
        sp = number(frame.read('sp'))
        check_prior_writes(frame, sp)
        check_consumer(frame, sp)
    slots = {int(edge['slot'], 16) for edge in TAIL} | {NEXT_SLOT, DEFERRED_SLOT}
    assert len(verify_original_fixups(slots)['records']) == 4
    print('2 matched replays, 14 symbolic field relations per class, 4 original fixups')


if __name__ == '__main__':
    main()
