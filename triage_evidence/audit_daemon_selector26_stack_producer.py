#!/usr/bin/env python3
"""Audit original selector 26 predecessor and stack-producer fragments offline."""

import json
import subprocess

import z3

from audit_daemon_selector26_return import FIXUP_SLOTS, SP, Frame, number
from daemon_receive_tools import CS, FIXUPS, IMAGE, ROOT, TABLE, verify_original_fixups

PHASE = 0xb22f
STATUS = 0x8b3dc651
HALFWORD = 0x1742
GATE = 0x10069a06c
WRITER = 0x1009dcfcc
SIBLING = 0x100962ce8


def sampled_frame(**registers):
    frame = Frame(x21=TABLE, x30=TABLE, **registers)
    # Supply distinct sentinels to check exact store widths and source cells.
    for offset, width, value in (
        (0x28, 8, 0x1200), (0x4f8, 8, 0x3800), (0x26c, 4, PHASE),
        (0x288, 8, 0x2800), (0x878, 8, 0x1020304050607080),
        (0x874, 4, 0x12345678), (0x79c, 4, 0x93a7c025),
        (0x618, 8, 0x281e3733), (0x750, 8, 0xcd2400),
        (0x2d8, 8, 0x4000), (0x280, 8, 0x3110),
    ):
        frame.put(SP + offset, width, value)
    return frame


def select_fragment(frame, start, end, target, slot):
    branch = end - 4
    frame.step(start, branch)
    insn = next(CS.disasm(IMAGE.read(branch, 4), branch))
    assert insn.mnemonic == 'braa'
    destination, modifier = insn.op_str.split(', ')
    assert number(frame.read(destination)) == FIXUPS[slot]['target'] == target
    assert (f'div=0x{number(frame.read(modifier)):X} ad=0 key=IA'
            in FIXUPS[slot]['annotation'])
    assert any(start <= pc < branch and (address, width) == (slot, 8)
               for pc, address, width in frame.loads)


def check_predecessors():
    for start, end, seed in (
        (0x10065f160, 0x10065f198, {'w8': 0x2435}),
        (0x100974074, 0x10097409c, {'w14': 0x86e814b9}),
    ):
        frame = sampled_frame(**seed)
        select_fragment(frame, start, end, GATE, 0x10104c098)
        assert number(frame.read('w8')) == PHASE
        assert number(frame.read('x30')) == TABLE
        if start == 0x10065f160:
            assert number(frame.get(SP + 0x750, 8)) == 0x4a0a
        else:
            assert number(frame.get(SP + 0x79c, 4)) == 0x86e814b9


def check_selector_predicate():
    status = z3.BitVec('gate_status', 32)
    halfword = z3.BitVec('gate_halfword', 16)
    frame = sampled_frame(w8=PHASE)
    frame.put(SP + 0x86c, 4, status)
    frame.put(SP + 0x872, 2, halfword)
    frame.put(SP + 0x438, 8, 0)
    frame.step(GATE, 0x10069a0b8)
    exact_match = z3.And(status == STATUS, halfword == HALFWORD)
    solver = z3.Solver()
    expected = z3.If(exact_match, z3.BitVecVal(0xc846, 32), z3.BitVecVal(0xc84a, 32))
    solver.add(frame.read('w11') != expected)
    assert solver.check() == z3.unsat


def check_arms():
    for status_match in (False, True):
        for halfword_match in (False, True):
            for pointer in (0, 0x2810):
                frame = sampled_frame(w8=PHASE)
                status = STATUS ^ int(not status_match)
                halfword = HALFWORD ^ int(not halfword_match)
                frame.put(SP + 0x86c, 4, status)
                frame.put(SP + 0x872, 2, halfword)
                frame.put(SP + 0x438, 8, pointer)
                if status_match and halfword_match:
                    select_fragment(frame, GATE, 0x10069a0c4, SIBLING, 0x10109e120)
                    select_fragment(frame, SIBLING, 0x100962d10, 0x1006449d8, 0x10106da70)
                    assert number(frame.get(SP + 0x70c, 4)) == STATUS
                    select_fragment(frame, 0x1006449d8, 0x100644a00, 0x10063ee68, 0x1010641e8)
                    assert number(frame.get(0x4000, 8)) == pointer
                    continue

                select_fragment(frame, GATE, 0x10069a0c4, WRITER, 0x10109e140)
                slot, target = (0x1010761a0, 0x100645600) if pointer else (0x101076218, 0x100967f08)
                select_fragment(frame, WRITER, 0x1009dd05c, target, slot)
                for offset, width, value in (
                    (0x7f0, 8, pointer), (0x910, 4, status), (0x916, 2, halfword),
                    (0x918, 4, 0x12345678), (0x91c, 4, 0x93a7c025),
                    (0x920, 8, 0x281e3733), (0x770, 8, 0xcd2400),
                ):
                    assert number(frame.get(SP + offset, width)) == value
                if not pointer:
                    select_fragment(frame, 0x100967f08, 0x100967f50, 0x100981e0c, 0x101052f98)
                    assert number(frame.get(SP + 0x70c, 4)) == 0x74c29d88


def check_original_replay():
    audit = json.loads(subprocess.check_output(
        ['zstd', '-dc', str(ROOT / 'daemon_selector26_helper_consumers_audit.json.zst')]
    ))
    profiles = [row for row in audit['profiles'] if row['outcome']['frontier'] == '0x10094326c']
    assert {p['class'] for p in profiles} == {'AvpFairPlayDriver', 'com_apple_driver_FairPlayIOKit'}
    for profile in profiles:
        edges = profile['authenticated_edges']
        assert edges[-1] == {'pc': '0x1009d0af8', 'slot': '0x101048cd0', 'target': '0x100943260'}
        assert {'0x10069a06c', '0x1009dcfcc'}.isdisjoint(edge['target'] for edge in edges)
    FIXUP_SLOTS.add(0x101048cd0)
    load = next(CS.disasm(IMAGE.read(0x10094326c, 4), 0x10094326c))
    assert (load.mnemonic, load.op_str) == ('ldrsh', 'w12, [sp, #0x916]')


if __name__ == '__main__':
    check_predecessors()
    check_selector_predicate()
    check_arms()
    check_original_replay()
    records = verify_original_fixups(FIXUP_SLOTS)
    assert len(records['records']) == 9
    print('2 predecessors, 8 gate cases, 1 full-domain proof, 2 saved profiles, 9 fixups')
