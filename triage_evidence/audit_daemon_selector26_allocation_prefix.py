#!/usr/bin/env python3
"""Verify the first ten writes into the private selector 26 allocation."""

import json
import subprocess

import z3
from capstone.arm64_const import ARM64_OP_REG

from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, NEXT_BLOCK, REPLAY, SOURCE, check_consumer, check_prior_writes,
    number, overlapping_stores, replay_to_frontier, sections, sha,
)
from audit_daemon_selector26_helper_consumers import authenticated_edge
from daemon_receive_tools import verify_original_fixups

EDGES = (
    (NEXT_BLOCK, 0x100652184, 0x1006d4db0, 0x1010435a8),
    (0x1006d4db0, 0x1006d4dd8, 0x1006574d0, 0x1010698b8),
    (0x1006574d0, 0x1006577f0, 0x100908b18, 0x10103a038),
    (0x100908b18, 0x100908b4c, 0x100a18e10, 0x10104f740),
    (0x100a18e10, 0x100a18e20, NEXT_BLOCK, 0x101055670),
    (NEXT_BLOCK, 0x100652184, 0x1009e1914, 0x101043888),
    (0x1009e1914, 0x1009e1920, 0x10070c470, 0x101074de0),
)
WRITES = (0x100651d1c, 0x100651ec0, 0x1006520bc, 0x100652170, 0x100657668,
          0x1006577e8, 0x100651d1c, 0x100651ec0, 0x1006520bc, 0x100652170)


def extend_lift(frame):
    previous = frame.step

    def step(start, end):
        for insn in CS.disasm(IMAGE.read(start, end - start), start):
            args = insn.operands
            if insn.mnemonic == 'ror':
                source = frame.read(insn.reg_name(args[1].reg))
                value = z3.RotateRight(source, args[2].imm)
            elif insn.mnemonic == 'lsr' and args[2].type == ARM64_OP_REG:
                source = frame.read(insn.reg_name(args[1].reg))
                shift = frame.read(insn.reg_name(args[2].reg)) & (source.size() - 1)
                value = z3.LShR(source, shift)
            else:
                previous(insn.address, insn.address + 4)
                continue
            frame.pc = insn.address
            frame.write(insn.reg_name(args[0].reg), value)

    frame.step = step


def check_prefix(frame, sp):
    check_prior_writes(frame, sp)
    check_consumer(frame, sp)
    base = number(frame.read('x17'))
    field = number(frame.read('x16'))
    assert (field, base) == (0x29000 + 0x18, 0x2a000)
    assert number(frame.get(sp + 0x250, 8)) == field
    assert not overlapping_stores(frame, base, 14)
    assert all(base + offset not in frame.ram for offset in range(14))
    first_store, first_load = len(frame.stores), len(frame.loads)
    extend_lift(frame)
    for start, branch, target, slot in EDGES:
        frame.step(start, branch)
        instruction = next(CS.disasm(IMAGE.read(branch, 4), branch))
        assert instruction.mnemonic == 'braa'
        assert authenticated_edge(frame, instruction) == (slot, target)
        assert any(start <= pc < branch and (address, width) == (slot, 8)
                   for pc, address, width in frame.loads)
    assert number(frame.read('sp')) == sp
    assert [(pc, address, size) for pc, address, size, _ in frame.stores[first_store:]] == [
        (pc, base + offset, 1) for offset, pc in enumerate(WRITES)
    ]
    assert [address for address in range(base, base + 14) if address in frame.ram] == list(range(base, base + 10))
    assert [(pc, address, width) for pc, address, width in frame.loads[first_load:]
            if address == field or base <= address < base + 14] == [
        (0x100651b20, field, 8), (0x1006574d0, field, 8), (0x100651b20, field, 8),
    ]
    assert [(insn.mnemonic, insn.op_str)
            for insn in CS.disasm(IMAGE.read(0x10070c470, 16), 0x10070c470)] == [
        ('ldr', 'w13, [sp, #0x1f8]'), ('ldr', 'w9, [sp, #0x1c0]'),
        ('cmp', 'w13, w9, sxth'), ('cset', 'w11, lt'),
    ]


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {p['class']: p for p in saved['profiles'] if p['outcome']['frontier'] == hex(FRONTIER)}
    data_sections = [section for section in sections() if section['segment'] == '__DATA']
    for fixture in (0x98, 0x99):
        frame = replay_to_frontier(fixture, data_sections, profiles)
        check_prefix(frame, number(frame.read('sp')))
    assert len(verify_original_fixups({slot for _, _, _, slot in EDGES})['records']) == 7
    print('2 matched profiles, 10 allocation writes per class, 7 original fixups')


if __name__ == '__main__':
    main()
