#!/usr/bin/env python3
"""Resolve the private continuations after selector 26 allocation readback."""

import json
import subprocess

import z3

from audit_daemon_selector26_allocation_completion import check_completion
from audit_daemon_selector26_allocation_readback import (
    READBACK, READBACK_BRANCH, READ_SITES, WORD_COMPARE, stage_readback,
)
from audit_daemon_selector26_helper_consumers import authenticated_edge, return_from_call
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, replay_to_frontier, sections, sha,
)
from daemon_receive_tools import verify_original_fixups

COMPARE_BRANCH = 0x1009d131c
HELPER = 0x100444dfc
CALL = 0x100645f40
MISMATCH = (
    (COMPARE_BRANCH, 0x1010737e8, 0x100641ec4),
    (0x100641edc, 0x101089f00, 0x100a2d86c),
    (0x100a2d8c4, 0x10105bc00, 0x10065467c),
    (0x100654690, 0x1010840a8, 0x100981570),
    (0x100981574, 0x10103edf8, 0x10064b71c),
    (0x10064b75c, 0x10104ffa0, 0x100641f84),
    (0x100641f90, 0x10103a410, 0x100690548),
    (0x100690590, 0x1010489d0, 0x100645e9c),
    (CALL, 0x1010a01b0, HELPER),
    (0x100645f7c, 0x101067548, 0x10091e1c4),
    (0x10091e204, 0x101075648, 0x100923c34),
    (0x100923c70, 0x10105a598, 0x1009b83a0),
    (0x1009b83f4, 0x101056b90, 0x1009aabac),
    (0x1009aac48, 0x101055798, 0x100948d5c),
    (0x100948dd0, 0x10109ff58, 'libSystem/_malloc'),
)
EQUAL_READS = READ_SITES + (0x1006a0e44, 0x1006a0ff0) + READ_SITES + READ_SITES


def walk(frame, pc, edges, calls):
    for _ in range(5000):
        insn = next(CS.disasm(IMAGE.read(pc, 4), pc))
        if insn.mnemonic in ('blraa', 'braa'):
            slot, target = authenticated_edge(frame, insn)
            edges.append((pc, slot, target))
            if insn.mnemonic == 'braa':
                assert isinstance(target, int)
                pc = target
                continue
            argument = number(frame.read('x0'))
            calls.append((pc, target, argument))
            if target == HELPER and pc == CALL:
                assert argument == number(frame.read('x29')) - 0xa0
                frame.put(argument + 8, 8, z3.BitVec('late_helper_result', 64))
                return_from_call(frame, pc + 4)
            else:
                return pc
        elif insn.mnemonic == 'sxth':
            dst, src = (insn.reg_name(op.reg) for op in insn.operands)
            frame.write(dst, z3.SignExt(16, z3.Extract(15, 0, frame.read(src))))
        else:
            assert insn.mnemonic not in ('ret', 'retab', 'b', 'blr', 'bl')
            assert not insn.mnemonic.startswith(('b.', 'cb', 'tb'))
            frame.step(pc, pc + 4)
        pc += 4
    raise AssertionError('continuation exceeded its instruction bound')


def prepare(fixture, data, profiles):
    frame = replay_to_frontier(fixture, data, profiles)
    check_completion(frame)
    sp, base = (number(frame.read(reg)) for reg in ('sp', 'x14'))
    stage_readback(frame, sp, base)
    frame.step(READBACK, READBACK_BRANCH)
    branch = next(CS.disasm(IMAGE.read(READBACK_BRANCH, 4), READBACK_BRANCH))
    assert authenticated_edge(frame, branch) == (0x10103d890, WORD_COMPARE)
    return frame, sp, base


def check_path(fixture, data, profiles, equal):
    frame, sp, base = prepare(fixture, data, profiles)
    output, reference = frame.read('w14'), frame.get(sp + 0xa14, 4)
    assert z3.is_false(z3.simplify(output == reference))
    owner = number(frame.get(sp + 0xa20, 8))
    assert number(frame.get(owner + 0x18, 8)) == base
    if equal:
        frame.put(sp + 0xa14, 4, output)
    edges, calls = [], []
    load_start, store_start = len(frame.loads), len(frame.stores)
    frontier = walk(frame, WORD_COMPARE, edges, calls)
    loads = frame.loads[load_start:]
    assert [(pc, at - base, width) for pc, at, width in loads
            if at < base + 14 and base < at + width] == (
        [(pc, offset, 1) for offset, pc in enumerate(EQUAL_READS)] if equal else [])
    stores = frame.stores[store_start:]
    assert not any(at < base + 14 and base < at + width for _, at, width, _ in stores)
    assert [(at - sp, width, number(value)) for pc, at, width, value in stores if pc == 0x100654680] == [
        (0x418, 8, owner if equal else 0),
    ]
    assert number(frame.get(owner + 0x18, 8)) == base
    if equal:
        assert edges[0] == (COMPARE_BRANCH, 0x101073728, 0x10065467c)
        assert [(slot, target) for pc, slot, target in edges if pc == READBACK_BRANCH] == [
            (0x10103d8a0, 0x10063fc4c), (0x10103d8b0, 0x10099ae54), (0x10103d658, 0x10090a944),
        ]
        assert (0x1006a119c, 0x10103aca8, 0x10063f740) in edges
        assert [(pc, at - sp, width) for pc, at, width, _ in stores
                if pc in (0x10063f748, 0x10063f75c, 0x10090a950)] == [
            (0x10063f748, 0x82e, 2), (0x10063f75c, 0x200, 4),
            (0x10090a950, 0x67c, 4),
        ]
        assert [(at - sp, width) for pc, at, width in loads if pc == 0x10090a958] == [(0x82e, 2)]
        assert frontier == 0x100a17948 and len(edges) == 32
        assert calls == [(0x100a17948, 'libSystem/_malloc', 32)]
    else:
        assert frontier == 0x100948dd0 and tuple(edges) == MISMATCH
        assert calls == [(CALL, HELPER, number(frame.read('x29')) - 0xa0),
                         (0x100948dd0, 'libSystem/_malloc', 32)]
    return edges


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    slots = set()
    for equal in (False, True):
        first = check_path(0x98, data, profiles, equal)
        assert check_path(0x99, data, profiles, equal) == first
        slots.update(slot for _, slot, _ in first)
    assert len(verify_original_fixups(slots)['records']) == len(slots) == 39
    print(f'2 class profiles, 2 comparison outcomes, 14 equality-path reads, {len(slots)} fixups')


if __name__ == '__main__':
    main()
