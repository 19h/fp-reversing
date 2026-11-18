#!/usr/bin/env python3
"""Verify the allocation readback and its decoded comparison input."""

import json
import subprocess
from struct import iter_unpack

import z3

from audit_daemon_selector26_allocation_completion import END, check_completion
from audit_daemon_selector26_helper_consumers import authenticated_edge
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, REPLAY, SOURCE, number, overlapping_stores, replay_to_frontier, sections, sha,
)
from daemon_receive_tools import FIXUPS, TABLE, verify_original_fixups

READBACK = 0x1009736fc
WORD_COMPARE = 0x1009d12bc
STAGING_BRANCH = 0x1006468fc
READBACK_BRANCH = 0x100973ed0
READ_SITES = (0x100973934, 0x100973998, 0x100973cf4, 0x100973ea0)
UNKNOWN_QWORDS = (
    0x938, 0x958, 0x978, 0x998, 0x9b8, 0x9b0, 0x9c8, 0x8f8, 0x8e8, 0x8d8,
    0x8c8, 0x8b8, 0xa30, 0x9c0, 0x908, 0xa28, 0x2a8, 0x570, 0x518, 0x900,
    0x4f8, 0x470, 0x578, 0x298, 0x6f8, 0x600, 0x758, 0x6d8, 0x380, 0x310,
)
UNKNOWN_HALVES = (0x872, 0x896, 0x886, 0x82e)


def stage_readback(frame, sp, base):
    original_load = frame.load
    missing = []

    def load(address, width):
        at = number(address)
        cells = range(at, at + width)
        if sp <= at < at + width <= sp + 0x1c00 and any(cell not in frame.ram for cell in cells):
            assert all(cell not in frame.ram for cell in cells)
            assert not overlapping_stores(frame, at, width)
            missing.append((at - sp, width))
            frame.put(at, width, z3.BitVec(f'frame_input_{at-sp:x}', width * 8))
        return original_load(address, width)

    frame.load = load
    frame.step(END, STAGING_BRANCH)
    frame.load = original_load
    assert missing == [(off, 8) for off in UNKNOWN_QWORDS] + [(off, 2) for off in UNKNOWN_HALVES]
    branch = next(CS.disasm(IMAGE.read(STAGING_BRANCH, 4), STAGING_BRANCH))
    assert branch.mnemonic == 'braa'
    assert authenticated_edge(frame, branch) == (0x10105fca8, READBACK)
    assert number(frame.read('x14')) == base
    assert (number(frame.read('x19')) + 0x99e5a6f4cfd4506a) % (1 << 64) == 0
    assert number(frame.read('w16')) == 0x734


def read_and_compare(frame, sp, base):
    actual = [frame.get(base + offset, 1) for offset in range(4)]
    symbolic = [z3.BitVec(f'allocation_byte_{offset}', 8) for offset in range(4)]
    for offset, value in enumerate(symbolic):
        frame.put(base + offset, 1, value)
    load_start = len(frame.loads)
    frame.step(READBACK, READBACK_BRANCH)
    branch = next(CS.disasm(IMAGE.read(READBACK_BRANCH, 4), READBACK_BRANCH))
    assert branch.mnemonic == 'braa'
    assert authenticated_edge(frame, branch) == (0x10103d890, WORD_COMPARE)
    assert [(pc, at, width) for pc, at, width in frame.loads[load_start:]
            if at < base + 14 and base < at + width] == [
        (pc, base + offset, 1) for offset, pc in enumerate(READ_SITES)
    ]
    word = z3.simplify(frame.read('w14'))
    assert number(frame.read('sp')) == sp
    assert set(z3.z3util.get_vars(word)) == set(symbolic)
    for value in symbolic:
        changed = z3.FreshConst(value.sort())
        solver = z3.Solver()
        solver.add(word != z3.substitute(word, (value, changed)))
        assert solver.check() == z3.sat
    assert number(frame.get(sp + 0x26c, 4)) == 0xb22f
    reference = frame.get(sp + 0xa14, 4)
    frame.step(WORD_COMPARE, 0x1009d1304)
    expected = z3.If(word == reference, z3.BitVecVal(0x7307, 32), z3.BitVecVal(0x731f, 32))
    solver = z3.Solver()
    solver.add(frame.read('w10') != expected)
    assert solver.check() == z3.unsat
    for index, target in ((0x7307, 0x10065467c), (0x731f, 0x100641ec4)):
        row = FIXUPS[TABLE + 8 * index]
        assert row['target'] == target and row['annotation'] == '(div=0x95ED ad=0 key=IA)'
    for offset, value in enumerate(actual):
        frame.put(base + offset, 1, value)


def candidate_stores(text):
    fields = UNKNOWN_QWORDS[:5]
    patterns = {0xf90003e0 | ((offset // 8) << 10): offset for offset in fields}
    start = text['start']
    hits = [(start + index * 4, patterns[word & ~31]) for index, (word,) in
            enumerate(iter_unpack('<I', IMAGE.read(start, text['size_bytes']))) if word & ~31 in patterns]
    candidate = (0x1006f5b08, 0x1006f5b2c, 0x1006f5b34, 0x1006f5b4c, 0x1006f5d6c)
    assert [sum(offset == field for _, offset in hits) for field in fields] == [23, 33, 65, 79, 183]
    assert [(pc, offset) for pc, offset in hits if pc in candidate] == list(zip(candidate, (
        0x998, 0x958, 0x938, 0x978, 0x9b8,
    )))


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    all_sections = sections()
    data = [row for row in all_sections if row['segment'] == '__DATA']
    for fixture in (0x98, 0x99):
        frame = replay_to_frontier(fixture, data, profiles)
        check_completion(frame)
        sp, base = (number(frame.read(reg)) for reg in ('sp', 'x14'))
        stage_readback(frame, sp, base)
        read_and_compare(frame, sp, base)
    candidate_stores(next(row for row in all_sections if row['segment'] == '__TEXT' and row['section'] == '__text'))
    slots = {0x10105fca8, 0x10103d890, 0x101073728, 0x1010737e8}
    assert len(verify_original_fixups(slots)['records']) == 4
    print('2 matched class paths, 34 missing fields per class, 4 allocation bytes read, 4 fixups')


if __name__ == '__main__':
    main()
