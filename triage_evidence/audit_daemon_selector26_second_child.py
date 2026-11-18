#!/usr/bin/env python3
"""Follow successful allocation returns to the common selector 26 child reload."""

import json
import subprocess

import z3

from audit_daemon_selector26_readback_continuations import WORD_COMPARE, prepare, walk
from audit_daemon_selector26_helper_consumers import authenticated_edge, return_from_call
from audit_daemon_selector26_record_consumer import (
    CS, FRONTIER, IMAGE, NEXT_BLOCK, NEXT_SLOT, REPLAY, SOURCE, number, sections, sha,
)
from audit_daemon_selector26_stack_producer import select_fragment
from daemon_receive_tools import verify_original_fixups

CONSUMER = 0x100943260
CONSUMER_BRANCH = 0x1009434b0
OWNER = 0x2b000
CHILD = 0x2c000


def check_consumer(frame, sp, original_owner, equal):
    assert number(frame.read('x16')) == OWNER + 0x18
    assert number(frame.read('w22')) == 0xb22f
    assert number(frame.read('w26')) == (0x1325 if equal else 0x12d7)
    saved_owner = frame.get(sp + 0x5b8, 8)
    load_start = len(frame.loads)
    for insn in CS.disasm(IMAGE.read(CONSUMER, CONSUMER_BRANCH - CONSUMER), CONSUMER):
        if insn.mnemonic == 'ldrsh':
            dst, mem = insn.operands
            frame.pc = insn.address
            halfword = frame.load(frame.address(insn, mem), 2)
            frame.write(insn.reg_name(dst.reg), z3.SignExt(16, halfword))
        else:
            frame.step(insn.address, insn.address + 4)
    dispatch = next(CS.disasm(IMAGE.read(CONSUMER_BRANCH, 4), CONSUMER_BRANCH))
    assert authenticated_edge(frame, dispatch) == (NEXT_SLOT, NEXT_BLOCK)
    assert [(pc, at - sp, width) for pc, at, width in frame.loads[load_start:]
            if pc in (0x1009432c4, 0x1009432fc)] == [
        (0x1009432c4, 0x2d0, 8), (0x1009432fc, 0x5b8, 8),
    ]
    assert number(frame.get(sp + 0x250, 8)) == (original_owner if equal else OWNER) + 0x18
    solver = z3.Solver()
    solver.add(frame.get(sp + 0x228, 8) != saved_owner + 0x18)
    assert solver.check() == z3.unsat
    if equal:
        assert number(frame.get(sp + 0x228, 8)) == OWNER + 0x18
    table_slot = 0x101043818 if equal else 0x1010435a8
    frame.step(NEXT_BLOCK, NEXT_BLOCK + 8)
    assert frame.loads[-2:] == [(NEXT_BLOCK, table_slot, 8), (NEXT_BLOCK + 4, OWNER + 0x18, 8)]
    assert number(frame.read('x17')) == CHILD
    return table_slot


def check_return(fixture, data, profiles, equal):
    frame, sp, base = prepare(fixture, data, profiles)
    original_owner = number(frame.get(sp + 0xa20, 8))
    assert number(frame.get(original_owner + 0x18, 8)) == base
    if equal:
        frame.put(sp + 0xa14, 4, frame.read('w14'))
    owner_call = walk(frame, WORD_COMPARE, [], [])
    slots, calls = [], []
    store_start, load_start = len(frame.stores), len(frame.loads)
    return_from_call(frame, owner_call + 4, OWNER)
    child_call = walk(frame, owner_call + 4, slots, calls)
    if equal:
        assert owner_call == 0x100a17948 and child_call == 0x100a5dcec
        owner_store = (0x100a17950, sp + 0x5b8, 8, OWNER)
        payload_store, extent_store, extent = 0x100a5dcf4, 0x100a5dc98, 26
        assert slots == [(0x100a1797c, 0x1010756c8, 0x100a5dc7c),
                         (child_call, 0x10109ff58, 'libSystem/_malloc')]
        fragments = ((0x100a5dcf0, 0x100a5dd2c, 0x10063d924, 0x101093dc8),
                     (0x10063d924, 0x10063d95c, CONSUMER, 0x101048cd0))
    else:
        assert owner_call == 0x100948dd0 and child_call == 0x100a2fc00
        owner_store = (0x100948dd8, sp + 0x2d0, 8, OWNER)
        payload_store, extent_store, extent = 0x100a2fc08, 0x100a2fbb8, 14
        assert slots == [(0x100948e14, 0x10105c310, 0x100a2fa8c),
                         (child_call, 0x10109ff58, 'libSystem/_malloc')]
        fragments = ((0x100a2fc04, 0x100a2fc34, 0x1009d0ac0, 0x10107ec68),
                     (0x1009d0ac0, 0x1009d0afc, CONSUMER, 0x101048cd0))
    assert calls == [(child_call, 'libSystem/_malloc', extent)]
    assert number(frame.read('x20')) == OWNER
    return_from_call(frame, child_call + 4, CHILD)
    for fragment in fragments:
        select_fragment(frame, *fragment)
    table_slot = check_consumer(frame, sp, original_owner, equal)
    assert [(pc, at, n, number(value)) for pc, at, n, value in frame.stores[store_start:]
            if (pc, at) == owner_store[:2] or OWNER <= at < OWNER + 32] == [
        owner_store,
        (0x100a5dc90 if equal else 0x100a2fab8, OWNER, 8, 0),
        (0x100a5dc90 if equal else 0x100a2fab8, OWNER + 8, 8, 0),
        (extent_store, OWNER + 0x10, 4, extent),
        (payload_store, OWNER + 0x18, 8, CHILD),
    ]
    assert number(frame.read('sp')) == sp
    assert number(frame.get(original_owner + 0x18, 8)) == base
    for at, width in ((base, 14), (CHILD, extent)):
        assert not any(p < at + width and at < p + n for _, p, n in frame.loads[load_start:])
        assert not any(p < at + width and at < p + n for _, p, n, _ in frame.stores[store_start:])
    fixups = {slot for _, slot, _ in slots} | {row[3] for row in fragments} | {NEXT_SLOT, table_slot}
    return frame, original_owner, fixups


def main():
    saved = json.loads(subprocess.check_output(['zstd', '-dc', str(REPLAY)]))
    assert sha(SOURCE) == saved['daemon_sha256']
    profiles = {row['class']: row for row in saved['profiles'] if row['outcome']['frontier'] == hex(FRONTIER)}
    data = [row for row in sections() if row['segment'] == '__DATA']
    slots = set()
    for equal in (False, True):
        _, _, first = check_return(0x98, data, profiles, equal)
        _, _, second = check_return(0x99, data, profiles, equal)
        assert second == first
        slots.update(first)
    assert len(verify_original_fixups(slots)['records']) == len(slots) == 9
    print('2 classes, 2 comparison outcomes, 4 new child reloads, 9 chained fixups')


if __name__ == '__main__':
    main()
