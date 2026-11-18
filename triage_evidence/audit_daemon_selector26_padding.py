#!/usr/bin/env python3
"""Audit the allocation and positive-padding route to both selector 26 records."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_callers import Caller, DATA, FP, INPUT, caller, fields
from audit_daemon_selector26_constructor import normal_malloc_return
from audit_daemon_selector26_header import HEADER, WRITERS
from audit_daemon_selector26_node import route
from audit_daemon_selector26_record_origin import FOURTH, SECOND, OriginFrame
from audit_daemon_selector26_return import FIXUP_SLOTS, RECORD, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import FIXUPS, SOURCE, selected, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

GUARD = (0x1000ee4e8, 0x1000ee5b0, 0x1000ee5a0, 0x101088c78, 0x6ff9, 0x10008f46c)
RETURN = (0x10008f4e4, 0x10008f50c, 0x10008f4fc, 0x101060830, 0xf6ab, 0x1000859ec)
PADDING = (0x1000fe08c, 0x1000fe3d8, 0x1000fe3d0, 0x10106d040, 0xa57c, 0x100011f88)
LOOP = 0x100011f88
SPLIT = 0x1000c62f0
LOOP_SLOT, EXIT_SLOT = 0x10106d040, 0x10106d138
GUARD_REJECT_SLOT = 0x10106b120
MALLOC_PC, MALLOC_SLOT = 0x10008f4e0, 0x10109ff58
PADDING_STORE = 0x100011fa0
LENGTH_KEY = 0x37c30c43


class JoinedFrame(Caller, OriginFrame):
    """Use the original bank readers for both the allocation and caller blocks."""


def frame(total, selector, bank):
    f = JoinedFrame()
    # Reuse the caller's stack, context and globals for the shared continuation.
    downstream = caller(0, selector)
    f.regs.update(downstream.regs)
    f.ram.update(downstream.ram)
    f.seed('w8', total)
    f.seed('w10', 0x6246)
    f.seed('x20', 0x7000)
    f.put(0x7000, 8, 0)
    f.put(SP + 0x90, 8, INPUT)
    f.put(FP - 0xe8, 8, bank[0])
    f.put(FP - 0xf0, 8, bank[1])
    return f


def size_proofs():
    total = z3.BitVec('incoming_w8', 32)
    pad = 16 - ((total + 10) & 15)
    subtotal = z3.ZeroExt(32, total) + z3.ZeroExt(32, pad)
    extent = subtotal + 10
    admitted = z3.ULE(total, 0xffffffe5)
    accepted_index = z3.BitVecVal(0x9db1, 32)
    rejected_index = z3.BitVecVal(0x6246, 32)
    f = frame(total, 0x2c, FOURTH)
    f.step(GUARD[0], GUARD[2])
    proofs = [
        solve('padding_and_guard_from_original_size_block', [], z3.Or(
            f.read('w21') != 0x4d28, f.read('w19') != LENGTH_KEY - pad,
            f.read('x22') != z3.ZeroExt(32, pad),
            f.read('w9') != z3.If(z3.ULT(subtotal, 0xfffffff6), accepted_index, rejected_index))),
        solve('admission_exact_u32_range', [], z3.Or(
            z3.ULT(subtotal, 0xfffffff6) != admitted,
            z3.ULT(pad, 1), z3.UGT(pad, 16))),
    ]
    assert f.step(GUARD[-1], MALLOC_PC + 4) == 'libSystem/_malloc'
    proofs.append(solve('admitted_malloc_argument_and_saved_extent', [admitted], z3.Or(
        f.read('w24') != 0x1983, f.read('x0') != extent, f.get(SP + 0x130, 8) != extent,
        z3.ULT(extent, 16), z3.UGT(extent, 0xfffffff0), (extent & 15) != 0)))
    return proofs


def loop_proofs():
    base = 0x49bbb99
    pad, index = z3.BitVecs('pad loop_index', 64)
    initial = JoinedFrame(x22=pad, w11=0x662a)
    initial.step(0x1000fe378, PADDING[2])
    first = solve('positive_padding_header_exit', [z3.UGE(pad, 1), z3.ULE(pad, 16)],
                  z3.Or(initial.read('x9') != base + pad, initial.read('w14') != 0x662a,
                        initial.read('w13') != 0x63))
    loop = JoinedFrame(x9=base + pad, x12=index, w11=0x662a, w13=0x63)
    loop.step(LOOP, PADDING_STORE)
    # Check the control recurrence separately from the byte store at the symbolic address.
    loop.step(PADDING_STORE + 4, 0x100011fec)
    repeats = z3.ULT(index + 1, pad)
    expected_index = z3.If(repeats, z3.BitVecVal(0x662a, 32), z3.BitVecVal(0x6649, 32))
    second = solve('padding_loop_counter_and_exit', [z3.ULE(pad, 16), z3.ULT(index, pad)],
                   z3.Or(loop.read('x15') != index + 1, loop.read('w12') != expected_index))
    return [first, second]


def profile(total, direct, bank):
    pad = 16 - ((total + 10) & 15)
    extent = total + 10 + pad
    selector = 0x2c if direct else 0x2d
    f = frame(total, selector, bank)
    start, edges = route(f, GUARD[0], (GUARD,))
    assert number(f.read('x22')) == pad
    assert f.step(start, MALLOC_PC + 4) == 'libSystem/_malloc'
    assert f.edges[-1]['slot'] == hex(MALLOC_SLOT)
    assert (0x10008f4d4, MALLOC_SLOT, 8) in f.loads
    assert number(f.get(SP + 0x130, 8)) == extent
    assert all(DATA + offset not in f.ram for offset in range(extent))
    allocation = normal_malloc_return(f, MALLOC_PC, extent, DATA)

    start, header_edges = route(f, RETURN[0], (RETURN, HEADER[0], PADDING))
    assert start == LOOP
    assert number(f.read('x7')) == DATA
    assert number(f.read('x8')) == DATA + 10 and number(f.read('x12')) == 0
    padding_edges = []
    for index in range(pad):
        last = index + 1 == pad
        slot, dest = (EXIT_SLOT, SPLIT) if last else (LOOP_SLOT, LOOP)
        start, step = route(f, start, ((LOOP, 0x100011ff8, 0x100011fec, slot, 0xa57c, dest),))
        assert number(f.read('x12')) == index + 1
        padding_edges.extend(step)
    assert number(f.read('w10')) == 0xa4c7

    target = f.step(start, 0x1000c635c)
    assert target == (0x1000f20f4 if direct else 0x100111684)
    assert (0x1000c62f0, INPUT, 1) in f.loads
    call = 0x1000f2204 if direct else 0x100111754
    assert f.step(target, call + 4) == (0x10043a018 if direct else 0x10043ee28)
    assert number(f.read('x0')) == RECORD
    assert z3.is_false(z3.simplify(fields(f, direct, extent)))
    writes = [(pc, at - DATA, width, number(value)) for pc, at, width, value in f.stores
              if at < DATA + extent and DATA < at + width]
    prefix = b'\x00\x00\x00\x00\x50\xdb' + pad.to_bytes(4, 'big')
    expected = [(pc, offset, 1, value) for offset, (pc, value) in enumerate(zip(WRITERS, prefix))]
    expected.extend((PADDING_STORE, 10 + offset, 1, 0) for offset in range(pad))
    assert writes == expected
    return {'incoming_total_bytes': total, 'padding_bytes': pad, 'allocation': allocation,
            'dispatch_byte': hex(selector), 'bank_left': hex(bank[0]),
            'guard_edges': edges, 'header_edges': header_edges, 'padding_edges': padding_edges,
            'call_edges': f.edges,
            'allocation_relative_byte_writes': [
                {'pc': hex(pc), 'offset_bytes': offset, 'value': byte}
                for pc, offset, _, byte in writes]}


def report():
    bank_checks = [selected(*bank, 0xd7, 0xcb81) for bank in (FOURTH, SECOND)]
    for row in bank_checks:
        assert (row['constant'], row['slot'], row['target'], row['inputs_checked']) == (
            '0x8c', hex(MALLOC_SLOT), 'libSystem/_malloc', 256)
    FIXUP_SLOTS.add(GUARD_REJECT_SLOT)
    rejected = FIXUPS[GUARD_REJECT_SLOT]
    assert rejected['target'] == 0x100013334 and 'div=0x6FF9 ad=0 key=IA' in rejected['annotation']
    proofs = size_proofs() + loop_proofs()
    assert all(result['result'] == 'unsat' for result in proofs)
    profiles = [profile(total, direct, bank) for total in range(16)
                for direct, bank in ((True, FOURTH), (False, SECOND))]
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'native_exchange_observed': False, 'proofs': proofs, 'bank_checks': bank_checks,
            'profiles': profiles, 'source_spans': list(SPANS.values()),
            'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
