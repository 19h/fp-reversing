#!/usr/bin/env python3
"""Recover the list extent and the empty/nonempty split after allocation."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_callers import DATA, FP, INPUT
from audit_daemon_selector26_constructor import normal_malloc_return
from audit_daemon_selector26_header import HEADER
from audit_daemon_selector26_node import route
from audit_daemon_selector26_padding import GUARD, MALLOC_PC, RETURN, JoinedFrame, frame
from audit_daemon_selector26_record_origin import FOURTH
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import FIXUPS, SOURCE, TABLE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

ENTRY = 0x1000c6b94
CHECK = 0x10020f0c8
ADVANCE = 0x1000c0898
NONEMPTY = 0x100083e80
TRANSFER = 0x1000e661c
SKIP = 0x100034ec8
OWNER = 0x7000
INITIAL = (
    (ENTRY, 0x1000c6bd0, 0x1000c6bc8, 0x10106a660, 0x8041, 0x100011ef4),
    (0x100011ef4, 0x100011f2c, 0x100011f1c, 0x101084d50, 0xfdf3, 0x1000bfd58),
)


def count_proofs():
    count, size = z3.BitVecs('prior_count node_extent', 32)
    node = 0x8000
    f = JoinedFrame(x9=node, w8=count, w11=0x5ff0)
    f.put(node + 16, 4, size)
    f.step(CHECK, 0x10020f0f4)
    sum64 = z3.ZeroExt(32, size) + z3.ZeroExt(32, count)
    limit = z3.ULE(sum64, 0xffffffff)
    carry_branch = solve('node_sum_carry_dispatch', [], z3.Or(
        f.read('w12') != size, f.read('w23') != 0xb11,
        f.read('w10') != z3.If(limit, z3.BitVecVal(0x5ff0, 32), z3.BitVecVal(0x600f, 32))))
    f = JoinedFrame(x9=node, w8=count, w11=0x5ff0, w12=size)
    next_pointer = z3.BitVec('node_next', 64)
    f.put(node, 8, next_pointer)
    f.step(ADVANCE, 0x1000c08e4)
    next_index = z3.If(next_pointer == 0, z3.BitVecVal(0x8cd5, 32), z3.BitVecVal(0x8cee, 32))
    step = solve('advance_adds_extent_then_selects_on_next_pointer', [limit], z3.Or(
        z3.ZeroExt(32, f.read('w8')) != sum64, f.read('x9') != next_pointer,
        f.read('w10') != 0x6246, f.read('w11') != 0x5ff0, f.read('w12') != next_index))
    return [carry_branch, step]


def head_proofs():
    size = z3.BitVec('first_extent', 32)
    source, dest = z3.BitVecs('first_source allocation_base', 64)
    node = 0x8000
    f = JoinedFrame(x0=dest, x10=node, w8=0x500c0e89, w12=0x87d1, x30=TABLE)
    f.put(node + 16, 4, size)
    f.put(node + 24, 8, source)
    f.step(NONEMPTY, 0x100084050)
    index = z3.If(size == 0, z3.BitVecVal(0x87d1, 32), z3.BitVecVal(0x87d6, 32))
    dispatch = solve('first_node_extent_zero_partition', [], f.read('w12') != index)
    assert f.step(TRANSFER, 0x1000e66c0) == 0x100090998
    last = z3.ZeroExt(32, size) - 1
    transfer = solve('first_positive_node_transfer_initial_state', [size != 0], z3.Or(
        f.read('x12') != source, f.read('x13') != last,
        f.read('x14') != dest + last, f.read('x15') != (source + last) << 3))
    return [dispatch, transfer]


def walk(f, nodes, extents):
    start, edges = route(f, ENTRY, INITIAL)
    first_target = CHECK if nodes else GUARD[0]
    first_slot = 0x101080660 if nodes else 0x101080598
    start, first_edge = route(f, start, (
        (0x1000bfd58, 0x1000bfdac, 0x1000bfda4, first_slot, 0x92ed, first_target),))
    edges.extend(first_edge)
    assert number(f.read('w8')) == 0 and number(f.read('x9')) == (nodes[0] if nodes else 0)
    assert number(f.read('w10')) == 0x6246
    total = 0
    for index, (node, extent) in enumerate(zip(nodes, extents)):
        assert number(f.read('x9')) == node and number(f.read('w8')) == total
        next_node = nodes[index + 1] if index + 1 < len(nodes) else 0
        target, slot = (CHECK, 0x101080660) if next_node else (GUARD[0], 0x101080598)
        start, step = route(f, start, (
            (CHECK, 0x10020f104, 0x10020f0f4, 0x101069e70, 0x8041, ADVANCE),
            (ADVANCE, 0x1000c08ec, 0x1000c08e4, slot, 0x92ed, target),
        ))
        total += extent
        assert number(f.read('w8')) == total and number(f.read('x9')) == next_node
        edges.extend(step)
    assert start == GUARD[0] and number(f.read('w10')) == 0x6246
    return total, edges


def profile(extents):
    f = frame(0, 0x2c, FOURTH)
    f.seed('w28', 0x8934)
    f.seed('w16', 0x8b3dc651)
    f.put(FP - 0xb8, 8, OWNER)
    nodes = [0x8000 + index * 32 for index in range(len(extents))]
    f.put(OWNER, 8, nodes[0] if nodes else 0)
    for node, following, extent in zip(nodes, nodes[1:] + [0], extents):
        f.put(node, 8, following)
        f.put(node + 16, 4, extent)
        f.put(node + 24, 8, node + 0x2000)

    total, count_edges = walk(f, nodes, extents)
    expected_loads = [(0x100011efc, FP - 0xb8, 8), (0x1000bfd80, OWNER, 8)]
    for node in nodes:
        expected_loads.extend(((0x10020f0d8, node + 16, 4), (0x1000c08c4, node, 8)))
    assert [row for row in f.loads if row[0] in {load[0] for load in expected_loads}] == expected_loads
    assert not f.stores and number(f.read('x20')) == OWNER
    assert number(f.get(SP + 0x90, 8)) == INPUT

    start, admitted = route(f, GUARD[0], (GUARD,))
    assert f.step(start, MALLOC_PC + 4) == 'libSystem/_malloc'
    pad = 16 - ((total + 10) & 15)
    allocation = normal_malloc_return(f, MALLOC_PC, total + 10 + pad, DATA)
    split = ((0x1000859ec, 0x100085a60, 0x100085a2c, 0x101046b78, 0x9dfb, NONEMPTY)
             if nodes else HEADER[0])
    start, buffer_edges = route(f, RETURN[0], (RETURN, split))
    assert number(f.read('x7')) == DATA and number(f.read('x6')) == INPUT
    assert (0x100085a14, OWNER, 8) in f.loads
    if nodes:
        assert number(f.read('x10')) == nodes[0]
        slot, target = (0x10107dda0, TRANSFER) if extents[0] else (0x10107dd78, SKIP)
        start, head_edges = route(f, start, (
            (NONEMPTY, 0x100084058, 0x100084050, slot, 0x8f7b, target),))
        buffer_edges.extend(head_edges)
        if extents[0]:
            start, transfer_edges = route(f, start, (
                (TRANSFER, 0x1000e66bc, 0x1000e6658, 0x10104dea8, 0x17c9, 0x100090998),))
            assert (TRANSFER, nodes[0] + 24, 8) in f.loads
            assert number(f.read('x13')) == extents[0] - 1
            assert number(f.read('x14')) == DATA + extents[0] - 1
            buffer_edges.extend(transfer_edges)
        else:
            assert (NONEMPTY + 0x1c, nodes[0] + 16, 4) in f.loads
            assert f.step(start, 0x100034f20) == (0x100083e80 if len(nodes) > 1 else 0x10008a358)
            assert (0x100034ef0, nodes[0], 8) in f.loads
            assert number(f.read('x10')) == (nodes[1] if len(nodes) > 1 else 0)
            assert all(address != nodes[0] + 24 for _, address, _ in f.loads)
            buffer_edges.append(f.edges[-1])

    return {'node_extents_bytes': extents, 'total_bytes': total, 'padding_bytes': pad,
            'count_edges': count_edges, 'guard_edges': admitted,
            'allocation': allocation, 'buffer_edges': buffer_edges}


def report():
    cases = [profile(extents) for extents in ([], [0], [0, 14], [14], [14, 14], [5, 0, 21])]
    proofs = count_proofs() + head_proofs()
    assert all(check['result'] == 'unsat' for check in proofs)
    overflow_slot = 0x101069f68
    FIXUP_SLOTS.add(overflow_slot)
    assert FIXUPS[overflow_slot]['target'] == 0x100013334
    assert 'div=0x8041 ad=0 key=IA' in FIXUPS[overflow_slot]['annotation']
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'native_exchange_observed': False, 'proofs': proofs, 'profiles': cases,
            'source_spans': list(SPANS.values()), 'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
