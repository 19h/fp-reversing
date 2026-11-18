#!/usr/bin/env python3
"""Join the five-node constructor to the list serializer and caller-record split."""

from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_constructor import normal_malloc_return
from audit_daemon_selector26_decode import RESTART, consume
from audit_daemon_selector26_list_extent import ENTRY, walk
from audit_daemon_selector26_list_transfer import (
    BYTE_LOOP, NODE_DONE, NONEMPTY_EDGE, TRAILER_SETUP, TransferFrame,
)
from audit_daemon_selector26_node import PROFILES, READBACK, REFILL, fill, route
from audit_daemon_selector26_padding import GUARD, LOOP, MALLOC_PC, PADDING, RETURN, SPLIT
from audit_daemon_selector26_readback import CONSUME, READ_PC, SECOND_INSERT
from audit_daemon_selector26_record_origin import CONTEXT, FP, RECORD, OriginFrame, SECOND
from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import IMAGE, SOURCE, TABLE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha

BIAS_STORE, BYTE_STORE = 0x10005be74, 0x1001f511c
JOIN = 0x1001e2e00
AFTER_THIRD = (
    (JOIN, 0x1001e2e0c, 0x10002bfd8, 0x101041a60, 0x7cb2, 0x100098968),
    (0x100098968, 0x1000989bc, 0x1000989b4, 0x101083458, 0x6ff9, 0x1001343c0),
    (0x1001343c0, 0x100134424, 0x100134410, 0x101056c38, 0xa551, 0x10002bfd0),
    *RESTART[-3:],
)
AFTER_FOURTH = (
    (JOIN, 0x1001e2e0c, 0x10002bfd8, 0x101041a40, 0x7cb2, 0x10008797c),
    (0x10008797c, 0x1000879c0, 0x1000879b8, 0x10104c918, 0xe2c, 0x10007fa24),
    (0x10007fa24, 0x10007fa80, 0x10007fa6c, 0x101056c38, 0xa551, 0x10002bfd0),
    *RESTART[-3:],
)
AFTER_FIFTH = ((JOIN, 0x1001e2e0c, 0x10002bfd8, 0x101041960, 0x7cb2, ENTRY),)


def adjusted_byte_proofs():
    record = z3.BitVec('aligned_caller_record', 64)
    word = z3.BitVec('caller_sp_4c', 32)
    f = OriginFrame(x29=record + 0x78, w24=0x3941)
    f.put(SP + 0x4c, 4, word)
    f.step(0x1001f50b0, 0x1001f5108)
    f.step(0x1001f510c, BYTE_STORE)
    g = OriginFrame(x0=record)
    g.step(0x100411240, 0x100411290)
    actual = z3.Extract(7, 0, f.read('w8') - g.read('w16'))
    expected = z3.Extract(7, 0, 2 * word + (word ^ 0xef) + 0x3e)
    return [
        solve('adjusted_dispatch_byte_cancels_record_address', [(record & 15) == 0], actual != expected),
        solve('descriptor_iff_caller_sp_4c_low_byte_is_zero', [(record & 15) == 0],
              (actual == 0x2d) != (z3.Extract(7, 0, word) == 0)),
    ]


def caller_record(word, words):
    f = OriginFrame(x29=RECORD + 0x78, x28=TABLE, w24=0x3941, x20=CONTEXT,
                    x22=0x6100, x26=0x6104, w25=0x7d18d723, w27=0x297027a6)
    f.put(SP + 0x4c, 4, word)
    f.put(SP + 0x40, 8, SECOND[0])
    f.put(SP + 0x38, 8, SECOND[1])
    f.put(0x6100, 4, words[0])
    f.put(0x6104, 4, words[1])
    f.step(0x1001f50b0, BYTE_STORE)
    landmark(BYTE_STORE, 'sturb', 'w8, [x29, #-0x78]')
    SPANS[BYTE_STORE, BYTE_STORE + 4] = {'start': hex(BYTE_STORE), 'end_exclusive': hex(BYTE_STORE + 4),
                                         'bytes_hex': IMAGE.read(BYTE_STORE, 4).hex()}
    f.store(f.read('x29') - 0x78, 1, f.read('w8'), BYTE_STORE)
    assert f.step(BYTE_STORE + 4, 0x1001f517c) == 0x1004110fc
    assert number(f.read('x0')) == RECORD
    return f


def append_node(f, start, node, buffer, linked):
    assert start == 0x10001bc34 and f.step(start, 0x10001bca0) == 'libSystem/_malloc'
    allocations = [normal_malloc_return(f, 0x10001bc9c, 32, node)]
    start, before_fill = route(f, 0x10001bca0, REFILL[:1])
    assert f.step(start, 0x100015af8) == 'libSystem/_malloc'
    allocations.append(normal_malloc_return(f, 0x100015af4, 14, buffer))
    start, refill = route(f, 0x100015af8, REFILL[1:])
    fill_edges, _ = fill(f, node, buffer)
    start = 0x10007ff30
    readback_edges = []
    for existing in linked:
        start, head = route(f, start, READBACK)
        assert number(f.read('x0')) == number(f.get(existing + 24, 8))
        f.step(start, READ_PC)
        start, inspect = route(f, READ_PC, CONSUME + SECOND_INSERT[:2])
        readback_edges.extend(head + inspect)
    start, insert = route(f, start, SECOND_INSERT[2:] + RESTART[:2])
    assert start == JOIN
    assert number(f.get(linked[-1], 8)) == node
    assert number(f.get(node + 8, 8)) == linked[-1]
    return allocations, before_fill + refill + fill_edges + readback_edges + insert


def construct(words, locations):
    owner, first, first_buffer, second, second_buffer = locations
    f, start, _ = consume(words, locations)
    start, _ = route(f, start, SECOND_INSERT + RESTART)
    nodes = [first, second]
    buffers = [first_buffer, second_buffer]
    visits = []
    for i, edges in enumerate((AFTER_THIRD, AFTER_FOURTH, AFTER_FIFTH)):
        node = 0x52000 + i * 0x200
        buffer = node + 0x40
        allocations, internal = append_node(f, start, node, buffer, nodes)
        nodes.append(node)
        buffers.append(buffer)
        start, continuation = route(f, JOIN, edges)
        visits.append({'linked_nodes': len(nodes), 'allocations': allocations,
                       'edges': internal + continuation})
    assert start == ENTRY and number(f.read('w16')) == 0x8b3dc651 and number(f.read('w28')) == 0x8934
    assert number(f.get(FP - 0xb8, 8)) == owner
    assert number(f.get(owner, 8)) == nodes[0] and number(f.get(owner + 8, 8)) == nodes[-1]
    assert [(number(f.get(node, 8)), number(f.get(node + 16, 4)), number(f.get(node + 24, 8)))
            for node in nodes] == [(following, 14, addr)
                                   for following, addr in zip(nodes[1:] + [0], buffers)]
    assert number(f.get(SP + 0x90, 8)) == RECORD
    assert not any(addr <= RECORD < addr + width for _, addr, width in f.loads)
    assert not any(addr <= RECORD < addr + size for _, addr, size, _ in f.stores)
    bias_store, = [(pc, addr, width) for pc, addr, width, _ in f.stores
                   if addr < SP + 0x40 and SP + 0x38 < addr + width]
    assert bias_store == (BIAS_STORE, SP + 0x38, 8)
    return f, nodes, visits


def call_record(f, nodes, word, base):
    total, count_edges = walk(f, nodes, [14] * len(nodes))
    assert total == 70
    start, guard_edges = route(f, GUARD[0], (GUARD,))
    assert f.step(start, MALLOC_PC + 4) == 'libSystem/_malloc'
    size = 96
    allocation = normal_malloc_return(f, MALLOC_PC, size, base)
    start, owner_edges = route(f, RETURN[0], (RETURN, NONEMPTY_EDGE))
    for node in nodes:
        assert number(f.read('x10')) == node
        start = f.step(start, 0x10008405c)
        assert f.step(start, 0x1000e66c0) == BYTE_LOOP
        for i in reversed(range(14)):
            assert f.step(BYTE_LOOP, 0x100090bc8) == (BYTE_LOOP if i else NODE_DONE)
        assert f.step(NODE_DONE, 0x100107b60) == 0x100034ec8
        start = f.step(0x100034ec8, 0x100034f20)
    assert start == TRAILER_SETUP
    start = f.step(start, 0x10008a3ac)
    start, trailer_edges = route(f, start, (PADDING,))
    assert start == LOOP and number(f.read('x8')) == base + 80
    for i in range(16):
        start = f.step(LOOP, 0x100011ffc)
        assert start == (SPLIT if i == 15 else LOOP)
    assert number(f.read('x6')) == RECORD
    raw = number(f.get(RECORD, 1))
    bias = number(f.get(SP + 0x38, 8)) & 255
    adjusted = (raw - bias) & 255
    assert adjusted == (2 * word + (word ^ 0xef) + 0x3e) & 255
    direct = (word & 255) != 0
    target = f.step(start, 0x1000c635c)
    assert (0x1000c62f0, RECORD, 1) in f.loads
    assert target == (0x1000f20f4 if direct else 0x100111684)
    call = 0x1000f2204 if direct else 0x100111754
    assert f.step(target, call + 4) == (0x10043a018 if direct else 0x10043ee28)
    out = number(f.read('x0'))
    assert out == FP - 0x80
    assert number(f.get(out + (0 if direct else 24), 8)) == base
    assert number(f.get(out + (8 if direct else 16), 8)) == CONTEXT
    if direct:
        key = ((out ^ 0xd71b18ee ^ 0x11cd78fa) * 0x6b86592f) & 0xffffffff
        decoded = (number(f.get(out + 16, 4)) ^ key) + 0xf537f77b
    else:
        key = ((out ^ 0xba958aeceaae0ac9) * 0x7398180b) & 0xffffffff
        decoded = (number(f.get(out, 4)) ^ key) + 0xbc30601d
    assert decoded & 0xffffffff == size
    assert sorted(byte - base for _, addr, width, _ in f.stores if base <= addr < base + size
                  for byte in range(addr, addr + width)) == list(range(size))
    data = bytes(number(f.get(base + offset, 1)) for offset in range(size))
    assert data[70:] == bytes.fromhex('0000000050db00000010') + bytes(16)
    return {'allocator': allocation, 'raw_dispatch_byte': raw, 'bias_low_byte': bias,
            'adjusted_byte': adjusted, 'helper_call_pc': hex(call), 'packet_sha256': hashlib.sha256(data).hexdigest(),
            'count_edges': count_edges, 'guard_edges': guard_edges, 'owner_edges': owner_edges,
            'trailer_edges': trailer_edges, 'other_edges': f.edges}


def report():
    profiles = []
    # Both callers receive identical constructor state, apart from their source-derived dispatch bytes.
    for words, locations in PROFILES:
        f, nodes, visits = construct(words, locations)
        for word in (16, 0):
            seed = caller_record(word, words)
            g = TransferFrame()
            g.regs.update(f.regs)
            g.ram.update(f.ram)
            assert all(z3.is_true(z3.simplify(seed.get(RECORD + off, width) == f.get(RECORD + off, width)))
                       for off, width in ((4, 4), (16, 8)))
            # Constructor reads and writes are disjoint from this caller-owned byte.
            g.put(RECORD, 1, seed.get(RECORD, 1))
            profiles.append({'caller_sp_4c': word, 'caller_edges': seed.edges,
                             'constructor_suffix': visits,
                             'handoff': call_record(g, nodes, word, 0x59000)})
    proofs = adjusted_byte_proofs()
    assert all(proof['result'] == 'unsat' for proof in proofs)
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'native_exchange_observed': False, 'proofs': proofs, 'profiles': profiles,
            'source_spans': list(SPANS.values()), 'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
