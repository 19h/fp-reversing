#!/usr/bin/env python3
"""Recover the nonempty list serializer and compose its selector 26 records."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import sys

import z3

from audit_daemon_selector26_callers import DATA, FP, INPUT, fields
from audit_daemon_selector26_constructor import normal_malloc_return
from audit_daemon_selector26_header import HEADER, WRITERS
from audit_daemon_selector26_list_extent import NONEMPTY, OWNER, SKIP, TRANSFER, walk
from audit_daemon_selector26_node import NodeFrame, route
from audit_daemon_selector26_padding import (
    GUARD, LOOP, MALLOC_PC, PADDING, PADDING_STORE, RETURN, SPLIT, JoinedFrame, frame,
)
from audit_daemon_selector26_record_origin import FOURTH
from audit_daemon_selector26_return import FIXUP_SLOTS, RECORD, SP, SPANS, number
from audit_userclient_fallback_metadata import solve
from daemon_receive_tools import CS, SOURCE, TABLE, verify_original_fixups
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import sha

BYTE_LOOP = 0x100090998
LOAD_BYTE = 0x100090b6c
STORE_BYTE = 0x100090ba8
NODE_DONE = 0x100107b48
TRAILER_SETUP = 0x10008a358
COUNT_BIAS = 0x500c0e89
LOOP_PHASE = 0x27f7
SOURCE_CONSTANTS = {'x20': 0xe70987b7a1f527b0, 'x21': 0x7faaf81a732f68b4,
                    'x23': 0x4f99108510ad96e0}
NONEMPTY_EDGE = (0x1000859ec, 0x100085a60, 0x100085a2c, 0x101046b78, 0x9dfb, NONEMPTY)


class TransferFrame(NodeFrame, JoinedFrame):
    def run(self, label):
        span, = self.c['spans']
        if int(span['start'], 16) != STORE_BYTE:
            return super().run(label)
        insn, = CS.disasm(bytes.fromhex(span['bytes_hex']), STORE_BYTE)
        assert (insn.mnemonic, insn.op_str) == ('strb', 'w17, [x14], #0xffffffffffffffff')
        address = self.read('x14')
        self.store(address, 1, self.read('w17'), STORE_BYTE)
        self.write('x14', address - 1)
        self.count += 1


class SymbolicTransfer(TransferFrame):
    def load(self, address, width):
        if self.pc == LOAD_BYTE:
            assert width == 1
            self.loads.append((self.pc, address, width))
            return self.input_byte
        return super().load(address, width)

    def store(self, address, width, value, pc):
        self.stores.append((pc, address, width, resize(value, width * 8)))


def byte_proofs():
    source, index, dest = z3.BitVecs('source_base source_index destination_byte', 64)
    first_byte = z3.BitVec('source_byte', 8)
    f = SymbolicTransfer(x12=source, x13=index, x14=dest, x15=(source + index) << 3,
                         w11=LOOP_PHASE, **SOURCE_CONSTANTS)
    f.input_byte = first_byte
    f.step(BYTE_LOOP, LOAD_BYTE + 4)
    g = SymbolicTransfer()
    g.regs.update(f.regs)
    g.seed('w17', 0)
    g.step(LOAD_BYTE + 4, STORE_BYTE)
    f.step(LOAD_BYTE + 4, 0x100090bb4)
    f.step(0x100090bb8, 0x100090bc0)
    (pc, address, width, value), = f.stores
    (load_pc, load_address, load_width), = f.loads
    assert (pc, width, load_pc, load_width) == (STORE_BYTE, 1, LOAD_BYTE, 1)
    mask = z3.Extract(7, 0, g.read('w17'))
    result = solve('byte_transfer_xor_addresses_and_recurrence', [], z3.Or(
        load_address != source + index, address != dest, value != (first_byte ^ mask),
        f.read('x14') != dest - 1, f.read('x13') != index - 1,
        f.read('x15') != (source + index - 1) << 3,
        f.read('w16') != 0x8934,
        f.read('w17') != z3.If(index == 0, z3.BitVecVal(0x2819, 32), z3.BitVecVal(LOOP_PHASE, 32))))
    return result, mask.sexpr()


def node_proofs():
    size, previous = z3.BitVecs('node_size prior_payload_size', 32)
    source, dest, next_node = z3.BitVecs('node_source buffer_base following_node', 64)
    node = 0x8000
    f = TransferFrame(x0=dest, x10=node, x30=TABLE, w8=COUNT_BIAS + previous, w12=0x87d1)
    f.put(node + 16, 4, size)
    f.put(node + 24, 8, source)
    f.put(node, 8, next_node)
    f.step(NONEMPTY, 0x100084050)
    assert f.step(TRANSFER, 0x1000e66c0) == BYTE_LOOP
    last = z3.ZeroExt(32, size) - 1
    setup = solve('positive_node_setup_uses_cumulative_byte_offset', [size != 0], z3.Or(
        f.read('x12') != source, f.read('x13') != last,
        f.read('x14') != dest + z3.ZeroExt(32, previous) + last,
        f.read('x15') != (source + last) << 3,
        f.read('w11') != LOOP_PHASE,
        *(f.read(reg) != value for reg, value in SOURCE_CONSTANTS.items())))
    # Compose the stable loop phase result, including W16.
    f.seed('w16', 0x8934)
    assert f.step(NODE_DONE, 0x100107b60) == SKIP
    f.step(SKIP, 0x100034f14)
    advance = solve('node_advance_preserves_encoded_count_and_new_head', [], z3.Or(
        f.read('w8') != COUNT_BIAS + previous + size, f.read('x10') != next_node,
        f.read('w12') != 0x87d1, f.read('w15') != 0x1983,
        f.read('w11') != z3.If(next_node == 0, z3.BitVecVal(0x7c44, 32), z3.BitVecVal(0x1991, 32))))
    return [setup, advance]


def trailer_proof():
    total = z3.BitVec('total_payload_bytes', 32)
    base = z3.BitVec('allocation_base', 64)
    pad = 16 - ((total + 10) & 15)
    f = SymbolicTransfer(x0=base, x7=base, w8=COUNT_BIAS + total, w9=0x5238187b + pad,
                         w15=0x1983, x22=z3.ZeroExt(32, pad), x30=TABLE)
    assert f.step(TRAILER_SETUP, 0x10008a3ac) == HEADER[1][0]
    f.step(HEADER[1][0], PADDING[2])
    start = base + z3.ZeroExt(32, total)
    header = [z3.BitVecVal(b, 8) for b in (0, 0, 0, 0, 0x50, 0xdb)]
    header.extend(z3.Extract(bit + 7, bit, pad) for bit in (24, 16, 8, 0))
    assert tuple(pc for pc, _, _, _ in f.stores) == WRITERS
    assert all(width == 1 for _, _, width, _ in f.stores)
    return solve('trailing_header_value_address_and_padding_base', [z3.ULE(total, 0xffffffe5)],
                 z3.Or(f.read('x8') != start + 10, f.read('x12') != 0, f.read('w14') != 0x662a,
                       *(z3.Or(address != start + i, byte != header[i])
                         for i, (_, address, _, byte) in enumerate(f.stores))))


def profile(extents, direct):
    selector = 0x2c if direct else 0x2d
    initial = frame(0, selector, FOURTH)
    f = TransferFrame()
    f.regs.update(initial.regs)
    f.ram.update(initial.ram)
    f.seed('w28', 0x8934)
    f.seed('w16', 0x8b3dc651)
    f.put(FP - 0xb8, 8, OWNER)
    nodes = [0x8000 + i * 32 for i in range(len(extents))]
    sources = [0xa000 + i * 0x100 for i in range(len(extents))]
    f.put(OWNER, 8, nodes[0] if nodes else 0)
    for node, following, source, extent in zip(nodes, nodes[1:] + [0], sources, extents):
        f.put(node, 8, following)
        f.put(node + 16, 4, extent)
        f.put(node + 24, 8, source)
        for i in range(extent):
            f.put(source + i, 1, (i * 13 + 17) & 255)

    total, count_edges = walk(f, nodes, extents)
    pad = 16 - ((total + 10) & 15)
    size = total + 10 + pad
    start, guard_edges = route(f, GUARD[0], (GUARD,))
    assert f.step(start, MALLOC_PC + 4) == 'libSystem/_malloc'
    allocation = normal_malloc_return(f, MALLOC_PC, size, DATA)
    start, buffer_edges = route(f, RETURN[0], (RETURN, NONEMPTY_EDGE if nodes else HEADER[0]))
    cumulative = 0
    offsets = []
    for node, source, extent in zip(nodes, sources, extents):
        assert start == NONEMPTY and number(f.read('x10')) == node
        target = f.step(start, 0x10008405c)
        if extent:
            assert target == TRANSFER and f.step(target, 0x1000e66c0) == BYTE_LOOP
            for i in reversed(range(extent)):
                assert f.step(BYTE_LOOP, 0x100090bc8) == (BYTE_LOOP if i else NODE_DONE)
                assert f.loads[-2] == (LOAD_BYTE, source + i, 1)
                offsets.append(cumulative + i)
            assert f.step(NODE_DONE, 0x100107b60) == SKIP
        else:
            assert target == SKIP
        start = f.step(SKIP, 0x100034f20)
        cumulative += extent
        assert number(f.read('w8')) == (COUNT_BIAS + cumulative) & 0xffffffff
    if nodes:
        assert start == TRAILER_SETUP and f.step(start, 0x10008a3ac) == HEADER[1][0]
        start = HEADER[1][0]
    start, header_edges = route(f, start, (PADDING,))
    assert start == LOOP and number(f.read('x8')) == DATA + total + 10
    for i in range(pad):
        assert f.step(LOOP, 0x100011ffc) == (SPLIT if i + 1 == pad else LOOP)
    target = f.step(SPLIT, 0x1000c635c)
    assert (0x1000c62f0, INPUT, 1) in f.loads
    assert target == (0x1000f20f4 if direct else 0x100111684)
    call = 0x1000f2204 if direct else 0x100111754
    assert f.step(target, call + 4) == (0x10043a018 if direct else 0x10043ee28)
    assert number(f.read('x0')) == RECORD and z3.is_false(z3.simplify(fields(f, direct, size)))

    writes = [(pc, at - DATA, width) for pc, at, width, _ in f.stores
              if at < DATA + size and DATA < at + width]
    assert writes == ([(STORE_BYTE, offset, 1) for offset in offsets] +
                      [(pc, total + i, 1) for i, pc in enumerate(WRITERS)] +
                      [(PADDING_STORE, total + 10 + i, 1) for i in range(pad)])
    assert sorted(offset for _, offset, _ in writes) == list(range(size))
    packet = bytes(number(f.get(DATA + i, 1)) for i in range(size))
    assert packet[total:] == bytes.fromhex('0000000050db') + pad.to_bytes(4, 'big') + bytes(pad)
    return {'node_extents_bytes': extents, 'dispatch_byte': hex(selector),
            'payload_bytes': total, 'padding_bytes': pad, 'allocation': allocation,
            'constructed_buffer_hex': packet.hex(), 'write_offsets_bytes': [off for _, off, _ in writes],
            'count_edges': count_edges, 'guard_edges': guard_edges, 'buffer_edges': buffer_edges,
            'header_edges': header_edges, 'other_edges': f.edges}


def report():
    byte_proof, mask = byte_proofs()
    proofs = [byte_proof, *node_proofs(), trailer_proof()]
    assert all(proof['result'] == 'unsat' for proof in proofs)
    profiles = [profile(extents, direct) for extents in ([], [0], [1], [6], [14, 14], [5, 0, 21])
                for direct in (True, False)]
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'native_exchange_observed': False, 'proofs': proofs, 'byte_xor_mask': mask,
            'profiles': profiles, 'source_spans': list(SPANS.values()),
            'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
