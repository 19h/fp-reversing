#!/usr/bin/env python3
"""Follow the two constructor nodes to the first buffer's local readback."""

from contextlib import redirect_stdout
import json
from pathlib import Path
import re
import sys

from capstone.arm64 import ARM64_EXT_SXTH, ARM64_SFT_ROR
import z3

from audit_daemon_selector26_constructor import constructor_frame, normal_malloc_return
from audit_daemon_selector26_record_origin import OriginFrame, trace_check
from audit_daemon_selector26_return import CS, FIXUP_SLOTS, SP, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, SOURCE, verify_original_fixups
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import sha

# Block start, original branch PC, pointer load PC, slot, modifier, logical target.
FILL = (
    (0x10005c5f4, 0x10005c7d8, 0x10005c6c0, 0x10106a2c0, 0x9634, 0x10006d3e8),
    (0x10006d3e8, 0x10006da84, 0x10006d3e8, 0x10103f510, 0x4cda, 0x10003c674),
    (0x10003c674, 0x10003c94c, 0x10003c928, 0x101050dc0, 0xd4f0, 0x1000acd28),
    (0x1000acd28, 0x1000acd38, 0x1000acd30, 0x10106a2c0, 0x9634, 0x10006d3e8),
    (0x10006d3e8, 0x10006da84, 0x10006d3e8, 0x10103f4f0, 0x4cda, 0x1000b2da8),
    (0x1000b2da8, 0x1000b2db4, 0x1000b2dac, 0x1010741f8, 0xa1c3, 0x10013e290),
    (0x10013e290, 0x10013e2d4, 0x10013e2b4, 0x1010699e8, 0x0c57, 0x10006f7c4),
    (0x10006f7c4, 0x10006f81c, 0x10006f80c, 0x101055470, 0x9bb4, 0x100102714),
    (0x100102714, 0x10010274c, 0x10010273c, 0x101076fd0, 0x9bb4, 0x1001f9b34),
    (0x1001f9b34, 0x1001f9b60, 0x1001f9b44, 0x101050dc0, 0xd4f0, 0x1000acd28),
    (0x1000acd28, 0x1000acd38, 0x1000acd30, 0x10106a2c0, 0x9634, 0x10006d3e8),
    (0x10006d3e8, 0x10006da84, 0x10006d3e8, 0x10103f538, 0x4cda, 0x1000d4810),
    (0x1000d4810, 0x1000d485c, 0x1000d4828, 0x101070778, 0x74a4, 0x1000db4c4),
    (0x1000db4c4, 0x1000db5fc, 0x1000db4e0, 0x10106d630, 0xd162, 0x10007ff30),
)
FIRST_INSERT = (
    (0x10007ff30, 0x10007ff60, 0x10007ff54, 0x101063158, 0xf000, 0x1000af2f0),
    (0x1000af2f0, 0x1000af30c, 0x1000db4d8, 0x1010429e0, 0xf09c, 0x100134830),
    (0x100134830, 0x100134870, 0x100134868, 0x1010476e8, 0xe3c6, 0x100081d6c),
    (0x100081d6c, 0x100081dac, 0x100081d9c, 0x10108f4d8, 0x65c0, 0x10005747c),
    (0x10005747c, 0x10005749c, 0x100057488, 0x1010592a8, 0x7aa4, 0x1000e72c4),
    (0x1000e72c4, 0x1000e72f0, 0x1000e72e8, 0x101089410, 0xf901, 0x10000c740),
    (0x10000c740, 0x10000c748, 0x10004e9f4, 0x10103b350, 0xa918, 0x1001e2e00),
    (0x1001e2e00, 0x1001e2e0c, 0x10002bfd8, 0x1010419f0, 0x7cb2, 0x1000c3060),
    (0x1000c3060, 0x1000c3098, 0x1000c3090, 0x101067a80, 0xf6ab, 0x100081d34),
    (0x100081d34, 0x100081d68, 0x100081d44, 0x101056c38, 0xa551, 0x10002bfd0),
    (0x10002bfd0, 0x10002c00c, 0x10002bffc, 0x10104fdb0, 0x2d3c, 0x10004e9d0),
    (0x10004e9d0, 0x10004ea30, 0x10004ea08, 0x101050040, 0x5530, 0x10008c8e8),
    (0x10008c8e8, 0x10008c990, 0x10008c988, 0x10109d158, 0xf901, 0x10001bc34),
)
REFILL = (
    (0x10001bca0, 0x10001bcd4, 0x10001bcc4, 0x101091b68, 0xd146, 0x100015a3c),
    (0x100015af8, 0x100015b24, 0x100015b14, 0x101059310, 0x7aa4, 0x10005c5f4),
)
READBACK = (
    (0x10007ff30, 0x10007ff60, 0x10007ff54, 0x1010630e8, 0xf000, 0x10006e1cc),
    (0x10006e1cc, 0x10006e1f0, 0x10006e1e4, 0x1010537b0, 0xfa2b, 0x10005468c),
)
SPILLED_BRANCHES = {
    0x1000af30c: (0x1000db4dc, 0x1000af300, 0x60),
    0x10000c748: (0x10004e9f8, 0x10000c740, 0xd0),
    0x1001e2e0c: (0x10002bfdc, 0x1001e2e04, 0xc8),
}
WRITE_PCS = (
    0x10006d5c8, 0x10006d76c, 0x10006d960, 0x10006da78,
    0x10003c7b4, 0x10003c91c,
) + (0x10006d5c8, 0x10006d76c, 0x10006d960, 0x10006da78) * 2


class NodeFrame(OriginFrame):
    def operand(self, insn, operand, width):
        if operand.ext == ARM64_EXT_SXTH:
            return z3.SignExt(width - 16, resize(self.read(insn.reg_name(operand.reg)), 16))
        if operand.shift.type == ARM64_SFT_ROR:
            return z3.RotateRight(resize(self.read(insn.reg_name(operand.reg)), width),
                                  operand.shift.value)
        return super().operand(insn, operand, width)

    def run(self, label):
        span, = self.c['spans']
        insn, = CS.disasm(bytes.fromhex(span['bytes_hex']), int(span['start'], 16))
        if insn.mnemonic == 'sxth':
            dst, src = insn.operands
            self.write(insn.reg_name(dst.reg), z3.SignExt(16, resize(self.read(insn.reg_name(src.reg)), 16)))
        elif insn.mnemonic == 'ror':
            dst, src, amount = insn.operands
            self.write(insn.reg_name(dst.reg), z3.RotateRight(self.read(insn.reg_name(src.reg)),
                                                            amount.imm))
        else:
            return super().run(label)
        self.count += 1


def follow(frame, spec):
    start, branch, load, slot, modifier, target = spec
    first_load = len(frame.loads)
    frame.step(start, branch)
    if branch in SPILLED_BRANCHES:
        store, reload, offset = SPILLED_BRANCHES[branch]
        location = SP + offset
        last_store = next((pc, address, width, value)
                          for pc, address, width, value in reversed(frame.stores)
                          if address < location + 8 and location < address + width)
        assert last_store[:3] == (store, location, 8) and number(last_store[3]) == target
        assert (reload, location, 8) in frame.loads[first_load:]
        assert (load, slot, 8) in frame.loads[:first_load]
    else:
        assert (load, slot, 8) in frame.loads[first_load:]
    raw = IMAGE.read(branch, 4)
    insn, = CS.disasm(raw, branch)
    assert insn.mnemonic == 'braa'
    destination, diversifier = (insn.reg_name(op.reg) for op in insn.operands)
    assert number(frame.read(destination)) == FIXUPS[slot]['target'] == target
    assert number(frame.read(diversifier)) == modifier
    assert re.fullmatch(fr'\(div=0x0*{modifier:X} ad=0 key=IA\)', FIXUPS[slot]['annotation'])
    SPANS[branch, branch + 4] = {'start': hex(branch), 'end_exclusive': hex(branch + 4),
                                 'bytes_hex': raw.hex()}
    return {'start': hex(start), 'pc': hex(branch), 'load_pc': hex(load), 'slot': hex(slot),
            'modifier': hex(modifier), 'target': hex(target)}


def route(frame, start, specs):
    edges = []
    for spec in specs:
        assert spec[0] == start
        edges.append(follow(frame, spec))
        start = spec[-1]
    return start, edges


def fill(frame, node, buffer):
    store_start, load_start = len(frame.stores), len(frame.loads)
    assert all(buffer + offset not in frame.ram for offset in range(14))
    end, edges = route(frame, 0x10005c5f4, FILL)
    assert end == 0x10007ff30
    assert [(pc, width) for pc, address, width in frame.loads[load_start:]
            if address == node + 24] == [
        (0x10006d3ec, 8), (0x10003c674, 8), (0x10006d3ec, 8), (0x10006d3ec, 8),
    ]
    writes = [(pc, address - buffer, width) for pc, address, width, _ in frame.stores[store_start:]
              if address < buffer + 14 and address + width > buffer]
    assert writes == [(pc, index, 1) for index, pc in enumerate(WRITE_PCS)]
    assert number(frame.get(SP + 0xd8, 8)) == node
    return edges, [{'pc': hex(pc), 'offset_bytes': offset, 'width_bytes': width}
                   for pc, offset, width in writes]


def node_frame(words, locations):
    owner, first_node, first_buffer, second_node, second_buffer = locations
    regions = sorted(zip(locations, (16, 32, 14, 32, 14)))
    assert all(left + extent <= right for (left, extent), (right, _) in zip(regions, regions[1:]))
    f, _, _ = constructor_frame(*words, frame_type=NodeFrame, locations=locations[:3],
                                registers={'x25': z3.BitVec('incoming_x25', 64)})
    incoming = z3.BitVec('incoming_sp_13c', 32)
    f.put(SP + 0x13c, 4, incoming)
    fill_edges, writes = fill(f, first_node, first_buffer)
    start, insert_edges = route(f, 0x10007ff30, FIRST_INSERT[:2])
    assert start == 0x100134830
    assert z3.is_true(z3.simplify(f.read('w1') == incoming))
    start, later_edges = route(f, start, FIRST_INSERT[2:])
    assert start == 0x10001bc34
    assert (0x10007ff3c, owner, 8) in f.loads
    assert (0x100081d80, owner + 8, 8) in f.loads
    assert (0x100081da0, SP + 0xd8, 8) in f.loads
    assert [(pc, address - owner, width, number(value))
            for pc, address, width, value in f.stores if owner <= address < owner + 16] == [
        (0x100015c5c, 0, 8, 0), (0x100015c5c, 8, 8, 0),
        (0x100057484, 0, 8, first_node), (0x100057484, 8, 8, first_node),
    ]
    first_bytes = f.get(first_buffer, 14)

    assert f.step(start, 0x10001bca0) == 'libSystem/_malloc'
    second_allocations = [normal_malloc_return(f, 0x10001bc9c, 32, second_node)]
    start, first_refill = route(f, 0x10001bca0, REFILL[:1])
    assert f.step(start, 0x100015af8) == 'libSystem/_malloc'
    second_allocations.append(normal_malloc_return(f, 0x100015af4, 14, second_buffer))
    start, second_refill = route(f, 0x100015af8, REFILL[1:])
    assert start == FILL[0][0]
    assert number(f.get(second_node + 16, 4)) == 14
    assert number(f.get(second_node + 24, 8)) == second_buffer
    second_fill, second_writes = fill(f, second_node, second_buffer)
    assert second_writes == writes and second_fill == fill_edges

    load_start = len(f.loads)
    start, readback = route(f, 0x10007ff30, READBACK)
    assert start == 0x10005468c
    assert (0x10007ff3c, owner, 8) in f.loads[load_start:]
    assert (0x10006e1d4, first_node + 24, 8) in f.loads[load_start:]
    assert number(f.read('x0')) == first_buffer
    assert number(f.get(SP + 0x80, 8)) == first_node
    assert number(f.get(SP + 0xd8, 8)) == second_node
    assert number(f.get(owner, 8)) == number(f.get(owner + 8, 8)) == first_node
    assert z3.is_true(z3.simplify(f.get(first_buffer, 14) == first_bytes))

    f.step(start, 0x100054958)
    assert not any(address < first_buffer + 14 and address + width > first_buffer
                   for _, address, width in f.loads)
    raw = IMAGE.read(0x100054958, 4)
    pending, = CS.disasm(raw, 0x100054958)
    assert (pending.mnemonic, pending.op_str) == ('ldr', 'x16, [sp, #0xf8]')
    missing = [offset for offset in range(8) if SP + 0xf8 + offset not in f.ram]
    assert missing
    observations = {
        'inputs': {'global_words': list(map(hex, words)), 'allocations': list(map(hex, locations))},
        'first_fill': writes, 'fill_edges': fill_edges, 'insert_edges': insert_edges + later_edges,
        'second_allocation_calls': second_allocations, 'second_allocation_edges': first_refill + second_refill,
        'readback_edges': readback,
        'handoff': {
            'first_node_staged': '0x1000d4810',
            'owner_fields_published': '0x100057484',
            'owner_offsets_bytes': [0, 8],
            'owner_head_loaded': '0x10007ff3c',
            'first_buffer_pointer_to_x0': '0x10006e1d4',
            'first_node_saved_at_sp_80': '0x10006e1e8',
            'buffer_payload_reads': 0,
        },
        'pending': {'pc': hex(pending.address), 'instruction': pending.op_str,
                    'bytes_hex': raw.hex(), 'missing_byte_offsets': missing},
    }

    return f, observations


PROFILES = (
    ((0x12345678, 0x98765432), (0xa000, 0x20000, 0x21000, 0x22000, 0x23000)),
    ((0xffffffff, 0), (0xb010, 0x24a30, 0x26b40, 0x28c50, 0x2ad60)),
    ((0, 0xffffffff), (0xc020, 0x49070, 0x4a080, 0x4b090, 0x4c0a0)),
)


def report():
    profiles = [node_frame(words, locations)[1] for words, locations in PROFILES]
    observations = {key: value for key, value in profiles[0].items() if key != 'inputs'}
    assert all({key: row[key] for key in observations} == observations for row in profiles)
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'entry_generator_sha256': sha(Path(__file__).with_name('audit_daemon_selector26_constructor.py')),
            'profiles': [row['inputs'] for row in profiles], 'observations': observations,
            'native_exchange_observed': False, 'trace': trace_check(),
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'source_spans': list(SPANS.values())}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
