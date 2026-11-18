#!/usr/bin/env python3
"""Audit the bit-clear selector 26 continuation and its private helper ABI."""

import json
from pathlib import Path

from capstone.arm64_const import ARM64_SFT_ROR
import z3

from audit_daemon_selector26_class_gate import F, R
from audit_daemon_selector26_class_retry import (
    FALLBACK, FINAL, REJECTED, initial_attempt, lookup, primary_check, publish_status, retire,
)
from audit_daemon_selector26_cleanup import landmark
from audit_daemon_selector26_match_entry import api_return
from audit_daemon_selector26_record_origin import FIRST, FOURTH
from audit_daemon_selector26_return import CS, FIXUP_SLOTS, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, POOL, SOURCE, selected, verify_original_fixups
from lskd_values_symbolic import resize
from recover_daemon_object_clock import sections
from verify_daemon_reader_record_payloads_publication import sha

ADAPTER = 0x100902878
CORE = 0x10087a590
SHARED = 0x100444dfc
FIRST_STATE, SECOND_STATE = 0x1010c6808, 0x1010c8260
PROBE_SLOT, GUARD_SLOT = 0x1010b1e28, 0x1010b1e18
TERMINALS = {'braa', 'blraa', 'retab', 'ret', 'pacibsp', 'ror', 'ldurb', 'sturb', 'b'}


def input_model(frame, data_sections):
    load, operand = frame.load, frame.operand
    inputs = {}

    def load_source(address, width):
        at = number(address)
        if width == 8 and at in FIXUPS and at != GUARD_SLOT:
            target = FIXUPS[at]['target']
            frame.loads.append((frame.pc, at, width))
            FIXUP_SLOTS.add(at)
            return at if isinstance(target, str) else target
        if at < 0x100000000 or at == GUARD_SLOT or all(at + i in frame.ram for i in range(width)):
            return load(address, width)
        owner = next((s for s in data_sections
                      if s['start'] <= at and at + width <= s['start'] + s['size_bytes']), None)
        zero_fill = owner and int(owner['flags'], 16) & 255 == 1
        raw = bytes(width) if zero_fill else IMAGE.read(at, width)
        if owner:
            inputs[at, width] = {'address': hex(at), 'bytes': raw.hex(), 'zero_fill': bool(zero_fill)}
        frame.loads.append((frame.pc, at, width))
        return int.from_bytes(raw, 'little')

    def shifted(instruction, operand_value, width):
        if operand_value.shift.type == ARM64_SFT_ROR:
            name = instruction.reg_name(operand_value.reg)
            return z3.RotateRight(resize(frame.read(name), width), operand_value.shift.value)
        return operand(instruction, operand_value, width)

    frame.load, frame.operand = load_source, shifted
    return inputs


def authenticated_edge(frame, insn):
    reg, modifier = [insn.reg_name(o.reg) for o in insn.operands]
    target, diversity = number(frame.read(reg)), number(frame.read(modifier))
    if insn.address == 0x10087a5c0:
        assert target == diversity == PROBE_SLOT
        assert FIXUPS[PROBE_SLOT]['annotation'] == '(div=0x0000 ad=1 key=IA)'
        assert FIXUPS[PROBE_SLOT]['target'] == 'libSystem/___chkstk_darwin'
        return PROBE_SLOT, FIXUPS[PROBE_SLOT]['target']
    candidates = {slot for _, slot, width in frame.loads if width == 8 and slot in FIXUPS
                  and target in (slot, FIXUPS[slot]['target'])
                  and FIXUPS[slot]['annotation'] == f'(div=0x{diversity:04X} ad=0 key=IA)'}
    assert len(candidates) == 1, (hex(insn.address), candidates)
    slot, = candidates
    return slot, FIXUPS[slot]['target']


def walk(frame, allocation_returns):
    allocations = iter(allocation_returns)
    calls, edges, returns = [], [], []
    pc = ADAPTER
    frame.seed('x30', 0x10028a8b4)
    for _ in range(1000):
        if pc == REJECTED:
            return pc, calls, edges, returns
        start = pc
        for insn in CS.disasm(IMAGE.read(start, 0x600), start):
            if insn.mnemonic in TERMINALS or insn.mnemonic.startswith('b.'):
                break
        pc, kind = insn.address, insn.mnemonic
        assert kind in TERMINALS or kind.startswith('b.'), hex(pc)
        if start != pc:
            frame.step(start, pc)
        landmark(pc, kind, insn.op_str)
        if kind in ('retab', 'ret'):
            target = number(frame.read('x30'))
            returns.append({'pc': hex(pc), 'target': hex(target), 'sp': hex(number(frame.read('sp')))})
            pc = target
            continue
        pc += 4
        if kind == 'pacibsp':
            continue
        if kind in ('ldurb', 'sturb'):
            frame.pc = insn.address
            address = frame.address(insn, insn.operands[1])
            name = insn.reg_name(insn.operands[0].reg)
            if kind == 'ldurb':
                frame.seed(name, frame.load(address, 1))
            else:
                frame.store(address, 1, frame.read(name), insn.address)
            continue
        if kind == 'ror':
            dst, src = [insn.reg_name(o.reg) for o in insn.operands[:2]]
            frame.seed(dst, z3.RotateRight(frame.read(src), insn.operands[2].imm))
            continue
        if kind == 'b' or kind.startswith('b.'):
            if kind == 'b' or z3.is_true(z3.simplify(frame.condition(kind[2:]))):
                pc = insn.operands[0].imm
            continue
        slot, target = authenticated_edge(frame, insn)
        edges.append({'pc': hex(insn.address), 'slot': hex(slot),
                      'target': hex(target) if isinstance(target, int) else target})
        if kind == 'blraa':
            frame.seed('x30', pc)
        if target == SHARED:
            assert insn.address == 0x100a2146c and slot == 0x1010a01b0
            calls.append({'pc': hex(insn.address), 'target': hex(target), 'argument': hex(number(frame.read('x0')))})
            return target, calls, edges, returns
        if target == 'libSystem/___chkstk_darwin':
            assert number(frame.read('w9')) == 0x1c00
        elif target == 'libSystem/_malloc':
            size = number(frame.read('x0'))
            assert size in (8, 120)
            pointer = next(allocations)
            calls.append({'pc': hex(insn.address), 'target': target, 'size_bytes': size, 'result': hex(pointer)})
            api_return(frame, pointer, 'x0')
        elif target == 'libSystem/_free':
            pointer = number(frame.read('x0'))
            calls.append({'pc': hex(insn.address), 'target': target, 'argument': hex(pointer)})
            api_return(frame, 0, 'x0')
        elif target == 0x10046faf8:
            dest, value, size = [number(frame.read(r)) for r in ('x0', 'w1', 'x2')]
            assert value == 0 and size in (4097, 32)
            calls.append({'pc': hex(insn.address), 'target': hex(target), 'size_bytes': size})
            frame.put(dest, size, value)
            api_return(frame, dest, 'x0')
        else:
            assert isinstance(target, int), (hex(insn.address), target)
            pc = target
    raise AssertionError('selected branch replay exceeded its instruction-block limit')


def profile(byte, allocations, data_sections):
    frame, entry, encoded = initial_attempt(byte, 0x70)
    if entry == FALLBACK:
        entry = primary_check(frame, True)
    row, after = lookup(frame, entry, 'success bit clear', 0)
    assert retire(frame, row, after) == ADAPTER
    seed = number(frame.get(F + 0x80, 8))
    original_load, original_operand = frame.load, frame.operand
    initial = input_model(frame, data_sections)
    target, calls, edges, returns = walk(frame, allocations)
    frame.load, frame.operand = original_load, original_operand
    outcome = {'next': hex(target)}
    if 0 in allocations:
        assert target == REJECTED and number(frame.read('sp')) == F
        assert number(frame.get(F + 0x80, 8)) == 0 and number(frame.get(R + 8, 4)) == 0x74c29d85
        assert [c['argument'] for c in calls if c['target'] == 'libSystem/_free'] == [
            hex(p) for p in allocations if p]
        next_step = retire(frame, row, target)
        second_class = None
        if next_step == FALLBACK:
            second, state = lookup(frame, primary_check(frame, True), 'open failure', 0x1000)
            second_class = second['class']
            next_step = retire(frame, second, state)
        assert next_step == FINAL
        outcome.update({'adapter_output': 0, 'private_status': '0x74c29d85',
                        'second_class': second_class, 'published': publish_status(frame, byte, encoded)})
    else:
        assert target == SHARED and returns == []
        assert [c['size_bytes'] for c in calls if c['target'] == 'libSystem/_malloc'] == [8, 120]
    return {'class': row['class'], 'initial_adapter_word': hex(seed), 'allocations': list(allocations),
            'calls': calls, 'edges': edges, 'returns': returns, 'outcome': outcome,
            'initial_data_reads': list(initial.values()), 'releases': row['releases']}


def state_provenance(data_sections):
    slot_ranges = ((0x100444f9c, 0x100445008), (0x1003b427c, 0x1003b42d8),
                   (0x1003b4370, 0x1003b43c8))
    for begin, end in slot_ranges:
        SPANS[begin, end] = {'start': hex(begin), 'end_exclusive': hex(end),
                             'bytes_hex': IMAGE.read(begin, end - begin).hex()}
    for address in (FIRST_STATE, SECOND_STATE):
        assert any(s['start'] <= address and address + 8 <= s['start'] + s['size_bytes']
                   and int(s['flags'], 16) & 255 == 1 for s in data_sections)
    landmark(0x100444fcc, 'ldr', 'x19, [x11]')
    landmark(0x100444ff0, 'ldr', 'x20, [x8]')
    landmark(0x100444ff4, 'ldrb', 'w8, [x19, #0x48]')
    banks = [selected(*FOURTH, 0x6d, 0x723, POOL, -0x7d6aa703),
             selected(*FIRST, 0x4e, 0x892, POOL, -0x17ef9f8f)]
    assert [r['target'] for r in banks] == [hex(FIRST_STATE), hex(SECOND_STATE)]
    FIXUP_SLOTS.update(int(r['slot'], 16) for r in banks)
    return {'banks': banks,
            'read_pc_to_zero_fill_cell': {'0x100444fcc': hex(FIRST_STATE), '0x100444ff0': hex(SECOND_STATE)},
            'initializer_publications': {'0x1003b42d4': hex(SECOND_STATE), '0x1003b43c4': hex(FIRST_STATE)}}


def report():
    data = [s for s in sections() if s['segment'] == '__DATA']
    profiles = [profile(byte, allocation_returns, data) for byte in (0x98, 0x99)
                for allocation_returns in ((0,), (0x23000, 0), (0x23000, 0x24000))]
    state = state_provenance(data)
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'profiles': profiles, 'shared_state': state, 'source_spans': list(SPANS.values()),
            'fixups': verify_original_fixups(FIXUP_SLOTS)}


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
