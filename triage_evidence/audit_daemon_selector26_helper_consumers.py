#!/usr/bin/env python3
"""Trace selector 26 postprocessing with one opaque result per shared-helper call."""

import json
from pathlib import Path

import z3

from audit_daemon_selector26_postprocess import (
    ADAPTER, FALLBACK, FINAL, REJECTED, SHARED, CS, F, FIXUP_SLOTS, IMAGE, R, SOURCE, SPANS,
    api_return, authenticated_edge, initial_attempt, input_model, lookup, number, primary_check,
    publish_status, retire, sections, verify_original_fixups, walk,
)
from audit_daemon_selector26_cleanup import landmark
from verify_daemon_reader_record_payloads_publication import read, sha

FIRST_CALL = 0x100a2146c
HELPER_SLOT = 0x1010a01b0
MALLOC_SIZES = {
    0x100a5f40c: 128, 0x1009447b4: 112, 0x1006bfff8: 16,
    0x100645b00: 16, 0x100948dd0: 32, 0x100a2fc00: 14,
}
COMMON_CALLS = (FIRST_CALL, 0x100646bbc, 0x10094bc5c, 0x100930840, 0x100641dbc, 0x100640144)
EXTENDED_CALLS = COMMON_CALLS + (0x10064881c,) * 4 + (0x10092425c,) * 4
MISSING_INPUTS = {0x10064ff10: ('ldr', 'x20, [x19]', 8),
                  0x10094326c: ('ldrsh', 'w12, [sp, #0x916]', 2)}


def return_from_call(frame, link, result=None):
    if result is None:
        for register in range(18):
            frame.regs.pop(f'x{register}', None)
    else:
        api_return(frame, result, 'x0')
    frame.seed('x30', link)
    frame.n, frame.z, frame.carry, frame.overflow = (z3.FreshBool('call_flag') for _ in range(4))


def continuation(frame, argument, allocation_returns):
    pc = FIRST_CALL + 4
    allocations = iter(allocation_returns)
    helper_calls, results, calls, edges, returns = [], [], [], [], []

    def helper_result(site):
        assert number(frame.read('x0')) == argument == number(frame.read('x29')) - 0xa0
        value = z3.BitVec(f'helper_result_{len(results) + 1}', 64)
        results.append(value)
        helper_calls.append(site)
        frame.put(argument + 8, 8, value)
        return_from_call(frame, site + 4)

    helper_result(FIRST_CALL)
    for _ in range(12000):
        if pc == REJECTED:
            return pc, helper_calls, results, calls, edges, returns, None
        if pc in MISSING_INPUTS:
            name, operands, width = MISSING_INPUTS[pc]
            landmark(pc, name, operands)
            insn = next(CS.disasm(IMAGE.read(pc, 4), pc))
            address = number(frame.address(insn, insn.operands[1]))
            if any(address + offset not in frame.ram for offset in range(width)):
                return pc, helper_calls, results, calls, edges, returns, width
        insn = next(CS.disasm(IMAGE.read(pc, 4), pc))
        op = insn.mnemonic
        if op in ('braa', 'blraa'):
            landmark(pc, op, insn.op_str)
            slot, target = authenticated_edge(frame, insn)
            edges.append({'pc': hex(pc), 'slot': hex(slot),
                          'target': hex(target) if isinstance(target, int) else target})
            if op == 'braa':
                assert isinstance(target, int)
                pc = target
                continue
            if target == SHARED:
                assert slot == HELPER_SLOT
                helper_result(pc)
            elif target == 'libSystem/_malloc':
                size = number(frame.read('x0'))
                assert size == MALLOC_SIZES[pc]
                pointer = next(allocations)
                calls.append({'pc': hex(pc), 'target': target, 'size_bytes': size, 'result': hex(pointer)})
                return_from_call(frame, pc + 4, pointer)
            elif target == 'libSystem/_free':
                calls.append({'pc': hex(pc), 'target': target, 'argument': hex(number(frame.read('x0')))})
                return_from_call(frame, pc + 4, 0)
            elif target == 0x10046faf8:
                destination, value, size = [number(frame.read(reg)) for reg in ('x0', 'w1', 'x2')]
                assert pc == 0x100a5f394 and (value, size) == (0, 24)
                calls.append({'pc': hex(pc), 'target': hex(target), 'size_bytes': size, 'value': value})
                frame.put(destination, size, value)
                return_from_call(frame, pc + 4, destination)
            else:
                raise AssertionError((hex(pc), target))
        elif op in ('retab', 'ret'):
            landmark(pc, op, insn.op_str)
            target = number(frame.read('x30'))
            returns.append({'pc': hex(pc), 'target': hex(target), 'sp': hex(number(frame.read('sp')))})
            pc = target
            continue
        elif op == 'b' or op.startswith('b.'):
            landmark(pc, op, insn.op_str)
            condition = z3.BoolVal(True) if op == 'b' else z3.simplify(frame.condition(op[2:]))
            assert z3.is_true(condition) or z3.is_false(condition), hex(pc)
            if z3.is_true(condition):
                pc = insn.operands[0].imm
                continue
        elif op == 'sturb':
            landmark(pc, op, insn.op_str)
            frame.pc = pc
            frame.store(frame.address(insn, insn.operands[1]), 1,
                        frame.read(insn.reg_name(insn.operands[0].reg)), pc)
        else:
            frame.step(pc, pc + 4)
        pc += 4
    raise AssertionError('post-helper continuation exceeded its instruction limit')


def check_initial_stores(stores, base, word):
    first = [(address, width, value) for pc, address, width, value in stores if pc == 0x100688238]
    assert [(address - base, width) for address, width, _ in first] == [(i, 1) for i in range(8)]
    solver = z3.Solver()
    expected = word
    mismatches = []
    for _, _, value in first:
        mismatches.append(value != (z3.Extract(7, 0, expected) ^ 0x37))
        expected = z3.LShR(expected, 8) ^ 0x66bc74f70cc400a6
    solver.add(z3.Or(*mismatches))
    assert solver.check() == z3.unsat


def profile(byte, allocation_returns, data_sections):
    frame, entry, encoded = initial_attempt(byte, 0x70)
    if entry == FALLBACK:
        entry = primary_check(frame, True)
    row, after = lookup(frame, entry, 'success bit clear', 0)
    assert retire(frame, row, after) == ADAPTER
    original_load, original_operand = frame.load, frame.operand
    input_model(frame, data_sections)
    target, _, _, _ = walk(frame, (0x23000, 0x24000))
    assert target == SHARED
    argument, buffer = (number(frame.read(reg)) for reg in ('x0', 'x20'))
    assert buffer == number(frame.read('sp')) + 0xa60
    first_store = len(frame.stores)
    end, helper_calls, results, calls, edges, returns, missing_width = continuation(
        frame, argument, allocation_returns)
    stores = frame.stores[first_store:]
    assert tuple(helper_calls) == (EXTENDED_CALLS if len(allocation_returns) == 6 else COMMON_CALLS), (
        hex(end), list(map(hex, helper_calls)), calls)
    assert edges[0] == {'pc': '0x100a214b0', 'slot': '0x1010827b0', 'target': '0x100688230'}
    check_initial_stores(stores, buffer, results[0])
    payload_stores = [{'pc': hex(pc), 'offset_bytes': address - buffer}
                      for pc, address, width, _ in stores if width == 1 and buffer <= address < buffer + 80]
    for site, offsets in ((0x10087a0a8, range(8, 16)), (0x1009c356c, range(8)),
                          (0x100951340, range(8, 16)), (0x10092c52c, range(16, 24)),
                          (0x100962ef0, range(24, 32)), (0x100908890, range(79, 47, -1))):
        assert [row['offset_bytes'] for row in payload_stores if row['pc'] == hex(site)] == list(offsets)
    frame.load, frame.operand = original_load, original_operand
    outcome = {'frontier': hex(end), 'unmodeled_read_width_bytes': missing_width}
    if allocation_returns == (0,):
        assert end == REJECTED and number(frame.read('sp')) == F
        assert number(frame.get(R + 8, 4)) == 0x74c29d85 and number(frame.get(F + 0x80, 8)) == 0
        assert [r['argument'] for r in calls if r['target'] == 'libSystem/_free'] == ['0x24000', '0x23000']
        resumed = retire(frame, row, end)
        second_class = None
        if resumed == FALLBACK:
            other, next_step = lookup(frame, primary_check(frame, True), 'open failure', 0x1000)
            second_class = other['class']
            resumed = retire(frame, other, next_step)
        assert resumed == FINAL
        outcome.update({'private_status': '0x74c29d85', 'adapter_output': 0, 'releases': row['releases'],
                        'fallback_class': second_class, 'published': publish_status(frame, byte, encoded)})
    else:
        assert end == (0x10064ff10 if allocation_returns[-1] == 0 else 0x10094326c)
    return {'class': row['class'], 'allocations': list(allocation_returns), 'helper_calls': list(map(hex, helper_calls)),
            'authenticated_edges': edges, 'private_buffer_stores': payload_stores,
            'calls': calls, 'returns': returns, 'outcome': outcome}


def report():
    data_sections = [section for section in sections() if section['segment'] == '__DATA']
    init_path = Path(__file__).with_name('arcade_subscription_initialization_profile.json')
    init = json.loads(read(init_path))
    writes = [row for row in init['image_writes'] if row['address'] in ('0x1010c8260', '0x1010c6808')]
    assert [(row['pc'], row['address'], row['size']) for row in writes] == [
        ('0x1003b42d4', '0x1010c8260', 8), ('0x1003b43c4', '0x1010c6808', 8)]
    assert [next(a['known_bytes'] for a in init['private_allocations'] if a['address'] == row['value'])
            for row in writes] == [58, 101]
    assert all('bytes_hex' not in alloc for alloc in init['private_allocations'])
    landmark(0x10044a3bc, 'str', 'x8, [x9, #8]')
    profiles = [profile(byte, allocations, data_sections) for byte in (0x98, 0x99)
                for allocations in ((0,), (0x25000, 0), tuple(range(0x25000, 0x2b000, 0x1000)))]
    return {'daemon_sha256': sha(SOURCE), 'generator_sha256': sha(Path(__file__)),
            'saved_initializer_sha256': sha(init_path), 'initializer_pointer_writes': writes,
            'profiles': profiles, 'source_spans': list(SPANS.values()),
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'native_exchange_observed': False}


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
