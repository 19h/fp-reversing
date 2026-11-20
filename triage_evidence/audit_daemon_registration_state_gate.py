#!/usr/bin/env python3
"""Audit the original daemon's post-registration comparison and local state gate."""

import json
from struct import pack, unpack_from

import audit_daemon_registration_continuation as continuation
from daemon_receive_tools import (
    CS, FIXUPS, IMAGE, MASK64, POOL, TABLE, bank, qword, verify_original_fixups,
)
from probe_daemon_registration import ar
from resolve_kernel_collection_interfaces import commands

U32 = (1 << 32) - 1
ENTRY = 0x100083778
HEAD = 0x10004e594
GENERATION = 0x1010c8258
GATE = 0x1010b5de0
COMPARE = 0x10004e71c
COMPARE_RETURN = COMPARE + 4
DISPATCH = 0x10004e7ac
CAS = 0x10002ed84
STATE_TABLE = 0x1010c784c
EXTENSION = [
    (HEAD, DISPATCH + 4),
    (0x10041a5e0, 0x10041a670),
    (0x10002ed44, 0x10002eda4),
    (0x10008201c, 0x10008211c),
    (0x1000bb970, 0x1000bb9ac),
    (0x100024c14, 0x100024c68),
]
TARGETS = {
    0x10109fd20: (0x10041a5e0, 0xec9d),
    0x101045730: (0x10002ed44, 0x5e5b),
    0x101045270: (0x1000bb970, 0x5e5b),
    0x101097880: (0x10008201c, 0x5e5b),
    0x101043a68: (0x10008a6a0, 0xac8a),
    0x101074848: (0x100024c14, 0x27ae),
    0x1010953e0: (0x10000c2cc, 0x27ae),
}


def instructions(start, end):
    source = IMAGE.read(start, end - start)
    rows = list(CS.disasm(source, start))
    assert len(rows) * 4 == len(source)
    return [{'pc': hex(i.address), 'asm': f'{i.mnemonic} {i.op_str}'.rstrip(),
             'bytes': i.bytes.hex()} for i in rows]


def source_pointer(load, offset, low, high, register, expected):
    slot = POOL + offset
    rows = instructions(load, load + 16)
    reg = rows[0]['asm'].split()[1].rstrip(',')
    temporary = rows[1]['asm'].split()[1].rstrip(',')
    assert [row['asm'] for row in rows] == [
        f'ldr {reg}, [x25, #{offset:#x}]',
        f'mov {temporary}, #-{low:#x}',
        f'movk {temporary}, #{high:#x}, lsl #16',
        f'add {register}, {reg}, {temporary}',
    ]
    bias = 0xffffffff00000000 | (high << 16) | (-low & 0xffff)
    pointer = (qword(slot) + bias) & MASK64
    assert pointer == expected
    return pointer, {'slot': hex(slot), 'bias': hex(bias), 'pointer': hex(pointer),
                     'slot_bytes': IMAGE.read(slot, 8).hex(), 'instructions': rows}


def inspect_sections(addresses):
    found = {}
    for at, command, _ in commands(IMAGE.data, 0):
        if command != 0x19:
            continue
        count = unpack_from('<I', IMAGE.data, at + 64)[0]
        for index in range(count):
            offset = at + 72 + index * 80
            name, segment, base, size = unpack_from('<16s16sQQ', IMAGE.data, offset)
            flags = unpack_from('<I', IMAGE.data, offset + 64)[0]
            for address in addresses:
                if base <= address < base + size:
                    found[address] = (segment.rstrip(b'\0').decode(),
                                      name.rstrip(b'\0').decode(), flags & 255)
    return found


class StateProbe(continuation.ContinuationProbe):
    def __init__(self, label, banks, generation, old_gate, **kwargs):
        super().__init__(label, entry=ENTRY, **kwargs)
        self.banks = banks
        self.generation = generation
        self.old_gate = old_gate
        self.comparison = {}
        self.atomic = None
        self.updates = []

    def hook(self, u, address, size, user):
        if address == ENTRY and self.banks is not None:
            sp = u.reg_read(ar.UC_ARM64_REG_SP)
            u.mem_write(sp + 0x100, pack('<QQ', *self.banks))
        if address == HEAD:
            assert unpack_from('<I', u.mem_read(GENERATION, 4))[0] == 0
            if self.generation:
                u.mem_write(GENERATION, pack('<I', self.generation))
            if self.old_gate is not None:
                u.mem_write(GATE, pack('<I', self.old_gate))
        if address == COMPARE:
            record = self.reg(0)
            assert record == self.reg(29) - 0x98
            raw = bytes(u.mem_read(record, 48))
            mode, a, _, mask, b, false_choice, true_choice = unpack_from('<I4xQII8xQII', raw)
            key = ((record ^ 0x4de3a292f9d49974) * 0xda51a827) & MASK64
            self.comparison = {
                'record': hex(record), 'raw_before': raw.hex(),
                'mode': (mode - key) & U32, 'a': (a - key) & MASK64,
                'b': b ^ key, 'mask': (mask - key) & U32,
                'false_choice': (false_choice + key) & U32,
                'true_choice': (true_choice ^ key) & U32,
            }
            assert self.reg(8) == 0x10041a5e0 and self.reg(17) == 0xec9d
        if address == COMPARE_RETURN:
            record = int(self.comparison['record'], 16)
            self.comparison['result'] = unpack_from('<I', u.mem_read(record + 16, 4))[0]
        if address == CAS:
            if self.atomic is not None:
                self.stop('would_retry_compare_and_swap', pc=hex(address))
                return
            self.visited.add(address)
            assert (self.reg(9), self.reg(8), self.reg(13)) == (GATE, 0x5d96, 0xa94ef)
            old = unpack_from('<I', u.mem_read(GATE, 4))[0]
            new = 0xa94ef if old == 0x5d96 else old
            self.atomic = {'address': hex(GATE), 'old': old, 'new': new,
                           'model': 'one serialized 32-bit compare-and-swap'}
            if old != new:
                u.mem_write(GATE, pack('<I', new))
            self.setreg(8, old)
            u.reg_write(ar.UC_ARM64_REG_PC, address + 4)
            return
        if address == 0x100024c44:
            pointer = self.reg(12)
            word = lambda addr: unpack_from('<I', u.mem_read(addr, 4))[0]
            following = word(pointer + 4)
            mixed = (word(pointer) & 0x80000000) | (following & 0x7ffffffe)
            expected = word(pointer + 0x634) ^ word(self.reg(3) + 4 * (following & 1))
            expected ^= (mixed >> 1) ^ (self.reg(4) & U32)
            assert self.reg(13) == expected
            self.updates.append([hex(pointer), expected])
        return super().hook(u, address, size, user)


def replay(banks):
    original_ranges = continuation.registration.RANGES
    continuation.registration.RANGES = [*original_ranges, *continuation.EXTENSION, *EXTENSION]
    cases = [
        ('unpopulated_frame_control', None, 0, None, 0, None, 0x10004e61c),
        ('image_words', banks, 0, None, 0, None, 0x10008a6a0),
        ('relocated_frame', banks, 0, None, -0x2000, None, 0x10008a6a0),
        ('earlier_registration_failure', banks, 0, None, 0, 0, 0x10008a6a0),
        ('different_gate_value', banks, 0, 0xa94ef, 0, None, CAS),
        ('nonzero_generation', banks, 1, None, 0, None, 0x10000c2cc),
        ('largest_generation', banks, U32, None, 0, None, 0x10000c2cc),
    ]
    rows = []
    try:
        for label, pair, generation, old_gate, offset, failure, frontier in cases:
            probe = StateProbe(label, pair, generation, old_gate, stack_offset=offset,
                               checkin_status=1102 if failure is not None else 0,
                               fail_service=failure)
            result = probe.run_registration()
            assert int(result['records'][-1]['pc'], 16) == frontier
            comparison = probe.comparison
            if pair is None:
                assert result['stop_reason'] == 'engine_error' and not comparison
            else:
                assert comparison['mode'] == comparison['a'] == 0
                assert comparison['b'] == generation
                assert (comparison['mask'], comparison['false_choice'],
                        comparison['true_choice']) == (0xfd69fa9d, 0xfd69eced, 0xfd69ed95)
                assert comparison['result'] == (0x1670 if generation else 0x1708)
            if generation:
                assert probe.atomic is None
                assert [int(address, 16) for address, _ in probe.updates] == [
                    STATE_TABLE + offset for offset in range(0, 0x38c, 4)
                ]
            elif pair is not None:
                assert probe.atomic['old'] == (0x5d96 if old_gate is None else old_gate)
                assert probe.atomic['new'] == 0xa94ef
                assert not probe.updates
            edges = [edge for edge in result['pac_bypasses']
                     if any(lo <= int(edge['site'], 16) < hi for lo, hi in EXTENSION)
                     and not (edge['site'] == '0x100024c64' and
                              edge.get('target') == '0x100024c14')]
            branch = next((edge for edge in edges if edge['site'] == hex(DISPATCH)), None)
            if branch is not None:
                slot = TABLE + 8 * comparison['result']
                assert (int(branch['target'], 16), int(branch['modifier'], 16)) == TARGETS[slot]
            rows.append({'case': label, 'frame_offset': offset, 'generation_override': generation or None,
                         'gate_override': old_gate, 'failed_checkin_ordinal': failure,
                         'stop': hex(frontier), 'stop_reason': result['stop_reason'],
                         'comparison': comparison, 'atomic': probe.atomic, 'state_updates': probe.updates,
                         'edges': edges, 'original_instructions': result['original_instruction_bytes_verified']})
    finally:
        continuation.registration.RANGES = original_ranges
    return rows


def inspect():
    x26, left = source_pointer(0x100413e94, 0x1658, 0x54b, 0xa6e7, 'x26', 0x100e99a00)
    x23, right = source_pointer(0x100413eb4, 0x26a0, 0x3f4e, 0x9d07, 'x23', 0x100f4e390)
    sections = inspect_sections((GENERATION, GATE, STATE_TABLE))
    assert sections == {GENERATION: ('__DATA', '__common', 1),
                        STATE_TABLE: ('__DATA', '__common', 1),
                        GATE: ('__DATA', '__data', 0)}
    assert IMAGE.read(GATE, 4) == pack('<I', 0x5d96)
    assert instructions(0x1000a352c, 0x1000a3530)[0]['asm'] == 'stp x23, x26, [sp, #0x100]'
    assert instructions(0x100097024, 0x100097028)[0]['asm'] == 'ldp x23, x1, [sp, #0x100]'
    assert instructions(CAS, CAS + 4)[0]['asm'] == 'casal w8, w13, [x9]'
    bank_checks = [
        (0x100fc4130, 0x101031ea0, 0xbb, 0xbb),
        (x26, x23, 0x78, 0xa1),
        (0x100e99700, 0x100f4e190, 0x81, 0x48),
        (0x100fc4130, 0x101031ea0, 0xa3, 0x72),
    ]
    for a, b, key, constant in bank_checks:
        assert bank(a, b, key) == constant
    for slot, (target, modifier) in TARGETS.items():
        assert FIXUPS[slot]['target'] == target
        assert FIXUPS[slot]['annotation'] == f'(div=0x{modifier:04X} ad=0 key=IA)'
    slots = {*TARGETS, POOL + 0x1658, POOL + 0x26a0}
    return {
        'source_sha256': '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e',
        'frame_bank_producers': [left, right],
        'sections': {hex(a): desc for a, desc in sections.items()},
        'banks': [[hex(value) for value in row] for row in bank_checks],
        'fixups': verify_original_fixups(slots),
        'code': [instructions(lo, hi) for lo, hi in EXTENSION],
        'cases': replay((x23, x26)),
        'native_ipc_observed': False,
    }


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
