#!/usr/bin/env python3
"""Check the selected cleanup's pending free and common local cursor rewind."""

from hashlib import sha256
import json

from audit_daemon_discovery_cache_codec import (
    CACHE, CONTROL, FRAME, FRONTIER, IMAGE, NEXT_INPUT, TABLE, CacheProbe, ar, producer,
)
from daemon_receive_tools import FIXUPS, verify_original_fixups

LEFT, RIGHT = 0x100fc4230, 0x101031fa0
NULL_ARM = 0x10083ea7c
STOP = 0x10083ea88
FREE = 0x1005bfaf0
ALLOC = 0x10077b058
POINTER = FRAME + 0xe800
CURSOR = FRAME + 0x16d0
CONTINUATION = FRAME + 0x57a8
SAVED_SLOT = 0x101040f40
MASK64 = (1 << 64) - 1


def bank(key, base, symbol):
    left, right = IMAGE.read(LEFT, 256), IMAGE.read(RIGHT, 256)
    indices = {base + (x ^ right[left[x] ^ key]) for x in range(256)}
    assert len(indices) == 1
    index, = indices
    slot = TABLE + 8 * index
    assert FIXUPS[slot]['target'] == symbol
    return {'slot': hex(slot), 'index': hex(index), 'left': hex(LEFT), 'right': hex(RIGHT),
            'key': hex(key), 'base': hex(base), 'checked_byte_inputs': 256, 'symbol': symbol}


class PointerProbe(CacheProbe):
    def __init__(self):
        self.returns = {}
        self.calls = []
        self.cursor_writes = []
        self.continuation_writes = []
        self.resume_target = None
        super().__init__(0)

    def read_hook(self, u, access, address, width, value, data):
        if u.reg_read(ar.UC_ARM64_REG_PC) == 0x1007cfa48:
            assert (address, width) == (SAVED_SLOT, 8)
            self.resume_target = self.memory_word(address)
        super().read_hook(u, access, address, width, value, data)

    def write_hook(self, u, access, address, width, value, data):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if CURSOR <= address < CURSOR + 8:
            self.cursor_writes.append((pc, width, value & MASK64))
        if address < CONTINUATION + 8 and CONTINUATION < address + width:
            self.continuation_writes.append((pc, address, width))
        super().write_hook(u, access, address, width, value, data)

    def hook(self, u, pc, size, data):
        if pc == 0x10083ea90:
            assert self.reg(8) == self.memory_word(CONTINUATION) == self.resume_target
            self.reads.append((0x1007cfa48, SAVED_SLOT))
        if pc in self.imports:
            call = self.reg(30) - 4
            if call in self.returns:
                expected, argument, result = self.returns[call]
                assert self.imports[pc] == expected and self.reg(0) == argument
                self.calls.append({'site': hex(call), 'symbol': expected, 'x0': hex(argument),
                                   'model_x0_after_call': hex(result)})
                self.finish_import(call + 4, result)
                return
        super().hook(u, pc, size, data)

    def install_bank(self):
        # These values are from the separately recovered initializer at
        # 0x1004c2584 and 0x1004c349c. The prior discovery replay omits it.
        self.put(FRAME + 0x9b0, 8, LEFT)
        self.put(FRAME + 0x9a8, 8, RIGHT)

    def run_cleanup_arms(self):
        self.install_bank()
        snapshot = self.u.context_save()
        cursor = self.memory_word(CURSOR)
        assert cursor == MASK64 + 1 - 0xf0
        assert not self.continuation_writes
        cache = self.memory_word(CACHE)
        cases = []
        for value, return_word in ((0, 0), (POINTER, 0), (POINTER, 0xffffffff)):
            self.u.context_restore(snapshot)
            self.put(CURSOR, 8, cursor)
            self.put(NEXT_INPUT, 8, value)
            step, edge, call = len(self.cursor_writes), len(self.branch_slots), len(self.calls)
            self.returns = {FREE: ('libSystem/_free', value, return_word)} if value else {}
            self.u.emu_start(FRONTIER, STOP, count=110)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == STOP
            assert self.u.reg_read(ar.UC_ARM64_REG_SP) == FRAME
            expected = (cursor - 0x7f0) & MASK64
            assert self.cursor_writes[step:] == [(0x10083ea84, 8, expected)]
            assert self.memory_word(CURSOR) == expected
            assert self.memory_word(CONTROL, 4) == 0 and self.memory_word(CACHE) == cache
            assert not self.continuation_writes and not self.output_accesses
            edges, calls = self.branch_slots[edge:], self.calls[call:]
            want_targets = ['0x1005bfa84', 'libSystem/_free', hex(NULL_ARM)] if value else [hex(NULL_ARM)]
            assert [entry['target'] for entry in edges] == want_targets
            assert len(calls) == int(bool(value))
            if value:
                assert edges[-1]['site'] == '0x1005bfb00'
                assert edges[-1]['fixup_slot'] == '0x10103b828'
            cases.append({'input_premise': hex(value), 'cursor_before': hex(cursor),
                          'cursor_after': hex(expected), 'pending_pointer_load': hex(STOP),
                          'api_requests': calls, 'edges': edges})
        return cases

    def run_allocator_component(self):
        start = 0x10077afe8
        self.returns = {ALLOC: ('libSystem/_malloc', 164, POINTER)}
        first = len(self.calls)
        self.u.emu_start(start, 0x10077b060, count=70)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x10077b060
        assert self.memory_word(FRAME + 0x1998) == POINTER
        assert len(self.calls[first:]) == 1
        alloc_edge = self.branch_slots[-1]
        self.u.emu_start(0x1002aa0dc, 0x1002aa0e4, count=4)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x1002aa0e4
        assert self.memory_word(NEXT_INPUT) == POINTER
        return {'separately_entered_copy_slice': ['0x1002aa0dc', '0x1002aa0e4'],
                'source_store_after_allocation': '0x10077b05c', 'allocation_edge': alloc_edge,
                'modeled_call': self.calls[-1], 'copied_value': hex(POINTER)}

    def run_saved_component(self):
        # Detached source component. These missing scalars are read by the
        # two source slices but do not determine either checked table index.
        frame_inputs = ((0x5cc4, 4, 0), (0x1360, 8, 0), (0x3650, 8, 0),
                        (0x8d4c, 4, 0), (0x14fc, 4, 0))
        for offset, size, value in frame_inputs:
            self.put(FRAME + offset, size, value)
        assert TABLE + 8 * 0xe0a == SAVED_SLOT
        self.setreg(22, 0xe0a)
        cursor_before = self.memory_word(CURSOR)
        first = len(self.branch_slots)
        self.u.emu_start(0x10058bc40, 0x10053b8a8, count=120)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x10053b8a8
        assert self.memory_word(CURSOR) == (cursor_before + 0x7f0) & MASK64
        assert self.continuation_writes == [(0x1007cfa4c, CONTINUATION, 8)]
        assert self.memory_word(CONTINUATION) == self.resume_target == 0x1005e6020
        self.u.emu_start(NULL_ARM, 0x1004ccbe4, count=80)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x1004ccbe4
        assert self.memory_word(CURSOR) == cursor_before
        edges = self.branch_slots[first:]
        assert [edge['site'] for edge in edges] == ['0x10058bca0', '0x1007cfaf8',
                                                   '0x10083ea90', '0x1005e6084']
        return {'writer_entry': '0x10058bc40', 'separate_w22': '0xe0a',
                'separate_frame_inputs': [[hex(off), size, hex(v)] for off, size, v in frame_inputs],
                'cursor_before_and_after': hex(cursor_before),
                'reservation_bytes': 0x7f0, 'rewind_bytes': 0x7f0, 'edges': edges,
                'native_reaching_definition_established': False}


def inspect():
    digest = sha256(IMAGE.data).hexdigest()
    assert digest == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    rows, image_cells, table = producer()
    probe = PointerProbe()
    parent = probe.run_cache(rows[-1], image_cells, table)
    cases = probe.run_cleanup_arms()
    allocator = probe.run_allocator_component()
    saved = probe.run_saved_component()
    calls = (bank(0xf3, 0xcbc5, 'libSystem/_free'), bank(0x6c, 0xcb86, 'libSystem/_malloc'))
    slots = {int(edge['fixup_slot'], 16) for row in cases for edge in row['edges']}
    slots.add(int(allocator['allocation_edge']['fixup_slot'], 16))
    slots.update(int(edge['fixup_slot'], 16) for edge in saved['edges'])
    return {'image_sha256': digest, 'parent_fixture': parent['fixture'],
            'profiles': cases, 'bank_checks': calls, 'allocator_component': allocator,
            'saved_continuation_component': saved,
            'fixups': verify_original_fixups(slots),
            'saved_continuation_source': {'load': '0x1007cfa48', 'store': '0x1007cfa4c',
                                          'cleanup_load': hex(STOP), 'branch': '0x10083ea90'},
            'native_allocation_or_free_executed': False,
            'native_mach_or_iokit_transfer_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
