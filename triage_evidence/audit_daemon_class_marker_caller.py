#!/usr/bin/env python3
"""Trace the discovery status into the adapter's parent record."""

import json

import z3

from audit_daemon_class_lock_gate import GateProbe, SP
from audit_daemon_class_status_route import CODEC, OUTER_KEY, verify
from audit_daemon_selector26_return import Frame, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, POOL, TABLE, selected, verify_original_fixups
from daemon_rpc502_probe import HALT, STACK, ar

PARENT = STACK + 0x7000
CURSOR = STACK + 0x7800
ALLOCATION = STACK + 0x8000
RESULT_BUFFER = ALLOCATION + 0xb00
PARENT_ENTRY = 0x10046fc5c
PARENT_PHASE = 0x7b68
OUTER_ENTRY = 0x100559b7c
ADAPTER_CALL = 0x1003f57bc
FIRST_READ = 0x1003f57d4
TAIL_DISPATCH = 0x1003f5950
PARENT_STORE = 0x1004ccb5c
COPY_START = 0x1004d0340
TAIL_CONTROL = 0x540148f9
PHASE_MASK = 0xffffffff


class CallerProbe(GateProbe):
    def __init__(self, marker, tail_control, parent=PARENT):
        super().__init__()
        self.marker = marker
        self.tail_control = tail_control
        self.parent = parent
        self.clobber = 0
        self.branch_slots = []
        self.child_record = None
        self.checkpoints = []
        self.parent_stores = []
        self.copy_offsets = []
        self.request_size = tail_control - TAIL_CONTROL

    def put(self, address, width, value):
        mask = (1 << (8 * width)) - 1
        self.u.mem_write(address, (value & mask).to_bytes(width, 'little'))

    def write_hook(self, u, access, address, size, value, user):
        if self.parent <= address < self.parent + 0x40:
            pc = u.reg_read(ar.UC_ARM64_REG_PC)
            self.parent_stores.append({'pc': hex(pc), 'offset_bytes': address - self.parent,
                                       'size_bytes': size, 'value': hex(value & ((1 << (size * 8)) - 1))})
        if RESULT_BUFFER <= address < RESULT_BUFFER + 16:
            assert u.reg_read(ar.UC_ARM64_REG_PC) == COPY_START + 0xc and size == 1
            self.copy_offsets.append(address - RESULT_BUFFER)
        super().write_hook(u, access, address, size, value, user)

    def hook(self, u, pc, size, user):
        if pc == 0x100412ebc:
            assert self.reg(30) == 0x10046fef8 and self.reg(0) == self.reg(29) - 0xa0
            self.put(self.reg(0) + 4, 1, 0)
            self.checkpoints.append({'kind': 'modeled_helper_return', 'entry': hex(pc),
                                     'record_byte_offset': 4, 'record_byte': 0})
            self.return_model()
            return
        if pc == self.import_addresses['libSystem/_malloc']:
            assert self.reg(30) == 0x1003a8468
            assert self.reg(0) == self.request_size
            self.checkpoints.append({'kind': 'modeled_malloc_return', 'site': hex(self.reg(30) - 4),
                                     'size_bytes': self.reg(0), 'pointer': hex(ALLOCATION)})
            self.finish_import(self.reg(30), ALLOCATION)
            return
        if pc == self.import_addresses['libSystem/_free']:
            assert self.reg(30) == 0x1003836f4 and self.reg(0) == ALLOCATION
            assert self.copy_offsets == list(reversed(range(self.request_size)))
            self.checkpoints.append({'kind': 'modeled_free_return', 'site': hex(self.reg(30) - 4),
                                     'pointer': hex(self.reg(0))})
            self.finish_import(self.reg(30), 0)
            return
        if pc == ADAPTER_CALL:
            self.child_record = self.reg(0)
            assert self.child_record == self.reg(29) - 0xa0
            assert self.reg(1) == u.reg_read(ar.UC_ARM64_REG_SP) + 0x6f8
        if pc == OUTER_ENTRY:
            assert self.reg(30) == 0x1006176d4 and self.reg(0) == self.child_record
            q = self.child_record
            key = ((q ^ OUTER_KEY) * CODEC) & PHASE_MASK
            assert (self.memory_word(q + 0x34, 4) - key) & PHASE_MASK == 0xb306
            assert self.memory_word(q + 0x18) == ALLOCATION
            self.put(q + 0x10, 4, self.marker)
            cursor = self.reg(1)
            self.put(cursor, 8, self.memory_word(cursor) + 0xe0)
            self.checkpoints.append({'kind': 'modeled_outer_return', 'entry': hex(pc),
                                     'record': hex(q), 'decoded_phase': '0xb306',
                                     'record_status': hex(self.marker)})
            self.return_model()
            return
        if pc == FIRST_READ:
            assert self.reg(29) - 0x90 == self.child_record + 0x10
            self.checkpoints.append({'kind': 'output_read', 'site': hex(pc),
                                     'address': hex(self.child_record + 0x10)})
        if pc == FIRST_READ + 4:
            assert self.reg(23) == self.marker
        if pc in (TAIL_DISPATCH, COPY_START, PARENT_STORE):
            assert self.reg(23) == self.marker
            self.checkpoints.append({'kind': 'tail', 'site': hex(pc), 'status_w23': hex(self.reg(23))})
        if pc == PARENT_STORE:
            assert self.reg(8) == self.parent
        if pc == HALT:
            assert u.reg_read(ar.UC_ARM64_REG_SP) == SP
            self.stop('boundary', pc=hex(pc))
            return
        super().hook(u, pc, size, user)

    def run(self):
        key = ((PARENT ^ 0xc6d66014) * 0x6b86592f) & PHASE_MASK
        for offset, width, value in ((0, 8, ALLOCATION + 0x900),
                                     (0x10, 8, ALLOCATION + 0xa00),
                                     (0x18, 8, RESULT_BUFFER), (0x20, 4, 0),
                                     (0x24, 4, self.tail_control - key),
                                     (0x30, 8, ALLOCATION + 0xc00),
                                     (0x38, 4, key ^ PARENT_PHASE)):
            self.put(PARENT + offset, width, value)
        payload = bytes(3 * offset + 1 for offset in range(16))
        self.u.mem_write(ALLOCATION, payload)
        self.u.mem_write(RESULT_BUFFER, b'\xdd' * 16)
        self.setreg(0, PARENT)
        self.setreg(1, CURSOR)
        self.setreg(30, HALT)
        self.u.reg_write(ar.UC_ARM64_REG_SP, SP)
        self.u.emu_start(PARENT_ENTRY, 0, count=4000)
        assert self.stop_reason == 'boundary'
        assert self.parent_stores == [{'pc': hex(PARENT_STORE), 'offset_bytes': 0x28,
                                       'size_bytes': 4, 'value': hex(self.marker)}]
        assert self.memory_word(PARENT + 0x28, 4) == self.marker
        expected = bytes(byte ^ 0x98 for byte in payload[:self.request_size])
        actual = bytes(self.u.mem_read(RESULT_BUFFER, 16))
        assert actual == expected + b'\xdd' * (16 - self.request_size)
        return {'status': hex(self.marker), 'tail_control': hex(self.tail_control),
                'checkpoints': self.checkpoints, 'boundary': self.records[-1],
                'copied_offsets': self.copy_offsets, 'destination_bytes_hex': actual.hex(),
                'parent_cursor': hex(self.memory_word(CURSOR)),
                'parent_stores': self.parent_stores, 'edges': self.branch_slots}


def source_checks():
    status = z3.BitVec('class_marker', 32)
    frame = Frame(x29=SP + 0x50, sp=SP)
    record = SP + 0x50 - 0xa0
    frame.put(record + 0x10, 4, status)
    frame.step(FIRST_READ, FIRST_READ + 4)
    verify(frame.read('w23') == status)
    frame.put(SP + 0x260, 8, PARENT)
    frame.step(PARENT_STORE - 4, PARENT_STORE + 4)
    verify(frame.get(PARENT + 0x28, 4) == status)

    control = z3.BitVec('tail_control', 32)
    frame = Frame(w26=control)
    frame.step(FIRST_READ + 4, 0x1003f5944)
    # W19 is independent of the status and fixes the selected branch pair.
    verify(frame.read('w8') == (frame.read('w19') ^ z3.If(
        control == TAIL_CONTROL, z3.BitVecVal(0x6a, 32), z3.BitVecVal(0, 32))))

    banks = [
        selected(0x100e99a00, 0x100f4e390, 0xd7, 0xcde2),
        selected(0x100e99a00, 0x100f4e390, 0x6d, 0xcd9c),
        selected(0x100fc4130, 0x101031ea0, 0x4e, 0xcd6a),
    ]
    assert [row['target'] for row in banks] == ['0x10061748c', '0x10047d47c', '0x100912ad8']
    return {'bit_vector_queries': 3, 'bank_partitions': banks, 'source_spans': list(SPANS.values())}


def inspect():
    proof = source_checks()
    slots = {int(row['slot'], 16) for row in proof['bank_partitions']}
    profiles = []
    for status, size in ((0x74c29dee, 0), (0x74c29dba, 0), (0x74c29d88, 0),
                         (0x74c29dee, 1), (0x74c29d88, 16)):
        probe = CallerProbe(status, TAIL_CONTROL + size)
        profiles.append(probe.run())
        slots.update(probe.slots)
    slots = {slot for slot in slots if FIXUPS[slot]['kind'] != 'bind'}
    return {'profiles': profiles, 'source': proof, 'fixups': verify_original_fixups(slots),
            'native_end_to_end_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
