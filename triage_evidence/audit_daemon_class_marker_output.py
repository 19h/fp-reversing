#!/usr/bin/env python3
"""Trace the discovery marker through the daemon's ordinary output return."""

import json

import z3

from audit_daemon_class_lock_gate import HEAP, SP, STATUS
from audit_daemon_class_lock_release import ReleaseProbe
from audit_daemon_class_redispatch import RedispatchProbe
from audit_daemon_class_status_route import ERROR_RELAY, PostCleanup, verify
from audit_daemon_selector26_return import Frame, SPANS, number
from daemon_receive_tools import FIXUPS, TABLE, verify_original_fixups
from daemon_rpc502_probe import HALT, STACK, Probe, ar

MARKER_OFFSET = 0x804
MARKER_READ = 0x100629bfc
OUTPUT_STORE = 0x10062b370
ORDINARY_RETURN = 0x10062b3a8
RECORD_SAVE = 0x100530450
SAVED_TARGET_READ = 0x10048ce78
SAVED_TARGET_STORE = 0x10048ce7c
LIVE_TARGET_BRANCH = 0x1004905d4


class OutputProbe(RedispatchProbe):
    def __init__(self, record, flag, primary, redispatch):
        self.redispatch = redispatch
        self.record = record
        self.following = False
        self.target_load = None
        self.visits = 0
        self.marker_accesses = []
        self.output_writes = []
        if redispatch is None:
            PostCleanup.__init__(self, flag, 0, primary)
        else:
            super().__init__(*redispatch)
        self.initial_record = bytes(range(0x40))
        self.u.mem_write(record, self.initial_record)
        self.setreg(0, record)

    def read_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == SAVED_TARGET_READ and self.following:
            assert address in FIXUPS and size == 8
            self.target_load = address
        if address < SP + MARKER_OFFSET + 4 and address + size > SP + MARKER_OFFSET:
            assert address == SP + MARKER_OFFSET and size == 4
            self.marker_accesses.append(('read', pc, self.memory_word(address, size)))
        super().read_hook(u, access, address, size, value, user)

    def write_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == SAVED_TARGET_STORE and self.following:
            assert address == SP + 0x768 and size == 8
            assert value == self.memory_word(self.target_load)
        if address < SP + MARKER_OFFSET + 4 and address + size > SP + MARKER_OFFSET:
            assert address == SP + MARKER_OFFSET and size == 4
            self.marker_accesses.append(('write', pc, value & 0xffffffff))
        if address < self.record + len(self.initial_record) and address + size > self.record:
            self.output_writes.append((pc, address - self.record, size, value & 0xffffffff))
        super().write_hook(u, access, address, size, value, user)

    def hook(self, u, pc, size, user):
        if pc == RECORD_SAVE:
            assert self.reg(0) == self.record
        if pc == ERROR_RELAY + 0xc:
            assert self.memory_word(SP + MARKER_OFFSET, 4) == self.reg(21)
            self.following = True
        if self.following:
            self.visits += 1
            if pc == LIVE_TARGET_BRANCH:
                assert self.target_load is not None
                assert self.reg(9) == self.memory_word(SP + 0x768)
                assert self.reg(9) == self.memory_word(self.target_load)
                Probe.hook(self, u, pc, size, user)
                edge = self.pac[-1]
                assert FIXUPS[self.target_load]['annotation'] == '(div=0x28D8 ad=0 key=IA)'
                assert int(edge['target'], 16) == FIXUPS[self.target_load]['target']
                self.branch_slots.append(dict(edge, load_pc=hex(SAVED_TARGET_READ),
                                              mirror_store_pc=hex(SAVED_TARGET_STORE),
                                              fixup_slot=hex(self.target_load)))
                self.target_load = None
                self.reads.clear()
                return
            if pc == OUTPUT_STORE:
                assert self.reg(0) == self.memory_word(SP + 0x30) == self.record
                assert self.reg(8) == self.memory_word(SP + MARKER_OFFSET, 4)
            if pc == ORDINARY_RETURN:
                assert self.reg(30) == HALT
            if pc == HALT:
                self.stop('source_boundary', epilogue_pc=hex(ORDINARY_RETURN))
                return
            assert pc not in self.imports
            ReleaseProbe.hook(self, u, pc, size, user)
            return
        if self.redispatch is None:
            PostCleanup.hook(self, u, pc, size, user)
        else:
            super().hook(u, pc, size, user)


def source_projection():
    marker = z3.BitVec('marker', 32)
    record = STACK + 0x4400
    frame = Frame(sp=SP, x0=record, x7=TABLE, w19=0xb306, w21=marker)
    frame.step(RECORD_SAVE, RECORD_SAVE + 4)
    frame.step(ERROR_RELAY + 8, ERROR_RELAY + 0xc)
    verify(frame.get(SP + MARKER_OFFSET, 4) == marker)
    frame.step(MARKER_READ - 4, 0x100629c0c)
    load_pc, slot, width = frame.loads[-2]
    assert (load_pc, slot, width) == (0x100629c00, 0x101091b78, 8)
    assert number(frame.read('x9')) == FIXUPS[slot]['target'] == OUTPUT_STORE
    assert number(frame.read('x17')) == 0xe347
    verify(frame.read('x0') == record)
    verify(frame.read('w8') == marker)
    frame.step(OUTPUT_STORE, OUTPUT_STORE + 4)
    verify(frame.get(record + 0x10, 4) == marker)
    return {'bit_vector_queries': 4, 'dispatch_slot': hex(slot),
            'source_spans': list(SPANS.values())}


def inspect():
    proof = source_projection()
    slots = set()
    profiles = []
    cases = [
        ('open_failure', 1, 0x70, HEAP, None, 0x74c29dee),
        ('class_skip', 1, 0, HEAP, None, 0x74c29dba),
        ('null_lock', 0xffffffff, 0x70, 0, None, 0x74c29d88),
        ('redispatch_null_equal', 0, 0x70, HEAP, (0, STATUS), 0x74c29d88),
        ('redispatch_null_unequal', 0, 0x70, HEAP, (0, STATUS ^ 1), 0x74c29d88),
        ('redispatch_nonnull_equal', 0, 0x70, HEAP, (HEAP, STATUS), 0x74c29d88),
    ]
    for index, (name, flag, primary, lock, redispatch, marker) in enumerate(cases):
        record = STACK + 0x4400 + index * 0x100
        probe = OutputProbe(record, flag, primary, redispatch)
        row = probe.run_case(name, lock, boundary_sp=SP + 0xcd0)
        assert probe.marker_accesses == [
            ('write', ERROR_RELAY + 8, marker), ('read', MARKER_READ, marker),
        ]
        assert probe.output_writes == [(OUTPUT_STORE, 0x10, 4, marker)]
        expected = bytearray(probe.initial_record)
        expected[0x10:0x14] = marker.to_bytes(4, 'little')
        assert probe.u.mem_read(record, len(expected)) == expected
        row.update(marker_accesses=[{'access': kind, 'pc': hex(pc), 'value': hex(value)}
                                    for kind, pc, value in probe.marker_accesses],
                   output_record=hex(record),
                   saved_flag=hex(flag),
                   redispatch_pair=list(map(hex, redispatch)) if redispatch else None,
                   output_store={'pc': hex(OUTPUT_STORE), 'offset_bytes': 0x10,
                                 'size_bytes': 4, 'value': hex(marker)},
                   post_store_instruction_visits=probe.visits)
        profiles.append(row)
        slots.update(probe.slots)
    slots = {slot for slot in slots if FIXUPS[slot]['kind'] != 'bind'}
    return {'profiles': profiles, 'source': proof, 'fixups': verify_original_fixups(slots),
            'native_marker_output_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
