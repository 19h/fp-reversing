#!/usr/bin/env python3
"""Follow the discovery status through the earlier adapter into its caller frame."""

import json

import z3

from audit_daemon_class_marker_caller import (
    ALLOCATION, CallerProbe, PARENT_ENTRY, PARENT_STORE, RESULT_BUFFER, TAIL_CONTROL,
)
from audit_daemon_class_status_route import verify
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import FIXUPS, TABLE, selected, verify_original_fixups
from daemon_rpc502_probe import STACK, Probe, ar

FRAME = STACK + 0x49000
RECORD = FRAME + 0x10cb8
CURSOR = FRAME + 0xb9d0
START = 0x100585034
ADAPTER = 0x10047d180
READ = 0x100585154
STORE = 0x100585158
TARGET_LOAD, TARGET_SAVE = 0x1009a1028, 0x1009a1030
TARGET_RELOAD, TARGET_BRANCH = 0x1005ae1d4, 0x1005ae1fc
TARGET_CELL, TARGET_SLOT = FRAME + 0x5990, TABLE + 8 * 0x10cd
STATUS_CELL = FRAME + 0xf48
PHASE = 0x6cf4
CONSUMER = 0x1005cfbd4
COMPARE = 0x1005cfbf4
EXPECTED = 0x8b3dc651
EQUAL_STOP, UNEQUAL_STOP = 0x1007956dc, 0x1006f6464


class FrameProbe(CallerProbe):
    def __init__(self, marker):
        super().__init__(marker, TAIL_CONTROL + 16, parent=RECORD)
        self.status_accesses = []
        self.saved_target = []

    def read_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == TARGET_LOAD:
            assert (address, size) == (TARGET_SLOT, 8)
            self.saved_target.append((pc, address, self.memory_word(address, size)))
        if pc == TARGET_RELOAD:
            assert (address, size) == (TARGET_CELL, 8)
            self.saved_target.append((pc, address, self.memory_word(address, size)))
        if address == STATUS_CELL:
            self.status_accesses.append(('read', pc, size, self.memory_word(address, size)))
        super().read_hook(u, access, address, size, value, user)

    def write_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == TARGET_SAVE:
            assert (address, size) == (TARGET_CELL, 8)
            self.saved_target.append((pc, address, value))
        if address == STATUS_CELL:
            self.status_accesses.append(('write', pc, size, value))
        super().write_hook(u, access, address, size, value, user)

    def hook(self, u, pc, size, user):
        if pc == ADAPTER:
            assert (self.reg(0), self.reg(1), self.reg(30)) == (RECORD, CURSOR, 0x100585144)
        if pc == PARENT_ENTRY:
            assert self.reg(0) == RECORD and self.reg(30) == 0x10047d3c4
        if pc == READ:
            assert self.reg(22) + 0xce0 == RECORD + 0x28
            assert self.memory_word(CURSOR) == 0
            assert self.memory_word(RECORD + 0x28, 4) == self.marker
            assert u.reg_read(ar.UC_ARM64_REG_SP) == FRAME
        if pc == TARGET_BRANCH:
            assert self.saved_target == [
                (TARGET_LOAD, TARGET_SLOT, CONSUMER), (TARGET_SAVE, TARGET_CELL, CONSUMER),
                (TARGET_RELOAD, TARGET_CELL, CONSUMER),
            ]
            assert self.reg(13) == FIXUPS[TARGET_SLOT]['target'] == CONSUMER
            assert self.reg(17) == 0x92a5
            assert FIXUPS[TARGET_SLOT]['annotation'] == '(div=0x92A5 ad=0 key=IA)'
            Probe.hook(self, u, pc, size, user)
            self.branch_slots.append(dict(self.pac[-1], load_pc=hex(TARGET_LOAD),
                                          store_pc=hex(TARGET_SAVE), reload_pc=hex(TARGET_RELOAD),
                                          fixup_slot=hex(TARGET_SLOT)))
            self.reads.clear()
            return
        if pc == COMPARE:
            assert self.reg(9) == self.marker and self.reg(10) == EXPECTED
        if pc in (EQUAL_STOP, UNEQUAL_STOP):
            assert pc == (EQUAL_STOP if self.marker == EXPECTED else UNEQUAL_STOP)
            if pc == UNEQUAL_STOP:
                assert self.reg(9) == self.marker
            self.stop('boundary', pc=hex(pc))
            return
        super().hook(u, pc, size, user)

    def run(self):
        self.u.reg_write(ar.UC_ARM64_REG_SP, FRAME)
        self.setreg(19, 0x7b68 - 0x6a9b)
        self.setreg(8, 0)
        for offset, value in {
            0x9938: ALLOCATION + 0xc00, 0x9940: ALLOCATION + 0xa00, 0xb48: RESULT_BUFFER,
            0x1e8: ALLOCATION + 0x900, 0x1f0: FRAME + 0x510, 0x510: 0x27,
            0x9b0: 0x100fc4230, 0x9a8: 0x101031fa0, 0x9c8: 0x1010b8dc8,
            0x9c0: 0x1010c4670, 0x9d8: TABLE, 0x9d0: PHASE,
        }.items():
            self.put(FRAME + offset, 8, value)
        self.u.mem_write(ALLOCATION, bytes(range(16)))
        self.u.emu_start(START, 0, count=12000)
        assert self.stop_reason == 'boundary'
        accesses = [('write', STORE, 4, self.marker), ('read', 0x1005cfbe4, 4, self.marker)]
        if self.marker != EXPECTED:
            accesses.append(('read', 0x10060646c, 4, self.marker))
        assert self.status_accesses == accesses
        assert self.memory_word(STATUS_CELL, 4) == self.marker
        publications = [row for row in self.parent_stores if row['pc'] == hex(PARENT_STORE)]
        assert publications == [{'pc': hex(PARENT_STORE), 'offset_bytes': 0x28, 'size_bytes': 4,
                                 'value': hex(self.marker)}]
        return {'marker': hex(self.marker), 'record': hex(RECORD), 'frame': hex(FRAME),
                'cursor_delta': hex(self.memory_word(CURSOR)), 'record_stores': self.parent_stores,
                'status_accesses': [{'kind': kind, 'pc': hex(pc), 'size_bytes': size,
                                     'value': hex(value)} for kind, pc, size, value in accesses],
                'child_checkpoints': self.checkpoints,
                'copied_offsets': self.copy_offsets, 'edges': self.branch_slots,
                'stop': self.records[-1]}


def source_checks():
    phase, status = z3.BitVecs('caller_phase returned_status', 32)
    frame = Frame(sp=FRAME, x22=RECORD - 0xcb8)
    frame.put(RECORD + 0x28, 4, status)
    frame.step(READ, STORE + 4)
    verify(frame.get(STATUS_CELL, 4) == status)
    frame.put(FRAME + 0x9d0, 8, z3.ZeroExt(32, phase))
    frame.step(CONSUMER, 0x1005cfc0c)
    expected = (0xcbb6 ^ (phase << 1)) + 0x8b3db3f3
    verify(frame.read('w24') + 0x8b3db3f3 == expected)
    verify(frame.read('w8') == ((phase - 0x5a96) ^
                              z3.If(status == expected, z3.BitVecVal(0x6a37, 32), 0)))
    return {'bit_vector_queries': 3, 'source_spans': list(SPANS.values())}


def inspect():
    proof = source_checks()
    bank = selected(0x100fc4230, 0x101031fa0, 0xe4, 0xcdf1)
    assert int(bank['target'], 16) == ADAPTER
    profiles, slots = [], {int(bank['slot'], 16)}
    for case, marker in (('open_failure', 0x74c29dee), ('class_skip', 0x74c29dba),
                         ('lock_or_redispatch', 0x74c29d88), ('equality_control', EXPECTED)):
        probe = FrameProbe(marker)
        profiles.append(dict(probe.run(), case=case))
        slots.update(probe.slots)
    return {'profiles': profiles, 'incoming_bank': bank, 'source': proof, 'phase': hex(PHASE),
            'fixups': verify_original_fixups(slot for slot in slots if FIXUPS[slot]['kind'] != 'bind'),
            'native_attribution': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
