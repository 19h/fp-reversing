#!/usr/bin/env python3
"""Audit the outer phase producer and post-discovery status routing."""

import json

import z3

from audit_daemon_class_lock_gate import GateProbe, HEAP, SP, STATUS
from audit_daemon_class_lock_release import FINAL, ReleaseProbe
from audit_daemon_selector26_return import Frame, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, TABLE, verify_original_fixups
from daemon_rpc502_probe import HALT, STACK, Probe, ar

RECORD = STACK + 0x4000
CURSOR = STACK + 0x5000
OPERANDS = (STACK + 0x6800, STACK + 0x6900, STACK + 0x6a00)
OUTER_PHASE = 0xb306
OUTER_KEY = 0x7e103facb521e742
CODEC = 0x74cae98d
BEFORE_GATE = 0x100639894
SAVED_STATUS = 0x1004c620c
ERROR_RELAY = 0x10052b5e8
MATCH_RELAY = 0x10062aad0


class EntryProbe(GateProbe):
    def __init__(self, absent):
        self.absent = absent
        self.branch_slots = []
        super().__init__()

    def hook(self, u, pc, size, user):
        if pc == self.import_addresses['libSystem/_malloc']:
            call = self.reg(30) - 4
            width = self.reg(0)
            assert (call, width) in ((0x10061b384, 49), (0x1004a8c54, 16))
            assert self.memory_word(SP + 0x2ec, 4) == OUTER_PHASE
            self.stop('allocator_request', pc=hex(call), size_bytes=width,
                      saved_outer_phase=hex(self.memory_word(SP + 0x2ec, 4)))
            return
        if pc == HALT:
            self.stop('ordinary_source_return', pc=hex(0x1006176f4),
                      record_status=hex(self.memory_word(RECORD + 0x10, 4)),
                      caller_cursor=hex(self.memory_word(CURSOR)))
            return
        super().hook(u, pc, size, user)

    def run(self, marker):
        key = ((RECORD ^ OUTER_KEY) * CODEC) & 0xffffffff
        for index, (offset, operand) in enumerate(zip((0, 8, 0x18), OPERANDS)):
            value = 0 if index == self.absent else operand
            self.u.mem_write(RECORD + offset, value.to_bytes(8, 'little'))
        fields = [(0x14, marker - key), (0x34, OUTER_PHASE + key), (0x38, OUTER_PHASE - key)]
        for offset, value in fields:
            self.u.mem_write(RECORD + offset, (value & 0xffffffff).to_bytes(4, 'little'))
        self.u.mem_write(CURSOR, (0x27).to_bytes(8, 'little'))
        self.setreg(0, RECORD)
        self.setreg(1, CURSOR)
        self.setreg(30, HALT)
        self.u.reg_write(ar.UC_ARM64_REG_SP, SP + 0xd20)
        self.u.emu_start(0x10061748c, 0, count=4000)
        expected = 'ordinary_source_return' if self.absent is not None else 'allocator_request'
        assert self.stop_reason == expected
        if self.absent is None:
            assert self.records[-1]['size_bytes'] == (49 if marker == 0x66257669 else 16)
        else:
            assert self.memory_word(RECORD + 0x10, 4) == 0x74c29d88
            assert self.memory_word(CURSOR) == 0 and self.u.reg_read(ar.UC_ARM64_REG_SP) == SP + 0xd20
        return {'absent_operand': self.absent, 'decoded_marker': hex(marker),
                'record_fields': [hex(self.memory_word(RECORD + off, 4)) for off in (0x14, 0x34, 0x38)],
                'boundary': self.records[-1], 'edges': self.branch_slots}


class PostCleanup(ReleaseProbe):
    def __init__(self, flag, env, primary):
        super().__init__(env, primary, 'open_failure', 0)
        self.flag = flag
        self.admissions = 0

    def hook(self, u, pc, size, user):
        if pc == 0x10053043c:
            # The separately replayed outer entry supplies the verified W6 value.
            self.setreg(6, OUTER_PHASE)
        if pc == BEFORE_GATE:
            self.admissions += 1
            if self.admissions == 1:
                self.setreg(8, self.flag)
            else:
                assert self.reg(9) == 0x65a1 and self.reg(8) == 1
                self.stop('source_boundary', pc=hex(pc), flag=hex(self.reg(8)),
                          restored_context=hex(self.reg(19)), restored_marker=hex(self.reg(11)))
                return
        if pc == FINAL:
            assert self.reg(24) == OUTER_PHASE
            assert self.reg(21) == self.memory_word(SP + 0x62c, 4)
            assert self.reg(8) == self.memory_word(SP + 0x89c, 4) == self.flag
            self.records.append({'kind': 'status_inputs', 'pc': hex(pc),
                                 'marker': hex(self.reg(21)), 'flag': hex(self.reg(8))})
            Probe.hook(self, u, pc, size, user)
            return
        if pc == SAVED_STATUS:
            Probe.hook(self, u, pc, size, user)
            return
        if pc == ERROR_RELAY + 0xc:
            assert self.memory_word(SP + 0x804, 4) == self.reg(21)
            self.stop('source_boundary', pc=hex(pc), stored_marker=hex(self.reg(21)))
            return
        super().hook(u, pc, size, user)


def verify(proposition):
    solver = z3.SolverFor('QF_BV')
    solver.set(timeout=30000)
    solver.add(z3.Not(proposition))
    assert solver.check() == z3.unsat


def proof():
    record_address = z3.BitVec('record_address', 64)
    frame = Frame(x0=record_address)
    frame.step(0x100559cc0, 0x100559d10)
    verify(frame.read('x11') == record_address ^ OUTER_KEY)
    verify(frame.read('w1') == z3.Extract(31, 0, (record_address ^ OUTER_KEY) * CODEC))

    product, phase, marker, flag = z3.BitVecs('product phase marker flag', 32)
    frame.seed('x0', RECORD)
    frame.seed('w1', product)
    frame.put(RECORD + 0x34, 4, product + phase)
    frame.step(0x100559d10, 0x100559d18)
    verify(frame.read('w6') == phase)

    frame = Frame(w10=0x5847, w21=marker, w8=flag)
    frame.step(SAVED_STATUS, 0x1004c6258)
    verify(frame.read('w13') == 0x1c42e196)
    verify(frame.read('w12') == 0x183f)
    verify(frame.read('w8') == z3.If(z3.And(marker != STATUS, flag == 0),
                                       z3.BitVecVal(0x5847, 32), z3.BitVecVal(0x5868, 32)))

    frame = Frame(w12=0x183f, w21=marker)
    frame.step(0x10051ac30, 0x10051ac6c)
    verify(frame.read('w9') == z3.If(marker == STATUS, z3.BitVecVal(0x485d, 32),
                                       z3.BitVecVal(0x183f, 32)))

    old_cursor, new_cursor = z3.BitVecs('old_cursor new_cursor', 64)
    frame = Frame(x20=RECORD, x19=CURSOR, x21=old_cursor)
    frame.put(RECORD, 8, new_cursor)
    frame.step(0x1006176d4, 0x1006176e4)
    difference = z3.Extract(15, 0, new_cursor - old_cursor)
    verify(frame.get(CURSOR, 8) == z3.ZeroExt(48, difference) << 4)
    return {'queries': 8, 'source_spans': list(SPANS.values()),
            'routing_xor_initial': hex(OUTER_KEY)}


def inspect():
    entry_cases = []
    slots = set()
    for marker, absent in ((0x66257669, None), (0x66257668, None),
                           (0x66257669, 0), (0x66257669, 1), (0x66257669, 2)):
        probe = EntryProbe(absent)
        entry_cases.append(probe.run(marker))
        slots.update(probe.slots)
    cases = []
    for name, flag, byte, pointer, marker in (
        ('primary_failure_zero_flag', 0, 0x70, HEAP, 0x74c29dee),
        ('primary_failure_nonzero_flag', 1, 0x70, HEAP, 0x74c29dee),
        ('class_skip_nonzero_flag', 1, 0, HEAP, 0x74c29dba),
        ('null_lock_nonzero_flag', 0xffffffff, 0x70, 0, 0x74c29d88),
    ):
        probe = PostCleanup(flag, 0, byte)
        row = probe.run_case(name, pointer)
        final = row['sequence'][-1]
        assert final['pc'] == hex(BEFORE_GATE if not flag else ERROR_RELAY + 0xc)
        input_row, = [item for item in row['sequence'] if item.get('kind') == 'status_inputs']
        assert input_row['marker'] == hex(marker)
        if flag:
            assert final['stored_marker'] == input_row['marker']
        row['saved_flag_control'] = hex(flag)
        cases.append(row)
        slots.update(probe.slots)

    # The match branch uses a separate direct original-source control.
    frame = Frame(x7=TABLE, sp=SP, w10=0x5847, w21=STATUS, w8=0)
    assert frame.step(SAVED_STATUS, 0x1004c6264) == 0x10051ac30
    assert frame.step(0x10051ac30, 0x10051ac78) == MATCH_RELAY
    assert number(frame.read('w21')) == STATUS
    slots.update({0x101066230, 0x10105e1d8})
    dispatch_control = frame.edges

    excluded = {slot for slot in slots if FIXUPS[slot]['kind'] == 'bind'}
    assert excluded == {0x1010a39c8, 0x1010b1e18}
    return {
        'outer_entry': entry_cases,
        'post_cleanup': cases,
        'isolated_marker_match_control': dispatch_control,
        'proof': proof(),
        'fixups': verify_original_fixups(slots - excluded),
        'uninterrupted_outer_entry_to_discovery_proved': False,
        'native_status_or_ipc_observed': False,
    }


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
