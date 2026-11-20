#!/usr/bin/env python3
"""Trace the saved discovery inputs and test their ordinary redispatch paths."""

import json

import z3

from audit_daemon_class_lock_gate import CACHE, HEAP, NULL_STATUS, SP, STATUS
from audit_daemon_class_lock_release import ReleaseProbe
from audit_daemon_class_status_route import BEFORE_GATE, ERROR_RELAY, PostCleanup, verify
from audit_daemon_selector26_return import Frame, SPANS, number
from daemon_receive_tools import FIXUPS, TABLE, verify_original_fixups

PAIR_COPY = 0x1006205f8


def source_checks():
    """Lift local instruction windows with independently declared input cells."""
    context, marker = z3.BitVec('context', 64), z3.BitVec('marker', 32)
    frame = Frame(sp=SP, w10=0x5bca)
    frame.put(SP + 0x808, 8, context)
    frame.put(SP + 0x40c, 4, marker)
    frame.step(PAIR_COPY, 0x10062063c)
    verify(frame.get(SP + 0x8c8, 8) == context)
    verify(frame.get(SP + 0x914, 4) == marker)
    verify(frame.read('x19') == context)
    verify(frame.read('w11') == marker)
    verify(frame.read('w8') == 0)
    verify(frame.read('w9') == 0x65a1)
    verify(frame.read('w10') == z3.If(context == 0,
                                     z3.BitVecVal(0x5bca, 32), z3.BitVecVal(0x5c26, 32)))

    frame.seed('w9', 0x65a1)
    frame.seed('w8', 1)
    frame.step(BEFORE_GATE, 0x1006398fc)
    verify(frame.get(SP + 0x89c, 4) == 1)
    verify(frame.read('w10') == 0x5847)
    verify(frame.read('w9') == z3.If(z3.And(context != 0, marker != STATUS),
                                    z3.BitVecVal(0x65b3, 32), z3.BitVecVal(0x65a1, 32)))

    edges = []
    for flag, target in ((0, ERROR_RELAY), (1, PAIR_COPY)):
        frame = Frame(sp=SP, x7=TABLE, w8=flag)
        frame.put(SP + 0x2ec, 4, 0xb306)
        assert frame.step(0x10062c260, 0x10062c2a4) == target
        assert number(frame.read('w10')) == 0x5bca
        edges.extend(frame.edges)

    for pointer, target in ((0, 0x10051ac30), (HEAP, BEFORE_GATE)):
        frame = Frame(sp=SP, x7=TABLE, w10=0x5bca)
        frame.put(SP + 0x808, 8, pointer)
        frame.put(SP + 0x40c, 4, STATUS)
        assert frame.step(PAIR_COPY, 0x100620650) == target
        edges.extend(frame.edges)
    return {'bit_vector_queries': 10, 'edges': edges, 'source_spans': list(SPANS.values())}


class RedispatchProbe(PostCleanup):
    def __init__(self, context, marker):
        super().__init__(0, 0, 0x70)
        self.context = context
        self.marker = marker

    def hook(self, u, pc, size, user):
        if pc == BEFORE_GATE and self.admissions == 0:
            # Supply the two retained values from the separately audited copy.
            self.u.mem_write(SP + 0x8c8, self.context.to_bytes(8, 'little'))
            self.u.mem_write(SP + 0x914, self.marker.to_bytes(4, 'little'))
        if pc == BEFORE_GATE and self.admissions:
            assert self.admissions == 1
            self.admissions += 1
            assert (self.reg(8), self.reg(9), self.reg(19), self.reg(11)) == (
                1, 0x65a1, self.context, self.marker,
            )
            self.records.append({'kind': 'redispatch_admission', 'pc': hex(pc),
                                 'context': hex(self.context), 'marker': hex(self.marker)})
            ReleaseProbe.hook(self, u, pc, size, user)
            return
        if pc == self.import_addresses['IOKit/_IOServiceMatching'] and self.attempt == 1:
            assert self.admissions == 2 and not self.owners
            assert self.reg(30) - 4 == 0x100079bf0
            label = bytes(self.u.mem_read(self.reg(0), 31)).split(b'\0', 1)[0].decode()
            assert label == 'com_apple_driver_FairPlayIOKit'
            assert self.memory_word(CACHE) == HEAP
            self.stop('source_boundary', pc=hex(self.reg(30) - 4), pending_class=label)
            return
        super().hook(u, pc, size, user)


def inspect():
    proof = source_checks()
    slots = {int(edge['slot'], 16) for edge in proof['edges']}
    profiles = []
    for context in (0, HEAP):
        for marker in (STATUS, STATUS ^ 1):
            probe = RedispatchProbe(context, marker)
            name = 'nonnull' if context else 'null'
            name += '_equal' if marker == STATUS else '_unequal'
            admitted = context != 0 and marker != STATUS
            row = probe.run_case(name, HEAP, boundary_sp=SP - 0x150 if admitted else SP)
            row['redispatch_inputs'] = {'context': hex(context), 'marker': hex(marker)}
            final = row['sequence'][-1]
            calls = [item.get('name') for item in row['sequence']]
            assert calls.count('_IOServiceOpen') == 1
            assert calls.count('_pthread_rwlock_unlock') == 1
            if admitted:
                assert final['pc'] == '0x100079bf0' and 'pending_class' in final
                assert calls.count('_pthread_rwlock_wrlock') == 2
            else:
                assert final['pc'] == hex(ERROR_RELAY + 0xc)
                assert final['stored_marker'] == hex(NULL_STATUS)
                assert calls.count('_pthread_rwlock_wrlock') == 1
            profiles.append(row)
            slots.update(probe.slots)
    slots = {slot for slot in slots if FIXUPS[slot]['kind'] != 'bind'}
    return {'profiles': profiles, 'source': proof, 'fixups': verify_original_fixups(slots),
            'native_redispatch_inputs_and_lookup_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
