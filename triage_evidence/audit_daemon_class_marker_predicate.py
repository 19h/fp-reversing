#!/usr/bin/env python3
"""Recover the saved discovery continuation and its field and branch effects."""

import json
import struct

import z3

from audit_daemon_class_marker_frame import EXPECTED, FRAME, PHASE, UNEQUAL_STOP
from audit_daemon_class_status_route import verify
from audit_daemon_selector26_return import Frame, SPANS, number
from daemon_receive_tools import FIXUPS, IMAGE, TABLE, verify_original_fixups
from daemon_rpc502_probe import Probe, ar
from audit_daemon_class_lock_gate import GateProbe
from resolve_kernel_collection_interfaces import commands

ENTRY = 0x100509ec8
PRODUCER = 0x10085d834
CONSUMER = 0x1005000d4
CELL = FRAME + 0xc28
FLAG = FRAME + 0x202f
CURSOR = FRAME + 0x16d0
EXPECTED_OTHER = ((PHASE + 0xa3d77b07) & 0x5c283b6d) ^ 0x76d8c9e9
UNEQUAL_RESULT, EQUAL_RESULT = 0x10053eac0, 0x10051d248
RETEST_UNEQUAL, RETEST_EQUAL = 0x1004cb6f4, 0x1005fac1c


def literal_writers():
    encoding = 0xf90003e0 | (0xc28 // 8 << 10)
    for at, command, _ in commands(IMAGE.data, 0):
        if command != 0x19:
            continue
        for index in range(struct.unpack_from('<I', IMAGE.data, at + 64)[0]):
            section = at + 72 + 80 * index
            name, _, start, size = struct.unpack_from('<16s16sQQ', IMAGE.data, section)
            if name.rstrip(b'\0') == b'__text':
                words = struct.iter_unpack('<I', IMAGE.read(start, size))
                sites = [hex(start + 4 * i) for i, (w,) in enumerate(words)
                         if w & 0xffffffe0 == encoding]
                return {'words_checked': size // 4, 'literal_store_sites': sites}
    raise ValueError('missing __text')


def source():
    phase, status, other, saved = z3.BitVecs('phase marker other saved', 32)
    frame = Frame(sp=FRAME, w9=status)
    frame.put(FRAME + 0x9d0, 8, z3.ZeroExt(32, phase))
    frame.put(FRAME + 0x3044, 4, other)
    frame.put(FRAME + 0x1074, 4, saved)
    frame.step(CONSUMER, 0x10050015c)
    neq = z3.If(status != EXPECTED, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
    match = other == (((phase + 0xa3d77b07) & 0x5c283b6d) ^ 0x76d8c9e9)
    selector = z3.If(match, z3.BitVecVal(1, 32), neq)
    verify(frame.get(FLAG, 1) == z3.Extract(7, 0, neq))
    verify(frame.get(FRAME + 0x7774, 4) == other)
    verify(frame.get(FRAME + 0x4dec, 4) == saved)
    verify(frame.read('w10') == ((phase + 0x3ad1) ^
                               (0x15 * ((((phase ^ 0x6abf) * 5) ^ selector) & 1))))
    verify(z3.And(frame.read('w8') == EXPECTED, frame.read('w9') == status))
    mix = (frame.read('w22') ^ 0x1f5c) * 0x3b9
    frame.put(FRAME + 0x3100, 8, FRAME + 0x600)
    frame.step(UNEQUAL_RESULT, 0x10053eaec)
    verify(frame.read('w8') == (frame.read('w22') ^ (neq * (mix ^ 0x316f))))

    frame = Frame(sp=FRAME, w19=0xc3e9)
    frame.put(FRAME + 0x3100, 8, FRAME + 0x600)
    frame.put(FRAME + 0x8040, 8, FRAME + 0x608)
    frame.put(FRAME + 0x9d8, 8, TABLE)
    assert frame.step(ENTRY, 0x100509f08) == PRODUCER
    frame.step(PRODUCER, 0x10085d850)
    assert frame.loads[-1] == (0x10085d848, 0x101041060, 8)
    assert number(frame.get(CELL, 8)) == CONSUMER
    return {'bit_vector_queries': 6, 'source_spans': list(SPANS.values()),
            'producer_edge': frame.edges[-1]}


class PredicateProbe(GateProbe):
    def __init__(self):
        super().__init__()
        self.cell_accesses = []
        self.checkpoints = []
        self.branch_slots = []

    def put(self, address, width, value):
        self.u.mem_write(address, value.to_bytes(width, 'little'))

    def write_hook(self, u, access, address, size, value, user):
        if address == CELL:
            self.cell_accesses.append(('write', u.reg_read(ar.UC_ARM64_REG_PC), size, value))
        super().write_hook(u, access, address, size, value, user)

    def read_hook(self, u, access, address, size, value, user):
        if address == CELL:
            self.cell_accesses.append(('read', u.reg_read(ar.UC_ARM64_REG_PC), size,
                                       self.memory_word(address, size)))
        super().read_hook(u, access, address, size, value, user)

    def hook(self, u, pc, size, user):
        if pc == 0x1006f6478:
            assert self.reg(8) == CONSUMER and self.reg(17) == 0x42bd
            Probe.hook(self, u, pc, size, user)
            self.branch_slots.append(dict(self.pac[-1], load_pc='0x10085d848',
                                          store_pc='0x10085d84c', reload_pc='0x1006f6470',
                                          fixup_slot='0x101041060'))
            self.reads.clear()
            return
        if pc == 0x100500108:
            self.checkpoints.append((pc, self.reg(9), self.reg(8)))
        super().hook(u, pc, size, user)

    def run(self, marker, other):
        self.u.reg_write(ar.UC_ARM64_REG_SP, FRAME)
        self.setreg(19, 0xc3e9)
        inputs = {0x9d8: TABLE, 0x9d0: PHASE, 0x3100: FRAME + 0x600,
                  0x8040: FRAME + 0x608, 0x16d0: 0, 0x1074: 0x11223344}
        for offset, value in inputs.items():
            self.put(FRAME + offset, 8, value)
        self.put(FRAME + 0x3044, 4, other)
        self.u.emu_start(ENTRY, 0x10085d890, count=100)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x10085d890
        assert self.memory_word(CURSOR) == 0x290
        assert self.memory_word(FRAME + 0xb48) == FRAME + 0xc1b0
        assert self.memory_word(FRAME + 0x9938) == FRAME + 0xc1c0
        assert self.memory_word(FRAME + 0x9940) == FRAME + 0xc1f1
        self.setreg(9, marker)
        first = EQUAL_RESULT if marker == EXPECTED and other != EXPECTED_OTHER else UNEQUAL_RESULT
        stop = first
        if first == UNEQUAL_RESULT:
            stop = RETEST_EQUAL if marker == EXPECTED else RETEST_UNEQUAL
        self.u.emu_start(UNEQUAL_STOP, stop, count=100)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == stop
        assert self.memory_word(CURSOR) == 0
        assert self.memory_word(FLAG, 1) == int(marker != EXPECTED)
        assert self.memory_word(FRAME + 0x7774, 4) == other
        assert self.memory_word(FRAME + 0x4dec, 4) == 0x11223344
        assert self.checkpoints == [(0x100500108, marker, EXPECTED)]
        assert self.cell_accesses == [('write', 0x10085d84c, 8, CONSUMER),
                                      ('read', 0x1006f6470, 8, CONSUMER)]
        assert self.branch_slots[2]['target'] == hex(first)
        return {'marker': hex(marker), 'other_word': hex(other), 'flag': int(marker != EXPECTED),
                'first_target': hex(first), 'endpoint': hex(stop), 'edges': self.branch_slots}


def inspect():
    proof = source()
    census = literal_writers()
    assert len(census['literal_store_sites']) == 5
    assert '0x10085d84c' in census['literal_store_sites']
    cases, slots = [], {0x101041060}
    for marker in (0x74c29dee, 0x74c29dba, 0x74c29d88, EXPECTED):
        for other in (EXPECTED_OTHER, EXPECTED_OTHER ^ 1):
            probe = PredicateProbe()
            cases.append(probe.run(marker, other))
            slots.update(probe.slots)
    return {'source': proof, 'census': census, 'cases': cases,
            'fixups': verify_original_fixups(slots),
            'continuous_producer_to_discovery_join': False,
            'native_ipc_attribution': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
