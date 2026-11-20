#!/usr/bin/env python3
"""Trace the discovery inequality branch into an internal byte-emitter request."""

from hashlib import sha256
import json

import z3

from audit_daemon_class_marker_predicate import EXPECTED, FLAG, FRAME, PHASE, PredicateProbe
from audit_daemon_class_status_route import verify
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import IMAGE, TABLE, selected, verify_original_fixups
from daemon_rpc502_probe import ar

INITIAL = 0x100790828
ENTRY = 0x1004cb6f4
JOIN = 0x1005fac1c
CALL = 0x1004cb8bc
ADAPTER = 0x100add594
FLAG_READER = 0x10051fed0
OTHER = FRAME + 0x6efc
REQUEST = FRAME + 0x10cb8
CURSOR = FRAME + 0xbc90
OUTPUT = FRAME + 0xc1b0
LENGTH = 16
MASK = 0xffffffff


def proofs():
    phase, flag = z3.BitVec('phase', 32), z3.BitVec('flag', 8)
    source = Frame(sp=FRAME)
    source.put(FRAME + 0x9d0, 8, z3.ZeroExt(32, phase))
    source.put(FLAG, 1, flag)
    source.step(FLAG_READER, 0x10051ff0c)
    x = phase ^ 0x6de8
    equals = z3.ZeroExt(24, flag) == (((x << 1) - 0x38) & 0xfe)
    expected_index = (phase + 0x2d3e) ^ z3.If(equals, x - 0xa8, 0)
    verify(source.read('w10') == expected_index)

    a = Frame(sp=FRAME, x19=OUTPUT, w22=0x1f77)
    a.step(0x1004cb7dc, 0x1004cb840)
    key = ((REQUEST ^ 0xeaae0ac9) * 0x7398180b) & MASK
    verify(a.get(REQUEST + 8, 8) == OUTPUT)
    verify(a.get(REQUEST + 0x10, 2) - (key & 0xffff) - 0x153b == LENGTH)
    verify(a.get(REQUEST + 0x14, 4) + key == 0xb399)

    value = z3.BitVec('companion', 32)
    a.seed('x25', FRAME + 0x6000)
    a.put(OTHER, 4, value)
    a.step(ENTRY, 0x1004cb7dc)
    result = a.get(OTHER, 4)
    for original, changed in ((EXPECTED, 0x8b3dc650), (0, 3)):
        verify(z3.Implies(value == original, result == changed))
    return {'bit_vector_queries': 6, 'source_spans': list(SPANS.values())}


class EmitterProbe(PredicateProbe):
    def __init__(self):
        super().__init__()
        self.output_writes = []
        self.companion_accesses = []

    def hook(self, u, pc, size, user):
        if pc == CALL:
            assert (self.reg(0), self.reg(1), self.reg(8), self.reg(17)) == (
                REQUEST, CURSOR, ADAPTER, 0x22a0)
        if pc == 0x1004cb8d0:
            assert u.reg_read(ar.UC_ARM64_REG_SP) == FRAME
            assert self.memory_word(CURSOR) == 0
        if pc in self.imports:
            raise AssertionError(('unexpected imported call', self.imports[pc]))
        super().hook(u, pc, size, user)

    def read_hook(self, u, access, address, size, value, user):
        if address == OTHER:
            self.companion_accesses.append(('read', u.reg_read(ar.UC_ARM64_REG_PC), size,
                                            self.memory_word(address, size)))
        super().read_hook(u, access, address, size, value, user)

    def write_hook(self, u, access, address, size, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if OUTPUT <= address < OUTPUT + LENGTH:
            assert pc == 0x100a0ca74 and size == 1
            self.output_writes.append((address - OUTPUT, value & 0xff))
        if address == OTHER:
            self.companion_accesses.append(('write', pc, size, value & MASK))
        super().write_hook(u, access, address, size, value, user)

    def run_route(self, counter, marker):
        self.u.reg_write(ar.UC_ARM64_REG_SP, FRAME)
        for offset, value in {
            0x9d0: PHASE, 0x9d8: TABLE, 0x9c8: 0x1010b8dc8, 0x9c0: 0x1010c4670,
            0x600: 0x100e99a00, 0x5f8: 0x100f4e390, 0x410: FRAME + 0x418,
            0x418: 0xa3b5994093212ef4, 0x3100: OUTPUT, 0x3044: 0x76d8ea80,
        }.items():
            self.put(FRAME + offset, 8, value)
        self.setreg(12, FRAME + 0x5000)
        self.u.emu_start(INITIAL, 0x100790840, count=10)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x100790840
        for address, width, value in (
            (0x1010c8258, 4, counter), (0x1010c67d4, 4, 0xff),
            (0x1010c8268, 8, FRAME + 0x3700), (0x1010c6800, 8, 0xfff0c012a7a74f13),
            (0x1010ca2a8, 8, 0x12af5505878878c7), (FRAME + 0x37c8, 4, 0xa0018891),
        ):
            self.put(address, width, value)
        self.setreg(9, marker)
        self.u.emu_start(0x1005000d4, JOIN, count=180000)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == JOIN
        assert self.memory_word(FLAG, 1) == 1
        assert self.memory_word(REQUEST, 4) == EXPECTED
        assert self.memory_word(CURSOR) == 0 and self.reg(9) == 0
        assert self.reg(21) == 0xa013 and self.reg(25) == FRAME + 0x6000
        assert self.companion_accesses == [
            ('write', 0x10079083c, 4, EXPECTED), ('read', 0x1004cb6f8, 4, EXPECTED),
            ('write', 0x1004cb7d8, 4, 0x8b3dc650),
        ]
        actual = bytes(self.u.mem_read(OUTPUT, LENGTH))
        latest = dict(self.output_writes)
        assert set(latest) == set(range(LENGTH))
        assert bytes(latest[i] for i in range(LENGTH)) == actual
        self.u.emu_start(JOIN, 0x1005fac30, count=8)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x1005fac30
        assert self.memory_word(FRAME + 0x3d78, 4) == 0x8b3dc650
        assert self.companion_accesses[-1] == ('read', 0x1005fac28, 4, 0x8b3dc650)
        assert self.memory_word(FLAG, 1) == 1
        return {'incoming_status': hex(marker), 'generation_counter_seed': counter,
                'output_hex': actual.hex(), 'output_writes': self.output_writes,
                'steps': self.steps, 'edges': self.branch_slots,
                'companion_accesses': [[kind, hex(site), size, hex(value)]
                                       for kind, site, size, value in self.companion_accesses]}


def inspect():
    source = proofs()
    bank = selected(0x100e99a00, 0x100f4e390, 0x54, 0xcb3e)
    assert bank['target'] == hex(ADAPTER)
    slots = {int(bank['slot'], 16), 0x101042fc8}
    cases = []
    for counter, marker in ((9, 0x74c29dee), (9, 0x74c29dba), (9, 0x74c29d88),
                            (1, 0x74c29dee)):
        probe = EmitterProbe()
        cases.append(probe.run_route(counter, marker))
        slots.update(int(edge['fixup_slot'], 16) for edge in probe.branch_slots)
    assert len({row['output_hex'] for row in cases[:3]}) == 1
    local_flag_routes = []
    for flag, stop in ((1, 0x100611520), (0, 0x100546c2c)):
        probe = EmitterProbe()
        probe.u.reg_write(ar.UC_ARM64_REG_SP, FRAME)
        probe.put(FRAME + 0x9d8, 8, TABLE)
        probe.put(FRAME + 0x9d0, 8, PHASE)
        probe.put(FLAG, 1, flag)
        probe.u.emu_start(FLAG_READER, stop, count=30)
        assert probe.u.reg_read(ar.UC_ARM64_REG_PC) == stop
        local_flag_routes.append({'flag': flag, 'edge': probe.branch_slots[-1]})
        slots.add(int(probe.branch_slots[-1]['fixup_slot'], 16))
    return {'source': source, 'adapter_bank': bank, 'emitter_profiles': cases,
            'flag_reader_profiles': local_flag_routes, 'image_sha256': sha256(IMAGE.data).hexdigest(),
            'fixups': verify_original_fixups(slots),
            'same_frame_flag_reader_reach': False, 'native_ipc_attribution': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
