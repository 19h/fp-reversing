#!/usr/bin/env python3
"""Trace the private post-emitter dispatch and owner record in the pinned daemon."""

from hashlib import sha256
import json

import z3

from audit_daemon_class_marker_predicate import EXPECTED, FLAG, FRAME, PHASE
from audit_daemon_class_status_route import verify
from audit_daemon_discovery_emitter import EmitterProbe, LENGTH, OUTPUT, REQUEST
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import IMAGE, selected, verify_original_fixups
from daemon_rpc502_probe import ar

HEADER = FRAME + 0xe100
OWNER = FRAME + 0xe200
CHILD = FRAME + 0xe300
BIAS = 0x4aba552460e435c6
START = 0x1005fac30
STOP = 0x1008eb594
PRODUCERS = ((0x1004ca7b4, 0x1004ca7bc), (0x10057f7e4, 0x10057f7f4),
             (0x1007907b8, 0x1007907c8))
WATCHED = {FRAME + offset for offset in (
    0xad0, 0x16d0, 0x1ba0, 0x202f, 0x2b7f, 0x3d78, 0x4804, 0x559c,
    0x61a0, 0x6a40, 0x7148, 0x7880, 0x8040,
)}
WATCHED.update(REQUEST + offset for offset in (0, 8, 0x10, 0x18, 0x20, 0x28, 0x30))
WATCHED.update((OWNER, OWNER + 0x18, OWNER + 0x1c))


def source():
    encoded, cursor, destination = z3.BitVecs('encoded cursor destination', 64)
    comparison = z3.BitVec('comparison', 32)
    frame = Frame(sp=FRAME, x20=HEADER, x19=destination, w21=0xa013, x25=FRAME + 0x6000)
    frame.put(HEADER + 8, 8, encoded)
    frame.put(FRAME + 0x43b0, 4, comparison)
    for start, stop in PRODUCERS:
        frame.step(start, stop)
    verify(frame.get(FRAME + 0x4360, 8) == HEADER + 8)
    verify(frame.get(FRAME + 0x8040, 8) == encoded)
    verify(frame.get(FRAME + 0x559c, 4) == comparison)

    frame.put(FRAME + 0x16d0, 8, cursor)
    frame.put(FRAME + 0x6efc, 4, 0x8b3dc650)
    frame.step(0x1005fac1c, 0x1005facac)
    gate = z3.Or(encoded == BIAS, comparison == EXPECTED)
    verify(frame.read('w12') == (0xa013 ^ z3.If(gate, z3.BitVecVal(0x56, 32), 0)))
    verify(frame.read('w23') == PHASE)
    verify(frame.get(FRAME + 0x3d78, 4) == 0x8b3dc650)
    scratch = FRAME + 0xc070 + cursor
    verify(z3.And(*(frame.get(FRAME + slot, 8) == scratch + displacement
                    for slot, displacement in ((0xad0, 0), (0x7880, 0), (0x6a40, 0x40),
                                               (0x7148, 0x181)))))
    verify(frame.get(FRAME + 0x16d0, 8) == cursor + 0x290)
    verify(frame.get(FRAME + 0x1ba0, 8) == destination)

    raw_owner = z3.BitVec('owner', 64)
    frame = Frame(x8=raw_owner + BIAS)
    frame.step(0x1005a88c4, 0x1005a88d8)
    verify(frame.read('x19') == raw_owner)
    frame.step(0x1005a88dc, 0x1005a8904)
    verify(z3.And(frame.read('x10') == raw_owner + 0x1c, frame.read('x8') == raw_owner + 0x18))
    return {'bit_vector_queries': 11, 'source_spans': list(SPANS.values())}


class OwnerProbe(EmitterProbe):
    def __init__(self):
        super().__init__()
        self.after_emitter = False
        self.accesses = []
        self.output_accesses = []

    def observe(self, kind, u, address, width, value):
        if self.after_emitter:
            if address in WATCHED or address < OUTPUT + LENGTH and OUTPUT < address + width:
                row = {'kind': kind, 'site': hex(u.reg_read(ar.UC_ARM64_REG_PC)),
                       'frame_offset': hex(address - FRAME), 'width': width,
                       'value': hex(value if kind == 'write' else self.memory_word(address, width))}
                self.accesses.append(row)
                if address < OUTPUT + LENGTH and OUTPUT < address + width:
                    self.output_accesses.append(row)

    def read_hook(self, u, access, address, width, value, user):
        self.observe('read', u, address, width, value)
        super().read_hook(u, access, address, width, value, user)

    def write_hook(self, u, access, address, width, value, user):
        self.observe('write', u, address, width, value & ((1 << (8 * width)) - 1))
        super().write_hook(u, access, address, width, value, user)

    def hook(self, u, pc, size, user):
        if pc == 0x1005a8a1c:
            assert (self.reg(0), self.reg(8), self.reg(17)) == (REQUEST, 0x10000cd98, 0x1491)
            for offset, pointer in ((8, OWNER + 0x1c), (0x18, FRAME + 0x5a2c),
                                    (0x20, CHILD), (0x28, FRAME + 0xaec)):
                assert self.memory_word(REQUEST + offset) == pointer
        super().hook(u, pc, size, user)

    def run_owner(self, owner, comparison):
        self.u.reg_write(ar.UC_ARM64_REG_SP, FRAME)
        self.setreg(20, HEADER)
        self.put(HEADER + 8, 8, BIAS + owner)
        self.put(FRAME + 0x43b0, 4, comparison)
        for start, stop in PRODUCERS:
            self.u.emu_start(start, stop, count=8)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == stop
        self.put(FRAME + 0x5f0, 8, 0x101031da0)
        self.put(FRAME + 0x5e0, 8, 0x100e99900)
        self.put(OWNER, 8, CHILD)
        self.put(OWNER + 0x18, 4, 0x12345678)
        self.put(FRAME + 0x16d0, 8, 0)
        self.put(FRAME + 0x33e8, 8, 0)
        emitter = self.run_route(9, 0x74c29dee)
        first_edge, first_step = len(self.branch_slots), self.steps
        self.after_emitter = True
        self.u.emu_start(START, STOP, count=30000)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == STOP
        edges = self.branch_slots[first_edge:]
        called = owner != 0 and comparison != EXPECTED
        status = 0x74c29d8c if called else 0x74c29d88
        assert edges[0]['target'] == hex(0x1005c5324 if called else 0x10060fe34)
        assert any(edge['site'] == '0x1005a8a1c' for edge in edges) == called
        assert edges[-1]['target'] == '0x1008eb564'
        assert self.memory_word(FRAME + 0x1ba0) == OUTPUT
        assert self.memory_word(FRAME + 0x16d0) == 0
        assert self.memory_word(FRAME + 0x4804, 4) == self.reg(22) == status
        assert self.memory_word(FRAME + 0x2b7f, 1) == 0
        assert self.memory_word(FRAME + 0x3d78, 4) == 0x8b3dc650
        assert self.memory_word(FLAG, 1) == 1
        assert not self.output_accesses
        assert bytes(self.u.mem_read(OUTPUT, LENGTH)).hex() == emitter['output_hex']
        if called:
            assert self.memory_word(FRAME + 0x61a0) == OWNER
            assert {'kind': 'write', 'site': '0x100081244', 'frame_offset': '0x10cc8',
                    'width': 4, 'value': hex(status)} in self.accesses
        return {'owner': hex(owner), 'comparison': hex(comparison), 'status': hex(status),
                'emitter_output_hex': emitter['output_hex'], 'steps': self.steps - first_step,
                'edges': edges, 'accesses': self.accesses}


def inspect():
    proof = source()
    bank = selected(0x101031da0, 0x100e99900, 0x86, 0xcbfa)
    assert (bank['slot'], bank['target']) == ('0x1010a0180', '0x10000cd98')
    cases = [OwnerProbe().run_owner(owner, comparison)
             for owner in (0, OWNER) for comparison in (0, EXPECTED)]
    slots = {int(edge['fixup_slot'], 16) for case in cases for edge in case['edges']}
    reads = IMAGE.read(0x100611530, 0x18)
    return {'image_sha256': sha256(IMAGE.data).hexdigest(), 'source': proof,
            'helper_bank': bank, 'fixups': verify_original_fixups(slots), 'profiles': cases,
            'flag_arm_load_span': {'start': '0x100611530', 'bytes_hex': reads.hex()},
            'post_emitter_start': hex(START), 'end_exclusive': hex(STOP)}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
