#!/usr/bin/env python3
"""Check the discovery unlock, acquisition, and shared control/cache dispatch."""

from hashlib import sha256
import json

import z3

from audit_daemon_class_status_route import verify
from audit_daemon_discovery_cleanup import CleanupProbe, FRAME, ar
from audit_daemon_discovery_record import CALL, LOCK, REQUEST, replay
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import IMAGE, POOL, selected, verify_original_fixups

CONTROL = 0x1010c5760
CACHE = 0x1010c9298
FALLBACK = 0x1010b9638
ONCE, CALLBACK = 0x1010b8cd0, 0x10040ebd4
ACQUIRE, CLEANUP2 = 0x10057b530, 0x1007fc208
CACHE_STOP, CLEANUP_STOP = 0x1005c8428, 0x10075a140
ROOTS = ((0x1004c2bf8, 0x1004c2c10), (0x1004c2f68, 0x1004c2f8c))
LOCK_CALLS = {
    0x100442650: 'libSystem/_pthread_once',
    0x10043e508: 'libSystem/_pthread_once',
    0x100208efc: 'libSystem/_pthread_rwlock_unlock',
    0x100361df4: 'libSystem/_pthread_rwlock_wrlock',
}


def source():
    word, phase = z3.BitVecs('control phase', 32)
    pointer = z3.BitVec('cache_pointer', 64)
    frame = Frame(sp=FRAME, w25=0x69e9, w9=word)
    frame.put(FRAME + 0x568, 8, CACHE)
    frame.put(CACHE, 8, pointer)
    frame.step(0x1007ca49c, 0x1007ca4dc)
    verify(frame.read('w11') == z3.If(z3.And(word == 1, pointer != 0),
                                       z3.BitVecVal(0x6a09, 32), 0x69e9))
    frame = Frame(sp=FRAME, w8=0x2e80, w9=word, x3=CONTROL)
    frame.step(0x10057f6f0, 0x10057f710)
    verify(frame.get(CONTROL, 4) == word - 1)
    verify(frame.read('w8') == 0x2e80)
    frame = Frame(sp=FRAME, x21=FRAME + 0x10000, x28=REQUEST, w27=phase)
    frame.step(0x10057b488, 0x10057b4e0)
    frame.seed('x0', REQUEST)
    frame.step(0x10043e3ac, 0x10043e3ec)
    verify(frame.read('w26') == phase + 0x2abd)
    verify(frame.get(REQUEST + 8, 8) == 0)
    return {'bit_vector_checks': 5, 'spans': list(SPANS.values())}


class RelockProbe(CleanupProbe):
    def __init__(self, status):
        super().__init__()
        self.clobber = 0x1357
        self.status = status
        self.models = []
        self.records_at_calls = []
        self.control_writes = []

    def write_hook(self, u, access, address, width, value, data):
        if address == CONTROL:
            assert width == 4
            self.control_writes.append((hex(u.reg_read(ar.UC_ARM64_REG_PC)), value & 0xffffffff))
        super().write_hook(u, access, address, width, value, data)

    def hook(self, u, pc, size, data):
        if pc in (0x100442640, 0x10043e4f8):
            assert bytes(u.mem_read(pc, 4)) == bytes.fromhex('f023c1da')
            assert self.reg(16) == CALLBACK
            u.reg_write(ar.UC_ARM64_REG_PC, pc + 4)
            return
        if pc in self.imports:
            name = self.imports[pc]
            call = self.reg(30) - 4
            assert LOCK_CALLS[call] == name
            args = [self.reg(0)]
            result = self.status
            if name.endswith('once'):
                args.append(self.reg(1))
                assert args == [ONCE, CALLBACK]
                result = 0
            self.models.append({'site': hex(call), 'name': name, 'args': list(map(hex, args)),
                                'model_return': result})
            self.finish_import(call + 4, result)
            return
        if pc in (CALL, ACQUIRE, CLEANUP2):
            assert self.reg(0) == REQUEST
            self.records_at_calls.append({'site': hex(pc), 'target': hex(self.reg(8)),
                                          'record': bytes(u.mem_read(REQUEST, 0x10)).hex()})
        super().hook(u, pc, size, data)

    def run_relock(self, lock, fallback, word, cache):
        replay(0, probe=self, lock=lock)
        first = len(self.branch_slots)
        cpu = self.u.context_save()
        for index, value in ((25, POOL), (6, 0x19), (12, 0x5d), (2, 0)):
            self.setreg(index, value)
        for start, stop in ROOTS:
            self.u.emu_start(start, stop, count=10)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == stop
        assert self.memory_word(FRAME + 0x570) == CONTROL
        assert self.memory_word(FRAME + 0x568) == CACHE
        self.u.context_restore(cpu)
        for address, size, value in (
            (FALLBACK, 8, fallback), (CONTROL, 4, word), (CACHE, 8, cache),
            (FRAME + 0x870, 8, 0x100e99700), (FRAME + 0x868, 8, 0x100f4e190),
            (FRAME + 0x8be0, 4, 0),
        ):
            self.put(address, size, value)
        positive = 0 < word < 2**31
        hit = word == 1 and cache != 0
        end = CACHE_STOP if hit else CLEANUP_STOP
        self.u.emu_start(CALL, end, count=4000)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == end
        assert self.u.reg_read(ar.UC_ARM64_REG_SP) == FRAME
        assert not self.output_accesses
        expected_writes = [('0x10057f70c', word - 1)] if positive and not hit else []
        assert self.control_writes == expected_writes
        assert self.memory_word(CONTROL, 4) == word - int(bool(expected_writes))

        initial, cleanup_sites = lock or fallback, [] if hit else [CLEANUP2]
        expected = [(0x100442650, ONCE)]
        if initial:
            expected.append((0x100208efc, initial))
        expected.append((0x10043e508, ONCE))
        if fallback:
            expected.append((0x100361df4, fallback))
        if not hit:
            expected.append((0x100442650, ONCE))
            if fallback:
                expected.append((0x100208efc, fallback))
        assert [(int(row['site'], 16), int(row['args'][0], 16)) for row in self.models] == expected
        assert [int(row['site'], 16) for row in self.records_at_calls] == [CALL, ACQUIRE, *cleanup_sites]
        if not hit:
            assert self.records_at_calls[0]['record'][16:24] == self.records_at_calls[2]['record'][16:24]
        edges = self.branch_slots[first:]
        entry = next(edge for edge in edges if edge['site'] == '0x10057b560')
        assert entry['target'] == ('0x1007ca49c' if positive else '0x1007fc14c')
        return {'lock': hex(lock), 'fallback': hex(fallback), 'control_before': hex(word),
                'control_after': hex(self.memory_word(CONTROL, 4)), 'cache': hex(cache),
                'reaching_calls': self.records_at_calls, 'modeled_imports': self.models,
                'edges': edges, 'endpoint': hex(end), 'control_writes': self.control_writes}


def inspect():
    proof = source()
    profiles = []
    for lock, fallback, word, cache, status in (
        (LOCK, LOCK, 0, 0, 0), (LOCK, LOCK + 8, 1, 0, 35),
        (LOCK, LOCK, 1, FRAME + 0xe800, 0), (LOCK, LOCK, 2, FRAME + 0xe800, 0),
        (0, 0, 0x80000000, 0, 35), (0, LOCK, 0, 0, 35),
        (LOCK, LOCK, 1, FRAME + 0xe800, 35),
    ):
        profiles.append(RelockProbe(status).run_relock(lock, fallback, word, cache))
    assert profiles[2]['edges'] == profiles[6]['edges']
    bank = selected(0x100e99700, 0x100f4e190, 0x81, 0xcbab)
    assert bank['target'] == '0x10043e280'
    slots = {0x1010a2ac8, 0x1010a9c88}
    slots.update(int(edge['fixup_slot'], 16) for profile in profiles for edge in profile['edges'])
    return {'image_sha256': sha256(IMAGE.data).hexdigest(), 'source': proof,
            'profiles': profiles, 'acquire_bank': bank, 'fixups': verify_original_fixups(slots)}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
