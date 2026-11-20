#!/usr/bin/env python3
"""Verify fairplayd startup environment inputs and the following source cuts."""

from hashlib import sha256
import json
from struct import pack, unpack

import audit_daemon_registration_state_gate as state
from daemon_receive_tools import FIXUPS, SOURCE, TABLE, bank, qword, verify_original_fixups

RANDOM = 'libSystem/_arc4random'
CLOCK = 'libSystem/_gettimeofday'
RANDOM_SITES = (0x10008a710, 0x10008c6d0, 0x10008c738)
CLOCK_SITE = 0x10008c64c
MATERIAL_EXIT = 0x10008c7a4
COLD_STOP = 0x10010daf8
REFILL_STOP = 0x10002fddc
SPANS = [
    (0x10008a6a0, 0x10008a75c),
    (0x1000b20b8, 0x1000b20f4),
    (0x10008c5d8, MATERIAL_EXIT + 4),
    (0x1001cf2f0, 0x1001cf528),
    (0x100444d6c, 0x100444dfc),
    (0x1000235a4, 0x1000235d8),
    (0x1000b7800, 0x1000b78d4),
    (0x100427514, 0x1004275b4),
    (0x1000bb168, 0x1000bb1a0),
    (0x10010dac8, COLD_STOP),
    (0x10000c2cc, 0x10000c310),
    (0x10003c950, 0x10003c9ac),
    (0x100080d10, 0x100080d80),
    (0x1000a0450, 0x1000a0534),
    (0x100011744, 0x10001179c),
    (0x100037f1c, 0x100037fa4),
    (0x10002fd24, REFILL_STOP),
]


def seed_words(seed):
    words = [seed]
    for index in range(1, 624):
        previous = words[-1]
        words.append((0x6c078965 * (previous ^ (previous >> 30)) + index) & state.U32)
    return words


def twist_words(words):
    words = list(words)
    for index in range(624):
        following = words[(index + 1) % 624]
        mixed = (words[index] & 0x80000000) | (following & 0x7fffffff)
        words[index] = words[(index + 397) % 624] ^ (mixed >> 1)
        if mixed & 1:
            words[index] ^= 0x9908b0df
    return words


class EnvironmentProbe(state.StateProbe):
    def __init__(self, label, random_words, clock, generation=0, seed=None, offset=0):
        x23 = qword(0x1010a4000) - 0x62f83f4e
        x26 = qword(0x1010a2fb8) - 0x5918054b
        super().__init__(label, (x23, x26), generation, None, stack_offset=offset)
        self.random_words = random_words
        self.clock = clock
        self.fixture_array = seed_words(seed) if seed is not None else None
        self.calls_after_registration = []
        self.checkpoints = {}

    def word(self, pointer):
        return unpack('<I', self.u.mem_read(pointer, 4))[0]

    def snapshot_table(self):
        return list(unpack('<624I', self.u.mem_read(state.STATE_TABLE, 624 * 4)))

    def hook(self, u, address, size, user):
        if address == state.HEAD and self.fixture_array is not None:
            u.mem_write(state.STATE_TABLE, pack('<624I', *self.fixture_array))
        if address == 0x10008a6c8:
            assert (self.reg(10), self.reg(9), self.word(state.GATE)) == (
                state.GATE, 0x5d96, 0xa94ef,
            )
        name = self.imports.get(address)
        if name in (RANDOM, CLOCK):
            site = self.reg(30) - 4
            event = {'symbol': name, 'site': hex(site), 'return_pc': hex(self.reg(30))}
            if name == RANDOM:
                assert self.word(state.GATE) == 0x5d96
                value = self.random_words[RANDOM_SITES.index(site)]
                event['result'] = value
            else:
                assert site == CLOCK_SITE and self.reg(1) == 0
                status, seconds, microseconds = self.clock
                output = self.reg(0)
                sp = u.reg_read(state.ar.UC_ARM64_REG_SP)
                assert output == sp + 0x2b0
                u.mem_write(output, pack('<qi', seconds, microseconds))
                event.update({'out_from_sp': output - sp, 'timezone': 0, 'status': status,
                              'seconds': seconds, 'microseconds': microseconds})
                value = status
            self.calls_after_registration.append(event)
            self.return_model(value)
            return
        if address == 0x10008c5ec:
            assert self.snapshot_table() == seed_words(self.random_words[0])
            assert self.word(self.reg(25) + 0x14) == 624
            self.checkpoints['seeded_array'] = self.snapshot_table()
        if address == MATERIAL_EXIT:
            q = self.reg(27)
            assert q == u.reg_read(state.ar.UC_ARM64_REG_SP) + 0x2a0
            words = list(unpack('<4I', u.mem_read(q, 16)))
            _, seconds, microseconds = self.clock
            assert words == [value ^ 0x0d875374 for value in (
                self.random_words[2], microseconds, seconds & state.U32, self.random_words[1])]
            self.checkpoints['material_words'] = words
        if address == 0x1000a0450:
            assert self.snapshot_table() == twist_words(self.fixture_array)
            self.checkpoints['refilled_array'] = self.snapshot_table()
        if address in (COLD_STOP, REFILL_STOP):
            if address == COLD_STOP:
                sp = u.reg_read(state.ar.UC_ARM64_REG_SP)
                assert unpack('<Q', u.mem_read(sp + 0x130, 8))[0] == 0
                pointer = self.reg(11)
                assert pointer == self.reg(10) == 4
            else:
                pointer = self.reg(15)
                sp = u.reg_read(state.ar.UC_ARM64_REG_SP)
                mask_cell, base_cell = unpack('<QQ', u.mem_read(sp + 0x138, 16))
                assert (mask_cell, base_cell) == (0x1010c67d4, 0x1010c8268)
                mask = self.word(mask_cell)
                base = unpack('<Q', u.mem_read(base_cell, 8))[0]
                assert pointer == base + (mask & 0x6f2523cc) == 0
                self.checkpoints['cached_table'] = {'mask_cell': hex(mask_cell),
                                                    'base_cell': hex(base_cell),
                                                    'mask': mask, 'base': hex(base)}
                self.checkpoints['extraction_index'] = self.word(0x1010c67dc)
                self.checkpoints['generation_counter'] = self.word(state.GENERATION)
                assert self.checkpoints['extraction_index'] == 1
                assert self.checkpoints['generation_counter'] == self.generation + 1
            assert not any(start <= pointer <= end for start, end, _ in u.mem_regions())
            self.stop('before_unmapped_read', pc=hex(address), read_address=hex(pointer),
                      read_width=4)
            return
        return super().hook(u, address, size, user)


def archived_trace():
    raw = (SOURCE.parent / 'annotated-strace-rax-user.txt').read_bytes()
    digest = sha256(raw).hexdigest()
    assert digest == '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
    lines = raw.decode().splitlines()
    clock_traps = [number for number, line in enumerate(lines, 1) if '] pc=' in line and
                   ' gettimeofday(' in line]
    entropy_traps = [number for number, line in enumerate(lines, 1) if '] pc=' in line and
                     ' getentropy(' in line]
    assert len(lines) == 1748 and max(clock_traps) == 1485 and entropy_traps == [1185]
    assert all(text in lines[number - 1] for number, text in {
        1668: 'port name=0x1603 disposition=PORT_RECEIVE',
        1675: '_kernelrpc_mach_port_insert_member_trap(515, 5635, 4099)',
        1676: 'host_self_trap()',
        1677: 'id=205 to host (host_get_io_main)',
        1736: 'id=2962',
    }.items())
    return {'sha256': digest, 'lines': len(lines), 'clock_trap_lines': clock_traps,
            'entropy_trap_lines': entropy_traps, 'final_checkin_delivery': 1668,
            'port_set_insertion': 1675, 'iokit_main_request': 1677, 'open_reply': 1736}


def inspect():
    banks = [
        (0x100e99a00, 0x100f4e390, 0x78, 0xcb8b, 0x1010a0050),
        (0x100e99a00, 0x100f4e390, 0x9c, 0xcbd8, 0x10109ff20),
        (0x100fc4130, 0x101031ea0, 0x4e, 0xcb2d, 0x1010a0050),
        (0x100e99a00, 0x100f4e390, 0x6d, 0xcb5c, 0x1010a0050),
    ]
    for first, second, key, additive, slot in banks:
        assert TABLE + 8 * (bank(first, second, key) + additive) == slot
    assert FIXUPS[0x1010a0050]['target'] == RANDOM
    assert FIXUPS[0x10109ff20]['target'] == CLOCK

    ranges = state.continuation.registration.RANGES
    state.continuation.registration.RANGES = [
        *ranges, *state.continuation.EXTENSION, *state.EXTENSION, *SPANS,
    ]
    rows = []
    slots = {0x1010a0050, 0x10109ff20}
    cold_words = (0x89abcdef, 0x23456789, 0xfedcba98)
    profiles = [
        EnvironmentProbe('initial_seed', cold_words, (0, 1700000000, 234567)),
        EnvironmentProbe('different_stack_and_words', (0, 0xffffffff, 0),
                         (0, 0x100000001, 999999), offset=-0x2000),
        EnvironmentProbe('clock_status_only', cold_words, (-1, 1700000000, 234567)),
        EnvironmentProbe('refill_pattern', (), None, generation=1, seed=0x12345678),
        EnvironmentProbe('refill_second_pattern', (), None, generation=7, seed=0xffffffff),
    ]
    try:
        for profile in profiles:
            result = profile.run_registration()
            expected_stop = REFILL_STOP if profile.generation else COLD_STOP
            assert result['stop_reason'] == 'before_unmapped_read'
            stop = result['records'][-1]
            assert int(stop['pc'], 16) == expected_stop
            expected_calls = [] if profile.generation else [
                RANDOM_SITES[0], CLOCK_SITE, *RANDOM_SITES[1:],
            ]
            assert [int(row['site'], 16) for row in profile.calls_after_registration] == expected_calls
            edges = {}
            for edge in result['pac_bypasses']:
                site = int(edge['site'], 16)
                if not any(lo <= site < hi for lo, hi in SPANS) or 'target' not in edge:
                    continue
                triple = (site, int(edge['target'], 16), int(edge['modifier'], 16))
                edges[triple] = edges.get(triple, 0) + 1
            edge_records = []
            for (site, target, modifier), visits in edges.items():
                symbol = profile.imports.get(target, target)
                matches = [slot for slot, row in FIXUPS.items() if row['target'] == symbol and
                           row['annotation'] == f'(div=0x{modifier:04X} ad=0 key=IA)']
                assert matches
                slots.update(matches)
                edge_records.append({'site': hex(site), 'target': symbol if isinstance(symbol, str) else hex(symbol),
                                     'modifier': hex(modifier), 'possible_slots': list(map(hex, matches)),
                                     'visits': visits})
            rows.append({'case': profile.label, 'frontier': stop, 'steps': result['steps'],
                         'imports': profile.calls_after_registration, 'edges': edge_records,
                         'checkpoints': profile.checkpoints})
    finally:
        state.continuation.registration.RANGES = ranges
    assert rows[0]['checkpoints'] == rows[2]['checkpoints']
    return {'cases': rows, 'fixups': verify_original_fixups(slots), 'trace': archived_trace(),
            'code': [state.instructions(lo, hi) for lo, hi in SPANS],
            'read_cuts': [state.instructions(a, a + 4)[0] for a in (COLD_STOP, REFILL_STOP)],
            'native_ipc_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
