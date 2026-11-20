#!/usr/bin/env python3
"""Replay discovery context sealing, publication and cleanup on the pinned image."""

from collections import Counter
from hashlib import sha256
import json
import struct

from audit_daemon_discovery_relock import (
    CACHE, CACHE_STOP, CLEANUP2, CLEANUP_STOP, CONTROL, FRAME, LOCK, POOL,
    RelockProbe, ar,
)
from daemon_receive_tools import CS, FIXUPS, IMAGE, TABLE, verify_original_fixups
from daemon_rpc502_probe import commands
from recover_daemon_context_unseal import D, TABLE_DATA, producer
from validate_daemon_context_seal import decode, encode, pick

MULTIPLIER = 0xeb36c1ca
FNV = 0x01000193
MASK32 = 0xffffffff
TEXT_BASE = 0x100822058
TEXT_MASK = 0x7fff
SPAN = (CACHE_STOP, 0x1005c88d0)
PUBLICATION = 0x1005c88b8
DECREMENT = 0x10057f6f0
FRONTIER = 0x100577fc0
SAVED_SLOT = 0x10103bc58
SCRATCH = FRAME + 0xb538
NEXT_INPUT = FRAME + 0x17a0
ROOTS = (
    (0x1004c2d20, 0x1004c2d34, 0x796, 0x858, 0x1010c8268),
    (0x1004c2dfc, 0x1004c2e18, 0x4bc, 0x878, 0x1010c67d4),
)
XOR3 = {0x1005c871c, 0x1005c8720, 0x1005c8724, 0x1005c8728, 0x1005c878c}
CONTEXT_LOADS = {0x1005c86d8, 0x1005c8774, 0x1005c87d4, 0x1005c87d8,
                 0x1005c87e4, 0x1005c87f0}
CONTINUATIONS = ((0, 0xa003, 0x10083ea7c), (FRAME + 0xe800, 0xa00d, 0x1005bfa84))


def fold(table):
    value = int.from_bytes(table[0xc8:0xcc], 'little') ^ MULTIPLIER
    reads = []
    for _ in range(8):
        address = TEXT_BASE + (value & TEXT_MASK)
        word = int.from_bytes(IMAGE.read(address, 4), 'little')
        reads.append((address, word))
        value ^= word
    return value, reads


def encode_reference(pointer, value):
    key = value * MULTIPLIER & MASK32
    raw = bytearray(pointer.to_bytes(8, 'little'))
    for i in range(7, 0, -1):
        j = pick(key, i)
        raw[i], raw[j] = raw[j], raw[i]
    words = [int.from_bytes(raw[i:i + 4], 'little') for i in (0, 4)]
    sums = [((key * (key | i)) & MASK32) ^ key for i in (0, 1)]
    lanes = [((word * FNV + add) & MASK32) ^ add for word, add in zip(words, sums)]
    return lanes[0] | (lanes[1] << 32)


def context_accesses(seed):
    reads = [(0x1005c86d8, offset, 8) for offset in range(0, 544, 8)]
    writes = [(0x1005c8734, offset, 8) for offset in range(0, 544, 8)]
    reads.extend((0x1005c8774, offset, 4) for offset in (544, 548))
    writes.extend((0x1005c879c, offset, 4) for offset in (544, 548))
    for i in range(68, 0, -1):
        high, low = i * 8, pick(seed, i) * 8
        reads.extend(((0x1005c87d4, high, 8), (0x1005c87d8, low, 8),
                      (0x1005c87e4, low, 8), (0x1005c87f0, high, 8)))
        writes.extend(((0x1005c87e0, high, 8), (0x1005c87ec, low, 8),
                       (0x1005c87f8, high, 8)))
    return reads, writes


def literal_uses():
    for offset, cmd, _ in commands(IMAGE.data, 0):
        if cmd != 0x19:
            continue
        for index in range(struct.unpack_from('<I', IMAGE.data, offset + 64)[0]):
            section = offset + 72 + 80 * index
            name, _, start, size = struct.unpack_from('<16s16sQQ', IMAGE.data, section)
            if name.rstrip(b'\0') != b'__text':
                continue
            load = 0xf94003e0 | (0x17a0 // 8 << 10)
            store = 0xf90003e0 | (0x17a0 // 8 << 10)
            addresses = {load: [], store: []}
            for i, (word,) in enumerate(struct.iter_unpack('<I', IMAGE.read(start, size))):
                opcode = word & ~31
                if opcode in addresses:
                    addresses[opcode].append(start + 4 * i)
            assert len(addresses[load]) == 7 and FRONTIER in addresses[load]
            assert addresses[store] == [0x1002aa0e0, 0x10050690c, 0x100544178, 0x100b030a8]
            return {'text_words': size // 4, 'loads': list(map(hex, addresses[load])),
                    'stores': list(map(hex, addresses[store]))}
    raise AssertionError('missing __text')


class CacheProbe(RelockProbe):
    def __init__(self, status):
        self.backing_reads = []
        self.backing_writes = []
        self.text_reads = []
        self.publications = []
        self.xor3_count = 0
        self.codec_visits = 0
        self.saved_load = self.saved_store = self.saved_reload = None
        self.next_writes = []
        self.scratch_defined = set()
        self.in_cache_route = False
        super().__init__(status)

    def read_hook(self, u, access, address, width, value, data):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == 0x10083c1d4:
            assert (address, width) == (SAVED_SLOT, 8)
            self.saved_load = self.memory_word(address)
        if pc == 0x10075a128:
            assert (address, width) == (FRAME + 0x7448, 8)
            self.saved_reload = self.memory_word(address)
        if SPAN[0] <= pc < SPAN[1]:
            if 0x1005c84a0 <= pc <= 0x1005c8510:
                assert width == 4 and TEXT_BASE <= address <= TEXT_BASE + TEXT_MASK
                self.text_reads.append((address, self.memory_word(address, width)))
            elif pc in CONTEXT_LOADS:
                assert D <= address < address + width <= D + 552
                self.backing_reads.append((pc, address - D, width))
            elif SCRATCH <= address < SCRATCH + 16:
                assert all(byte in self.scratch_defined for byte in range(address, address + width))
            else:
                assert not D <= address < D + 552
        elif self.in_cache_route:
            assert not (D <= address < D + 552 or address == CACHE)
        super().read_hook(u, access, address, width, value, data)

    def write_hook(self, u, access, address, width, value, data):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if address < NEXT_INPUT + 8 and NEXT_INPUT < address + width:
            self.next_writes.append((hex(pc), hex(address), width))
        if pc == 0x10083c1d8:
            assert (address, width, value) == (FRAME + 0x7448, 8, self.saved_load)
            self.saved_store = value
        if SPAN[0] <= pc < SPAN[1]:
            if address == CACHE:
                assert width == 8 and pc == PUBLICATION
                self.publications.append((self.codec_visits, value & ((1 << 64) - 1)))
            elif SCRATCH <= address < address + width <= SCRATCH + 16:
                self.scratch_defined.update(range(address, address + width))
            else:
                assert D <= address < address + width <= D + 552
                self.backing_writes.append((pc, address - D, width))
        elif self.in_cache_route:
            assert not (D <= address < D + 552 or address == CACHE)
        super().write_hook(u, access, address, width, value, data)

    def hook(self, u, pc, size, data):
        if SPAN[0] <= pc < SPAN[1]:
            self.codec_visits += 1
            original = IMAGE.read(pc, 4)
            assert size == 4 and u.mem_read(pc, size) == original
            if pc in XOR3:
                # The configured Unicorn CPU faults on EOR3. Lift only these
                # source-verified three-input 128-bit bitwise XORs.
                ins = next(CS.disasm(original, pc))
                assert ins.mnemonic == 'eor3'
                regs = [getattr(ar, 'UC_ARM64_REG_Q' + op.strip()[1:].split('.')[0])
                        for op in ins.op_str.split(',')]
                a, b, c = map(u.reg_read, regs[1:])
                u.reg_write(regs[0], a ^ b ^ c)
                u.reg_write(ar.UC_ARM64_REG_PC, pc + 4)
                self.xor3_count += 1
                return
        if pc == CLEANUP_STOP:
            assert self.saved_load == self.saved_store == self.saved_reload == self.reg(9)
            assert self.reg(9) == FIXUPS[SAVED_SLOT]['target']
            self.reads.append((0x10083c1d4, SAVED_SLOT))
        super().hook(u, pc, size, data)

    def install_roots(self):
        cpu = self.u.context_save()
        for start, stop, index, offset, target in ROOTS:
            self.setreg(25, POOL)
            self.setreg(9, index)
            self.setreg(2, 0)
            self.u.emu_start(start, stop, count=10)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == stop
            assert self.memory_word(FRAME + offset) == target
        self.u.context_restore(cpu)

    def run_cache(self, row, image_cells, table):
        gate = self.run_relock(LOCK, LOCK, 1, D)
        for field in ('reaching_calls', 'modeled_imports', 'control_writes'):
            gate[field] = list(gate[field])
        assert self.reg(10) == D
        self.install_roots()
        for cell in image_cells:
            self.u.mem_write(int(cell['address'], 16), bytes.fromhex(cell['bytes_hex']))
        raw = bytes.fromhex(row['raw_context_hex'])
        self.u.mem_map(D & ~0xfff, 4096)
        self.u.mem_write(D, raw)
        self.u.mem_write(TABLE_DATA, table)
        value, reads = fold(table)
        assert value == 0xc41c69cd
        seed = (D * MULTIPLIER & MASK32) ^ value
        assert seed == int(row['context_seed32'], 16)
        expect_context = bytes.fromhex(row['sealed_context_hex'])
        expect_reference = encode_reference(D, value)
        assert expect_reference.to_bytes(8, 'little').hex() == row['publication']['events'][0]['value']['hex']
        start = len(self.branch_slots)
        self.in_cache_route = True
        self.u.emu_start(CACHE_STOP, DECREMENT, count=4000)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == DECREMENT
        actual = bytes(self.u.mem_read(D, 552))
        assert actual == expect_context == encode(raw, seed)
        assert decode(actual, seed) == raw
        assert self.memory_word(CACHE) == expect_reference
        assert len(self.publications) == 1 and self.publications[0][1] == expect_reference
        assert self.memory_word(CONTROL, 4) == 1 and not self.control_writes
        assert self.text_reads == reads
        assert self.xor3_count == 34 * 4 + 2
        assert (self.backing_reads, self.backing_writes) == context_accesses(seed)
        self.u.emu_start(DECREMENT, FRONTIER, count=4000)
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == FRONTIER
        assert self.control_writes == [('0x10057f70c', 0)]
        assert self.memory_word(CONTROL, 4) == 0
        assert self.memory_word(CACHE) == expect_reference
        assert bytes(self.u.mem_read(D, 552)) == actual
        assert self.records_at_calls[-1]['site'] == hex(CLEANUP2)
        assert self.models[-1] == {'site': '0x100208efc', 'name': 'libSystem/_pthread_rwlock_unlock',
                                   'args': [hex(LOCK)], 'model_return': self.status}
        assert not self.output_accesses and not self.next_writes
        return {'fixture': row['name'], 'retained_payload_sha256': row['payload_sha256'],
                'gate': gate, 'step_count_within_codec': self.codec_visits,
                'xor3_lift_visits': self.xor3_count, 'new_edges': self.branch_slots[start:],
                'context_sha256': sha256(actual).hexdigest(), 'encoded_reference': hex(expect_reference),
                'reference_publication': hex(PUBLICATION),
                'replayed_fold': hex(value), 'context_seed': hex(seed),
                'backing_reads_by_pc': self.access_counts(self.backing_reads),
                'backing_writes_by_pc': self.access_counts(self.backing_writes),
                'cleanup_call': self.records_at_calls[-1], 'cleanup_imports': self.models[-2:],
                'control_writes': self.control_writes,
                'stop_before_unwritten_input': {'pc': hex(FRONTIER), 'address': hex(NEXT_INPUT)},
                'emitter_buffer_access_count': len(self.output_accesses)}

    @staticmethod
    def access_counts(events):
        return dict(Counter(hex(pc) for pc, _, _ in events))

    def check_frontier(self):
        assert self.memory_word(FRAME + 0x9d0, 4) == 0x6cf4
        cpu = self.u.context_save()
        controls = []
        for value, index, target in CONTINUATIONS:
            self.u.context_restore(cpu)
            self.put(NEXT_INPUT, 8, value)
            self.u.emu_start(FRONTIER, target, count=20)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == target
            assert self.reg(0) == value
            edge = self.branch_slots[-1]
            assert edge['fixup_slot'] == hex(TABLE + index * 8)
            assert edge['site'] == '0x100577fec' and edge['modifier'] == '0x4cdb'
            controls.append({'separate_input_premise': hex(value), 'edge': edge})
        return controls


def inspect():
    image_digest = sha256(IMAGE.data).hexdigest()
    assert image_digest == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    rows, cells, table = producer()
    cases, slots = [], {POOL + row[2] * 8 for row in ROOTS} | {POOL + 0x87b * 8}
    profiles = [(row, 0) for row in rows] + [(rows[-1], 35)]
    for index, (row, status) in enumerate(profiles):
        probe = CacheProbe(status)
        cases.append(probe.run_cache(row, cells, table))
        if index == 0:
            frontier = probe.check_frontier()
        slots.update(int(edge['fixup_slot'], 16) for edge in probe.branch_slots)
        del probe
    assert cases[-1]['context_sha256'] == cases[-2]['context_sha256']
    assert cases[-1]['new_edges'] == cases[-2]['new_edges']
    return {'source_sha256': image_digest, 'profiles': cases,
            'frontier_controls': frontier, 'frontier_literal_uses': literal_uses(),
            'root_writer_slices': [[hex(value) for value in row] for row in ROOTS],
            'source_codec_span': list(map(hex, SPAN)),
            'encoded_text_inputs': cells, 'metadata_table_sha256': sha256(table).hexdigest(),
            'fold_reads': [[hex(a), hex(w)] for a, w in fold(table)[1]],
            'context_backing': {'address': hex(D), 'bytes': 552},
            'table_backing': {'address': hex(TABLE_DATA), 'bytes': len(table)},
            'fixups': verify_original_fixups(slots),
            'native_synchronization_observed': False,
            'native_mach_or_iokit_transfer_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
