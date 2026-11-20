#!/usr/bin/env python3
"""Trace the client object fields and saved continuation after discovery cleanup."""
from hashlib import sha256
import json
import struct

from audit_daemon_discovery_pointer_cleanup import PointerProbe, producer
from audit_daemon_discovery_cache_codec import FRAME, IMAGE, ar
from daemon_receive_tools import TABLE, verify_original_fixups
from daemon_rpc502_probe import commands

OWNER_SLOT = FRAME + 0x3650
OBJECT = FRAME + 0xe900
REENTRY = 0x1005e6020
SAVED_SLOT = 0x101040ec8
MARKER = 0x8b3dc651
MATCH = 0x10082a800
FAIL = 0x1004de1d4
ALLOC = 0x1006185ac
ALT_LEFT, ALT_RIGHT = 0x101031da0, 0x100e99900
ALLOC_SLOT = 0x10109ff58


def direct_writers():
    for off, cmd, _ in commands(IMAGE.data, 0):
        if cmd != 0x19:
            continue
        for i in range(struct.unpack_from('<I', IMAGE.data, off + 64)[0]):
            name, _, address, size = struct.unpack_from('<16s16sQQ', IMAGE.data, off + 72 + 80 * i)
            if name.rstrip(b'\0') != b'__text':
                continue
            writers = {0xf90003e0 | (offset // 8 << 10): [] for offset in (0x3650, 0x58d0)}
            for i, (word,) in enumerate(struct.iter_unpack('<I', IMAGE.read(address, size))):
                opcode = word & ~31
                if opcode in writers:
                    writers[opcode].append(address + 4 * i)
            owner, alternate = writers.values()
            assert owner == [0x1005596e4, 0x100592ff8, 0x100ad6fd0]
            assert alternate == [0x100592f94]
            return {'owner': list(map(hex, owner)), 'alternate': list(map(hex, alternate))}
    raise AssertionError('missing __text')


class ClientProbe(PointerProbe):
    def __init__(self):
        self.entry = None
        self.carry_slot = None
        self.client_reads = []
        self.checked_slice = False
        super().__init__()

    def hook(self, u, pc, size, data):
        if pc == REENTRY and self.entry is None:
            self.entry = u.context_save()
        if pc == 0x100713fe0:
            assert self.carry_slot == 0x1004d7f48
            assert self.carry_slot == self.reg(8) == self.memory_word(FRAME + 0x7738)
            self.reads.append((0x1004ccbf0, SAVED_SLOT))
        assert not self.checked_slice or pc not in self.imports
        super().hook(u, pc, size, data)

    def read_hook(self, u, access, address, width, value, data):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == 0x1004ccbf0:
            assert (address, width) == (SAVED_SLOT, 8)
            self.carry_slot = self.memory_word(address)
        if self.checked_slice and OBJECT <= address < OBJECT + 32:
            assert address + width <= OBJECT + 28
            self.client_reads.append((hex(pc), address - OBJECT, width, hex(self.memory_word(address, width))))
        super().read_hook(u, access, address, width, value, data)

    def run_client(self, present, marker, alternate):
        self.u.context_restore(self.entry)
        if alternate:
            self.put(FRAME + 0x58d0, 8, alternate)
        else:
            self.u.emu_start(0x100592f94, 0x100592f98, count=2)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x100592f98
            assert self.memory_word(FRAME + 0x58d0) == 0
        if present:
            self.u.mem_write(OBJECT, bytes([0xa5]) * 32)
            self.setreg(0, OBJECT)
            self.u.emu_start(0x1005596c4, 0x1005596e8, count=16)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x1005596e8
            assert self.memory_word(OWNER_SLOT) == OBJECT
            assert self.memory_word(OBJECT + 0x18, 4) == MARKER
            assert self.memory_word(OBJECT + 0x10, 4) == MARKER
            assert self.memory_word(OBJECT + 0x1c, 4) == 0xa5a5a5a5
            if marker != MARKER:
                self.put(OBJECT + 0x18, 4, marker)
        else:
            self.u.emu_start(0x100592ff8, 0x100592ffc, count=2)
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == 0x100592ffc
            assert self.memory_word(OWNER_SLOT) == 0
        self.u.context_restore(self.entry)
        first = len(self.branch_slots)
        self.checked_slice = True
        self.client_reads.clear()
        endpoint = MATCH if present and marker == MARKER else (ALLOC if alternate else FAIL)
        self.u.emu_start(REENTRY, endpoint, count=330)
        self.checked_slice = False
        assert self.u.reg_read(ar.UC_ARM64_REG_PC) == endpoint
        assert self.memory_word(FRAME + 0x1cf0) == (OBJECT if present else 0)
        expected = [('0x10081a370', 24, 4, hex(marker))] if present else []
        if endpoint == MATCH:
            expected.extend((('0x1004ba49c', 16, 4, hex(MARKER)),
                             ('0x10082a7fc', 12, 4, hex(MARKER))))
            assert self.memory_word(FRAME + 0x3730) == OBJECT + 0x18
            assert self.memory_word(FRAME + 0x7238) == OBJECT + 0x10
            assert self.memory_word(FRAME + 0xa648, 4) == MARKER
            assert self.memory_word(FRAME + 0x4ee4, 4) == 12
        request = None
        if endpoint == ALLOC:
            assert self.reg(8) == self.import_addresses['libSystem/_malloc']
            assert (self.reg(17), self.reg(0)) == (0x6aa4, 16)
            request = {'pending_pc': hex(ALLOC), 'symbol': 'libSystem/_malloc', 'size_bytes': 16,
                       'slot': hex(ALLOC_SLOT), 'modifier': '0x6aa4'}
        assert self.client_reads == expected
        assert not self.output_accesses
        return {'separately_entered_owner_writer': '0x1005596e4' if present else '0x100592ff8',
                'effective_marker': hex(marker) if present else None, 'alternate_premise': hex(alternate),
                'client_reads': list(self.client_reads), 'endpoint': hex(endpoint),
                'pending_allocation': request,
                'edges': self.branch_slots[first:]}


def inspect():
    image_digest = sha256(IMAGE.data).hexdigest()
    assert image_digest == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    rows, cells, table = producer()
    probe = ClientProbe()
    probe.run_cache(rows[-1], cells, table)
    probe.run_cleanup_arms()
    probe.run_saved_component()
    probe.put(FRAME + 0x5f0, 8, ALT_LEFT)
    probe.put(FRAME + 0x5e0, 8, ALT_RIGHT)
    left, right = IMAGE.read(ALT_LEFT, 256), IMAGE.read(ALT_RIGHT, 256)
    indices = {0xcb28 + (i ^ right[left[i] ^ 0x9a]) for i in range(256)}
    assert indices == {0xcc0d} and TABLE + 8 * 0xcc0d == ALLOC_SLOT
    profiles = [probe.run_client(*case) for case in (
        (True, MARKER, 0), (True, MARKER ^ 1, 0), (False, 0, 0),
        (False, 0, FRAME + 0x5900),
    )]
    slots = {ALLOC_SLOT} | {int(e['fixup_slot'], 16) for profile in profiles for e in profile['edges']}
    return {'image_sha256': image_digest, 'profiles': profiles,
            'literal_stack_writers': direct_writers(),
            'allocator_bank': {'left': hex(ALT_LEFT), 'right': hex(ALT_RIGHT), 'u8_inputs_checked': 256},
            'fixups': verify_original_fixups(slots), 'native_owner_epoch_established': False,
            'native_ipc_observed': False}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
