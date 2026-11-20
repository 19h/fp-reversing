#!/usr/bin/env python3
"""Follow the post-discovery marker dispatch and identify literal output uses."""

from hashlib import sha256
import json
import struct

import z3

from audit_daemon_class_status_route import verify
from audit_daemon_discovery_owner import FRAME, OWNER, STOP, OwnerProbe, ar
from audit_daemon_selector26_return import Frame, SPANS
from daemon_receive_tools import FIXUPS, IMAGE, TABLE, selected, verify_original_fixups
from resolve_kernel_collection_interfaces import commands

NULL_STOP = 0x10080a4d4
FREE_CALL = 0x10079dca0
SAVED_BRANCH = 0x1006902ec
PENDING = FRAME + 0xe400
BYTE_READS = {0x100986634: (8, 0x5e4), 0x100a145b4: (11, 0x1360),
              0x100a44f98: (9, 0x170), 0x100b52810: (13, 0xaa4)}


def source():
    marker, flag, phase = z3.BitVecs('marker flag phase', 32)
    pending = z3.BitVec('pending', 64)
    frame = Frame(sp=FRAME, w23=phase)
    frame.put(FRAME + 0x2b7f, 1, z3.Extract(7, 0, flag))
    frame.put(FRAME + 0x4804, 4, marker)
    frame.put(FRAME + 0x8878, 8, pending)
    frame.step(0x1008eb564, 0x1008eb5b4)
    verify(frame.read('w22') == z3.If(z3.And(marker == 0x8b3dc651,
                                           (flag & 0xff) == 1), 0x74c29db1, marker))
    verify(frame.read('x0') == pending)
    verify(frame.read('w8') == ((phase + 0x3520) ^ z3.If(pending == 0, z3.BitVecVal(0, 32), 0x3d)))

    destination = FRAME + 0xc1b0
    byte = z3.BitVec('first_byte', 8)
    for site, (register, field) in BYTE_READS.items():
        frame = Frame(sp=FRAME)
        frame.put(FRAME + 0x1ba0, 8, destination)
        frame.put(destination, 1, byte)
        frame.step(site, site + 12)
        verify(frame.get(FRAME + field, 4) == z3.ZeroExt(24, byte))
        assert [pc for pc, _, _ in frame.loads] == [site, site + 4]
        assert frame.read(f'w{register}').size() == 32

    frame = Frame(sp=FRAME)
    frame.put(FRAME + 0x1ba0, 8, destination)
    frame.step(0x100bbde58, 0x100bbde64)
    verify(frame.get(destination, 1) == 0xe9)
    return {'bit_vector_checks': 8, 'spans': list(SPANS.values())}


def literal_uses():
    for offset, cmd, _ in commands(IMAGE.data, 0):
        if cmd != 0x19:
            continue
        for index in range(struct.unpack_from('<I', IMAGE.data, offset + 64)[0]):
            section = offset + 72 + 80 * index
            name, _, start, size = struct.unpack_from('<16s16sQQ', IMAGE.data, section)
            if name.rstrip(b'\0') != b'__text':
                continue
            load = 0xf94003e0 | (0x1ba0 // 8 << 10)
            store = 0xf90003e0 | (0x1ba0 // 8 << 10)
            loads, stores = [], []
            for index, (word,) in enumerate(struct.iter_unpack('<I', IMAGE.read(start, size))):
                if word & ~31 == load:
                    loads.append(start + 4 * index)
                if word & ~31 == store:
                    stores.append(start + 4 * index)
            assert loads == [0x10038553c, 0x100518d24, *BYTE_READS, 0x100bbde58]
            assert stores == [0x1004079f0, 0x1005fac70, 0x100b39fe0, 0x100ba0658]
            return {'words': size // 4, 'loads': list(map(hex, loads)), 'stores': list(map(hex, stores))}
    raise AssertionError('missing __text')


class CleanupProbe(OwnerProbe):
    def __init__(self):
        super().__init__()
        self.saved_slot = None
        self.spilled = None
        self.reloaded = None
        self.boundary = None

    def read_hook(self, u, access, address, width, value, user):
        pc = u.reg_read(ar.UC_ARM64_REG_PC)
        if pc == 0x1006c3e6c:
            assert width == 8 and address in FIXUPS
            self.saved_slot = address
        if pc == 0x1006902e4:
            assert address == FRAME + 0x3aa8 and width == 8
            self.reloaded = self.memory_word(address)
        super().read_hook(u, access, address, width, value, user)

    def write_hook(self, u, access, address, width, value, user):
        if u.reg_read(ar.UC_ARM64_REG_PC) == 0x1006c3e70:
            assert address == FRAME + 0x3aa8 and width == 8
            self.spilled = value
        super().write_hook(u, access, address, width, value, user)

    def hook(self, u, pc, size, user):
        if pc == SAVED_BRANCH:
            assert self.spilled == self.reloaded == self.reg(8) == FIXUPS[self.saved_slot]['target']
            self.reads.append((0x1006c3e6c, self.saved_slot))
        if pc in self.imports:
            assert self.imports[pc] == 'libSystem/_free'
            assert self.reg(30) == FREE_CALL + 4 and self.reg(0) == PENDING
            self.boundary = {'symbol': self.imports[pc], 'argument': hex(PENDING),
                             'site': hex(FREE_CALL)}
            u.emu_stop()
            return
        super().hook(u, pc, size, user)

    def run_cleanup(self, owner, pending):
        self.run_owner(owner, 0)
        start = len(self.branch_slots)
        self.u.emu_start(0x10057f7f4, 0x10057f808, count=8)
        self.u.emu_start(0x100790820, 0x100790828, count=3)
        if pending:
            self.put(FRAME + 0x8878, 8, PENDING)
        self.put(FRAME + 0x5d0, 8, 0x100e99800)
        self.put(FRAME + 0x5d8, 8, 0x100f4e290)
        self.u.emu_start(STOP, NULL_STOP if not pending else 0, count=1200)
        edges = self.branch_slots[start:]
        assert edges[0]['target'] == hex(0x10079dc3c if pending else 0x1005bb048)
        if pending:
            assert self.boundary and edges[-1]['target'] == 'libSystem/_free'
        else:
            assert self.u.reg_read(ar.UC_ARM64_REG_PC) == NULL_STOP
            assert self.reg(20) == self.memory_word(FRAME + 0x6fb8) == 0
            assert self.spilled == 0x1005840bc
            assert edges[-1]['target'] == '0x10080a4b8'
        assert not self.output_accesses
        return {'owner_nonnull': bool(owner), 'pending_nonnull': pending, 'edges': edges,
                'endpoint': self.boundary or {'before_load': hex(NULL_STOP), 'offset': '0x6fb8'}}


def inspect():
    proof = source()
    uses = literal_uses()
    cases = [CleanupProbe().run_cleanup(owner, pending) for owner in (0, OWNER)
             for pending in (False, True)]
    frees = selected(0x100e99800, 0x100f4e290, 0x61, 0xcbef)
    assert frees['target'] == 'libSystem/_free'
    root = TABLE + 8 * (0x6cf4 - 0x45be)
    assert FIXUPS[root]['target'] == 0x1005bb048
    slots = {root} | {int(edge['fixup_slot'], 16) for case in cases for edge in case['edges']}
    return {'image_sha256': sha256(IMAGE.data).hexdigest(), 'source': proof,
            'literal_uses': uses, 'profiles': cases, 'free_bank': frees,
            'post_free_index_slot': hex(root), 'fixups': verify_original_fixups(slots)}


if __name__ == '__main__':
    print(json.dumps(inspect(), indent=2, sort_keys=True))
