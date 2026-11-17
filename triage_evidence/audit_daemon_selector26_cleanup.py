#!/usr/bin/env python3
"""Check the original selector 26 cleanup dispatch, calls and immediate effects."""

import json
from pathlib import Path

import z3

from audit_daemon_selector26_return import FIXUP_SLOTS, SP, SPANS, Frame, number
from daemon_receive_tools import CS, FIXUPS, IMAGE, ROOT, SOURCE, TABLE
from daemon_receive_tools import selected, verify_original_fixups
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import read, sha

FP = 0x8000
P, Q, FIELD, NEXT = 0x9000, 0xa000, 0xb000, 0xc000
STATUS = 0x74c29ded
CONTINUATION = 0x10103f778
PAIR_A = (0x100e99a00, 0x100f4e390)
PAIR_B = (0x100fc4230, 0x101031fa0)


class CleanupFrame(Frame):
    def load(self, address, width):
        at = number(address)
        if width == 1 and any(base <= at < base + 256 for base in PAIR_A + PAIR_B):
            self.loads.append((self.pc, at, width))
            return resize(IMAGE.read(at, width)[0], 8)
        return super().load(address, width)


def landmark(pc, mnemonic, operands):
    raw = IMAGE.read(pc, 4)
    insn = next(CS.disasm(raw, pc))
    assert (insn.mnemonic, insn.op_str) == (mnemonic, operands)
    SPANS[pc, pc + 4] = {'start': hex(pc), 'end_exclusive': hex(pc + 4),
                        'bytes_hex': raw.hex()}


def profile(p, q, field, successor):
    f = CleanupFrame(x29=FP, x30=TABLE, x12=FP - 0xc0, w8=0x3232, w23=0xb11,
                     x19=0, x25=0, w10=STATUS, w7=0,
                     x28=z3.BitVec('inherited_x28', 64))
    f.put(FP - 0xc0, 8, p)
    f.put(FP - 0xd0, 8, TABLE)
    f.put(FP - 0xe0, 8, 0x4000)
    f.put(FP - 0xd8, 8, 0x4004)
    f.put(0x4000, 4, 0x12345678)
    f.put(0x4004, 4, 0x98765432)
    f.put(FP - 0xe8, 8, PAIR_A[0])
    f.put(FP - 0xf0, 8, PAIR_A[1])
    f.put(FP - 0xf8, 8, PAIR_B[0])
    f.put(FP - 0x100, 8, PAIR_B[1])
    f.put(SP + 0x124, 4, z3.BitVec('saved_w28', 32))
    f.put(P, 8, q)
    f.put(Q, 8, successor)
    f.put(Q + 24, 8, field)
    assert f.step(0x1000c3174, 0x1000c31c0) == 0x100008f88
    assert f.step(0x100008f88, 0x100008fbc) == (0x1000c2020 if p else 0x100026478)
    assert (0x100008f94, CONTINUATION, 8) in f.loads
    assert number(f.read('x2')) == 0x1000242f8
    assert 'div=0xF2D5 ad=0 key=IA' in FIXUPS[CONTINUATION]['annotation']
    frees = []
    if p:
        assert f.step(0x1000c2020, 0x1000c2068) == (0x100127c48 if q else 0x100025c4c)
        if q:
            assert f.step(0x100127c48, 0x100127c8c) == (0x1000d2950 if field else 0x10000c238)
            if field:
                assert f.step(0x1000d2950, 0x1000d29a0) == 'libSystem/_free'
                assert number(f.read('x0')) == field
                frees.append('Q+24 B value')
                assert f.step(0x1000d29a0, 0x1000d29b4) == 0x10000c238
                assert number(f.get(Q + 24, 8)) == 0
            assert f.step(0x10000c238, 0x10000c2a4) == 'libSystem/_free'
            assert number(f.read('x0')) == q
            frees.append('Q')
            f.step(0x10000c2a4, 0x10000c2cc)
            assert number(f.read('x23')) == successor
        else:
            assert f.step(0x100025c4c, 0x100025c9c) == 'libSystem/_free'
            assert number(f.read('x0')) == p
            frees.append('P')
            f.step(0x100025c9c, 0x100025cd0)
            assert number(f.get(FP - 0xc0, 8)) == 0
            slot = 0x10104f570
            assert number(f.read('x8')) == FIXUPS[slot]['target'] == 0x100026478
            assert 'div=0x0F65 ad=0 key=IA' in FIXUPS[slot]['annotation']
            assert number(f.read('x17')) == 0xf65
    if not q:
        f.step(0x100026478, 0x100026484)
        assert number(f.read('x0')) == 0
        assert number(f.read('x2')) == 0x1000242f8
        assert number(f.read('x17')) == 0xf2d5
    assert all(not (at < SP + 0xec and at + width > SP + 0xe8)
               for _, at, width in f.loads)
    assert number(f.get(SP + 0xe8, 4)) == STATUS
    return {'inputs': [hex(value) for value in (p, q, field, successor)],
            'edges': f.edges, 'free_arguments': frees}


def report():
    upstream = json.loads(read(ROOT / 'daemon_selector26_callers_audit.json'))
    digest = sha(SOURCE)
    assert digest == upstream['daemon_sha256']
    witnesses = ((0, 0, 0, 0), (P, 0, 0, 0), (P, Q, 0, 0),
                 (P, Q, 0, NEXT), (P, Q, FIELD, 0), (P, Q, FIELD, NEXT))
    profiles = [profile(*args) for args in witnesses]
    landmark(0x100025cd0, 'braa', 'x8, x17')
    landmark(0x100026484, 'braa', 'x2, x17')
    landmark(0x1000242f8, 'add', 'w23, w28, w16')
    landmark(0x1000242fc, 'eor', 'w8, w23, w1')
    banks = [selected(*pair, key, additive) for pair, key, additive in (
        (PAIR_A, 0x9c, 0xcbda), (PAIR_B, 0xe4, 0xcbab), (PAIR_A, 0x78, 0xcb67))]
    assert all(row['index'] == '0xcc08' and row['target'] == 'libSystem/_free'
               and row['inputs_checked'] == 256 for row in banks)
    return {'daemon_sha256': digest, 'generator_sha256': sha(Path(__file__)),
            'upstream_sha256': sha(ROOT / 'daemon_selector26_callers_audit.json'),
            'source_spans': list(SPANS.values()), 'profiles': profiles, 'banks': banks,
            'fixups': verify_original_fixups(FIXUP_SLOTS), 'native_exchange_observed': False}


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
