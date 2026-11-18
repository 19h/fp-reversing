#!/usr/bin/env python3
"""Check the local selector 26 stack-input path against original instruction bytes."""

import json
import subprocess

import z3
from capstone.arm64_const import ARM64_OP_REG, ARM64_SFT_ROR

from audit_daemon_selector26_return import CS, FIXUP_SLOTS, SP, Frame, number
from audit_daemon_selector26_stack_producer import check_original_replay, select_fragment
from daemon_receive_tools import IMAGE, ROOT, TABLE, verify_original_fixups

FIRST = 0x1006ae330
BYTE_PAIR = 0x1006a0e20
HALF_STORE = 0x10064adec
TABLE_HOP = 0x100907aac
BYTE_WORD = 0x1009736fc
WORD_STORE = 0x10064f0e0


class ByteFrame(Frame):
    def operand(self, instruction, operand, width):
        if operand.shift.type == ARM64_SFT_ROR:
            return z3.RotateRight(self.read(instruction.reg_name(operand.reg)), operand.shift.value)
        return super().operand(instruction, operand, width)

    def run(self, label):
        row = self.c['spans'][0]
        instruction = next(CS.disasm(bytes.fromhex(row['bytes_hex']), int(row['start'], 16)))
        args = instruction.operands
        if instruction.mnemonic in ('ror', 'lsr') and args[2].type == ARM64_OP_REG:
            assert instruction.mnemonic == 'lsr'
            source = self.read(instruction.reg_name(args[1].reg))
            shift = self.read(instruction.reg_name(args[2].reg))
            value = z3.LShR(source, shift & (source.size() - 1))
        elif instruction.mnemonic == 'ror':
            value = z3.RotateRight(self.read(instruction.reg_name(args[1].reg)), args[2].imm)
        elif instruction.mnemonic == 'cset' and instruction.op_str.endswith(', hi'):
            value = z3.If(z3.UGT(self.cmp_left, self.cmp_right),
                          z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        else:
            return super().run(label)
        self.write(instruction.reg_name(args[0].reg), z3.simplify(value))


def check_path(lane, above):
    pair_address = 0x88000 + lane
    word_address = 0x98000 + lane
    base = 0x36800
    frame = ByteFrame(x21=TABLE, x30=TABLE, w14=0x13579bdf, x27=1,
                      x0=2, x1=3, x2=4, x3=5, x4=6, x5=7, x6=8, x7=9,
                      x8=0x12345678, x10=10, x11=11, x12=12, x13=13, x15=15, x28=28)
    for offset, width, value in (
        (0x26c, 4, 0xb22f), (0x250, 8, base), (0x288, 8, 0x2000),
        (0xb0, 8, pair_address - base - 0x864f69af3c097da8),
        (0xa0, 8, word_address - base - 0x99e5a6f4cfd4506a),
        (0x68, 8, 0 if above else 0xfffffffff), (0x70, 8, 0x2000),
    ):
        frame.put(SP + offset, width, value)
    for address, data in ((pair_address, b'\x12\x34'), (word_address, b'\x56\x78\x9a\xbc')):
        frame.put(address, len(data), int.from_bytes(data, 'little'))
    select_fragment(frame, FIRST, 0x1006ae35c, BYTE_PAIR, 0x101047760)
    # The downstream branches use a target preloaded much earlier in the block.
    select_fragment(frame, BYTE_PAIR, 0x1006a11a0, HALF_STORE, 0x10103ad98)
    half = number(frame.read('w19'))
    select_fragment(frame, HALF_STORE, 0x10064ae1c, TABLE_HOP, 0x10104b850)
    select_fragment(frame, TABLE_HOP, 0x100907ac0, BYTE_WORD, 0x10105fca8)
    select_fragment(frame, BYTE_WORD, 0x100973ed4, WORD_STORE, 0x10103d968)
    word = number(frame.read('w14'))
    offset = number(frame.read('w19')) ^ 0x8ec35f08
    target, slot = (0x100967f08, 0x101096530) if above else (0x1006526c0, 0x101096558)
    select_fragment(frame, WORD_STORE, 0x10064f13c, target, slot)
    assert number(frame.get(SP + 0x878, 8)) == 0x2000 + offset
    assert number(frame.read('w5')) == 0x74c29d8f
    if not above:
        select_fragment(frame, target, 0x1006526d4, 0x10063f0dc, 0x101063840)
        instructions = CS.disasm(IMAGE.read(0x10063f104, 12), 0x10063f104)
        assert [(insn.mnemonic, insn.op_str) for insn in instructions] == [
            ('mov', 'w20, #-0x2f12'), ('ldr', 'w5, [sp, #0x1f4]'),
            ('cmp', 'w20, w5, sxth'),
        ]
    assert number(frame.read('sp')) == SP
    assert [(pc, address, width) for pc, address, width, _ in frame.stores][:4] == [
        (0x1006ae334, SP + 0x86c, 4), (0x10064adf4, SP + 0x872, 2),
        (0x10064ae08, SP + 0x1f4, 4), (0x10064f0ec, SP + 0x874, 4),
    ]
    for offset, width, value in (
        (0x86c, 4, 0x13579bdf), (0x872, 2, half & 0xffff),
        (0x1f4, 4, half), (0x874, 4, word),
    ):
        assert number(frame.get(SP + offset, width)) == value
    assert [(pc, address) for pc, address, width in frame.loads if width == 1] == [
        (0x1006a0e44, pair_address), (0x1006a0ff0, pair_address + 1),
        (0x100973934, word_address), (0x100973998, word_address + 1),
        (0x100973cf4, word_address + 2), (0x100973ea0, word_address + 3),
    ]


def check_saved_profiles():
    check_original_replay()
    audit = json.loads(subprocess.check_output(
        ['zstd', '-dc', str(ROOT / 'daemon_selector26_helper_consumers_audit.json.zst')]
    ))
    branch_pcs = {'0x1006ae358', '0x1006a119c', '0x10064ae18', '0x100907abc',
                  '0x100973ed0', '0x10064f138', '0x1006526d0'}
    profiles = [row for row in audit['profiles'] if row['outcome']['frontier'] == '0x10094326c']
    assert len(profiles) == 2
    for profile in profiles:
        assert branch_pcs.isdisjoint(edge['pc'] for edge in profile['authenticated_edges'])


if __name__ == '__main__':
    for lane in range(8):
        for above in (False, True):
            check_path(lane, above)
    check_saved_profiles()
    assert len(verify_original_fixups(FIXUP_SLOTS)['records']) == 9
    print('16 modeled paths, all 8 byte lanes, 2 saved profiles, 9 original fixups')
