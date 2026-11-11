#!/usr/bin/env python3
"""Independent integer/byte-memory checks for original configuration cuts.

All objects and payload bytes are declared test data. No native target,
register, key, API or IDB operation executes. O(cases * source visits) time;
O(private byte cells + decoded instructions) space.
"""
import json
import re

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read

H = 0xfffffe0009d40000
MASK64 = (1 << 64)-1


class Integers:
    def __init__(self, code):
        self.code = code; self.regs = {}; self.memory = {}; self.flags = None; self.visits = 0

    def width(self, name):
        return 128 if re.fullmatch('[qv][0-9]+', name) else 32 if re.fullmatch('[ws][0-9]+|wzr', name) else 64

    def key(self, name):
        if re.fullmatch('[qvds][0-9]+', name): return 'v'+name[1:]
        return 'x'+name[1:] if name.startswith('w') else name

    def get(self, name):
        if name in ['wzr', 'xzr']: return 0
        assert self.key(name) in self.regs, ('undefined integer register', name)
        return self.regs[self.key(name)] & ((1 << self.width(name))-1)

    def put(self, name, value):
        if name not in ['wzr', 'xzr']: self.regs[self.key(name)] = value & ((1 << self.width(name))-1)

    def load(self, address, n):
        assert all(address+j in self.memory for j in range(n)), ('undefined byte cell', hex(address), n)
        return int.from_bytes(bytes(self.memory[address+j] for j in range(n)), 'little')

    def store(self, address, n, value):
        for j, byte in enumerate((value & ((1 << (n*8))-1)).to_bytes(n, 'little')): self.memory[address+j] = byte

    def value(self, ins, operand):
        if operand.type == ARM64_OP_REG: value = self.get(ins.reg_name(operand.reg))
        else: assert operand.type == ARM64_OP_IMM; value = operand.imm
        assert not operand.ext
        if operand.shift.type: value <<= operand.shift.value
        return value

    def address(self, ins, operand):
        mem = operand.mem; value = self.get(ins.reg_name(mem.base))+mem.disp
        if mem.index: value += self.get(ins.reg_name(mem.index)) << operand.shift.value
        return value & MASK64

    def condition(self, name):
        a, b, width = self.flags; a &= (1 << width)-1; b &= (1 << width)-1
        signed = lambda x: x-(1 << width) if x & (1 << (width-1)) else x
        return {'eq': a == b, 'ne': a != b, 'gt': signed(a) > signed(b), 'lo': a < b,
                'hi': a > b, 'hs': a >= b, 'ls': a <= b}[name]

    def step(self, pc):
        ins = self.code[pc]; self.visits += 1; m = ins.mnemonic; o = ins.operands
        names = [ins.reg_name(x.reg) for x in o if x.type == ARM64_OP_REG]
        if m == 'b': return o[0].imm & MASK64
        if m.startswith('b.'): return (o[0].imm & MASK64) if self.condition(m[2:]) else pc+4
        if m in ['cbz', 'cbnz']:
            take = (self.get(names[0]) == 0) == (m == 'cbz')
            return (o[1].imm & MASK64) if take else pc+4
        if m == 'cmp': self.flags = (self.value(ins, o[0]), self.value(ins, o[1]), self.width(names[0]))
        elif m == 'mov': self.put(names[0], self.value(ins, o[1]))
        elif m == 'movi':
            assert ins.op_str in ['v0.2d, #0000000000000000', 'v0.2s, #2']
            self.put('q0', 0 if '.2d' in ins.op_str else 0x0000000200000002)
        elif m in ['add', 'sub', 'orr']:
            a, b = self.value(ins, o[1]), self.value(ins, o[2]); self.put(names[0], a+b if m == 'add' else a-b if m == 'sub' else a | b)
        elif m == 'csel': self.put(names[0], self.get(names[1] if self.condition(ins.op_str.rsplit(',', 1)[1].strip()) else names[2]))
        elif m == 'ubfx': self.put(names[0], (self.get(names[1]) >> o[2].imm) & ((1 << o[3].imm)-1))
        elif m == 'bfi':
            mask = ((1 << o[3].imm)-1) << o[2].imm
            self.put(names[0], (self.get(names[0]) & ~mask) | ((self.get(names[1]) << o[2].imm) & mask))
        elif m in ['ldr', 'ldur']: self.put(names[0], self.load(self.address(ins, o[1]), self.width(names[0])//8))
        elif m in ['str', 'stur']: self.store(self.address(ins, o[1]), self.width(names[0])//8, self.get(names[0]))
        elif m in ['ldp', 'stp']:
            address = self.address(ins, o[2]); n = self.width(names[0])//8
            for j, name in enumerate(names[:2]):
                if m == 'ldp': self.put(name, self.load(address+j*n, n))
                else: self.store(address+j*n, n, self.get(name))
        elif m == 'ld1':
            assert ins.op_str == '{v0.s}[1], [x8]'
            word = self.load(self.get('x8'), 4)
            self.put('q0', (self.get('q0') & ~(0xffffffff << 32)) | (word << 32))
        else: raise AssertionError(('unsupported independent instruction', hex(pc), m, ins.op_str))
        return pc+4

    def cut(self, start, end):
        pc = start
        while pc < end: assert self.step(pc) == pc+4; pc += 4

    def route(self, start, stops):
        pc = start; bound = self.visits+64
        while pc not in stops: assert self.visits < bound; pc = self.step(pc)
        return pc


def audit():
    evidence = json.loads(read(ROOT/'aes_configuration_commands_checks.json'))
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
    code = {i.address: i for row in evidence['spans'] for i in cs.disasm(bytes.fromhex(row['bytes_hex']), int(row['start'], 16))}
    C, K, P, S, E = 0x110000, 0x120000, 0x130000, 0x500000, 0x140000
    operation_cases = 0
    for operation in [*range(9), 0x7fffffff, 0x80000000, 0xffffffff, 0x40000004]:
        for selector in [0, 3102, 0x80000c1e]:
            m = Integers(code); m.put('x1', C); m.put('x21', C)
            m.store(C+0x40, 4, operation); m.store(C+0x48, 8, K); m.store(K+0x24, 4, selector)
            frontier = m.route(H+0xfd3c, {H+0xfdb8, H+0xfe68, H+0x10028})
            admitted = operation <= 5 or (operation == 6 and selector == 3102)
            assert (frontier == H+0xfdb8) == admitted
            if admitted:
                assert m.get('w24') == {0: 0x10000, 1: 0x10000, 2: 0, 3: 0, 4: 0x20000, 5: 0x20000, 6: 0}[operation]
                assert m.get('w25') == (0x100000 if operation in [0, 2, 4, 5] else 0)
            operation_cases += 1
    routes = {0: H+0x10048, 1000: H+0x100c4, 1001: H+0xfe00, 2000: H+0x100a4, 2001: H+0x100e4,
              3000: H+0xff74, 3100: H+0xff74, 3102: H+0xfeb4, **{i: H+0xfe4c for i in range(4000, 4004)}}
    selector_cases = 0
    for selector in [*range(4097), 0x7fffffff, 0x40000000, 0x100000]:
        m = Integers(code); m.put('w10', selector)
        assert m.route(H+0xfddc, set(routes.values()) | {H+0x100fc}) == routes.get(selector, H+0x100fc)
        selector_cases += 1
    size_cases = 0
    for size_code in range(4):
        for other_bits in [0, 0x3fffff, 0xc0000000]:
            m = Integers(code); m.put('w1', (size_code << 22) | other_bits)
            frontier = m.route(H+0x10864, {H+0x10894, H+0x108b4})
            assert (frontier == H+0x108b4) == (size_code != 3)
            if size_code != 3: assert m.get('w21') == [16, 24, 32][size_code]
            size_cases += 1
    def packet_machine():
        m = Integers(code); m.put('sp', S)
        for j in range(0x90): m.memory[S+j] = 0xa5
        for j in range(64): m.memory[K+j] = (j*37+11) & 255; m.memory[E+j] = (j*19+71) & 255
        return m
    u32 = lambda n: (n & 0xffffffff).to_bytes(4, 'little')
    block = bytes((j*37+11) & 255 for j in range(32)); extra = bytes((j*19+71) & 255 for j in range(16))
    extended_cases = 0
    for header in [0, 0xffffffff, 0x10000000, 0x18200000]:
        for argument in [0, 0xffffffff]:
            m = packet_machine(); m.put('w1', header); m.cut(H+0x107e4, H+0x107f4)
            m.put('x3', E); m.put('x20', K); m.put('x19', P); m.put('w2', argument)
            m.cut(H+0x10838, H+0x10858)
            expected = u32(header)+u32(argument)+bytes(12)+extra+block
            assert m.load(S+0x1c, 68).to_bytes(68, 'little') == expected
            assert m.get('x1') == S+0x1c and m.get('w2') == 68
            extended_cases += 1
    iv_cases = 0
    for flags in [0, 0xffffffff]:
        for route in [0, 0x1800000]:
            for channel in [0, 1, 3, 0xffffffff]:
                for present in [False, True]:
                    m = packet_machine(); m.put('w26', flags); m.put('w28', route); m.put('w20', channel)
                    m.cut(H+0x1038c, H+0x103a4)
                    if present: m.put('x8', E); m.cut(H+0x103a8, H+0x103b4)
                    header = (flags & ~0x0c000000) | ((channel & 3) << 26) | route | 0x20000000
                    assert m.load(S+0x18, 20).to_bytes(20, 'little') == u32(header)+(extra if present else bytes(16))
                    iv_cases += 1
    inline_cases = 0
    for width in [0, 1, 128, 192, 256, 0xffffffff]:
        m = packet_machine(); m.put('w9', width); m.put('x27', K)
        m.cut(H+0x1006c, H+0x1008c); m.cut(H+0x1009c, H+0x100a0)
        assert m.load(S+0x40, 32).to_bytes(32, 'little') == bytes(m.memory[K+4+j] for j in range(32))
        assert m.get('w9') == {192: 0x400000, 256: 0x800000}.get(width, 0)
        inline_cases += 1
    dsb_cases = 0
    for first, second in [(K, E), (E, K)]:
        m = packet_machine(); m.put('x1', first); m.put('x2', second)
        m.cut(H+0x10944, H+0x10960)
        expected = u32(0x30000000)+bytes(m.memory[first+j] for j in range(16))+bytes(m.memory[second+j] for j in range(16))
        assert m.load(S+0xc, 36).to_bytes(36, 'little') == expected and m.get('w2') == 36
        dsb_cases += 1
    trace_cases = 0
    for word in [0, 1, 0xffffffff, 0x87654321]:
        m = packet_machine(); m.store(E, 4, word); m.put('x8', E); m.put('x11', S+0x20)
        m.cut(H+0x11ed4, H+0x11ee0)
        assert m.load(S+0x20, 8).to_bytes(8, 'little') == u32(2)+u32(word)
        trace_cases += 1
    return {'operation_integer_cases': operation_cases, 'selector_integer_cases': selector_cases, 'size_integer_cases': size_cases,
            'extended_record_byte_cases': extended_cases, 'IV_record_byte_cases': iv_cases, 'inline_copy_byte_cases': inline_cases,
            'dsb_record_byte_cases': dsb_cases, 'trace_record_byte_cases': trace_cases}


if __name__ == '__main__': print(json.dumps(audit()))
