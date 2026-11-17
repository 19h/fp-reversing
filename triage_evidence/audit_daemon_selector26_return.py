#!/usr/bin/env python3
"""Lift the pinned fairplayd selector 26 call and local return instructions."""

from contextlib import redirect_stdout
import hashlib
import json
import sys

import z3
from capstone.arm64_const import ARM64_EXT_SXTW, ARM64_EXT_UXTB

from audit_userclient_fallback_metadata import solve
from daemon_arena_lifetime_symbolic import CS
from daemon_receive_tools import FIXUPS, IMAGE, POOL, ROOT, SOURCE, TABLE
from daemon_receive_tools import selected, verify_original_fixups
from lskd_values_symbolic import resize
from prove_kernel_reply_send import Local
from verify_daemon_reader_record_payloads_publication import read, sha

SCOPE = 'Original fairplayd selector 26 arguments, return predicates and local record writes.'
KEY = 0x8b3dc651
BAD_SHAPE = 0x74c29fc9
STATUS = z3.BitVec('api_status', 32)
NAME = z3.BitVec('connection_name', 32)
SP, RECORD, CONTEXT, DATA, SEED = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000
TRAIL = [z3.BitVec(f'payload_byte_{offset}', 8) for offset in range(14)]
SPANS = {}
FIXUP_SLOTS = set()
POOL_SLOTS = {0x1010a3ba0, 0x1010a7a50, 0x1010a6230}


def number(value):
    return z3.simplify(value).as_long()


class Frame(Local):
    def __init__(self, **registers):
        super().__init__({'spans': []})
        self.ram = {}
        self.loads = []
        self.edges = []
        self.return_pc = None
        self.seed('sp', SP)
        self.seed('x19', RECORD)
        for register, value in registers.items():
            self.seed(register, value)

    def put(self, address, width, value):
        word = resize(value, width * 8)
        for offset in range(width):
            self.ram[address + offset] = z3.Extract(8 * offset + 7, 8 * offset, word)

    def get(self, address, width):
        cells = [self.ram[address + offset] for offset in reversed(range(width))]
        return cells[0] if width == 1 else z3.Concat(*cells)

    def load(self, addr, width):
        address = number(addr)
        self.loads.append((self.pc, address, width))
        if width == 8 and address in FIXUPS:
            assert address in POOL_SLOTS or TABLE <= address < POOL
            FIXUP_SLOTS.add(address)
            target = FIXUPS[address]['target']
            return resize(target if isinstance(target, int) else address, 64)
        if width == 1 and any(base <= address < base + 256
                              for base in (0x100fc4230, 0x101031fa0)):
            return resize(IMAGE.read(address, width)[0], 8)
        return self.get(address, width)

    def store(self, address, width, value, pc):
        location = number(address)
        self.put(location, width, value)
        self.stores.append((pc, location, width, resize(value, width * 8)))

    def address(self, instruction, operand):
        if operand.ext != ARM64_EXT_SXTW:
            return super().address(instruction, operand)
        mem = operand.mem
        index = z3.SignExt(32, self.read(instruction.reg_name(mem.index)))
        return self.read(instruction.reg_name(mem.base)) + (index << operand.shift.value)

    def operand(self, instruction, operand, width):
        if operand.ext == ARM64_EXT_UXTB:
            return resize(self.read(instruction.reg_name(operand.reg)), width) & 0xff
        return super().operand(instruction, operand, width)

    def step(self, start, end):
        raw = IMAGE.read(start, end - start)
        SPANS[start, end] = {'start': hex(start), 'end_exclusive': hex(end),
                             'bytes_hex': raw.hex()}
        for insn in CS.disasm(raw, start):
            self.pc = insn.address
            args = insn.operands
            if insn.mnemonic in ('braa', 'blraa'):
                assert self.pc + 4 == end
                _, slot, width = self.loads[-1]
                target = FIXUPS[slot]['target']
                modifier = number(self.read(insn.reg_name(args[1].reg)))
                assert width == 8 and f'div=0x{modifier:X} ad=0 key=IA' in FIXUPS[slot]['annotation']
                reg_target = number(self.read(insn.reg_name(args[0].reg)))
                assert reg_target == (target if isinstance(target, int) else slot)
                self.edges.append({'pc': hex(self.pc), 'slot': hex(slot),
                                   'target': hex(target) if isinstance(target, int) else target,
                                   'modifier': hex(modifier)})
                return target
            if insn.mnemonic == 'retab':
                assert self.pc + 4 == end
                self.return_pc = self.pc
                return None
            if insn.mnemonic == 'adrp':
                self.write(insn.reg_name(args[0].reg), args[1].imm)
            elif insn.mnemonic == 'ands':
                assert insn.op_str == 'w15, w14, #7'
                value = self.read('w14') & 7
                self.write('w15', value)
                self.equal = value == 0
                self.negative = z3.BoolVal(False)
                self.carry = self.overflow = z3.BoolVal(False)
            else:
                self.c = {'spans': [{'label': 'word', 'start': hex(self.pc),
                                     'bytes_hex': bytes(insn.bytes).hex()}]}
                self.run('word')
                continue
            self.count += 1
        assert self.pc + 4 == end
        return None


def static_bank(key, add, index):
    row = selected(0x100fc4230, 0x101031fa0, key, add)
    assert int(row['index'], 16) == index
    return row


def arguments(frame, pointer, outer_size):
    return z3.Or(frame.read('w0') != NAME, frame.read('w1') != 26,
                 frame.read('x2') != pointer, frame.read('x3') != outer_size,
                 frame.read('x4') != pointer, frame.read('x5') != SP)


def first_entry():
    f = Frame(x10=SEED, x14=SEED + 4, x11=SEED + 8 - 0x88,
              x12=SEED + 12 - 0x670, w8=7, w9=47)
    f.put(CONTEXT + 4, 4, NAME)
    for offset in range(0, 16, 4):
        f.put(SEED + offset, 4, offset + 5)
    key = ((RECORD ^ 0xd71b18ee ^ 0x11cd78fa) * 0x6b86592f) & 0xffffffff
    f.put(RECORD, 8, DATA)
    f.put(RECORD + 8, 8, CONTEXT)
    f.put(RECORD + 16, 4, key ^ ((16 - 0xf537f77b) & 0xffffffff))
    f.put(RECORD + 20, 4, key ^ 0xbf1d)
    # Compose the original pool-base definition with the later record decode.
    f.step(0x10043a08c, 0x10043a094)
    assert f.step(0x10043a14c, 0x10043a240) == 0x10020693c
    assert number(f.read('w21')) == KEY and number(f.read('x22')) == TABLE
    assert f.step(0x10020693c, 0x1002069c8).endswith('/_IOConnectCallStructMethod')
    return f


def restore(frame, start, end, saved_start, frame_size):
    for offset in range(saved_start, frame_size, 8):
        frame.put(SP + offset, 8, z3.BitVec(f'saved_stack_{offset}', 64))
    frame.step(start, end)
    assert number(frame.read('sp')) == SP + frame_size
    assert frame.return_pc == end - 4


def first_return(status, returned_size):
    f = first_entry()
    f.put(SP, 8, returned_size)
    f.seed('w0', status)
    first_load = len(f.loads)
    target = f.step(0x1002069c8, 0x100206a10)
    if status == 0:
        assert target == 0x1002724a0
        target = f.step(target, 0x1002724c0)
    assert target == 0x10020e6b0
    f.step(target, target + 4)
    restore(f, target + 4, 0x10020e6cc, 0x10, 0x50)
    assert [at for _, at, _ in f.loads[first_load:] if at == SP] == ([SP] if status == 0 else [])
    assert [(addr, size) for _, addr, size, _ in f.stores] == [(SP, 8), (RECORD + 24, 4)]
    return f


def second_entry():
    # K is a source-decoded record word. Only its consumed value is needed here.
    key = 0x4ce640eb
    f = Frame(x8=POOL, x11=SEED, x12=SEED + 4, w16=key, w9=7, w10=47,
              x13=SEED + 8 - 0x828, x14=SEED + 12 - 0x670)
    for offset in range(0, 16, 4):
        f.put(SEED + offset, 4, offset + 5)
    f.put(CONTEXT + 4, 4, NAME)
    f.put(RECORD + 4, 4, key + 0xb469)
    f.put(RECORD, 4, key ^ ((14 - 0xbc30601d) & 0xffffffff))
    f.put(RECORD + 16, 8, CONTEXT)
    f.put(RECORD + 24, 8, DATA)
    for offset, byte in enumerate(TRAIL):
        f.put(DATA + offset, 1, byte)
    assert f.step(0x10043efa0, 0x10043f03c) == 0x100292fc0
    assert f.step(0x100292fc0, 0x100293078).endswith('/_IOConnectCallStructMethod')
    return f


def second_return(size, extent):
    f = second_entry()
    f.put(SP, 8, size)
    f.put(SP + 16, 4, extent)
    f.seed('w0', STATUS)
    before = len(f.stores)
    after_api = len(f.loads)
    target = f.step(0x100293078, 0x1002930ac)
    if size == 16:
        assert target == 0x1001dc080
        target = f.step(target, 0x1001dc0c0)
    if size == 16 and extent == 14:
        assert target == 0x1002f9c48
        target = f.step(target, 0x1002f9ce0)
        assert target == 0x1002ffc08
        target = f.step(target, 0x1002ffc68)
        for _ in range(6):
            assert target == 0x1003e5104
            target = f.step(target, 0x1003e5148)
        assert target == 0x100309968
        target = f.step(target, 0x100309994)
        assert target == 0x1002bfadc
        target = f.step(target, 0x1002bfb78)
    assert target == 0x1001f48bc
    f.step(target, target + 4)
    restore(f, target + 4, 0x1001f48dc, 0x20, 0x70)
    payload = list(range(DATA + 13, DATA - 1, -1)) if size == 16 and extent == 14 else []
    assert [at for _, at, width in f.loads[after_api:] if width == 1] == payload
    assert [(addr, width) for _, addr, width, _ in f.stores[before:]] == (
        [(addr, 1) for addr in payload] + [(RECORD + 8, 4)])
    return f


def receipt(frame):
    return {'edges': frame.edges, 'retab_pc': hex(frame.return_pc), 'stores': [
        {'pc': hex(pc), 'width_bytes': width, 'location': (
            f'record+{addr - RECORD}' if RECORD <= addr < RECORD + 32 else
            f'stack+{addr - SP}' if SP <= addr < SP + 32 else f'buffer+{addr - DATA}'),
         'value': z3.simplify(value).sexpr()}
        for pc, addr, width, value in frame.stores]}


def report():
    upstream = json.loads(read(ROOT / 'iokit_sync_error_reply_audit.json'))
    statuses = {name: int(word, 16) for name, word in upstream['statuses'].items()}
    assert statuses == {'miss': 0xffff5bbc, 'match': 0xffff5a87}
    banks = [static_bank(0x6c, 0xcc63, 0xccea), static_bank(0xf3, 0xcca7, 0xccea),
             static_bank(0xe4, 0x8bd, 0x91a)]
    phase = z3.BitVec('first_entry_phase', 32)
    f = first_entry()
    proofs = [solve('first_arguments', [], z3.Or(arguments(f, DATA, 16), f.get(SP, 8) != 16))]
    f.seed('w21', phase)
    f.step(0x10020693c, 0x100206948)
    f.seed('w0', STATUS)
    f.step(0x1002069c8, 0x100206a04)
    base = phase + 0x74c26032
    proofs.append(solve('first_status_encoding_and_slot', [], z3.Or(
        f.read('w11') != (STATUS ^ KEY),
        f.read('w9') != (base ^ z3.If((STATUS ^ KEY) == phase, resize(0x9fe, 32), resize(0, 32))))))
    g = second_entry()
    proofs.append(solve('second_arguments_and_descriptor', [], z3.Or(
        arguments(g, SP + 8, 16), g.get(SP, 8) != 16, g.get(SP + 8, 8) != DATA,
        g.get(SP + 16, 4) != 14, g.get(SP + 20, 4) != 0)))
    size = z3.BitVec('returned_size', 64)
    extent = z3.BitVec('returned_extent', 32)
    g.put(SP, 8, size)
    g.put(SP + 16, 4, extent)
    g.step(0x100293078, 0x100293098)
    proofs.append(solve('second_outer_size_partition', [], g.read('w8') !=
                        z3.If(size == 16, resize(0xa5bd, 32), resize(0x4c2c, 32))))
    g.step(0x1001dc080, 0x1001dc0ac)
    proofs.append(solve('second_inner_extent_partition', [], g.read('w8') !=
                        z3.If(extent == 14, resize(0x4c27, 32), resize(0x4c2c, 32))))
    profiles = {}
    for name, status in statuses.items():
        first = first_return(status, 16)
        proofs.append(solve('first_' + name, [], first.get(RECORD + 24, 4) != (status ^ KEY)))
        profiles['first_' + name] = receipt(first)
    for size in (16, 15):
        first = first_return(0, size)
        expected = KEY if size == 16 else BAD_SHAPE
        proofs.append(solve(f'first_zero_size_{size}', [], first.get(RECORD + 24, 4) != expected))
        profiles[f'first_zero_size_{size}'] = receipt(first)
    for size, extent in ((16, 14), (0x100000010, 14), (16, 13)):
        f = second_return(size, extent)
        expected = STATUS ^ KEY if (size, extent) == (16, 14) else BAD_SHAPE
        label = f'second_size_{size}_extent_{extent}'
        proofs.append(solve(label, [], z3.Or(f.get(RECORD + 8, 4) != expected,
            *[f.get(DATA + offset, 1) != byte for offset, byte in enumerate(TRAIL)])))
        profiles[label] = receipt(f)
    return {'scope': SCOPE, 'daemon_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            'generator_sha256': sha(ROOT / 'audit_daemon_selector26_return.py'),
            'dependencies': {name: sha(ROOT / name) for name in (
                'iokit_sync_error_reply_audit.json', 'daemon_receive_tools.py',
                'daemon_receive_fixups.txt', 'daemon_arena_lifetime_symbolic.py',
                'prove_kernel_reply_send.py', 'lskd_values_symbolic.py',
                'audit_userclient_fallback_metadata.py')},
            'statuses': {name: {'api': hex(value), 'encoded': hex(value ^ KEY)}
                         for name, value in statuses.items()},
            'banks': banks, 'fixups': verify_original_fixups(FIXUP_SLOTS),
            'source_spans': list(SPANS.values()), 'proofs': proofs, 'profiles': profiles,
            'native_exchange_observed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        result = report()
    print(json.dumps(result, indent=2))
