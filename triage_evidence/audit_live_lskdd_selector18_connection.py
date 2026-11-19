#!/usr/bin/env python3
"""Replay lskdd's selector 18 connection setup with offline IOKit results."""

import argparse
import json
from collections import Counter
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn import arm64_const

from audit_live_lskdd_selector18_binding import (
    POOL, SHA, TABLE, ThinView, bindings, daemon_slices, selected_identity, selection, window,
)

ENTRY = 0x1005aff44
GLOBAL = 0x100e82af8
TASK_SLOT = 0x100e76520
STACK = 0x700000000
CONTEXT = STACK + 0x40000
EXTERNAL = 0x200000000
SERVICE_CLASS = b'com_apple_driver_FairPlayIOKit\0'
PORT_SITE = 0x1009e9100
CALLS = (
    (0x1006521e0, 'IOMainPort'),
    (0x1005c48c4, 'IOServiceMatching'),
    (0x100404584, 'IOServiceGetMatchingServices'),
    (0x1006154c0, 'IOIteratorNext'),
    (0x1003e8ff8, 'IOServiceOpen'),
    (0x1003e9058, 'IOObjectRelease'),
    (0x1005e3c98, 'IOObjectRelease'),
    (0x100584cc8, 'IOConnectCallStructMethod'),
)


def replay(image, fixups, connection, method_reply=None):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm64_const.UC_CPU_ARM64_MAX)
    cpu.mem_map(0x100000000, 0xf00000)
    cpu.mem_map(STACK, 0x80000)
    cpu.mem_map(EXTERNAL + 0xe76000, 0x1000)

    def register(name, value=None):
        index = getattr(arm64_const, 'UC_ARM64_REG_' + name.upper())
        if value is None:
            return cpu.reg_read(index)
        cpu.reg_write(index, value)

    def number(address, width):
        return int.from_bytes(cpu.mem_read(address, width), 'little')

    def put(address, value, width=8):
        cpu.mem_write(address, value.to_bytes(width, 'little'))

    for address, offset, size in image.segments:
        if size:
            cpu.mem_write(address, image.data[offset:offset + size])
    for address, row in fixups.items():
        kind, target, *_ = row.split()
        value = int(target, 16) if kind.endswith('rebase') else EXTERNAL + address - 0x100000000
        put(address, value)
    put(EXTERNAL + TASK_SLOT - 0x100000000, 0x503, 4)
    mask = 0x2cba6c00d6dd725f
    state = ((CONTEXT ^ 0x0045804209208c20) & ~mask) | ((CONTEXT ^ 0x200a2c005259624e) & mask)
    entry_word = ((state ^ 0x417a042e7eb57615) * 0x5e9a20bb + 0x6a8e) & 0xffffffff
    put(CONTEXT + 0x20, entry_word)
    put(CONTEXT + 0x28, CONTEXT + 0x800)
    put(CONTEXT + 0x1c, 0x57, 1)
    put(0x100e7f930, CONTEXT + 0x8000)
    register('x0', CONTEXT)
    register('x1', CONTEXT + 0x200)
    register('sp', STACK + 0x30000)
    register('x29', STACK + 0x30050)
    assert number(GLOBAL, 4) == 0

    last_slot = None
    edges = Counter()
    calls = []
    result = {}

    def track_read(_, _access, address, size, _value, _data):
        nonlocal last_slot
        if size == 8 and fixups.get(address, '').startswith('auth-'):
            last_slot = address
        if address == GLOBAL and size == 4:
            assert register('pc') == 0x100584c9c
            result['connection_read'] = number(address, size)

    def handle_call(address, row):
        pc, symbol = CALLS[len(calls)]
        assert address == pc and row.split()[1] == 'IOKit/_' + symbol
        args = [register(f'x{i}') for i in range(6)]
        calls.append(dict(site=hex(pc), symbol=symbol, arguments=list(map(hex, args))))
        sp = register('sp')
        return_value = 0
        if symbol == 'IOMainPort':
            assert args[:2] == [0, sp + 0x88]
            put(args[1], 0x103, 4)
        elif symbol == 'IOServiceMatching':
            assert cpu.mem_read(args[0], len(SERVICE_CLASS)) == SERVICE_CLASS
            result['service_class'] = SERVICE_CLASS[:-1].decode()
            result['service_class_pointer'] = args[0]
            return_value = CONTEXT + 0x1000
        elif symbol == 'IOServiceGetMatchingServices':
            assert args[:3] == [0x103, CONTEXT + 0x1000, sp + 0x8c]
            put(args[2], 0x303, 4)
        elif symbol == 'IOIteratorNext':
            assert args[0] == 0x303
            return_value = 0x203
        elif symbol == 'IOServiceOpen':
            assert args[:4] == [0x203, 0x503, 0, GLOBAL]
            put(args[3], connection, 4)
        elif symbol == 'IOObjectRelease':
            assert args[0] == (0x203 if pc == 0x1003e9058 else 0x303)
        elif symbol == 'IOConnectCallStructMethod':
            assert args[:2] == [connection, 18]
            assert result['connection_read'] == connection
            assert args[2:] == [sp + 0xb0, 3096, sp + 0xcc8, sp + 0x90]
            assert number(args[5], 8) == args[3]
            assert cpu.mem_read(result['service_class_pointer'], len(SERVICE_CLASS)) == bytes(len(SERVICE_CLASS))
            result['method_input_size_bytes'] = args[3]
            result['method_initial_capacity_bytes'] = number(args[5], 8)
            if method_reply is None:
                cpu.emu_stop()
                return
            return_value = method_reply(cpu, args)
        register('x0', return_value)
        register('pc', address + 4)

    def step(_, address, _size, _data):
        if address == PORT_SITE:
            assert register('x0') == POOL and register('w11') == 0x686
        word = number(address, 4)
        opcode = word & 0xfffffc00
        if opcode not in (0xd71f0800, 0xd73f0800):
            return
        target = register(f'x{(word >> 5) & 31}')
        modifier = register(f'x{word & 31}')
        row = fixups[last_slot]
        assert target == number(last_slot, 8)
        assert row.endswith(f'(div=0x{modifier:04X} ad=0 key=IA)'), (hex(address), row)
        edges[(address, last_slot)] += 1
        if row.startswith('auth-bind'):
            assert opcode == 0xd73f0800
            handle_call(address, row)
            return
        if opcode == 0xd73f0800:
            register('x30', address + 4)
        register('pc', target)

    cpu.hook_add(UC_HOOK_MEM_READ, track_read)
    cpu.hook_add(UC_HOOK_CODE, step)
    cpu.emu_start(ENTRY, 0, count=180000)
    assert len(calls) == len(CALLS)
    result.pop('service_class_pointer')
    return dict(result, synthetic_connection=connection, calls=calls,
                matched_authenticated_branches=sum(edges.values()),
                edges=[dict(site=hex(pc), slot=hex(slot), binding=fixups[slot], visits=count)
                       for (pc, slot), count in edges.items()])


def audit(path):
    thin, = [data for _, subtype, data in daemon_slices(path.read_bytes()) if subtype == 0x80000002]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    banks = (0x100d06370, 0x100d3f620)
    for offset, bank in zip((0x1da0, 0x28c8), banks, strict=True):
        assert fixups[POOL + offset] == f'rebase 0x{bank + 4:X}'
    assert fixups[TASK_SLOT] == 'bind libSystem/_mach_task_self_'
    equations = {
        'connection cell': selection(image, fixups, banks, 0xe2, 0x636, POOL, GLOBAL),
        'open': selection(image, fixups, banks, 0x1e, 0x8c20, TABLE, 'IOKit/_IOServiceOpen'),
        'service release': selection(image, fixups, banks, 0x1e, 0x8c25, TABLE, 'IOKit/_IOObjectRelease'),
    }
    runs = [replay(image, fixups, value) for value in (0x403, 0x1403)]
    return dict(identity=identity, equations=equations, runs=runs,
                call_instructions=[window(image, pc - 4, pc + 4) for pc, _ in CALLS],
                native_ipc_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='unmodified fat lskdd executable')
    print(json.dumps(audit(parser.parse_args().image), indent=2))
