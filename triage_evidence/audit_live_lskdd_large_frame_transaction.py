#!/usr/bin/env python3
"""Audit the transaction helper on lskdd's large-frame initializer path."""

import argparse
import json
from collections import Counter
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm64_const

from audit_live_lskdd_selector19_binding import (
    SHA, ThinView, bindings, daemon_slices, selected_identity, window,
)

ENTRY = 0x1005b38b8
GLOBAL = 0x100e82af8
STACK = 0x700000000
CONTEXT = STACK + 0x40000
EXTERNAL = 0x200000000
COUNTER = 0x100e837c0
TRANSACTION = 0x100e83798
LOCK = 0x100e80730
STUB_TRANSACTION = CONTEXT + 0x3000
CALLS = {
    0x100325284: 'pthread_rwlock_wrlock',
    0x10017f990: 'os_transaction_create',
    0x10012a184: 'os_transaction_needs_more_time',
    0x100323220: 'pthread_rwlock_unlock',
}


def replay(image, fixups, counter, decoded_state):
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm64_const.UC_CPU_ARM64_MAX)
    cpu.mem_map(0x100000000, 0xf00000)
    cpu.mem_map(STACK, 0x80000)
    cpu.mem_map(EXTERNAL + 0xe70000, 0x10000)

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
    put(EXTERNAL + 0xe771b0, CONTEXT + 0x1010)
    assert number(COUNTER, 4) == number(TRANSACTION, 8) == 0
    if counter:
        put(COUNTER, counter, 4)
        put(TRANSACTION, STUB_TRANSACTION)
    residue = ((CONTEXT ^ 0x113ef3f5 ^ 0xc86cc8b9) * 0x58fbd727) & 0xffffffff
    put(CONTEXT + 0x28, (residue + decoded_state) & 0xffffffff, 4)
    put(0x100e7f930, CONTEXT + 0x8000)
    register('x0', CONTEXT)
    register('x1', CONTEXT + 0x200)
    register('sp', STACK + 0x2ff60)
    register('x29', STACK + 0x2fff0)
    return_pc = EXTERNAL + 0x1000
    put(STACK + 0x2fff8, return_pc)

    last_slot = None
    edges = Counter()
    calls = []
    events = []
    visited = set()
    mismatch = None
    watched = {COUNTER, TRANSACTION, GLOBAL, CONTEXT + 0x2c}

    def track_read(_, _access, address, size, _value, _data):
        nonlocal last_slot
        if size == 8 and fixups.get(address, '').startswith('auth-'):
            last_slot = address
        if address in watched:
            events.append(('read', hex(register('pc')), hex(address), size, hex(number(address, size))))

    def track_write(_, _access, address, size, value, _data):
        if address in watched or register('pc') == 0x1005c1ef4:
            events.append(('write', hex(register('pc')), hex(address), size, hex(value)))

    def handle_call(address, row, linked):
        name = CALLS[address]
        assert row.split()[1] == 'libSystem/_' + name
        argument = register('x0')
        calls.append((hex(address), name, hex(argument)))
        if name == 'os_transaction_create':
            assert bytes(cpu.mem_read(argument, 22)) == b'com.apple.daemon.lskd\0'
            register('x0', STUB_TRANSACTION)
        elif name == 'os_transaction_needs_more_time':
            assert argument == STUB_TRANSACTION
        else:
            assert argument == LOCK
            register('x0', 0)
        register('pc', address + 4 if linked else register('x30'))

    def step(_, address, _size, _data):
        nonlocal mismatch
        visited.add(address)
        word = number(address, 4)
        opcode = word & 0xfffffc00
        if opcode not in (0xd71f0800, 0xd73f0800):
            return
        target = register(f'x{(word >> 5) & 31}')
        modifier = register(f'x{word & 31}')
        row = fixups[last_slot]
        assert target == number(last_slot, 8)
        if not row.endswith(f'(div=0x{modifier:04X} ad=0 key=IA)'):
            mismatch = (hex(address), hex(last_slot), hex(modifier), row)
            cpu.emu_stop()
            return
        edges[(address, last_slot)] += 1
        if row.startswith('auth-bind'):
            handle_call(address, row, opcode == 0xd73f0800)
            return
        if opcode == 0xd73f0800:
            register('x30', address + 4)
        register('pc', target)

    cpu.hook_add(UC_HOOK_MEM_READ, track_read)
    cpu.hook_add(UC_HOOK_MEM_WRITE, track_write)
    cpu.hook_add(UC_HOOK_CODE, step)
    cpu.emu_start(ENTRY, return_pc, count=180_000)
    if decoded_state == 0x45a7:
        assert mismatch == (
            '0x10033c534', '0x100e49c80', '0xc309',
            'auth-rebase 0x1008BC5A8 (div=0x02ED ad=0 key=IA)',
        )
        assert [call[1] for call in calls] == ['pthread_rwlock_wrlock']
    else:
        assert mismatch is None and register('pc') == return_pc
        assert len(edges) == 16 and 0x100aff4b0 in visited
        assert not visited.intersection((0x1003e8ff8, 0x100b5c91c, 0x100474e38))
        action = 'os_transaction_needs_more_time' if counter else 'os_transaction_create'
        assert [call[1] for call in calls] == ['pthread_rwlock_wrlock', action, 'pthread_rwlock_unlock']
        assert number(COUNTER, 4) == counter + 1
        assert number(TRANSACTION, 8) == STUB_TRANSACTION
        assert number(CONTEXT + 0x2c, 4) == 0x2edf880f
        assert ('write', '0x1005c1ef4', '0x700019134', 4, '0x45b9') in events
    return dict(initial_counter=counter, decoded_entry_state=hex(decoded_state), calls=calls,
                observed_memory=events, stop_pc=hex(register('pc')), mismatch=mismatch,
                edges=[dict(site=hex(pc), slot=hex(slot), binding=fixups[slot], visits=count)
                       for (pc, slot), count in edges.items()])


def audit(path):
    thin, = [data for _, subtype, data in daemon_slices(path.read_bytes()) if subtype == 0x80000002]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    assert identity['uuid'] == '28d510e5-3b91-3916-97ab-b765a3a7ba21'
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    assert fixups[0x100e771b0] == 'bind CoreFoundation/_kCFAllocatorNull'
    runs = [replay(image, fixups, counter, state)
            for counter, state in ((0, 0x45b9), (1, 0x45b9), (0, 0x45a7))]
    sites = (0x1005b3a98, 0x1005b3c5c, 0x10033c4a8, 0x10033c4dc, 0x10033c534,
             0x10017f994, 0x10012a16c, 0x100137abc, 0x100137ac4,
             0x1005c1ef4, 0x100aff464, 0x100aff4b0)
    return dict(identity=identity, runs=runs, native_ipc_observed=False,
                instructions=[window(image, pc, pc + 4)[0] for pc in sites])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='unmodified fat lskdd executable')
    print(json.dumps(audit(parser.parse_args().image), indent=2))
