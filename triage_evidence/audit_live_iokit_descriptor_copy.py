#!/usr/bin/env python3
"""Audit the installed IOMemoryDescriptor copy loop with offline segment fixtures."""

import argparse
import json
from pathlib import Path

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, Uc, arm64_const
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
)

from audit_daemon_selector26_request_bytes import archive, sha
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import descriptor_slots, words

COPY = 0xfffffe000bec4274
SEGMENT_SLOT = 0x158
SEGMENT_CALLS = {'write': 0xfffffe000c5809f0, 'read': 0xfffffe000c580c04}
COPY_CALLS = {'write': 0xfffffe000c5809ac, 'read': 0xfffffe000c580bc0}
COPY_OPTIONS = {'write': 0x75, 'read': 0x66}
BOUNDS = {'write': (0xfffffe000c5808d8, 0xfffffe000c580b0c),
          'read': (0xfffffe000c580b0c, 0xfffffe000c580cb4)}
CODE, DESCRIPTOR, VTABLE, BUFFER, PHYSICAL, STACK = (
    0x100000, 0x200000, 0x210000, 0x300000, 0x400000, 0x500000
)
STOP = CODE + 0x800
REGISTERS = tuple(getattr(arm64_const, f'UC_ARM64_REG_X{index}') for index in range(29)) + (
    UC_ARM64_REG_X29, UC_ARM64_REG_X30,
)
REGION_SIZE = 0x1000


def source_bindings(image):
    prior, digest = archive('live_kext_selector26_transfer_audit')
    assert digest == '19568bd216d51e18fc15710d6a61e1d496df9493ea99706dba8cda2398d84e79'
    previous = prior['current']
    nominal = previous['nominal_dispatch']['IOGeneralMemoryDescriptor']
    slots = descriptor_slots(image, 'IOGeneralMemoryDescriptor',
                             {0x208: 'readBytes', 0x210: 'writeBytes', SEGMENT_SLOT: 'getPhysicalSegment'})
    assert all(nominal[key] == slots[key] for key in ('0x208', '0x210'))
    segment = slots[hex(SEGMENT_SLOT)]
    assert segment['fixup']['auth'] == segment['fixup']['address_diversity'] == 1
    assert segment['fixup']['diversity'] == '0x649a'
    assert int(slots['0x208']['address'], 16) == BOUNDS['read'][0]
    assert int(slots['0x210']['address'], 16) == BOUNDS['write'][0]
    for mode in BOUNDS:
        assert image.branch(COPY_CALLS[mode], 'bl') == COPY
        image.instruction(SEGMENT_CALLS[mode], 'blraa', 'x8, x16')
    for pc, mnemonic, operands in (
        (0xfffffe000c5808dc, 'ldr', 'x8, [x0, #0x50]'),
        (0xfffffe000c58091c, 'adds', 'x9, x3, x1'),
        (0xfffffe000c580930, 'and', 'w10, w9, #0x78000'),
        (0xfffffe000c580934, 'and', 'w10, w10, #0xfffcffff'),
        (0xfffffe000c58098c, 'mov', 'w27, #-0x3fff'),
        (0xfffffe000c580990, 'mov', 'w28, #-0x4000'),
        (0xfffffe000c5809e8, 'mov', 'w3, #0x800'),
        (0xfffffe000c5809f4, 'cbz', 'x0, #0xfffffe000c580a38'),
        (0xfffffe000c580acc, 'sub', 'x0, x21, x23'),
        (0xfffffe000c580b10, 'ldr', 'x8, [x0, #0x50]'),
        (0xfffffe000c580b4c, 'adds', 'x9, x3, x1'),
        (0xfffffe000c580b68, 'tbnz', 'w9, #0x12, #0xfffffe000c580c30'),
        (0xfffffe000c580ba4, 'mov', 'w26, #-0x3fff'),
        (0xfffffe000c580ba8, 'mov', 'w27, #-0x4000'),
        (0xfffffe000c580bfc, 'mov', 'w3, #0x800'),
        (0xfffffe000c580c08, 'cbz', 'x0, #0xfffffe000c580c5c'),
        (0xfffffe000c580ca4, 'sub', 'x0, x22, x24'),
    ):
        image.instruction(pc, mnemonic, operands)
    provider = {}
    for mode, call, end in (('read', 0xfffffe000a54647c, 0xfffffe000a546490),
                            ('write', 0xfffffe000a5464d4, 0xfffffe000a546514)):
        start = call - 0x10
        window = words(image, start, end - start)
        assert window == [row for row in previous['provider'] if start <= int(row['pc'], 16) < end]
        provider[mode] = window
    image.instruction(0xfffffe000a546480, 'mov', 'x0, x24')
    image.instruction(0xfffffe000a546500, 'mov', 'x0, x23')
    return slots, provider


class CopyReplay:
    def __init__(self, image, mode, count, segments, copy_result, segment_target):
        start, end = BOUNDS[mode]
        self.mode, self.count = mode, count
        self.segments, self.copy_result = segments, copy_result
        self.segment_target = segment_target
        self.start = start
        self.instructions = {row['pc']: row for row in words(image, start, end - start)}
        self.calls = []
        self.visits = []
        self.copied = 0
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for base in (CODE, DESCRIPTOR, VTABLE, BUFFER, STACK):
            self.u.mem_map(base, REGION_SIZE)
        self.u.mem_map(PHYSICAL, 0x9000)
        self.u.mem_write(CODE, image.read(start, end - start))
        self.write64(DESCRIPTOR, VTABLE)
        self.write64(DESCRIPTOR + 0x50, count)
        self.write64(VTABLE + SEGMENT_SLOT, segment_target)
        for reg, value in zip(REGISTERS, (DESCRIPTOR, 0, BUFFER, count)):
            self.u.reg_write(reg, value)
        for index in range(19, 30):
            self.u.reg_write(REGISTERS[index], 0xf000 + index)
        self.sp = STACK + REGION_SIZE
        self.u.reg_write(UC_ARM64_REG_SP, self.sp)
        self.u.reg_write(UC_ARM64_REG_X30, STOP)
        self.data = bytes((17 + 31 * index) & 0xff for index in range(count))
        self.initial = bytes([0xa5]) * count
        self.u.mem_write(BUFFER, self.data if mode == 'write' else self.initial)
        offset = 0
        for physical, size in segments.values():
            data = self.data if mode == 'read' else self.initial
            self.u.mem_write(physical, data[offset:offset+size])
            offset += size

    def write64(self, address, value):
        self.u.mem_write(address, value.to_bytes(8, 'little'))

    def hook(self, machine, address, size, _):
        pc = self.start + address - CODE
        row = self.instructions[hex(pc)]
        self.visits.append(hex(pc))
        assert size == 4
        mnemonic = row['mnemonic']
        if mnemonic in ('pacibsp', 'autibsp', 'autda'):
            machine.reg_write(UC_ARM64_REG_PC, address + 4)
            return
        if mnemonic not in ('bl', 'blraa'):
            return

        x0, x1, x2, x3 = (machine.reg_read(reg) for reg in REGISTERS[:4])
        if pc == SEGMENT_CALLS[self.mode]:
            assert mnemonic == 'blraa'
            assert (x0, x1, x2, x3) == (DESCRIPTOR, self.copied, machine.reg_read(UC_ARM64_REG_SP)+8, 0x800)
            assert machine.reg_read(REGISTERS[8]) == self.segment_target
            assert machine.reg_read(REGISTERS[16]) == (0x649a << 48) | (VTABLE + SEGMENT_SLOT)
            assert int.from_bytes(machine.mem_read(x2, 8), 'little') == 0
            physical, size = self.segments.get(x1, (0, 0))
            self.write64(x2, size)
            result = physical
            self.calls.append(dict(pc=hex(pc), kind='segment_lookup', offset_bytes=x1, options=hex(x3),
                                   physical=hex(physical), length_bytes=size))
        else:
            assert pc == COPY_CALLS[self.mode] and mnemonic == 'bl'
            physical, available = self.segments[self.copied]
            buffer = BUFFER + self.copied
            assert x2 == min(available, self.count - self.copied)
            assert (x0, x1) == ((buffer, physical) if self.mode == 'write' else (physical, buffer))
            assert x3 == COPY_OPTIONS[self.mode]
            machine.mem_write(x1, bytes(machine.mem_read(x0, x2)))
            self.calls.append(dict(pc=hex(pc), kind='copy', source=hex(x0), destination=hex(x1),
                                   length_bytes=x2, options=hex(x3), result_fixture=self.copy_result))
            self.copied += x2
            result = self.copy_result

        for index, reg in enumerate(REGISTERS[:18]):
            machine.reg_write(reg, 0xc000 + index)
        machine.reg_write(REGISTERS[0], result)
        machine.reg_write(UC_ARM64_REG_X30, address + 4)
        machine.reg_write(UC_ARM64_REG_PC, address + 4)

    def run(self):
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.u.emu_start(CODE, STOP, count=1000)
        assert self.u.reg_read(UC_ARM64_REG_PC) == STOP
        assert self.u.reg_read(UC_ARM64_REG_SP) == self.sp
        assert [self.u.reg_read(reg) for reg in REGISTERS[19:30]] == list(range(0xf013, 0xf01e))
        result = self.u.reg_read(REGISTERS[0])
        assert result == self.copied == sum(size for _, size in self.segments.values())
        if self.mode == 'read':
            assert bytes(self.u.mem_read(BUFFER, self.count)) == self.data[:result] + self.initial[result:]
        else:
            for offset, (physical, size) in self.segments.items():
                assert bytes(self.u.mem_read(physical, size)) == self.data[offset:offset+size]
        assert len(self.calls) == 2 * len(self.segments) + (result < self.count)
        return dict(mode=self.mode, requested_bytes=self.count, returned_bytes=result,
                    modeled_bytes_sha256=sha(self.data[:result]), copy_result_fixture=self.copy_result,
                    calls=self.calls, instruction_visits=self.visits)


def audit(image):
    bindings, provider = source_bindings(image)
    segment_target = int(bindings[hex(SEGMENT_SLOT)]['fixup']['target'], 16)
    cases = []
    for mode in ('read', 'write'):
        for count in (272, 288):
            first, second = PHYSICAL + 0x3ff0, PHYSICAL + 0x8000
            plans = {
                'one_segment': {0: (PHYSICAL, count)},
                'two_segments': {0: (first, 16), 16: (second, count-16)},
                'first_lookup_missing': {},
                'second_lookup_missing': {0: (first, 16)},
            }
            for plan, segments in plans.items():
                for copy_result in (0, 5) if segments else (0,):
                    replay = CopyReplay(image, mode, count, segments, copy_result, segment_target)
                    cases.append(dict(segment_plan=plan, **replay.run()))
    assert len(cases) == 28
    return dict(collection_identity=IDENTITIES[1], bindings=bindings, cases=cases,
                descriptor_bodies={mode: words(image, start, end - start) for mode, (start, end) in BOUNDS.items()},
                provider_windows=provider, lower_copy_prefix=words(image, COPY, 0x6c), native_transfer_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(audit(image), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
