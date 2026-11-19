#!/usr/bin/env python3
"""Audit the primary adid selector 26 continuation using retained private cases."""

import json
import struct
from unittest.mock import patch

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ

import adid_reader
from probe_adid_iokit_callers import Callers

ROOT = adid_reader.ROOT
CURRENT_FAT_SHA = '9c872e64548288f7d1a9db5e2dbd97311e30b4df5745f52936ae277c80a4abe1'
CURRENT_THIN_SHA = 'b9e0043fbbc4525ad1a78545155c6c096422688de2ce3a3fc0144ab6adab9895'
CALL, RETURN = 0x10001f908, 0x10001f90c
HELPER_STORE, HELPER_RETURN = 0x10001fa84, 0x10001fa9c
CALLER_STORE = 0x100059820
MASK = 0xffffffff


class ReplyTrace(Callers):
    def __init__(self, image, fixture, checkpoint):
        super().__init__(image, fixture, checkpoint)
        self.copy_offsets = {'load': [], 'store': []}
        self.fields = []
        self.status_accesses = []
        self.phase = None
        self.in_reply = False

    def watch_status(self, address, label):
        self.u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.status_access,
                        label, begin=address, end=address + 3)

    def status_access(self, u, access, address, size, value, label):
        pc = self.reg('pc')
        if access == UC_MEM_READ:
            value = int.from_bytes(u.mem_read(address, size), 'little')
        self.status_accesses.append({
            'pc': hex(pc), 'cell': label, 'operation': 'load' if access == UC_MEM_READ else 'store',
            'width_bytes': size, 'value': hex(value & (2 ** (8 * size) - 1)),
        })

    def watch_fields(self, address):
        self.u.hook_add(UC_HOOK_MEM_READ, self.field_read, address, begin=address, end=address + 23)

    def field_read(self, u, access, address, size, value, base):
        pc = self.reg('pc')
        if self.in_reply:
            self.fields.append([hex(pc), address - base, size])

    def code(self, u, pc, n, data):
        if pc == 0x100059544:
            self.watch_status(self.reg('x0') + 4, 'parent_result')
        if pc == CALL:
            self.phase = self.reg('w22')
            self.payload = self.reg('x20')
            self.watch_status(self.reg('x19') + 4, 'local_result')
            self.watch_fields(self.reg('sp'))
        if pc == RETURN:
            self.in_reply = True
            self.api_status = self.reg('w0')
            self.return_fields = struct.unpack('<QQII', u.mem_read(self.reg('sp'), 24))
        if pc == 0x10001fa48:
            self.copy_offsets['load'].append(self.reg('x11') - self.payload)
        if pc == 0x10001fa50:
            self.copy_offsets['store'].append(self.reg('x9') - self.payload)
        if pc == HELPER_STORE:
            self.local_status = self.reg('w12')
        if pc == HELPER_RETURN:
            self.in_reply = False
        if pc == CALLER_STORE:
            self.caller_status = self.reg('w25')
        return super().code(u, pc, n, data)


def profile(image, frozen, checkpoint, expected_parent, expected_caller):
    trace = ReplyTrace(image, frozen['fixture'], checkpoint)
    result = trace.run_continuation()
    assert result['stop_reason'] == frozen['stop_reason'] == 'returned_to_private_fixture'
    assert result['ordered_original_instruction_sha256'] == frozen['ordered_original_instruction_sha256']
    assert trace.phase == 0x10d0
    assert trace.return_fields == (16, trace.payload, 96, 0)
    assert trace.fields == [['0x10001f90c', 0, 8], ['0x10001f950', 16, 4], ['0x10001f9b4', 8, 8]]
    assert trace.copy_offsets['load'] == trace.copy_offsets['store'] == list(range(95, -1, -1))
    constant = 0xfddffdaf
    assert (trace.phase + 0x1279) ^ 0xfbbfd817 == (constant << 1) & MASK
    assert (constant + 0x027926e0) & MASK == 0x0059248f
    assert trace.local_status == (trace.api_status + 0x0059248f) & MASK
    for pc, operation, value in (
        (HELPER_STORE, 'store', trace.local_status),
        (0x10004c120, 'load', trace.local_status),
        (0x10002193c, 'store', expected_parent),
        (0x100059558, 'load', expected_parent),
    ):
        label = 'local_result' if pc in (HELPER_STORE, 0x10004c120) else 'parent_result'
        assert trace.status_accesses.count({
            'pc': hex(pc), 'cell': label, 'operation': operation,
            'width_bytes': 4, 'value': hex(value),
        }) == 1
    assert trace.caller_status == expected_caller
    return {
        'api_status': hex(trace.api_status), 'phase': hex(trace.phase),
        'local_status': hex(trace.local_status), 'outer_status': hex(trace.caller_status),
        'field_loads': trace.fields, 'payload_copy_offsets': trace.copy_offsets,
        'status_accesses': trace.status_accesses,
        'matched_ordered_pc_and_word_digest': result['ordered_original_instruction_sha256'],
        'original_instruction_count': result['visited_original_instruction_count'],
    }


def audit():
    with patch.multiple(adid_reader, SOURCE_SHA=CURRENT_FAT_SHA, THIN_SHA=CURRENT_THIN_SHA):
        image = adid_reader.Adid()
    source = json.loads((ROOT / 'adid_iokit_caller_profiles.json').read_text())
    checkpoint = json.loads((ROOT / 'adid_peer_checkpoint.json').read_text())
    runs = {}
    for name, parent, caller in (
        ('primary_identity', 0x0059248f, 0x00587c85),
        ('primary_error', 0x00587c93, 0x00587c93),
    ):
        frozen, = [row for row in source['profiles'] if row['fixture']['label'] == name]
        runs[name] = profile(image, frozen, checkpoint, parent, caller)
    return {'adid_thin_sha256': CURRENT_THIN_SHA, 'profiles': runs, 'native_exchange_observed': False}


if __name__ == '__main__':
    print(json.dumps(audit(), indent=2))
