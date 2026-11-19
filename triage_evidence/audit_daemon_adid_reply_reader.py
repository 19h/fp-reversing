#!/usr/bin/env python3
"""Replay source-local CoreADI reply consumption using private API return fixtures."""

from hashlib import sha256
import json

from unicorn import arm64_const as ar

from audit_daemon_adid_request_origin import (
    BUFFER, CLIENT, DICT, KEY, MODELS, P, QUEUE, RECORD, Replay, reference,
)
from daemon_receive_tools import CS, FIXUPS, IMAGE, SOURCE, qword, verify_original_fixups
import recover_daemon_environment_outputs as environment

REPLY = P + 0x56000
BORROWED = P + 0x57000
RESPONSE_RECORD = P + 0x59000
RESPONSE_BUFFER = P + 0x5a000
RETURN = environment.RETURN
SYNC = 0x100e21718
GET_TYPE = 0x100e21770
GET_DATA = 0x100e21a08
DISPATCH = 0x1010abb60
COPY_PAIRS = {
    0x100e24c90: (0x250, 0x48, 'x9, [x11, #0x70]'),
    0x100e24c98: (0x240, 0x40, 'x9, [x11, #0x60]'),
    0x100e24ca0: (0x248, 0x38, 'x9, [x11, #0x68]'),
}
COPY_STORES = {pc + 4: (source, target) for pc, (source, target, _) in COPY_PAIRS.items()}
IMPORTS = {address: name for name, address in environment.Base.IMPORTS.items()}


class ReplyReplay(Replay):
    def __init__(self, config, parent, before_send, payload, fail_at=None):
        super().__init__(config, parent)
        self.payload = payload
        self.fail_at = fail_at
        self.before_send = before_send
        self.reply_calls = []
        self.reply_copies = []
        self.released = set()
        self.owners = {RECORD: 24, BUFFER: 4096}
        self.retired_ranges = []
        self.size_gate = None

    def preflight(self, insn):
        if insn.address in COPY_PAIRS:
            _, target, operands = COPY_PAIRS[insn.address]
            assert (insn.mnemonic, insn.op_str) == ('ldr', operands)
            following = next(self.cs.disasm(IMAGE.read(insn.address + 4, 4), insn.address + 4))
            assert (following.mnemonic, following.op_str) == ('str', f'x9, [sp, #{target:#x}]')
            assert self.reg(11) == self.register('sp') + 0x1e0
            return True
        return super().preflight(insn)

    def check_retired(self, address, size):
        assert all(address + size <= start or start + extent <= address
                   for start, extent in self.retired_ranges), (hex(address), size, self.retired_ranges)

    def read(self, u, kind, address, size, value, data):
        self.check_retired(address, size)
        pc = self.register('pc')
        if pc not in COPY_PAIRS:
            return super().read(u, kind, address, size, value, data)
        source, target, _ = COPY_PAIRS[pc]
        frame = self.register('sp')
        assert (address, size) == (frame + source, 8)
        s = self.snapshot(address, size)
        assert s['known_mask_hex'] == '00' * 8
        self.reply_copies.append({'load_pc': hex(pc), 'source_offset': hex(source),
                                  'target_offset': hex(target), 'known_mask_hex': s['known_mask_hex']})
        self.reads.append({'pc': hex(pc), 'source_visit_index': self.seq - 1, **s})

    def write(self, u, kind, address, size, value, data):
        self.check_retired(address, size)
        super().write(u, kind, address, size, value, data)
        pc = self.register('pc')
        if pc in COPY_STORES:
            _, target = COPY_STORES[pc]
            assert (address, size) == (self.register('sp') + target, 8)
            self.known[address - P:address - P + size] = b'\0' * size
            self.writes[-1]['known_mask_hex'] = '00' * size

    def call_result(self, pc, symbol):
        x0, x1, x2 = (self.reg(j) for j in range(3))
        if pc == SYNC:
            assert symbol == '_xpc_connection_send_message_with_reply_sync'
            assert (x0, x1) == (CLIENT, DICT) and self.request is not None
            assert self.request == self.before_send['request']
            assert len(self.visits) == self.before_send['source_visits']
            words = b''.join(int(item['pc'], 16).to_bytes(8, 'little') + bytes.fromhex(item['bytes_hex'])
                             for item in self.visits)
            assert sha256(words).hexdigest() == self.before_send['ordered_source_words_sha256']
            assert [hex(self.reg(j)) for j in range(31)] == self.before_send['boundary']['registers31']
            assert hex(self.register('sp')) == self.before_send['boundary']['SP']
            return (x0, x1), REPLY
        if pc == GET_TYPE:
            assert symbol == '_xpc_get_type' and x0 == REPLY
            return (x0,), self.callee_address('_xpc_type_dictionary')
        if pc == GET_DATA:
            assert symbol == '_xpc_dictionary_get_data' and (x0, x1) == (REPLY, KEY)
            assert x2 == self.register('sp') + 0x1b0
            if self.payload is None:
                return (x0, x1, x2), 0
            self.fixture(BORROWED, self.payload)
            self.fixture(x2, len(self.payload).to_bytes(8, 'little'))
            return (x0, x1, x2), BORROWED
        if pc in (0x100e21aa8, 0x100e21b54):
            assert symbol == '_malloc'
            expected, address = ((24, RESPONSE_RECORD) if pc == 0x100e21aa8 else (4096, RESPONSE_BUFFER))
            assert x0 == expected
            if pc == self.fail_at:
                return (x0,), 0
            assert address not in self.owners
            self.owners[address] = x0
            return (x0,), address
        if symbol == '_free':
            self.retired_ranges.append((x0, self.owners.pop(x0)))
            return (x0,), None
        if symbol == '_xpc_release':
            assert x0 in (QUEUE, CLIENT, DICT, REPLY) and x0 not in self.released
            self.released.add(x0)
            if x0 == REPLY and self.payload:
                self.retired_ranges.append((BORROWED, len(self.payload)))
            return (x0,), None
        return None

    def code(self, u, pc, size, data):
        if pc == 0x100e21c10:
            indices = (self.reg(20), self.reg(20) ^ (self.reg(10) ^ 0x49f))
            self.size_gate = {'extent_bytes': self.reg(9), 'biased_base': self.reg(25),
                              'limit_bytes': self.reg(25) + 0xfc3, 'selected_target': hex(self.reg(12)),
                              'branch_slots': [hex(DISPATCH + index * 8) for index in indices],
                              'branch_targets': [hex(qword(DISPATCH + index * 8)) for index in indices]}
            assert self.size_gate['limit_bytes'] == 4096 and self.reg(9) == len(self.payload)
            assert self.size_gate['branch_targets'] == ['0x100e241c4', '0x100e21c14']
            assert self.size_gate['selected_target'] == '0x100e241c4'
            assert all(FIXUPS[int(slot, 16)]['annotation'] == '(div=0xB51A ad=0 key=IA)'
                       for slot in self.size_gate['branch_slots'])
        if pc not in MODELS:
            raw = bytes(u.mem_read(pc, size))
            insn = next(self.cs.disasm(raw, pc))
            if insn.mnemonic == 'blraa':
                target, selector = insn.op_str.split(', ')
                name = IMPORTS.get(self.register(target))
                if name and (result := self.call_result(pc, name.split('/')[-1])) is not None:
                    self.flush()
                    assert raw == IMAGE.read(pc, size)
                    arguments, result_value = result
                    discriminator = self.register(selector)
                    candidates = (int(row['address'], 16) for row in reversed(self.reads[-16:]))
                    slot = next(address for address in candidates if address in FIXUPS
                                and FIXUPS[address]['target'] == name
                                and f'div=0x{discriminator:04X}' in FIXUPS[address]['annotation'])
                    self.reply_calls.append({'pc': hex(pc), 'api': name, 'arguments': list(map(hex, arguments)),
                                             'slot': hex(slot), 'diversity': hex(discriminator),
                                             'return': None if result_value is None else hex(result_value)})
                    pattern = self.caller_configuration['pattern']
                    for j in range(18):
                        self.set(j, 0x537ffdb9dfca0637 * (j + 1) ^ pattern)
                    u.reg_write(ar.UC_ARM64_REG_NZCV, (pattern & 15) << 28)
                    if result_value is not None:
                        self.set(0, result_value)
                    self.set(30, pc + 4)
                    return u.reg_write(ar.UC_ARM64_REG_PC, pc + 4)
        return super().code(u, pc, size, data)

    def consume(self):
        row = self.run()
        outputs = [self.snapshot(self.C + offset, size) for _, offset, size in environment.OUTPUTS]
        reply_reads = [item for item in row['source_reads']
                       if BORROWED <= int(item['address'], 16) < BORROWED + 4096]
        assert self.prefix_rechecked and self.request is not None
        assert all(output['bytes_hex'] == '00' * output['size_bytes'] for output in outputs)
        assert not reply_reads
        if self.payload is None or self.fail_at is not None:
            assert row['boundary']['pc'] == hex(RETURN)
            assert not self.owners and self.released == {REPLY, QUEUE, DICT, CLIENT}
            assert self.reg(0) == (0xffff5028 if self.payload is None else 0xffff5035)
        else:
            assert row['boundary']['pc'] == '0x100e24cc0'
            assert row['boundary']['kind'] == 'before_unknown_private_read'
            assert row['boundary']['detail']['snapshot']['known_mask_hex'] == '00' * 4
            assert not self.released and len(self.reply_copies) == 3 and len(self.owners) == 4
        return {'configuration': self.caller_configuration, 'boundary': row['boundary'],
                'prefix_rechecked': self.prefix_rechecked, 'request': self.request,
                'payload': None if self.payload is None else self.payload.hex(),
                'modeled_malloc_failure_at': None if self.fail_at is None else hex(self.fail_at),
                'reply_calls': self.reply_calls, 'reply_copies': self.reply_copies,
                'reply_reads': reply_reads, 'outputs': outputs, 'source_visits': len(row['source_visits']),
                'unretired_allocations': {hex(addr): n for addr, n in sorted(self.owners.items())},
                'size_gate': self.size_gate, 'released_objects': sorted(map(hex, self.released))}


def main():
    prior = reference('daemon_environment_outputs_checks')
    parents = [case for case in prior['cases'] if case['configuration']['kind'] == 'caller'
               and case['boundary']['pc'] == '0x100e1ea4c']
    request_cases = reference('daemon_adid_request_origin_audit')['cases']
    available = [case for case in request_cases if case['prefix_rechecked'] and case['request']]
    assert len(available) == len(parents) == 8
    otp, = [row for row in reference('akd_adid_pair_profiles')['pairs'] if row['label'] == 'otp']
    reference_error = bytes.fromhex(otp['source_reply_bytes'])
    assert reference_error.hex() == 'ffff4ffb'
    cases = []
    for parent in parents:
        before_send, = [case for case in available if case['configuration'] == parent['configuration']]
        for packet, fail_at in ((None, None), (reference_error, None),
                                (bytes.fromhex('00000000 00000003 616263 00000004 5758595a'), None),
                                (reference_error, 0x100e21aa8), (reference_error, 0x100e21b54)):
            cases.append(ReplyReplay(parent['configuration'], parent, before_send, packet, fail_at).consume())
    slots = [int(call['slot'], 16) for case in cases for call in case['reply_calls']]
    slots += [int(slot, 16) for case in cases if case['size_gate'] for slot in case['size_gate']['branch_slots']]
    gate_words = [(i.mnemonic, i.op_str) for i in CS.disasm(IMAGE.read(0x100e21be8, 0x2c), 0x100e21be8)]
    assert gate_words[:4] == [('ldr', 'x9, [sp, #0x1b0]'), ('add', 'x12, x25, #0xfc3'),
                              ('cmp', 'x9, x12'), ('cset', 'w12, hi')]
    assert gate_words[-1] == ('braa', 'x12, x17')
    print(json.dumps({'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'cases': cases,
                      'size_gate_original_words': gate_words,
                      'native_api_or_ipc_executed': False, 'reply_field_contract_established': False,
                      'verified_fixups': verify_original_fixups(slots)}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
