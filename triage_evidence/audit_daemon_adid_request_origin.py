#!/usr/bin/env python3
"""Replay the source-local request producer without calling any native API."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from unicorn import arm64_const as ar
import z3

from audit_daemon_iokit_native_registry import daemon_slices
from audit_live_fairplay_adid_ipc import ARM64E, PROVIDER_SHA, ThinView, reference
from daemon_receive_tools import IMAGE, SOURCE
from lskd_values_symbolic import Lift, resize
import recover_daemon_environment_outputs as environment

P = environment.Base.P
RECORD = P + 0x30000
BUFFER = P + 0x40000
DICT = P + 0x50000
QUEUE = P + 0x52000
CLIENT = P + 0x54000
KEY = 0x101032f80
SERVICE = 0x101033900
COMMAND = 0xcfe0b46a
HEADER = struct.pack('>III', 1, COMMAND, 1)
TAG = 0x7dd5cf10709e5799
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1

MODELS = {
    0x100e1ea4c: ('malloc', 0x57e4, (24,), RECORD),
    0x100e1eb04: ('malloc', 0x57e4, (4096,), BUFFER),
    0x100e21370: ('xpc_dictionary_create_empty', 0x89e0, (), DICT),
    0x100e21448: ('xpc_dictionary_set_data', 0x70e2, (DICT, KEY, BUFFER, 20), None),
    0x100e214ac: ('dispatch_queue_create', 0x6463, (SERVICE, 0), QUEUE),
    0x100e21578: ('xpc_connection_create_mach_service', 0x7d61, (SERVICE, QUEUE, 0), CLIENT),
    0x100e21678: ('xpc_connection_set_event_handler', 0x7d61, (CLIENT, 0x1010abb40), None),
    0x100e216c8: ('xpc_connection_activate', 0x89e0, (CLIENT,), None),
}
EXPECTED_WRITES = (
    0x100e208ac, 0x100e208c4, 0x100e208d8, 0x100e208bc,
    0x100e20b84, 0x100e20b94, 0x100e20bc8, 0x100e20bd4,
    0x100e20e60, 0x100e20e78, 0x100e20e84, 0x100e20e90,
    0x100e211d4, 0x100e211e8, 0x100e211fc, 0x100e2120c,
    0x100e2121c, 0x100e2122c, 0x100e2123c, 0x100e21248,
)


class Replay(environment.Run):
    def __init__(self, config, parent=None, failure=None):
        super().__init__(config)
        self.caller_configuration = config
        self.parent = parent
        self.failure = failure
        self.modeled_calls = []
        self.cuts = {}
        self.request = None
        self.prefix_rechecked = False

    def check_parent(self, pc):
        if self.parent is None:
            return
        parent = self.parent
        assert parent['boundary']['pc'] == hex(pc)
        assert parent['boundary']['registers31'] == [hex(self.reg(j)) for j in range(31)]
        assert parent['boundary']['SP'] == hex(self.register('sp'))
        assert parent['boundary_NZCV'] == hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
        for current, field in ((self.visits, 'source_visits'), (self.reads, 'source_reads'),
                               (self.writes, 'source_writes'), (self.frames, 'source_frames'),
                               (self.edges, 'logical_edges'), (self.unknown_copies, 'unknown_copy_effects')):
            assert current == parent[field], field
        self.prefix_rechecked = True

    def check_request(self):
        frame = self.register('sp')
        address, = struct.unpack('<Q', self.u.mem_read(frame + 0x1c0, 8))
        assert address == (RECORD + TAG) & MASK64
        assert (address + 0x822a30ef8f61a867) & MASK64 == RECORD
        assert (address + 0x822a30ef8f61a873) & MASK64 == RECORD + 12
        source = self.snapshot(RECORD, 24)
        pointer, capacity, used, state = struct.unpack('<QIII', bytes.fromhex(source['bytes_hex'])[:20])
        assert (source['known_mask_hex'], pointer, state) == ('01' * 20 + '00' * 4, BUFFER, 0)
        assert (capacity - 0x1d6d1efe) & MASK32 == 4096
        assert (used + 0x9aa4ac59) & MASK32 == 20
        hits = [row for row in self.writes if BUFFER <= int(row['address'], 16) < BUFFER + 4096]
        writes = sorted(hits, key=lambda row: int(row['address'], 16))
        assert [int(row['pc'], 16) for row in writes] == list(EXPECTED_WRITES)
        assert all(int(row['address'], 16) == BUFFER + offset and row['size_bytes'] == 1
                   for offset, row in enumerate(writes))
        raw = self.snapshot(BUFFER, 20)
        argument = self.caller_configuration['argument64']
        assert raw['known_mask_hex'] == '01' * 20
        assert bytes.fromhex(raw['bytes_hex']) == HEADER + struct.pack('>Q', argument)
        assert ''.join(row['after_hex'] for row in writes) == raw['bytes_hex']
        length_stores = [row for row in self.writes if row['address'] == hex(RECORD + 12)]
        lengths = [(int.from_bytes(bytes.fromhex(row['after_hex']), 'little') + 0x9aa4ac59) & MASK32
                   for row in length_stores]
        assert lengths == [0, 4, 8, 12, 20]
        self.request = {'buffer': raw, 'record_fields_bytes': source['bytes_hex'][:40],
                        'record_known_mask': source['known_mask_hex'],
                        'private_frame_encoded_record': hex(address),
                        'encoded_length_writes': length_stores, 'decoded_lengths_bytes': lengths,
                        'buffer_byte_writes': writes}

    def code(self, u, pc, size, data):
        if pc in (0x100e21180, 0x100e21294):
            self.cuts[hex(pc)] = {f'x{j}': hex(self.reg(j)) for j in (8, 10, 11, 19, 20)}
        if pc not in MODELS:
            return super().code(u, pc, size, data)
        self.flush()
        if pc == 0x100e1ea4c:
            self.check_parent(pc)
        api, modifier, expected, default = MODELS[pc]
        assert bytes(u.mem_read(pc, size)) == IMAGE.read(pc, size)
        insn = next(self.cs.disasm(IMAGE.read(pc, size), pc))
        assert insn.mnemonic == 'blraa'
        target, discriminator = insn.op_str.split(', ')
        assert self.register(target) == self.callee_address(api)
        assert self.register(discriminator) == modifier
        args = tuple(self.reg(j) for j in range(len(expected)))
        assert args == expected, (hex(pc), args, expected)
        if pc == 0x100e21448:
            self.check_request()
        result = 0 if pc == self.failure else default
        self.modeled_calls.append({'pc': hex(pc), 'api': api, 'args': list(map(hex, args)),
                                   'return': None if result is None else hex(result)})
        clobber = self.caller_configuration['pattern']
        for j in range(18):
            self.set(j, (0x9f71ac52f30dbcee * (j + 1)) ^ clobber)
        u.reg_write(ar.UC_ARM64_REG_NZCV, (clobber & 15) << 28)
        if result is not None:
            self.set(0, result)
        self.set(30, pc + 4)
        u.reg_write(ar.UC_ARM64_REG_PC, pc + 4)

    @staticmethod
    def callee_address(api):
        return environment.Base.IMPORTS['libSystem/_' + api]

    def capture(self):
        row = self.run()
        pc = int(row['boundary']['pc'], 16)
        if self.failure == 0x100e1ea4c:
            assert pc == environment.RETURN and self.reg(0) == 0xffff5035
            assert len(self.modeled_calls) == 1 and self.request is None
        elif self.failure == 0x100e1eb04:
            assert pc == 0x100e2507c and self.reg(0) == RECORD
            assert row['boundary']['detail']['symbol'] == 'libSystem/_free'
            assert len(self.modeled_calls) == 2 and self.request is None
        else:
            assert pc == 0x100e21718 and self.reg(0) == CLIENT and self.reg(1) == DICT
            assert row['boundary']['detail']['symbol'] == 'libSystem/_xpc_connection_send_message_with_reply_sync'
            assert self.request is not None and len(self.modeled_calls) == len(MODELS)
            assert self.cuts['0x100e21294']['x8'] == '0x0'
            registers = self.cuts['0x100e21180']
            assert [registers[f'x{j}'] for j in (8, 10, 11, 20)] == [
                '0x18', hex(BUFFER), '0xeff747673edb3fc1', '0x21ef6621']
        if self.failure is not None:
            for arg, offset, size in environment.OUTPUTS:
                assert self.snapshot(self.C + offset, size)['bytes_hex'] == '00' * size, arg
        words = b''.join(int(item['pc'], 16).to_bytes(8, 'little') + bytes.fromhex(item['bytes_hex'])
                         for item in row['source_visits'])
        return {'configuration': self.caller_configuration, 'prefix_rechecked': self.prefix_rechecked,
                'modeled_calls': self.modeled_calls, 'request': self.request, 'boundary': row['boundary'],
                'source_visits': len(row['source_visits']), 'ordered_source_words_sha256': sha256(words).hexdigest(),
                'cuts': self.cuts}


def proof():
    start, end = 0x100e21180, 0x100e2124c
    frame = P + 0x60000 - 0x4a0
    argument = z3.BitVec('argument', 64)
    code = IMAGE.read(start, end - start)
    lift = Lift({'spans': [{'label': 'writer', 'start': hex(start), 'bytes_hex': code.hex()}]})
    for name, value in (('sp', frame), ('x8', 0x18), ('x10', BUFFER),
                        ('x11', 0xeff747673edb3fc1), ('x20', 0x21ef6621)):
        lift.seed(name, value)
    lift.memory[(resize(frame + 0x138, 64).sexpr(), 8)] = argument
    lift.run('writer')
    assert [store['address'].as_long() for store in lift.stores] == list(range(BUFFER + 12, BUFFER + 20))
    assert all(store['size_bytes'] == 1 for store in lift.stores)
    actual = z3.Concat(*(store['value'] for store in lift.stores))
    solver = z3.Solver()
    solver.set(timeout=30000)
    assert solver.check() == z3.sat
    solver.push()
    solver.add(actual != argument)
    assert solver.check() == z3.unsat
    solver.pop()
    reversed_arg = z3.Concat(*(z3.Extract(offset + 7, offset, argument) for offset in range(0, 64, 8)))
    solver.add(actual != reversed_arg, argument == 0x1122334455667788)
    assert solver.check() == z3.sat
    endian_witness = solver.model().eval(argument).as_long()
    return {'width_bits': 64, 'value_result': 'unsat', 'inverse_endian_control': 'sat',
            'inverse_endian_witness': hex(endian_witness), 'original_instructions': lift.count,
            'original_bytes': code.hex(), 'start': hex(start), 'end': hex(end)}


def provider_command(path):
    fat_image = path.read_bytes()
    blob, = [b for cpu, sub, b in daemon_slices(fat_image) if (cpu, sub) == ARM64E]
    assert sha256(blob).hexdigest() == PROVIDER_SHA
    provider = ThinView(blob)
    report = reference('adid_command_dispatch_contracts')
    tree = report['command_tree']
    code, = [item for item in report['original_windows'] if item['start'] == tree['entry']]
    expected_bytes = bytes.fromhex(code['bytes'])
    assert provider.read(int(code['start'], 16), len(expected_bytes)) == expected_bytes
    chosen, = [row for row in tree['accepted'] if row['wire_command_u32'] == COMMAND]
    assert (COMMAND + 0x46d726) & MASK32 == chosen['encoded_command_u32']
    assert chosen['parser_entry'] == '0x10016dab8'
    akd = reference('akd_adid_pair_profiles')
    named_operation, = [row for row in akd['pairs'] if row['label'] == 'otp']
    request = bytes.fromhex(named_operation['source_request_bytes'])
    assert len(request) == 20 and request[:12] == HEADER
    return {'provider_code_bytes_rechecked': len(expected_bytes), 'provider_code_sha256': sha256(expected_bytes).hexdigest(),
            'provider_code_start': code['start'], 'installed_adid_arm64e_sha256': PROVIDER_SHA,
            'dispatch_path': chosen, 'akd_otp_request_bytes': request.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('adid', type=Path)
    args = parser.parse_args()
    prior = reference('daemon_environment_outputs_checks')
    parents = [case for case in prior['cases'] if case['configuration']['kind'] == 'caller'
               and case['boundary']['pc'] == '0x100e1ea4c']
    assert len(parents) == 8
    cases = [Replay(case['configuration'], parent=case).capture() for case in parents]
    for parent in (parents[0], parents[-1]):
        for failure in (0x100e1ea4c, 0x100e1eb04):
            cases.append(Replay(parent['configuration'], parent=parent, failure=failure).capture())
        for argument in (0, 1, MASK64, 0x1122334455667788):
            config = {**parent['configuration'], 'kind': 'direct', 'argument64': argument}
            cases.append(Replay(config).capture())
    case_packet = cases[0]['request']['buffer']['bytes_hex']
    assert case_packet == '00000001cfe0b46a00000001fffffffffffffffe'
    peer = provider_command(args.adid)
    akd = [case for case in cases if case['configuration']['argument64'] == 0x1122334455667788]
    assert len(akd) == 2
    assert all(case['request']['buffer']['bytes_hex'] == peer['akd_otp_request_bytes'] for case in akd)
    result = {'fairplayd_thin_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
              'provider_and_akd': peer, 'cases': cases, 'serializer_proof': proof(),
              'native_api_or_ipc_executed': False, 'native_daemon_kext_pairing_established': False}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
