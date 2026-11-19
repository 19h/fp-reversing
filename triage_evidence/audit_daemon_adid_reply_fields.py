#!/usr/bin/env python3
"""Recover the normal CoreADI reply copy and field reads from retained source state."""

from collections import defaultdict
from hashlib import sha256
import json
import re
import subprocess

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64_const import ARM64_OP_MEM

from audit_daemon_adid_reply_reader import (
    BORROWED, P, REPLY, RESPONSE_BUFFER, RESPONSE_RECORD, ReplyReplay, environment, reference,
)
from audit_daemon_adid_request_origin import BUFFER, CLIENT, DICT, QUEUE, RECORD
from daemon_receive_tools import IMAGE, SOURCE, verify_original_fixups

RESTORE = 0x100e24cc0
NOTIFY = 0x100e1fe88
FRAME_BYTES = 0x4a0
OPAQUE = {0x168: 8, 0x210: 8, 0x21c: 4, 0x220: 8, 0x22c: 4, 0x230: 8,
          0x358: 8, 0x360: 8}
ALLOCATIONS = {0x100e24bb0: (3, P + 0x70000), 0x100e1fc98: (4, P + 0x71000)}
ERROR = bytes.fromhex('ffff4ffb')
MARKERS = bytes.fromhex('00000000 00000003 616263 00000004 5758595a')
STATUS_READS = (0x100e246dc, 0x100e246e4, 0x100e246f4, 0x100e24700)
SPAN_A_READS = (0x100e2481c, 0x100e2482c, 0x100e24838, 0x100e24840)
SPAN_B_READS = (0x100e24a44, 0x100e24a50, 0x100e24a64, 0x100e24a6c)
RELEASES = (QUEUE, CLIENT, DICT, REPLY)

CS = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
CS.detail = True


class FieldReplay(ReplyReplay):
    def __init__(self, parent, before_send, payload, pattern):
        super().__init__(parent['configuration'], parent, before_send, payload)
        self.residue_pattern = pattern
        self.cut = None
        self.import_at = {}

    def code(self, u, pc, size, data):
        if pc == RESTORE and self.cut is None:
            frame = self.register('sp')
            before = self.snapshot(frame, FRAME_BYTES)
            self.cut = (self.seq, frame, before)
            mask = bytes.fromhex(before['known_mask_hex'])
            for offset, width in OPAQUE.items():
                assert not any(mask[offset:offset + width])
                raw = bytes((self.residue_pattern + offset + i * 29) & 255 for i in range(width))
                self.fixture(frame + offset, raw)
        previous = len(self.reply_calls)
        index = self.seq
        result = super().code(u, pc, size, data)
        if len(self.reply_calls) != previous and self.cut is not None:
            assert index not in self.import_at
            self.import_at[index] = self.reply_calls[-1]
        return result

    def call_result(self, pc, symbol):
        if pc in ALLOCATIONS:
            extent, address = ALLOCATIONS[pc]
            assert self.payload == MARKERS and symbol == '_malloc'
            assert self.reg(0) == extent and address not in self.owners
            self.owners[address] = extent
            return (extent,), address
        return super().call_result(pc, symbol)


def normal(register):
    if register == 'lr':
        return 'x30'
    if register == 'fp':
        return 'x29'
    return 'x' + register[1:] if re.fullmatch(r'w\d+', register) else register


def decode(pc, raw=None):
    return next(CS.disasm(IMAGE.read(pc, 4) if raw is None else raw, pc))


def register_access(insn):
    reads, writes = ({normal(insn.reg_name(reg)) for reg in group} for group in insn.regs_access())
    if insn.mnemonic in ('braa', 'blraa'):
        reads.update(map(normal, insn.op_str.split(', ')))
    if insn.mnemonic in ('ret', 'retab', 'retaa'):
        reads.add('x30')
    return reads, writes


def opaque_dependency_check(probe):
    # Follow all frame bytes over this particular straight-line/dispatch trace.
    # A tainted source is accepted only as data in a local load/store transfer.
    start, frame, cut = probe.cut
    obscure = {frame + i for i, defined in enumerate(bytes.fromhex(cut['known_mask_hex'])) if not defined}
    registers = set()
    locations = defaultdict(set)
    reads_at, writes_at = defaultdict(list), defaultdict(list)
    for row in probe.reads:
        reads_at[row['source_visit_index']].append(row)
    for row in probe.writes:
        writes_at[row['source_visit_index']].append(row)

    def interval(row):
        address = int(row['address'], 16)
        return set(range(address, address + row['size_bytes']))

    for index, step in enumerate(probe.visits[start:], start):
        if index in probe.import_at:
            previous_call = probe.import_at[index]
            uses, _ = register_access(decode(int(previous_call['pc'], 16)))
            uses.update(f'x{i}' for i in range(len(previous_call['arguments'])))
            assert not registers & uses, previous_call
            registers.difference_update({f'x{i}' for i in range(18)} | {'x30', 'nzcv'})

        insn = decode(int(step['pc'], 16), bytes.fromhex(step['bytes_hex']))
        used, changed = register_access(insn)
        tainted = used & registers
        inputs = reads_at[index]
        outputs = writes_at[index]
        load_taint = any(interval(row) & obscure for row in inputs)
        if load_taint:
            assert not tainted and insn.mnemonic in ('ldr', 'ldp'), insn
            assert all(frame <= min(interval(row)) <= max(interval(row)) < frame + FRAME_BYTES
                       for row in inputs)
            locations['opaque_loads'].add(step['pc'])
        if tainted:
            assert insn.mnemonic in ('str', 'stp') and not inputs and outputs, (
                step['pc'], insn.mnemonic, insn.op_str, sorted(tainted))
            address_registers = {normal(insn.reg_name(reg)) for operand in insn.operands
                                 if operand.type == ARM64_OP_MEM for reg in (operand.mem.base, operand.mem.index) if reg}
            assert not registers & address_registers
            assert all(frame <= min(interval(row)) <= max(interval(row)) < frame + FRAME_BYTES
                       for row in outputs)
            locations['opaque_stores'].add(step['pc'])
        for row in outputs:
            covered = interval(row)
            if tainted:
                obscure.update(covered)
            else:
                obscure.difference_update(covered)
        registers.difference_update(changed)
        if load_taint:
            registers.update(changed)
    for pending, count in ((environment.RETURN, 1), (NOTIFY, 2)):
        if int(probe.boundary['pc'], 16) == pending:
            uses = {f'x{i}' for i in range(count)}
            if pending == NOTIFY:
                uses.update(register_access(decode(pending))[0])
            assert not registers & uses
    return {label: sorted(pcs) for label, pcs in locations.items()}


def record_fields(probe, payload):
    def group(rows, address, extent):
        return [row for row in rows if address <= int(row['address'], 16) < address + extent]

    def offsets(rows, base):
        return [int(row['address'], 16) - base for row in rows]

    read = group(probe.reads, BORROWED, 4096)
    written = group(probe.writes, RESPONSE_BUFFER, 4096)
    assert offsets(read, BORROWED) == offsets(written, RESPONSE_BUFFER) == list(range(len(payload) - 1, -1, -1))
    assert all(row['size_bytes'] == 1 for row in read + written)
    assert bytes(int(row['bytes_hex'], 16) for row in reversed(read)) == payload
    assert bytes(int(row['after_hex'], 16) for row in reversed(written)) == payload
    release, = [index for index, call in probe.import_at.items() if call['arguments'] == [hex(REPLY)]]
    assert read[-1]['source_visit_index'] < release

    parsed = group(probe.reads, RESPONSE_BUFFER, 4096)
    fields = (('status', 0, STATUS_READS, 0x100e24708, 28),)
    if payload == MARKERS:
        fields += (('length0', 4, SPAN_A_READS, 0x100e2484c, 24),
                   ('length1', 11, SPAN_B_READS, 0x100e24a7c, 0))
        shift, = [row for row in probe.frames if row['pc'] == '0x100e24a5c']
        assert int(shift['registers31'][1], 16) & 31 == 16
    result = {}
    for name, offset, sites, after, register in fields:
        site_names = list(map(hex, sites))
        field = [row for row in parsed if row['pc'] in site_names]
        assert [row['pc'] for row in field] == site_names
        assert offsets(field, RESPONSE_BUFFER) == list(range(offset, offset + 4))
        assert all(row['size_bytes'] == 1 and row['source_visit_index'] >= release for row in field)
        state, = [row for row in probe.frames if row['pc'] == hex(after)]
        value = int.from_bytes(payload[offset:offset + 4], 'big')
        assert int(state['registers31'][register], 16) == value
        result[name] = {'offset_bytes': offset, 'sites': site_names, 'raw_u32': value,
                        'pre_store_pc': hex(after), 'register': f'w{register}'}
    fields_end = sum(len(sites) for _, _, sites, _, _ in fields)
    assert probe.released == set(RELEASES)
    outputs = []
    for _, offset, size in environment.OUTPUTS:
        address = probe.C + offset
        stores = group(probe.writes, address, size)
        outputs.append({'observed_width_bytes': size, 'value_hex': probe.snapshot(address, size)['bytes_hex'],
                        'write_sites': [row['pc'] for row in stores]})
    if payload == ERROR:
        assert probe.boundary['pc'] == hex(environment.RETURN) and probe.reg(0) == int.from_bytes(ERROR, 'big')
        assert len(parsed) == fields_end and all(int(row['value_hex'], 16) == 0 for row in outputs)
        assert not probe.owners
        assert [call['arguments'] for call in probe.reply_calls if call['api'].endswith('/_free')] == [
            [hex(addr)] for addr in (RESPONSE_BUFFER, RESPONSE_RECORD, BUFFER, RECORD)]
        allocation_outputs = []
    else:
        assert probe.boundary['pc'] == hex(NOTIFY)
        assert probe.boundary['detail']['symbol'] == 'libSystem/_notify_register_check'
        assert IMAGE.read(probe.reg(0), len(b'com.apple.adid.midchangedV1\0')) == b'com.apple.adid.midchangedV1\0'
        assert probe.reg(1) == 0x1010ca2c0
        assert set(ALLOCATIONS.values()) <= {(size, address) for address, size in probe.owners.items()}
        allocation_outputs = []
        for (extent, address), start in zip(ALLOCATIONS.values(), (8, 15)):
            stores = group(probe.writes, address, extent)
            assert offsets(stores, address) == list(reversed(range(extent)))
            assert bytes.fromhex(probe.snapshot(address, extent)['bytes_hex']) == payload[start:start + extent]
            allocation_outputs.extend((address, extent))
        assert [int.from_bytes(bytes.fromhex(row['value_hex']), 'little') for row in outputs] == allocation_outputs
        assert offsets(parsed[fields_end:], RESPONSE_BUFFER) == [10, 9, 8, 18, 17, 16, 15]
    return {'wire_bytes_hex': payload.hex(), 'copy_sites': sorted({row['pc'] for row in read}),
            'copy_store_sites': sorted({row['pc'] for row in written}),
            'copy_indices_bytes': offsets(read, BORROWED), 'fields': result, 'outputs': outputs,
            'extra_span_reads': offsets(parsed[fields_end:], RESPONSE_BUFFER),
            'modeled_calls': probe.reply_calls, 'boundary_pc': probe.boundary['pc'],
            'boundary_call_or_return': ('notify_register_check' if payload == MARKERS else 'caller'),
            'boundary_args': ([hex(probe.reg(0)), hex(probe.reg(1))] if payload == MARKERS else [hex(probe.reg(0))]),
            'allocation_outputs': list(map(hex, allocation_outputs))}


def function_stores():
    output = subprocess.check_output(['xcrun', 'dyld_info', '-function_starts', str(SOURCE)], text=True)
    starts = [int(row, 16) for row in re.findall(r'^\s+(0x[0-9a-fA-F]+)\s', output, re.M)]
    start = 0x100e1e5ec
    limit = starts[starts.index(start) + 1]
    assert limit == 0x100e25560
    stores = [insn for insn in CS.disasm(IMAGE.read(start, limit - start), start)
              if insn.mnemonic == 'str' and insn.op_str.endswith('[sp, #0x21c]')]
    assert len(stores) == 11
    return [insn.address for insn in stores]


def main():
    parents = [case for case in reference('daemon_environment_outputs_checks')['cases']
               if case['configuration']['kind'] == 'caller' and case['boundary']['pc'] == '0x100e1ea4c']
    starts = reference('daemon_adid_request_origin_audit')['cases']
    strict = reference('daemon_adid_reply_reader_audit')['cases']
    direct_writers = function_stores()
    cases = []
    for parent in parents:
        start, = [case for case in starts if case['configuration'] == parent['configuration']
                  and case['request'] and case['prefix_rechecked']]
        for payload in (ERROR, MARKERS):
            previous, = [case for case in strict if case['configuration'] == parent['configuration']
                         and case['payload'] == payload.hex() and case['modeled_malloc_failure_at'] is None]
            expected = previous['boundary']
            results = []
            for pattern in (0x18, 0xe7):
                probe = FieldReplay(parent, start, payload, pattern)
                probe.run()
                cut, frame, _ = probe.cut
                assert (expected['source_visits'], int(expected['SP'], 16)) == (cut, frame)
                assert probe.prefix_rechecked and expected['pc'] == hex(RESTORE)
                assert probe.frames[cut]['registers31'] == expected['registers31']
                assert not set(direct_writers).intersection(int(row['pc'], 16) for row in probe.visits[:cut])
                assert not any(int(row['address'], 16) < frame + 0x220 and
                               frame + 0x21c < int(row['address'], 16) + row['size_bytes']
                               for row in probe.writes if row['source_visit_index'] < cut)
                result = record_fields(probe, payload)
                result['opaque_dependency_check'] = opaque_dependency_check(probe)
                result['visits'] = len(probe.visits)
                result['continuation_visits'] = len(probe.visits) - cut
                result['continuation_pc_sha256'] = sha256(
                    b''.join(int(row['pc'], 16).to_bytes(8, 'little') for row in probe.visits[cut:])
                ).hexdigest()
                results.append(result)
            assert results[0] == results[1]
            cases.append({'configuration': parent['configuration'], 'patterns': 2, **results[0]})
    assert len(cases) == 16
    fixups = verify_original_fixups([int(call['slot'], 16) for case in cases for call in case['modeled_calls']])
    print(json.dumps({'source_image_sha256': sha256(SOURCE.read_bytes()).hexdigest(), 'cases': cases,
                      'direct_candidate_writers': list(map(hex, direct_writers)),
                      'defined_prefix_writer_observed': False,
                      'native_api_or_ipc_executed': False, 'verified_fixups': fixups},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
