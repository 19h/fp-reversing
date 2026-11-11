#!/usr/bin/env python3
"""Original DMA binding, prepared-range and cache-operation source contracts.

Static instruction certificates with explicit call/owner premises. No mapper,
device, descriptor API, barrier or IDB operation executes. O(B+I) source and
expression time/space; SMT solver cost is separate.
"""
import argparse
import json

import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_aes_provider_admission import ProviderLift
from lskd_values_symbolic import resize, part
from verify_daemon_reader_record_payloads_publication import read, sha

F = 0xfffffe0053000000
KERNEL_FUNCTIONS = {
    'binding': 0xfffffe000c528964,
    'clear_binding': 0xfffffe000c52887c,
    'DMA_prepare': 0xfffffe000c52818c,
    'descriptor_operation': 0xfffffe000c531be4,
    'descriptor_DMA_operation': 0xfffffe000c5365e8,
    'generate': 0xfffffe000c527544,
    'output_shim': 0xfffffe000c527590,
    'output_little64': 0xfffffe000c529dd8,
    'walk': 0xfffffe000c526dc8,
    'direction': 0xfffffe000c5316b8,
    'length': 0xfffffe000c5316ac,
}


class DMALift(ProviderLift):
    def run(self, label):
        saved = self.c
        row = next(s for s in saved['spans'] if s['label'] == label)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True
        raw = bytes.fromhex(row['bytes_hex'])
        insns = list(cs.disasm(raw, int(row['start'], 16)))
        assert len(insns) * 4 == len(raw)
        for ins in insns:
            self.pc = ins.address
            ops = ins.operands
            if ins.mnemonic == 'cinc':
                assert ins.op_str.endswith(', eq')
                d, a = [ins.reg_name(o.reg) for o in ops[:2]]
                self.write(d, z3.If(self.equal, self.read(a)+1, self.read(a)))
                self.count += 1
            elif ins.mnemonic == 'sturh':
                self.store(self.address(ins, ops[1]), 2, self.read(ins.reg_name(ops[0].reg)), ins.address)
                self.count += 1
            elif ins.mnemonic == 'csel' and ins.op_str.endswith(', ne'):
                d, a, b = [ins.reg_name(o.reg) for o in ops[:3]]
                self.write(d, z3.If(z3.Not(self.equal), self.read(a), self.read(b)))
                self.count += 1
            else:
                self.c = {'spans': [{'label': label, 'start': hex(ins.address), 'bytes_hex': bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c = saved
        return self


def cache_paths(capture):
    """Source branch ledgers for the two selected codes and flag-bit outcomes."""
    row = next(r for r in capture['spans'] if r['label'] == 'descriptor_operation')
    code = {int(i['ea'], 16): i for i in row['instructions']}
    result = []
    for operation in [1, 2]:
        for forbidden in [False, True]:
            pc, visits, barriers, status = 0xfffffe000c531c08, [], 0, 0xe00002c7
            while pc != 0xfffffe000c531c54:
                assert len(visits) < 32
                ins = code[pc]; visits.append(hex(pc))
                m, operand = ins['mnemonic'], ins['operands']
                if pc == 0xfffffe000c531c18:
                    assert (m, operand) == ('tbnz', 'w8, #0x12, #0xfffffe000c531c50')
                    if forbidden: pc = 0xfffffe000c531c50; continue
                elif pc == 0xfffffe000c531c30:
                    assert (m, operand) == ('b.gt', '#0xfffffe000c531c74') and operation <= 0x31
                elif pc == 0xfffffe000c531c38:
                    assert (m, operand) == ('b.eq', '#0xfffffe000c531c44')
                    if operation == 1: pc = 0xfffffe000c531c44; continue
                elif pc == 0xfffffe000c531c40:
                    assert (m, operand) == ('b.ne', '#0xfffffe000c531c54') and operation == 2
                elif pc == 0xfffffe000c531c44:
                    assert (m, operand) == ('dsb', 'sy'); barriers += 1
                elif pc == 0xfffffe000c531c48:
                    assert (m, operand) == ('mov', 'w0, #0'); status = 0
                elif pc == 0xfffffe000c531c4c:
                    assert (m, operand) == ('b', '#0xfffffe000c531c54')
                    pc = 0xfffffe000c531c54; continue
                elif pc == 0xfffffe000c531c50:
                    assert (m, operand) == ('add', 'w0, w0, #0x12'); status += 0x12
                assert m not in ['bl', 'blr', 'blraa']
                pc += 4
            result.append({'operation32': operation, 'descriptor_bit18_set': forbidden,
                           'path': visits, 'raw_status32': status, 'barriers_in_source': barriers,
                           'native_barriers_executed': 0})
    return result


def prove(capture):
    queries, pieces, counts = {}, {}, {}
    dma, descriptor, state, output = z3.BitVecs('DMA64 descriptor64 DMA_state64 output64', 64)
    length, offset, capacity, cursor = z3.BitVecs('descriptor_length64 offset64 max_transfer64 cursor64', 64)
    flags, count, word68, word98, word9c = z3.BitVecs('flags32 active_count32 descriptor_word68_32 descriptor_word98_32 descriptor_word9c_32', 32)

    def run(name, start, end, seeds, cells=(), writes=()):
        obj = DMALift(part(capture, name, start, end))
        for reg, value in seeds.items():
            obj.seed(reg, value)
        for at, n, value in cells:
            obj.fixed[(z3.simplify(resize(at, 64)).sexpr(), n)] = resize(value, n*8)
        for at, n in writes:
            obj.fixed_stores.add((z3.simplify(resize(at, 64)).sexpr(), n))
        obj.run(name)
        assert obj.count == (end-start)//4
        pieces[name] = {'start': hex(start), 'end': hex(end), 'instructions': obj.count}
        counts[name] = obj.count
        return obj

    def cell(obj, at, n):
        return obj.fixed[(z3.simplify(resize(at, 64)).sexpr(), n)]

    obj = run('binding_identity', 0xfffffe000c52897c, 0xfffffe000c528988,
              {'x0': dma, 'x1': descriptor}, [(dma+0x48, 8, output)])
    queries['binding_identity'] = z3.Or(obj.read('x19') != dma, obj.equal != (descriptor == output))
    obj = run('binding_busy_status', 0xfffffe000c52899c, 0xfffffe000c5289a4, {})
    queries['binding_busy_status'] = obj.read('x0') != 0xe00002d5
    obj = run('binding_summary_opcode', 0xfffffe000c528a38, 0xfffffe000c528a48,
              {'x19': dma}, [(dma+0x64, 4, flags)])
    queries['binding_summary_opcode'] = obj.read('w1') != z3.If((flags & 15) == 0, resize(0x02000001, 32), resize(0x02000000, 32))
    obj = run('binding_summary_record', 0xfffffe000c528a68, 0xfffffe000c528a74,
              {'x8': state, 'x20': descriptor})
    queries['binding_summary_record'] = z3.Or(obj.read('x0') != descriptor, obj.read('x2') != state+0x40, obj.read('w3') != 32)
    obj = run('descriptor_summary_prefix', 0xfffffe000c536760, 0xfffffe000c536778,
              {'x0': descriptor, 'x2': output}, [(descriptor+0x50, 8, length), (descriptor+0x68, 4, word68), (descriptor+0x98, 4, word98)],
              [(output, 8), (output+8, 4), (output+12, 4)])
    queries['descriptor_summary_prefix'] = z3.Or(cell(obj, output, 8) != length, cell(obj, output+8, 4) != word68, cell(obj, output+12, 4) != word98)
    obj = run('descriptor_direction', 0xfffffe000c5316bc, 0xfffffe000c5316c4,
              {'x0': descriptor}, [(descriptor+0x20, 4, flags)])
    queries['descriptor_direction'] = obj.read('w0') != (flags & 7)
    obj = run('descriptor_length', 0xfffffe000c5316b0, 0xfffffe000c5316b4,
              {'x0': descriptor}, [(descriptor+0x50, 8, length)])
    queries['descriptor_length'] = obj.read('x0') != length
    obj = run('descriptor_summary_direction', 0xfffffe000c5367a4, 0xfffffe000c5367b0,
              {'x0': resize(flags & 7, 64), 'x20': output, 'x19': descriptor}, [(descriptor+0x88, 4, count)], [(output+0x18, 4)])
    queries['descriptor_summary_direction'] = cell(obj, output+0x18, 4) != (flags & 7)
    obj = run('descriptor_summary_word14', 0xfffffe000c5367bc, 0xfffffe000c5367c4,
              {'x19': descriptor, 'x8': output}, [(descriptor+0x9c, 4, word9c)], [(output+0x14, 4)])
    queries['descriptor_summary_word14'] = cell(obj, output+0x14, 4) != word9c
    obj = run('binding_publish_descriptor', 0xfffffe000c528ae4, 0xfffffe000c528aec,
              {'x19': dma, 'x20': descriptor}, [(dma+0x48, 8, output)], [(dma+0x48, 8)])
    queries['binding_publish_descriptor'] = z3.Or(obj.read('x21') != output, cell(obj, dma+0x48, 8) != descriptor)
    obj = run('binding_prepare_arguments', 0xfffffe000c528b98, 0xfffffe000c528bac, {'x19': dma})
    queries['binding_prepare_arguments'] = z3.Or(obj.read('x0') != dma, obj.read('x1') != 0, obj.read('x2') != 0, obj.read('w3') != 1, obj.read('w4') != 1)
    obj = run('binding_zero_return', 0xfffffe000c528bf0, 0xfffffe000c528bf4, {})
    queries['binding_zero_return'] = obj.read('x0') != 0
    obj = run('prepare_initial_status', 0xfffffe000c5281c0, 0xfffffe000c5281cc,
              {'x0': dma}, [(dma+0x50, 8, output)])
    queries['prepare_initial_status'] = z3.Or(obj.read('w8') != 0xe00002d8, obj.read('x9') != output)
    obj = run('prepare_default_length', 0xfffffe000c5281d8, 0xfffffe000c5281dc,
              {'x21': state}, [(state+0x40, 8, length)])
    queries['prepare_default_length'] = obj.read('x2') != length
    obj = run('prepare_transfer_limit', 0xfffffe000c5281dc, 0xfffffe000c5281e4,
              {'x0': dma, 'x2': length}, [(dma+0x30, 8, capacity)])
    queries['prepare_transfer_limit'] = z3.ULE(obj.cmp_left, obj.cmp_right) != z3.ULE(length, capacity)
    obj = run('prepare_count', 0xfffffe000c5281f0, 0xfffffe000c5281fc,
              {'x0': dma}, [(dma+0x64, 4, flags), (dma+0x68, 4, count)], [(dma+0x68, 4)])
    queries['prepare_count'] = z3.Or(obj.read('w9') != count, cell(obj, dma+0x68, 4) != count+1)
    obj = run('prepare_repeat_offset', 0xfffffe000c528200, 0xfffffe000c528208,
              {'x21': state, 'x1': offset}, [(state+0x60, 8, cursor)])
    queries['prepare_repeat_offset'] = obj.equal != (cursor == offset)
    obj = run('prepare_repeat_length', 0xfffffe000c52820c, 0xfffffe000c528218,
              {'x21': state, 'x2': length, 'w8': 0xe00002d8}, [(state+0x68, 8, capacity)])
    queries['prepare_repeat_length'] = obj.read('w8') != z3.If(capacity == length, resize(0, 32), resize(0xe00002d8, 32))
    obj = run('prepare_length_mask', 0xfffffe000c52821c, 0xfffffe000c528224,
              {'x0': dma, 'x2': length}, [(dma+0x38, 4, flags)])
    queries['prepare_length_mask'] = obj.read('x9') != (length & z3.ZeroExt(32, flags))
    previous = z3.BitVec('previous_prepared_length64', 64)
    obj = run('prepare_previous_length_high', 0xfffffe000c528230, 0xfffffe000c528238,
              {'x21': state}, [(state+0x68, 8, previous)])
    queries['prepare_previous_length_high'] = (obj.read('x9') == 0) != z3.ULT(previous, 1 << 46)
    obj = run('prepare_range_publication', 0xfffffe000c528244, 0xfffffe000c528260,
              {'x21': state, 'x1': offset, 'x2': length}, [(state+0xb0, 8, output)],
              [(state+o, n) for o, n in [(0x60, 8), (0x68, 8), (0x77, 2), (0x79, 1), (0x80, 8), (0x88, 8), (0x98, 4), (0x90, 8)]])
    queries['prepare_range_publication'] = z3.Or(*[cell(obj, state+o, n) != resize(v, n*8) for o, n, v in
              [(0x60, 8, offset), (0x68, 8, length), (0x77, 2, 0), (0x79, 1, 0), (0x80, 8, 0), (0x88, 8, 0), (0x98, 4, 0), (0x90, 8, 0)]])
    obj = run('cache_initial_status', 0xfffffe000c531c08, 0xfffffe000c531c18,
              {'x0': descriptor}, [(descriptor+0x20, 4, flags)])
    queries['cache_initial_status'] = z3.Or(obj.read('x0') != 0xe00002c7, obj.read('w8') != flags)
    obj = run('cache_forbidden_status', 0xfffffe000c531c50, 0xfffffe000c531c54, {'w0': 0xe00002c7})
    queries['cache_forbidden_status'] = obj.read('x0') != 0xe00002d9
    obj = run('cache_barrier_return', 0xfffffe000c531c48, 0xfffffe000c531c4c, {})
    queries['cache_barrier_return'] = obj.read('x0') != 0
    obj = run('generate_pointer_shift', 0xfffffe000c527548, 0xfffffe000c527554,
              {'x1': cursor, 'x2': output, 'x3': capacity})
    queries['generate_pointer_shift'] = z3.Or(obj.read('x4') != cursor, obj.read('x5') != output, obj.read('x6') != capacity)
    obj = run('generate_flags', 0xfffffe000c527588, 0xfffffe000c52758c, {})
    queries['generate_flags'] = obj.read('x1') != 0x80
    bits = z3.BitVec('DMA_address_bits32', 32)
    address, segment_length = z3.BitVecs('output_segment_address64 output_segment_length64', 64)
    obj = run('shim_address_bits', 0xfffffe000c5275c4, 0xfffffe000c5275d8,
              {'x1': dma}, [(dma+0x5c, 4, bits)])
    queries['shim_address_bits'] = z3.Or(obj.read('w19') != 0xe00002e1,
              z3.ULE(obj.cmp_left, obj.cmp_right) != z3.And(z3.UGE(bits, 1), z3.ULE(bits, 63)))
    obj = run('shim_segment_endpoint', 0xfffffe000c5275dc, 0xfffffe000c5275e8,
              {'x2': address, 'x3': segment_length, 'x9': resize(bits, 64)})
    queries['shim_segment_endpoint'] = obj.read('x9') != z3.LShR(address+segment_length-1, resize(bits, 64) & 63)
    obj = run('shim_error_status', 0xfffffe000c5275f8, 0xfffffe000c527600, {})
    queries['shim_error_status'] = obj.read('w20') != 0xe00002e1
    obj = run('shim_success_status', 0xfffffe000c52760c, 0xfffffe000c527610, {})
    queries['shim_success_status'] = obj.read('w20') != 0
    obj = run('shim_callback_arguments', 0xfffffe000c527610, 0xfffffe000c527624,
              {'x1': dma, 'x2': address, 'x3': segment_length, 'x4': output, 'x5': cursor})
    queries['shim_callback_arguments'] = z3.Or(obj.read('x0') != dma, obj.read('x1') != address,
              obj.read('x2') != segment_length, obj.read('x3') != output, obj.read('x4') != cursor)
    callback_result, candidate_status = z3.BitVecs('output_callback_return32 candidate_status32', 32)
    obj = run('shim_callback_status', 0xfffffe000c52762c, 0xfffffe000c527634,
              {'w0': callback_result, 'w20': candidate_status, 'w19': 0xe00002e1})
    queries['shim_callback_status'] = obj.read('w0') != z3.If(callback_result != 0, candidate_status, resize(0xe00002e1, 32))
    index = z3.BitVec('output_record_index32', 32)
    record = output+z3.ZeroExt(32, index << 4)
    obj = run('output_little64_record', 0xfffffe000c529ddc, 0xfffffe000c529df0,
              {'w4': index, 'x3': output, 'x1': address, 'x2': segment_length}, writes=[(record, 8), (record+8, 8)])
    queries['output_little64_record'] = z3.Or(cell(obj, record, 8) != address, cell(obj, record+8, 8) != segment_length, obj.read('w0') != 1)
    obj = run('walk_coordinate_gate', 0xfffffe000c526e2c, 0xfffffe000c526e40,
              {'x4': output, 'x24': state}, [(output, 8, cursor), (state+0x60, 8, offset), (state+0x68, 8, length)])
    absolute, end = obj.read('x25'), obj.read('x27')
    queries['walk_coordinate_gate'] = z3.Or(absolute != offset+cursor, end != offset+length,
              z3.UGE(obj.cmp_left, obj.cmp_right) != z3.UGE(offset+cursor, offset+length))
    queries['walk_zero_base_coordinate_gate'] = z3.And(offset == 0, z3.ULT(absolute, end) != z3.ULT(cursor, length))
    wide_max = resize((1 << 64)-1, 65)
    no_wrap = z3.And(z3.ULE(z3.ZeroExt(1, offset)+z3.ZeroExt(1, cursor), wide_max),
                     z3.ULE(z3.ZeroExt(1, offset)+z3.ZeroExt(1, length), wide_max))
    queries['walk_nonwrapping_coordinate_gate'] = z3.And(no_wrap, z3.ULT(absolute, end) != z3.ULT(cursor, length))
    for name, a, z, expected in [('walk_unprepared_status', 0xfffffe000c526ea4, 0xfffffe000c526ea8, 0xe00002d8),
                                ('walk_end_status', 0xfffffe000c526eac, 0xfffffe000c526eb0, 0xe00002e8)]:
        obj = run(name, a, z, {'w17': 0xe00002c2})
        queries[name] = obj.read('x0') != expected
    position, segment = z3.BitVecs('walk_position64 segment_length64', 64)
    obj = run('walk_end_clip', 0xfffffe000c527358, 0xfffffe000c52736c,
              {'x22': segment, 'x27': end, 'x25': position, 'x24': state}, writes=[(state+8, 8), (state+16, 8), (state+0x7c, 1)])
    queries['walk_end_clip'] = z3.Or(obj.read('x22') != segment+end-position, obj.read('x25') != end,
              cell(obj, state+8, 8) != 0, cell(obj, state+16, 8) != 0, cell(obj, state+0x7c, 1) != 0)
    start = z3.BitVec('segment_logical_start64', 64)
    queries['walk_end_clip_bound'] = z3.And(z3.ULT(start, end), z3.ULE(end, position),
              z3.ULE(start, position), segment == position-start,
              z3.Or(obj.read('x22') == 0, z3.UGT(obj.read('x22'), segment), obj.read('x22') != end-start))
    obj = run('walk_success_outputs', 0xfffffe000c5273a8, 0xfffffe000c5273c0,
              {'x24': state, 'x25': position, 'x4': output, 'x6': dma, 'w7': count}, [(state+0x60, 8, offset)],
              [(state, 8), (output, 8), (dma, 4)])
    queries['walk_success_outputs'] = z3.Or(obj.read('x0') != 0, cell(obj, state, 8) != position,
              cell(obj, output, 8) != position-offset, cell(obj, dma, 4) != count)
    first, second, remaining = z3.BitVecs('segment_A_length64 segment_B_length64 remaining64', 64)
    obj = run('transfer_minimum', 0xfffffe0009d51268, 0xfffffe0009d5127c,
              {'sp': F, 'x26': first, 'x21': remaining}, [(F+0x58, 8, output), (F+0x60, 8, second)])
    minimum = z3.If(z3.ULT(first, second), first, second)
    minimum = z3.If(z3.ULT(remaining, minimum), remaining, minimum)
    queries['transfer_minimum'] = obj.read('x26') != minimum
    queries['transfer_minimum_bounds'] = z3.Or(z3.UGT(obj.read('x26'), first), z3.UGT(obj.read('x26'), second), z3.UGT(obj.read('x26'), remaining))
    controls = {'general_coordinate_simplification_requires_no_wrap': z3.ULT(offset+cursor, offset+length) != z3.ULT(cursor, length)}
    proofs, negative = {}, {}
    for name, query in queries.items():
        s = z3.Solver(); s.set(timeout=15000); s.add(query); result = s.check()
        assert result == z3.unsat, (name, str(result), s.reason_unknown())
        proofs[name] = {'result': 'unsat', 'query': s.sexpr()}
        print(name, result, flush=True)
    for name, query in controls.items():
        s = z3.Solver(); s.set(timeout=15000); s.add(query); result = s.check()
        assert result == z3.sat, (name, str(result))
        negative[name] = {'result': 'sat', 'query': s.sexpr(),
                          'scope': 'Abstract modular-coordinate premise control; no native input or reachability claim.'}
    return {'proofs': proofs, 'negative_controls': negative, 'source_pieces': pieces, 'source_lift_counts': counts,
            'verified_counts': {'queries_unsat': len(proofs), 'controls_sat': len(negative), 'source_pieces': len(pieces), 'source_lifted_instances': sum(counts.values())}}


def build():
    k = Kernel()
    spans = []
    for label, address in KERNEL_FUNCTIONS.items():
        row = k.function(address)
        row['bytes_hex'] = row.pop('bytes'); row['label'] = label
        spans.append(row)
    entry = next(e for e in k.entries if e['name'] == 'com.apple.driver.AppleS8000AES')
    for label, address in [('quantum', 0xfffffe0009d50a28), ('transfer', 0xfffffe0009d51168)]:
        row = function(k, entry, address); row['label'] = label; spans.append(row)
    slots = {hex(a): pointer(k, a) for a in
             [0xfffffe0007f411f8+o for o in [0x148, 0x150, 0x160, 0x168, 0x178]] +
             [0xfffffe0007f85d80+o for o in [0x148, 0x150, 0x1e8, 0x1f0]]}
    capture = {'spans': spans}
    result = prove(capture)
    result['cache_source_paths'] = cache_paths(capture)
    result['verified_counts'].update(spans=len(spans), instructions=sum(len(r['instructions']) for r in spans),
                                    code_B=sum(len(bytes.fromhex(r['bytes_hex'])) for r in spans), original_slots=len(slots),
                                    cache_source_paths=len(result['cache_source_paths']))
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'kernel_collection_sha256': k.sha256,
            'spans': spans, 'slots': slots, 'exact_symbols': k.symbols([int(r['target'], 16) for r in slots.values()]+list(KERNEL_FUNCTIONS.values())),
            'dependencies': {n: sha(ROOT/n) for n in ['kernel_native_reader.py', 'recover_kext_aes_handoff.py', 'recover_kext_cold_init.py',
                'recover_aes_provider_admission.py', 'aes_provider_admission_checks.json', 'lskd_values_symbolic.py',
                'verify_daemon_reader_record_payloads_publication.py', 'aes_quantum_binding_source.json', 'aes_hardware_job_source.json', 'kext_buffer_contracts.json']},
            'solver_version': z3.get_version_string(), 'selected_contract': {
                'binding_prepare_offset64': 0, 'binding_prepare_length64': 0, 'binding_prepare_flags': [True, True],
                'descriptor_length_field_B': 0x50, 'DMA_state_pointer_field_B': 0x70,
                'state_summary_length_field_B': 0x40, 'state_prepared_offset_field_B': 0x60, 'state_prepared_length_field_B': 0x68,
                'cache_operation_codes': [1, 2], 'cache_barrier': 'dsb sy', 'generate_flags': 0x80,
                'native_descriptor_extent_matched': False, 'complete_mapper_semantics_proven': False,
                'native_hardware_completion_proven': False, 'daemon_request_lineage_proven': False},
            'new_IDA_access': False, 'new_native_execution': False, 'new_IDB_mutations': False, 'full_goal_complete': False, **result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    result = build()
    path = ROOT/'aes_dma_preparation_checks.json'
    if args.verify:
        assert json.loads(read(path)) == result
    else:
        path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']))
