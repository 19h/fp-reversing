#!/usr/bin/env python3
"""Original-source SecureTime reader and conditional stored-clock admission.

Fixed symbolic storage and explicitly conditional entry phase; no target or IDB
execution. Extraction O(B+I+L+256R), scalar DAG construction O(I), solver cost
separate. This does not establish an upstream request or native clock epoch.
"""
import argparse
import json
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_SXTW
import z3

from kernel_native_reader import Kernel
from kext_port_tools import ROOT, SOURCE, IMAGE, selected
from lskd_values_symbolic import Lift, part, mem, cell, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
MASK = 0x7fffffffffffffff
K = 0x46ec7c7424bcc931
SPANS = {
    'reader': (0xfffffe000a517624, 0xfffffe000a517898),
    'zero_clock': (0xfffffe000a517898, 0xfffffe000a5178f0),
    'nonzero_clock': (0xfffffe000a521aa8, 0xfffffe000a521bf8),
    'common_followon': (0xfffffe000a524054, 0xfffffe000a5246c4),
    'greater_followon': (0xfffffe000a5271b8, 0xfffffe000a52744c),
}
ANCHORS = {
    0xfffffe000a517640: ('sub', 'w25, w12, #0x563'),
    0xfffffe000a51766c: ('ldr', 'x9, [x9, #0x18]'),
    0xfffffe000a51769c: ('stur', 'x9, [x29, #-0xb0]'),
    0xfffffe000a5176b0: ('stur', 'w9, [x29, #-0xa8]'),
    0xfffffe000a517710: ('blraa', 'x8, x17'),
    0xfffffe000a517730: ('str', 'wzr, [sp, #0x20c]'),
    0xfffffe000a517738: ('str', 'x8, [sp, #0x200]'),
    0xfffffe000a5177d0: ('blraa', 'x8, x17'),
    0xfffffe000a5177f8: ('ldr', 'w11, [sp, #0x20c]'),
    0xfffffe000a517848: ('ldr', 'x14, [x11, #0x30]'),
    0xfffffe000a517878: ('cmp', 'x17, x5'),
    0xfffffe000a517888: ('orr', 'w17, w17, w25'),
    0xfffffe000a517894: ('braa', 'x3, x17'),
    0xfffffe000a5178dc: ('str', 'x13, [x11, #0x30]'),
    0xfffffe000a521bdc: ('csel', 'w17, w2, w17, ne'),
    0xfffffe000a521be8: ('eor', 'w17, w17, w21'),
}


class ReaderLift(Lift):
    """Exact SXTW/index extension, byte store, HI and CSEL for selected slices."""
    def address(self, ins, operand):
        if operand.mem.index and operand.ext == ARM64_EXT_SXTW:
            index = self.read(ins.reg_name(operand.mem.index))
            assert index.size() == 32
            return z3.simplify(resize(self.read(ins.reg_name(operand.mem.base)), 64)
                + operand.mem.disp + (z3.SignExt(32, index) << operand.shift.value))
        return super().address(ins, operand)

    def run(self, label):
        saved = self.c
        row = next(r for r in saved['spans'] if r['label'] == label)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True
        data = bytes.fromhex(row['bytes_hex'])
        insns = list(cs.disasm(data, int(row['start'], 16)))
        assert len(insns)*4 == len(data)
        for ins in insns:
            self.pc = ins.address
            operands = ins.operands
            if ins.mnemonic == 'sxtw':
                self.write(ins.reg_name(operands[0].reg), z3.SignExt(32, self.read(ins.reg_name(operands[1].reg))))
                self.count += 1
            elif ins.mnemonic == 'sturb':
                self.store(self.address(ins, operands[1]), 1, self.read(ins.reg_name(operands[0].reg)), ins.address)
                self.count += 1
            elif ins.mnemonic == 'cset' and ins.op_str.endswith(', hi'):
                self.write(ins.reg_name(operands[0].reg), z3.If(z3.UGT(self.cmp_left, self.cmp_right),
                    z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)))
                self.count += 1
            elif ins.mnemonic == 'csel':
                assert ins.op_str == 'w17, w2, w17, ne'
                self.write('w17', z3.If(z3.Not(self.equal), self.read('w2'), self.read('w17')))
                self.count += 1
            else:
                self.c = {'spans': [{'label': label, 'start': hex(ins.address), 'bytes_hex': bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c = saved
        return self


def prove(capture):
    f = 0x51000000
    fp, p, lock = z3.BitVecs('reader_frame64 secure_time64 embedded_RW64', 64)
    phase = z3.BitVec('incoming_phase32', 32)
    a, t, field = z3.BitVecs('seed_A0_64 seed_10_64 field_30_64', 64)
    fresh, initial = z3.BitVecs('fresh_clock32 initial_clock32', 32)
    q, counts, controls = {}, {}, {}

    def run(name, start, end, seeds, cells=()):
        obj = ReaderLift(part(capture, name, start, end))
        for register, value in seeds.items():
            obj.seed(register, value)
        for address, width, value in cells:
            mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    obj = run('phase_prefix', 0xfffffe000a51762c, 0xfffffe000a5176b4,
        {'sp': f, 'x24': 0x53000000, 'x25': 0x54000000, 'x13': 0x55000000,
         'w12': phase, 'x9': p, 'x29': fp}, [(p + 24, 8, lock)])
    r = fp - 0xb0
    key = resize((r ^ 0x1d65dad0)*0xe9655f4d, 32)
    decoded_phase = cell(obj, r + 8, 4) - key
    q['record_pointer_and_aligned_phase'] = z3.And((r & 1) == 0, z3.Or(cell(obj, r, 8) != lock,
        decoded_phase != phase - 0x411))
    # Compose the preceding source identity with this independent u32 identity.
    q['compatible_acquire_phase_iff'] = ((phase - 0x411) == 0x2d2) != (phase == 0x6e3)
    controls['odd_record_alignment'] = z3.And((r & 1) == 1, phase == 0x6e3,
        decoded_phase != 0x2d2)
    q['compatible_derived_registers'] = z3.And(phase == 0x6e3, z3.Or(
        obj.read('w25') != 0x180, cell(obj, f + 0x1b8, 4) != 0x3de))

    # W23 is computed after the bank, from preserved W8/W10. Re-lift it separately.
    obj = run('compatible_W23', 0xfffffe000a5176f4, 0xfffffe000a5176f8,
        {'w8': 0x3de ^ 0x384, 'w10': 11})
    q['compatible_W23'] = obj.read('w23') != 0x3de
    seed_d8 = z3.BitVec('seed_D8_64', 64)
    obj = run('pre_query_seed_read', 0xfffffe000a517714, 0xfffffe000a517730,
        {'sp': f}, [(f + 0x198, 8, 0x57000000), (f + 0x1a0, 8, 0x56000000),
         (0x56000000, 4, 255), (0x57000000, 8, 0x58000000), (0x580000d8, 8, seed_d8)])
    q['pre_query_seed_D8'] = obj.read('x19') != seed_d8
    obj = run('clock_preparation', 0xfffffe000a517730, 0xfffffe000a517774,
        {'sp': f, 'x29': fp})
    expected = b'kern.monotonicclock\0\0'
    q['name_and_prezeroed_output_length'] = z3.Or(cell(obj, f + 0x20c, 4) != 0,
        cell(obj, f + 0x200, 8) != 4,
        cell(obj, fp - 0xf5, 8) != int.from_bytes(expected[:8], 'little'),
        cell(obj, fp - 0xed, 8) != int.from_bytes(expected[8:16], 'little'),
        cell(obj, fp - 0xe5, 4) != int.from_bytes(expected[16:20], 'little'),
        cell(obj, fp - 0xe1, 1) != 0)
    obj = run('clock_arguments', 0xfffffe000a5177b8, 0xfffffe000a5177d0,
        {'sp': f, 'x29': fp})
    q['clock_five_arguments'] = z3.Or(obj.read('x0') != fp - 0xf5,
        obj.read('x1') != f + 0x20c, obj.read('x2') != f + 0x200,
        obj.read('x3') != 0, obj.read('x4') != 0)
    obj = run('clock_name_clear', 0xfffffe000a5177d4, 0xfffffe000a5177e0, {'x29': fp})
    q['clock_name_clear'] = z3.Or(cell(obj, fp - 0xed, 8) != 0,
        cell(obj, fp - 0xf5, 8) != 0, cell(obj, fp - 0xe5, 4) != 0)
    obj = run('clock_reader_fold', 0xfffffe000a5177e0, 0xfffffe000a51788c,
        {'sp': f, 'x19': seed_d8, 'x21': 0x56000000,
         'x22': 0x57000000, 'x24': 0x55000000, 'x23': 0x3de, 'w25': 0x180},
        [(f + 0x20c, 4, fresh), (0x56000000, 4, 255), (0x57000000, 8, 0x58000000),
         (0x58000010, 8, t), (0x580000a0, 8, a), (0x55000000, 8, p), (p + 0x30, 8, field)])
    folded = (t & MASK) ^ 0x5e129968b0f85b1f
    old = (a & MASK) ^ field ^ K
    q['fresh_clock_fold'] = z3.Or(obj.read('x0') != folded,
        obj.read('x13') != folded ^ resize(fresh, 64))
    q['stored_zero_partition'] = obj.read('w17') != z3.If(old == 0,
        z3.BitVecVal(0x180, 32), z3.BitVecVal(0x1f5, 32))
    q['initial_writer_reader_join'] = z3.substitute(old,
        (field, (a & MASK) ^ K ^ resize(initial, 64))) != resize(initial, 64)
    obj = run('zero_clock_writer', 0xfffffe000a51789c, 0xfffffe000a5178e0,
        {'sp': f, 'x1': t, 'x2': a, 'x13': folded ^ resize(fresh, 64), 'x11': p},
        [(f + 0x1b8, 4, 0x3de)])
    q['zero_clock_field_update'] = z3.Or(cell(obj, p + 0x30, 8) !=
        (a & MASK) ^ K ^ resize(fresh, 64), obj.read('w16') != 0x3de,
        obj.read('x12') != 0x6e3)
    obj = run('nonzero_clock_compare', 0xfffffe000a521aac, 0xfffffe000a521bec,
        {'x23': 0x3de, 'x15': t & MASK, 'x13': folded ^ resize(fresh, 64),
         'x16': a & MASK, 'x14': field, 'x5': K, 'x0': folded})
    bias = 0x5bd8be02
    q['compare_fresh_operand'] = obj.values[(0xfffffe000a521bb0, 'x17')] - bias != resize(fresh, 64)
    q['compare_stored_operand'] = obj.values[(0xfffffe000a521bb8, 'x1')] - bias != old
    # Compose the two source operand identities with the complete original
    # comparison suffix. This removes repeated MBA expressions, not behavior.
    obj = run('normalized_comparison_suffix', 0xfffffe000a521bbc, 0xfffffe000a521bec,
        {'x17': resize(fresh, 64) + bias, 'x1': old + bias, 'x4': bias, 'w21': 0x3de})
    q['nonzero_clock_unsigned_partition'] = obj.read('w17') != z3.If(
        z3.UGT(resize(fresh, 64), old), z3.BitVecVal(0x7e6, 32), z3.BitVecVal(0x3de, 32))
    # Reject replacing the branch predicate with its converse.
    controls['reversed_comparison_rejected'] = z3.And(old != 0,
        obj.read('w17') != z3.If(z3.ULT(resize(fresh, 64), old),
            z3.BitVecVal(0x7e6, 32), z3.BitVecVal(0x3de, 32)))
    results = {}
    for name, query in q.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(query)
        result = solver.check()
        print(name, result, flush=True)
        assert result == z3.unsat, (name, str(result), solver.model() if result == z3.sat else solver.reason_unknown())
        results[name] = {'result': str(result), 'query': solver.sexpr()}
    counterexamples = {}
    for name, query in controls.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(query)
        assert solver.check() == z3.sat
        model = solver.model()
        counterexamples[name] = {'result': 'sat', 'query': solver.sexpr(),
            'model': {str(v): hex(model[v].as_long()) for v in sorted(model, key=str)}}
    return results, counts, counterexamples


def build():
    kernel = Kernel()
    spans = []
    for label, bounds in SPANS.items():
        row = span(kernel, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        spans.append(row)
    instructions = {int(i['ea'], 16): (i['mnemonic'], i['operands']) for s in spans for i in s['instructions']}
    assert all(instructions[pc] == operands for pc, operands in ANCHORS.items())
    proofs, counts, counterexamples = prove({'spans': spans})
    slots = {}
    for index, target, diversity in [
        (0x737, 0xfffffe000a517624, 0x30e7),
        (0x180, 0xfffffe000a517898, 0xb39c),
        (0x1f5, 0xfffffe000a521aa8, 0xb39c),
        (0x3de, 0xfffffe000a524054, 0x4c8d),
        (0x7e6, 0xfffffe000a5271b8, 0x4c8d),
    ]:
        slot = TABLE + index*8
        row = pointer(kernel, slot)
        assert row['authenticated'] and int(row['target'], 16) == target
        assert int(row['diversity'], 16) == diversity
        assert struct.unpack('<Q', IMAGE.read(slot, 8))[0] == target
        slots[hex(index)] = row
    # Exact literal-call census of the supplied C, not every computed name/call.
    path = SOURCE.parent / (SOURCE.name + '.c')
    lines = path.read_text().splitlines(keepends=True)
    census, heading, start = [], None, None
    for number, line in enumerate(lines, 1):
        if line.startswith('// --- Function:'):
            heading, start = line.rstrip(), number
        if 'strcpy(' in line and '"kern.monotonicclock"' in line:
            census.append({'function_heading': heading, 'function_heading_line': start,
                'literal_copy_line': number, 'first_excerpt_line': max(start, number - 8),
                'last_excerpt_line': number + 18,
                'text': ''.join(lines[max(start, number - 8)-1:number+18])})
    assert len(census) == 10
    reader_excerpt = {'path': path.name, 'sha256': sha(path), 'first_line': 25528,
        'last_line': 25659, 'text': ''.join(lines[25527:25659])}
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    defined, status_reads, overwrites, length_loads = False, [], [], []
    for ins in cs.disasm(kernel.read(0xfffffe000a5177d4, 0xc0), 0xfffffe000a5177d4):
        reads, writes = ins.regs_access()
        canon = lambda reg: re.sub('^w', 'x', ins.reg_name(reg))
        if not defined and 'x0' in {canon(r) for r in reads}:
            status_reads.append(hex(ins.address))
        if 'x0' in {canon(r) for r in writes}:
            defined = True
            overwrites.append(hex(ins.address))
        if ins.mnemonic.startswith('ld') and '[sp, #0x200]' in ins.op_str:
            length_loads.append(hex(ins.address))
    assert not status_reads and not length_loads and overwrites == ['0xfffffe000a517834']
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'spans': spans,
        'proofs': proofs, 'source_lift_counts': counts, 'solver_version': z3.get_version_string(),
        'negative_controls': counterexamples, 'control_slots': slots,
        'supplied_reference': reader_excerpt, 'literal_clock_call_census': census,
        'source_status_audit': {'incoming_sysctl_status_reads_before_overwrite': status_reads,
            'X0_overwrites': overwrites, 'returned_length_reloads': length_loads},
        'composition': {'phase': 'Source aligned-record phase identity then independent u32 phase equivalence.',
            'comparison': 'Complete source operand identities then complete original comparison suffix with normalized operands.',
            'excluded_initial_direct_queries': 'Two direct composed queries returned unknown at 10000 ms; replaced by exact compositional certificates.'},
        'selected_contract': {'conditional_incoming_phase32': '0x6e3', 'record_required_alignment_B': 2,
            'compatible_acquire_phase32': '0x2d2', 'actual_incoming_phase_proven': False,
            'actual_reader_frame_roots_proven': False, 'selected_table_base_premise': hex(TABLE), 'seed_flag_premise32': 255,
            'seed_offsets_B': [216, 16, 160], 'stored_clock_expression': '(seed_A0 & 0x7fffffffffffffff) XOR field30 XOR 0x46ec7c7424bcc931',
            'fresh_clock_B': 4, 'stored_relation_width_B': 8,
            'zero_stored_index32': '0x180', 'nonzero_stored_index32': '0x1f5',
            'fresh_greater_index32': '0x7e6', 'fresh_not_greater_index32': '0x3de',
            'zero_branch_updates_field30': True, 'helper_bank_roots_recovered': False,
            'upstream_request_recovered': False, 'daemon_reply_recovered': False,
            'native_epoch_matched': False},
        'dependencies': {name: sha(ROOT / name) for name in [
            'kernel_native_reader.py', 'kext_port_tools.py', 'lskd_values_symbolic.py',
            'recover_aes_cleanup_epoch.py', 'recover_kext_cold_init.py',
            'verify_daemon_reader_record_payloads_publication.py', 'lskd_clock_completion_checks.json',
            'lskd_continuations_proofs.json']},
        'verified_counts': {'spans': len(spans), 'instructions': len(instructions), 'code_B': len(instructions)*4,
            'operand_anchors': len(ANCHORS), 'source_lifted_instances': sum(counts.values()),
            'queries_unsat': len(proofs), 'negative_controls_sat': len(counterexamples),
            'original_control_slots': len(slots), 'literal_clock_calls': len(census),
            'semantically_lifted_spans': 3, 'captured_only_followon_spans': 2},
        'kernel_collection_sha256': kernel.sha256, 'normalized_image_sha256': sha(SOURCE),
        'all_checks_pass': True,
        'full_goal_complete': False, 'new_target_execution': False, 'new_IDA_access': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    output = build()
    path = ROOT / 'lskd_clock_reader_checks.json'
    if args.verify:
        assert json.loads(read(path)) == output
    else:
        path.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(output.get('verified_counts', {'queries': len(output['proofs'])})))
