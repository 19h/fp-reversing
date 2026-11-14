#!/usr/bin/env python3
"""Composed packed-word source proof, bit-count recovery and retained replay.
O(parent bytes + selected visits*32 + proof DAG) time/space;
solver search is separate, bounded at 30 s/query. The first-stage
modulo-2**27 ring normalization composes explicit source contracts.
No monolithic full-producer SMT result or native execution is claimed.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_OP_MEM
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_packed_words as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py']
M = 0x07ffffff


def obligations():
    out, norms = [], []
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat, label
        s.add(z3.simplify(bad))
        result = s.check()
        assert result == z3.unsat, (label, str(result), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)

    raw, n, y, a, b, h, k, x = z3.BitVecs('pw_raw32 pw_count32 pw_y32 pw_a32 pw_b32 pw_h32 pw_scalar_raw32 pw_x32', 32)
    fp, sp = z3.BitVecs('pw_FP64 pw_SP64', 64)
    v = Lift()
    v.seed('w8', raw)
    v.seed('x29', fp)
    mem(v, fp-0xcc, 4, n)
    v.run_block(*R.SPANS['shift'])
    shifted = (raw^0x6703cce9) << (n&31)
    prove('original_shift_and_count_load', z3.Or(v.read('w8') != shifted, v.read('w9') != n))
    v = Lift()
    v.seed('w8', y)
    v.run_block(*R.SPANS['products'])
    term = (y<<1)&0x012b4c04
    prove('original_modular_product_inputs', z3.Or(v.read('w8') != y*0x4990dd09,
          v.read('w10') != term*0xb66f22f7, v.read('w11') != 0x074d6fed))
    v = Lift()
    for name, value in {'w8': a, 'w10': b, 'w11': 0x074d6fed}.items():
        v.seed(name, value)
    v.run_block(*R.SPANS['combiner'])
    prove('original_combiner_low27', (v.read('w8')&M) != ((a+b+0x28b29012)&M))
    v = Lift()
    v.seed('w8', h)
    v.run_block(*R.SPANS['inverse'])
    prove('original_inverse_multiply_and_projection', z3.Or(v.read('w8') != ((h*0x0103c139)&M),
          v.read('w8') != (((h&M)*0x0103c139)&M)))
    u27, t27 = z3.BitVecs('pw_ring_input27 pw_ring_term27', 27)
    source27 = (u27*0x4990dd09+t27*0xb66f22f7+0x28b29012)*0x0103c139
    target27 = u27-t27+0x0095a602
    difference = z3.simplify(source27-target27, som=True)
    assert z3.is_bv_value(difference) and difference.as_long() == 0
    norms.append({'label': 'original_coefficients_cancel_in_modulo_2pow27_ring', 'width_bits': 27,
                  'source': source27.sexpr(), 'target': target27.sexpr(), 'difference_normal_form': difference.sexpr(),
                  'substitution': {'pw_ring_input27': 'low27(y32)', 'pw_ring_term27': 'low27((y32<<1)&0x012b4c04)'},
                  'source_contracts': ['original_modular_product_inputs', 'original_combiner_low27', 'original_inverse_multiply_and_projection']})
    prove('masked_subtraction_is_XOR', ((y-term+0x0095a602)&M) != ((y^0x0095a602)&M))
    t = z3.BitVec('pw_masked_input27', 27)
    v = Lift()
    v.seed('w8', z3.ZeroExt(5, t))
    v.seed('w9', n)
    v.run_block(*R.SPANS['count_pack'])
    q = (z3.ZeroExt(5, t)|(n<<27))^0x53ca1e3d
    prove('original_count_in_upper5', v.read('w8') != q)
    v = Lift()
    v.seed('w8', x)
    v.run_block(*R.SPANS['bias'])
    prove('original_packed_value_bias', v.read('w8') != (x^0x535fb83f)+0x95097265)
    v = Lift()
    v.seed('w8', x)
    v.seed('x29', fp)
    mem(v, fp-0xd0, 4, k)
    v.run_block(*R.SPANS['scalar_add'])
    prove('original_decoded_scalar_addition', v.read('w8') != x+(k^0x8b3dc651)+0x759f5b7b)
    # Prove the cancellation for every possible quotient before composing it.
    quotient, word = z3.BitVecs('pw_quotient32 pw_word32', 32)
    v = Lift()
    v.seed('w10', quotient)
    v.seed('w11', word)
    v.run_block(*R.SPANS['quotient_cancel'])
    prove('original_quotient_reconstruction_is_shift8', v.read('w10') != word<<8)
    v = Lift()
    v.seed('w8', x)
    v.run_block(R.SPANS['mask'][0], 0x100c29708)
    # The omitted quotient calculation writes only X10. Its value is arbitrary
    # in the cancellation theorem. W12/W13 from the cancellation are dead at
    # the tail entry, verified by seeding only the four live tail registers.
    tail = Lift()
    for name, value in {'w8': v.read('w8'), 'w9': v.read('w9'), 'w10': v.read('w11')<<8, 'w11': v.read('w11')}.items():
        tail.seed(name, value)
    tail.run_block(0x100c2972c, R.SPANS['mask'][1])
    prove('composed_final_bias_removal_and_XOR', tail.read('w11') != ((x-0x0aa8cde0)^0xc156f94e))
    packed_base = (shifted&M)|(n<<27)
    staged_t = (shifted^0x0095a602)&M
    staged_q = (staged_t|(n<<27))^0x53ca1e3d
    biased = (staged_q^0x535fb83f)+0x95097265
    after_add = biased+(k^0x8b3dc651)+0x759f5b7b
    composed = (after_add-0x0aa8cde0)^0xc156f94e
    value = packed_base+(k^0x8b3dc651)
    prove('composed_full_producer_and_pinned_caller_XOR', z3.Or(composed != value^0xc156f94e,
          (composed^0x25e3467a) != value^0xe4b5bf34))
    v = Lift()
    for i, value in R.PHASE.items():
        v.seed('x'+str(i), value)
    v.seed('w11', raw)
    v.seed('w10', n)
    v.run_block(*R.SPANS['count_math'])
    d = raw^0x8b3dc651
    prove('original_bit_count_step_all_u32', z3.Or(v.read('x10') != z3.ZeroExt(32, n+1),
          v.read('x12') != z3.ZeroExt(32, z3.LShR(d, 1)^0x8b3dc651),
          v.read('w11') != z3.If(z3.ULT(d, 2), z3.BitVecVal(0x926d, 32), z3.BitVecVal(0x7550, 32)),
          *[v.read('x'+str(i)) != value for i, value in R.PHASE.items()]))
    for index, slot, target in [(0x7550, R.SLOTS[0], 0x100cc81e0), (0x926d, R.SLOTS[1], 0x100add458)]:
        v = Lift()
        v.seed('w11', index)
        v.seed('x12', z3.ZeroExt(32, word))
        v.seed('x20', R.PHASE[20])
        mem(v, slot, 8, qword(slot))
        v.run_block(*R.SPANS['count_dispatch'])
        prove('original_count_dispatch_'+hex(index), z3.Or(v.read('x13') != target,
              v.read('x11') != z3.ZeroExt(32, word), v.read('x17') != 0x73a4))
    v = Lift()
    v.run_block(*R.SPANS['count_init'])
    prove('original_count_initializes_zero', v.read('x10') != 0)
    for kind, register, off in [('raw_store', 'w11', 0xd0), ('count_store', 'w10', 0xcc)]:
        v = Lift()
        v.seed('x29', fp)
        v.seed('sp', sp)
        v.seed(register, word)
        v.run_block(*R.SPANS[kind])
        assert len(v.stores) == 1
        w = v.stores[0]
        prove('original_'+kind+'_cell', z3.Or(w['address'] != fp-off, w['value'] != word, w['size_bytes'] != 4))
    # Exact scalar bit-width partitions cover every u32, including zero.
    scalar = z3.BitVec('pw_width_scalar32', 32)
    for width in range(1, 33):
        premises = [z3.ULE(scalar, 1)] if width == 1 else [z3.UGE(scalar, 1 << (width-1))]
        if 1 < width < 32:
            premises.append(z3.ULT(scalar, 1 << width))
        bad = [z3.ULT(z3.LShR(scalar, j), 2) for j in range(width-1)]
        bad.append(z3.UGE(z3.LShR(scalar, width-1), 2))
        prove('complete_do_while_width_partition_'+str(width), z3.Or(*bad), premises)
    auxiliary, width, scalar = z3.BitVecs('pw_auxiliary32 pw_width32 pw_scalar32', 32)
    encoded = (((auxiliary<<width)&M)|(width<<27))+scalar
    scalar_mask = (z3.BitVecVal(1, 32)<<width)-1
    prove('canonical_format_scalar_count_auxiliary_inverse', z3.Or(
          encoded != (((auxiliary<<width)&M)|(width<<27)|scalar),
          z3.LShR(encoded, 27) != width, (encoded&scalar_mask) != scalar,
          z3.LShR(encoded&M, width) != (auxiliary&z3.LShR(z3.BitVecVal(M, 32), width))),
          [z3.ULE(width, 27), z3.ULT(scalar, z3.BitVecVal(1, 32)<<width)])
    assert len(out) == 50 and len(norms) == 1
    return out, norms


def replay(e):
    _, growth = R.parents()
    rows, totals = {}, Counter()
    for field in e['fields']:
        ci, ii = field['class_index'], field['interval_index']
        if (ci, ii) not in rows:
            rows[ci, ii] = R.Parent.Parent.unpack(growth['classes'][ci]['intervals'][ii]['interval_packed'])
        row = rows[ci, ii]
        slices = field['count_slices']+[x['slice'] for x in field['count_steps']]
        for s in slices:
            lo, hi = s['start_visit'], s['end_visit_exclusive']
            v = Trace(s['reads'], s['writes'])
            for k, x in enumerate(s['entry']['registers31']):
                v.seed('x'+str(k), int(x, 16))
            v.seed('sp', int(s['entry']['SP'], 16))
            initial_flags = int(s['entry']['NZCV'], 16)
            v.n, v.z, v.carry, v.overflow = [z3.BoolVal(bool(initial_flags&(1 << b))) for b in [31, 30, 29, 28]]
            for j in range(lo, hi+1):
                f = row['source_frames'][j]
                assert f['Q_registers32'] == s['entry']['Q_registers32']
                for k in range(31):
                    assert number(v.read('x'+str(k))) == int(f['registers31'][k], 16)
                assert number(v.read('sp')) == int(f['SP'], 16)
                flags = [z3.simplify(x) for x in [v.n, v.z, v.carry, v.overflow]]
                assert all(z3.is_true(x) or z3.is_false(x) for x in flags)
                assert sum(int(z3.is_true(x)) << b for x, b in zip(flags, [31, 30, 29, 28])) == int(f['NZCV'], 16)
                totals.update(GP_SP_values_checked=32, NZCV_frames_checked=1)
                if j == hi:
                    break
                pc = int(row['source_visits'][j]['pc'], 16)
                assert row['source_visits'][j]['bytes_hex'] == IMAGE.read(pc, 4).hex()
                v.one(next(DEC.disasm(IMAGE.read(pc, 4), pc)))
                totals['source_visits_checked'] += 1
            assert v.ri == len(s['reads']) and v.wi == len(s['writes'])
            totals.update(read_events_checked=v.ri, write_events_checked=v.wi, slices_checked=1)
        for step in field['count_steps']:
            f, edge = step['slice']['exit'], step['edge']
            assert f['registers31'][13] == edge['target'] and f['registers31'][17] == edge['modifier']
            assert IMAGE.read(0x100cc822c, 4) == bytes.fromhex(next(r['bytes_hex'] for r in e['source_spans'] if r['kind'] == 'count_branch'))
            totals['logical_count_edges_checked'] += 1
        scalar = field['decoded_scalar32']
        width = field['count32']
        packed = int(field['packed32'], 16)
        assert packed >> 27 == width and packed&((1 << width)-1) == scalar
        assert (packed&M) >> width == int(field['retained_auxiliary_value'], 16)
        assert field['retained_auxiliary_bits'] == 27-width
        totals['retained_field_decodes_checked'] += 1
    return dict(totals)


def controls():
    out = []
    def sat(label, assertions, **values):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*assertions)
        assert s.check() == z3.sat
        out.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), **values})
    width = z3.BitVec('pw_zero_width_control32', 32)
    zero = Lift()
    for i, value in R.PHASE.items():
        zero.seed('x'+str(i), value)
    zero.seed('w11', 0x8b3dc651)
    zero.run_block(*R.SPANS['count_init'])
    zero.run_block(*R.SPANS['count_math'])
    zero_count, zero_index = number(zero.read('w10')), number(zero.read('w11'))
    assert zero_count == 1 and zero_index == 0x926d
    sat('zero_has_minimum_width_one', [width == zero_count, width != 0], scalar32=0,
        actual_width32=zero_count, source_exit_index32=hex(zero_index), rejected_width32=0)
    scalar, auxiliary = 0x08000000, 0
    n = max(1, scalar.bit_length())
    packed = ((((auxiliary << (n&31))&M)|((n<<27)&0xffffffff))+scalar)&0xffffffff
    value = z3.BitVec('pw_outside_format_control32', 32)
    sat('outside27bit_scalar_changes_count_field', [value == packed, z3.LShR(value, 27) != n],
        scalar32=hex(scalar), source_count32=n, packed32=hex(packed), decoded_count32=packed >> 27,
        admitted_native_input_established=False)
    a, b = z3.BitVecs('pw_auxiliary_A32 pw_auxiliary_B32', 32)
    def pack(x):
        return (((x<<1)&M)|0x08000000)+1
    sat('auxiliary_upper_bits_are_discarded', [a == 0, b == 0x80000000, a != b, pack(a) == pack(b)],
        scalar32=1, source_count32=1, auxiliary_A32='0x0', auxiliary_B32='0x80000000', packed32='0x08000001')
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert R.extract() == e
    for r in e['source_spans']:
        a, b = int(r['start'], 16), int(r['end_exclusive'], 16)
        assert r['bytes_hex'] == IMAGE.read(a, b-a).hex()
    quotient_effects = []
    for pc in range(0x100c29708, 0x100c29718, 4):
        ins = next(DEC.disasm(IMAGE.read(pc, 4), pc))
        assert not any(o.type == ARM64_OP_MEM for o in ins.operands)
        writes = [ins.reg_name(r) for r in ins.regs_access()[1]]
        assert {'x'+n[1:] if n.startswith('w') else n for n in writes} == {'x10'}
        quotient_effects.append({'pc': hex(pc), 'bytes_hex': bytes(ins.bytes).hex(),
                                 'mnemonic': ins.mnemonic, 'operands': ins.op_str, 'writes': writes})
    assert [i['mnemonic'] for i in quotient_effects] == ['mov', 'movk', 'umull', 'lsr']
    counts = replay(e)
    proofs, normalizations = obligations()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'parent_pins': R.PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': counts, 'source_proofs': proofs, 'source_queries_unsat': len(proofs),
            'ring_normalizations': normalizations, 'format_controls': controls(),
            'quotient_cut': {'arbitrary_quotient_obligation': 'original_quotient_reconstruction_is_shift8',
                'quotient_source_effects': quotient_effects, 'replacement_W10': 'u32(W11 << 8)',
                'tail_entry': '0x100c2972c', 'seeded_tail_inputs': ['W8', 'W9', 'W10', 'W11'],
                'unseeded_dead_scratch_registers': ['W12', 'W13'],
                'target_execution_modified': False},
            'composition': {'initial_masked_data': 'low27(((raw32^0x6703cce9)<<(count32&31))^0x0095a602)',
                'ring27_first_stage_proved': True, 'producer32': '(((((raw32^0x6703cce9)<<(count32&31))&0x07ffffff)|(count32<<27))+(scalar_raw32^0x8b3dc651))^0xc156f94e; all arithmetic modulo 2**32',
                'caller_XOR32': '0x25e3467a', 'writer_input_XOR32': '0xe4b5bf34',
                'width': 'max(1, bit_length(decoded_scalar32))', 'canonical_scalar_max32': '0x07ffffff',
                'native_admission_bounds_established': False},
            'inherited_admissions_rerun': False, 'inherited_producer_replay_rerun': False,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'source_queries_unsat': result['source_queries_unsat'],
                      'ring_normalizations': len(result['ring_normalizations'])}), flush=True)
