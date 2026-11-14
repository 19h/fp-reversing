#!/usr/bin/env python3
"""Independently replay selected source and prove record-selection contracts.
O(parent bytes + selected visits*32 + proof DAG) time/space excluding solver
search; 30 s/query. No native operation or full prior admission rerun.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_record_selection as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py']


def replay(e):
    data = R.parents()
    totals, key, row = Counter(), None, None
    for s in e['slices']:
        current = s['group'], s['class_index'], s['interval_index']
        if current != key:
            group, ci, ii = current
            packed = data[0]['classes'][ci]['interval_packed'] if group == 'initializer' else (
                data[1]['prefixes'][ci]['interval_packed'] if group == 'prefix' else data[2]['classes'][ci]['intervals'][ii]['interval_packed'])
            row, key = R.B.unpack(packed), current
        v = Trace(s['reads'], s['writes'])
        for k, x in enumerate(s['entry']['registers31']):
            v.seed('x'+str(k), int(x, 16))
        v.seed('sp', int(s['entry']['SP'], 16))
        flags = int(s['entry']['NZCV'], 16)
        v.n, v.z, v.carry, v.overflow = [z3.BoolVal(bool(flags&(1 << b))) for b in [31, 30, 29, 28]]
        for j in range(s['start_visit'], s['end_visit_exclusive']+1):
            f = row['source_frames'][j]
            assert f['Q_registers32'] == s['entry']['Q_registers32']
            assert all(number(v.read('x'+str(k))) == int(f['registers31'][k], 16) for k in range(31))
            assert number(v.read('sp')) == int(f['SP'], 16)
            actual = [z3.simplify(t) for t in [v.n, v.z, v.carry, v.overflow]]
            assert all(z3.is_true(t) or z3.is_false(t) for t in actual)
            assert sum(int(z3.is_true(t)) << b for t, b in zip(actual, [31, 30, 29, 28])) == int(f['NZCV'], 16)
            totals.update(GP_SP_values_checked=32, NZCV_frames_checked=1)
            if j == s['end_visit_exclusive']:
                break
            pc = int(row['source_visits'][j]['pc'], 16)
            assert row['source_visits'][j]['bytes_hex'] == IMAGE.read(pc, 4).hex()
            ins = next(DEC.disasm(IMAGE.read(pc, 4), pc))
            assert not any(ins.reg_name(r).startswith(('v', 'q', 'd', 's')) and ins.reg_name(r) != 'sp'
                           for r in ins.regs_access()[0]+ins.regs_access()[1])
            v.one(ins)
            totals['source_visits_checked'] += 1
        assert v.ri == len(s['reads']) and v.wi == len(s['writes'])
        totals.update(read_events_checked=v.ri, write_events_checked=v.wi, slices_checked=1)
    return dict(totals)


def obligations():
    out = []
    def prove(label, bad):
        s = z3.Solver()
        s.set(timeout=30000)
        assert s.check() == z3.sat
        s.add(z3.simplify(bad))
        result = s.check()
        assert result == z3.unsat, (label, str(result), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    x, bias, default, extent, offset, span, flag, transformed = z3.BitVecs(
        'sel_word32 sel_bias32 sel_default_offset32 sel_extent32 sel_offset32 sel_span32 sel_flag32 sel_transformed32', 32)
    pointer, sp = z3.BitVecs('sel_pointer64 sel_frame64', 64)
    v = Lift()
    for reg, value in {'sp': R.SP, 'x11': R.U, 'w8': bias}.items():
        v.seed(reg, value)
    mem(v, R.SP+0x3608, 4, x)
    v.run_block(*R.SPANS['initializer'])
    assert len(v.stores) == 3
    prove('original_default_coordinate_initializer', z3.Or(v.stores[1]['address'] != R.U+0x18,
          v.stores[1]['value'] != x, v.stores[1]['size_bytes'] != 4))
    v = Lift()
    v.seed('x14', R.U)
    v.seed('w15', 0x6968)
    mem(v, R.U, 8, pointer)
    v.run_block(*R.SPANS['availability0'])
    prove('original_primary_pointer_availability', v.read('w17') != z3.If(pointer == 0, z3.BitVecVal(0x8ecf, 32), z3.BitVecVal(0x8ee5, 32)))
    v = Lift()
    v.seed('x14', R.U)
    v.seed('w2', 0x8ee5)
    mem(v, R.U+8, 8, pointer)
    v.run_block(*R.SPANS['availability8'])
    prove('original_secondary_pointer_availability', v.read('w17') != z3.If(pointer == 0, z3.BitVecVal(0xb760, 32), z3.BitVecVal(0x8ee5, 32)))
    v = Lift()
    for reg, value in {'x0': 0x6800060008, 'x14': R.U, 'w16': bias, 'w1': 0x6993, 'sp': R.SP}.items():
        v.seed(reg, value)
    mem(v, 0x6800060018, 4, x)
    mem(v, R.U+0x14, 4, extent-0xef133bef)
    mem(v, R.U+0x18, 4, default-0x89271580)
    v.run_block(*R.SPANS['coordinate_and_first_bound'])
    q = x+bias
    selected = z3.If(q == 0x76d8ea80, default, q+0x89271580)
    index = z3.If(z3.ULT(selected+default, extent), z3.BitVecVal(0x6fc3, 32), z3.BitVecVal(0x6993, 32))
    prove('original_selected_coordinate_and_strict_first_bound', z3.Or(
        v.read('w16') != index, v.read('w5')+0x89271580 != selected, v.read('w2') != 0x76d8ea80))
    v = Lift()
    v.seed('sp', sp)
    v.seed('w1', 0x6993)
    mem(v, sp+0x68, 4, offset-0x89271580)
    v.run_block(*R.SPANS['saved_operands'])
    assert len(v.stores) == 2
    prove('original_saved_coordinate_operands', z3.Or(
        v.stores[0]['address'] != sp+0x7c, v.stores[0]['value'] != offset+0x36fe01a4,
        v.stores[0]['size_bytes'] != 4, v.stores[1]['size_bytes'] != 4,
        v.stores[1]['address'] != sp+0x78, v.stores[1]['value'] != offset+0x79396704))
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('w16', span^0x8b3dc651)
    for off, value in [(0x78, offset+0x79396704), (0x7c, offset+0x36fe01a4), (0x70, 0x1bc3)]:
        mem(v, R.SP+off, 4, value)
    v.run_block(*R.SPANS['positive_span'])
    expected = z3.If(z3.UGT(offset+span, offset), z3.BitVecVal(0x1ffb, 32), z3.BitVecVal(0x1bc3, 32))
    prove('original_positive_nonwrapping_span_gate', z3.Or(v.read('w16') != expected, v.read('w15') != offset+span+0xabc03b53))
    v = Lift()
    for reg, value in {'w1': 0xa71d, 'w15': offset+span+0xabc03b53, 'x14': R.U}.items():
        v.seed(reg, value)
    mem(v, R.U+0x14, 4, extent-0xef133bef)
    v.run_block(*R.SPANS['span_end_bound'])
    expected = z3.If(z3.UGT(offset+span, extent), z3.BitVecVal(0xa743, 32), z3.BitVecVal(0xa71d, 32))
    prove('original_span_end_at_or_below_extent_gate', v.read('w16') != expected)
    v = Lift()
    v.seed('w6', 0x6ce1)
    v.seed('x14', R.U)
    mem(v, R.U+0x28, 4, flag)
    v.run_block(*R.SPANS['flag_gate'])
    prove('original_bit_two_storage_path_selector', v.read('w17') != z3.If(flag&4 == 0, z3.BitVecVal(0x6ce1, 32), z3.BitVecVal(0x6ce6, 32)))
    v = Lift()
    for reg, value in {'w1': transformed, 'w6': 0x3a61, 'w15': x}.items():
        v.seed(reg, value)
    v.run_block(*R.SPANS['transformed_half_gate'])
    expected = z3.If(z3.Extract(15, 0, transformed) == 0x739e, z3.BitVecVal(0x83da, 32), z3.BitVecVal(0x3a61, 32))
    prove('original_transformed_halfword_equality_selector', v.read('w15') != expected)
    v = Lift()
    v.seed('sp', sp)
    mem(v, sp+0x68, 4, x)
    v.run_block(*R.SPANS['selected_reload'])
    prove('original_selected_coordinate_reload', v.read('w2') != x)
    v = Lift()
    v.seed('x0', pointer)
    v.seed('w2', x)
    v.run_block(*R.SPANS['return_store'])
    assert len(v.stores) == 1
    prove('original_private_result_store', z3.Or(v.stores[0]['address'] != pointer, v.stores[0]['value'] != x, v.stores[0]['size_bytes'] != 4))
    for kind in ['availability_zero', 'span_zero', 'extent_zero']:
        v = Lift()
        v.run_block(*R.SPANS[kind])
        prove('original_'+kind+'_return_value', v.read('w2') != 0x76d8ea80)
    prove('nonwrapping_span_equivalence', z3.UGT(offset+span, offset) != z3.And(span != 0, z3.ULE(span, ~offset)))
    prove('composed_span_bounds', z3.And(z3.UGT(offset+span, offset), z3.ULE(offset+span, extent),
          z3.Not(z3.And(z3.ULT(offset, extent), span != 0, z3.ULE(span, extent-offset)))))
    assert len(out) == 16
    return out


def controls():
    out = []
    for label, o, n, c, accepted in [('root_span_exact_end', 1, 20, 21, True),
                                    ('appended_span_exact_end', 57, 20, 77, True),
                                    ('zero_span_fails_positive_gate', 1, 0, 21, False),
                                    ('end_above_extent_fails_end_gate', 1, 21, 21, False)]:
        x, p, cap = z3.BitVecs('sel_control_offset32 sel_control_span32 sel_control_extent32', 32)
        passed = z3.And(z3.UGT(x+p, x), z3.ULE(x+p, cap))
        s = z3.Solver()
        s.add(x == o, p == n, cap == c, passed == accepted)
        assert s.check() == z3.sat
        out.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), 'span_gates_pass': accepted,
                    'native_admission_established': False})
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p:sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': obligations(), 'interpretation_controls': controls(),
            'general_word_decoder_contract_established': False, 'general_half_decoder_contract_established': False,
            'earlier_default_word_epoch_established': False,
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
