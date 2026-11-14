#!/usr/bin/env python3
"""Independent source replay and private resize ABI arithmetic obligations.
O(parent bytes + selected visits*32 + proof DAG) time/space, excluding solver
search; 30 s/query. No native operation or prior admission rerun.
"""
import json
import z3
from daemon_receive_tools import ROOT, SOURCE
from audit_daemon_append_fields import Lift
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_record_spans import replay
import recover_daemon_resize_callers as R

DEPS = ['audit_daemon_record_spans.py', 'audit_daemon_append_fields.py', 'lskd_values_symbolic.py']


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
    field, bias, x, p, s, t, coord, default = z3.BitVecs(
        'rc_field32 rc_bias32 rc_input32 rc_old_span32 rc_new_span32 rc_partial32 rc_coordinate32 rc_default32', 32)
    v = Lift()
    for name, value in {'x16': R.A, 'w13': bias, 'w9': 0, 'w10': 0}.items():
        v.seed(name, value)
    mem(v, R.A+0x2c, 4, field)
    mem(v, R.A+0x1c, 4, 0)
    v.run_block(0x100bab354, 0x100bab364)
    prove('original_record_word_plus_frame_bias', v.read('w0') != field+bias)
    v = Lift()
    v.seed('w10', 0x7a6302fa)
    v.seed('w13', x)
    v.run_block(*R.SPANS['new_span'])
    prove('original_biased_payload_plus_twenty', v.read('w12') != (x-0x0d38177c+20)^0x8b3dc651)
    v = Lift()
    for name, value in {'sp': R.LSP, 'w11': 0x12b6, 'w12': s^0x8b3dc651, 'w10': coord}.items():
        v.seed(name, value)
    mem(v, R.LSP+0x364, 4, p^0x8b3dc651)
    v.run_block(*R.SPANS['sum_prefix'])
    prove('original_span_sum_prefix', z3.Or(v.read('w13') != p+s-0x167b8ca2, v.read('w8') != 0xa180))
    v = Lift()
    v.seed('w8', 0xa180)
    v.seed('w13', t)
    v.run_block(*R.SPANS['sum_tail'])
    prove('original_span_sum_tail', v.read('w13') != t+0x167b8ca2)
    prove('composed_span_target', (p+s-0x167b8ca2)+0x167b8ca2 != p+s)
    prove('composed_caller_target', p+(field+bias-0x0d38177c+20) != p+field+bias-0x0d38177c+20)
    base, sp = z3.BitVecs('rc_owner64 rc_frame64', 64)
    v = Lift()
    v.seed('x5', base)
    v.seed('sp', sp)
    v.run_block(0x100babb10, 0x100babb28)
    assert len(v.stores) == 3
    for store, frame_off, owner_off in zip(v.stores, [0x268, 0x188, 0x180], [8, 0x14, 0x10]):
        prove('original_owner_pointer_binding_'+hex(owner_off), z3.Or(
            store['address'] != sp+frame_off, store['value'] != base+owner_off, store['size_bytes'] != 8))
    v = Lift()
    for name, value in {'x0': R.V, 'x14': R.U, 'w16': bias, 'w1': x}.items():
        v.seed(name, value)
    mem(v, R.V+0x10, 4, field)
    mem(v, R.U+0x14, 4, t)
    mem(v, R.U+0x18, 4, default)
    v.run_block(0x1004983ec, 0x100498420)
    q = field+bias
    chosen = z3.If(q == 0x76d8ea80, default, q)
    prove('original_zero_coordinate_default_selection', v.read('w5') != chosen)
    prove('encoded_zero_coordinate_is_zero_offset', z3.BitVecVal(0x76d8ea80, 32)+0x89271580 != 0)
    v = Lift()
    v.seed('w9', coord)
    v.run_block(*R.SPANS['coordinate_math'])
    prove('original_coordinate_reader_operand', v.read('w8') != coord+0xcb4c6ab4)
    prove('composed_coordinate_to_byte_offset', coord+0xcb4c6ab4+0xbddaaacc != coord+0x89271580)
    for kind, reg, offset in [('span_save', 'w27', 0x364), ('span_input_save', 'w0', 0x260),
                              ('target_save', 'w13', 0x3dc)]:
        v = Lift()
        v.seed('sp', sp)
        v.seed(reg, x)
        v.run_block(*R.SPANS[kind])
        assert len(v.stores) == 1
        store = v.stores[0]
        prove('original_'+kind, z3.Or(store['address'] != sp+offset, store['value'] != x, store['size_bytes'] != 4))
    assert len(out) == 16
    return out


def controls():
    out = []
    for label, q, fallback, offset in [('explicit_coordinate_overrides_default', 0x76d8eab9, 0x76d8ea81, 57),
                                      ('zero_coordinate_uses_default', 0x76d8ea80, 0x76d8ea81, 1)]:
        x = z3.BitVec('rc_control_coordinate32', 32)
        chosen = z3.If(x == 0x76d8ea80, z3.BitVecVal(fallback, 32), x)
        s = z3.Solver()
        s.add(x == q, chosen+0x89271580 == offset)
        assert s.check() == z3.sat
        out.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), 'offset_bytes': offset,
                    'native_admission_established': False})
    x = z3.BitVec('rc_wrong_input32', 32)
    s = z3.Solver()
    s.add(x == 0, x-0x0d38177c+20 != (x^0x0d38177c)+20)
    assert s.check() == z3.sat
    out.append({'label': 'xor_input_unbiasing_is_not_equivalent', 'result': 'sat', 'query': s.to_smt2(),
                'counterexample_input32': hex(s.model().eval(x).as_long()), 'native_admission_established': False})
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': obligations(), 'interpretation_controls': controls(),
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
