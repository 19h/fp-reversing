#!/usr/bin/env python3
"""Universal clear-storage decoder and counted-walk source contracts.
O(receipt bytes + selected replay*32 + source DAG) time/space, excluding
solver search (30 s/query). Abstract scalar controls are not guest inputs.
No target interval, native operation, proof cut or instruction rewrite.
"""
import json
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, FIXUPS
from audit_daemon_append_fields import Lift
from audit_daemon_record_selection import replay
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_record_walk as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_record_selection.py', 'audit_daemon_environment_outputs.py',
        'lskd_values_symbolic.py', 'recover_daemon_return_bank_origins.py']
F, U = 0x680005fa30, 0x6600060000
BIAS = 0x89271580
PROTECTED = ['x0', 'x25', 'x26', 'x27', 'x21', 'x12', 'x28', 'x9', 'x10', 'x11']


class Reader(Lift):
    def __init__(self, inputs):
        super().__init__()
        self.inputs = inputs
        self.input_addresses = []

    def load(self, address, n):
        if self.pc in self.inputs:
            assert n == 1
            self.input_addresses.append(address)
            return self.inputs[self.pc]
        return super().load(address, n)


def reader(kind, residue, high, base, raw):
    offset = z3.Concat(high, z3.BitVecVal(residue, 4))
    pcs = [0x100405d9c, 0x100405dfc, 0x100405e4c, 0x100405e98] if kind == 'word' else [0x1003cbb20, 0x1003cbb5c]
    v = Reader(dict(zip(pcs, raw)))
    for name, value in {'sp': F, 'x14': U}.items():
        v.seed(name, value)
    for name in PROTECTED:
        v.seed(name, z3.BitVec('walk_preserved_'+name+'64', 64))
    mem(v, U+8, 8, base)
    d, e, k = (R.BANKS[n][0] for n in ['D', 'E', 'K'])
    protected = [(U+8, 8)]
    if kind == 'word':
        for name, value in {'w22': offset, 'w15': offset-BIAS, 'w2': 0x602d, 'w19': BIAS+2, 'w20': BIAS+3}.items():
            v.seed(name, value)
        cells = [(0x80, 8, k), (0x88, 8, e), (0x90, 8, d)]
        addresses = [base+z3.ZeroExt(32, offset+j) for j in range(4)]
        a, b = 0x100405d98, 0x100405f9c
    else:
        v.seed('w16', 0x4dc0)
        r0, r1 = (residue+14)&15, (residue+15)&15
        cells = [(0x60, 8, z3.ZeroExt(32, offset+14)), (0x40, 8, z3.ZeroExt(32, offset+15)),
                 (0x28, 8, e+r0+4), (0x30, 8, d+r0), (0x20, 8, k+r0+1), (0x4c, 4, 31*r0),
                 (0x10, 8, e+r1+4), (0x18, 8, d+r1), (8, 8, k+r1+1), (0x3c, 4, 31*r1)]
        addresses = [base+z3.ZeroExt(32, offset+j) for j in [14, 15]]
        a, b = 0x1003cbb0c, 0x1003cbd2c
    for off, n, value in cells:
        mem(v, F+off, n, value)
        protected.append((F+off, n))
    for at, n in R.BANKS.values():
        protected.append((at, n))
        for j, byte in enumerate(IMAGE.read(at, n)):
            mem(v, at+j, 1, byte)
    v.run_block(a, b)
    premises = [z3.UGE(address-start, n) for address in addresses for start, n in protected]
    return v, addresses, premises


def obligations():
    out = []
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat, label
        s.add(z3.simplify(bad))
        answer = s.check()
        assert answer == z3.unsat, (label, str(answer), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    high = z3.BitVec('walk_offset_high28', 28)
    base = z3.BitVec('walk_buffer64', 64)
    data = [z3.BitVec('walk_raw'+str(j)+'_8', 8) for j in range(4)]
    for residue in range(16):
        v, addresses, premises = reader('word', residue, high, base, data)
        packed = z3.Concat(*[byte^R.Parent.S.STREAM[(residue+j)&15] for j, byte in enumerate(data)])
        n = z3.LShR(packed, 27)
        scalar = z3.If(n == 0, packed, packed&((z3.BitVecVal(1, 32)<<n)-1))
        prove('clear_word_decoder_residue_'+str(residue), z3.Or(v.read('w16') != scalar^0x8b3dc651,
              *[a != b for a, b in zip(v.input_addresses, addresses)], v.read('w2') != 0x602d,
              v.read('w15') != z3.Concat(high, z3.BitVecVal(residue, 4))-BIAS,
              *[v.read(name) != z3.BitVec('walk_preserved_'+name+'64', 64) for name in PROTECTED]), premises)
        v, addresses, premises = reader('half', residue, high, base, data[:2])
        packed = z3.Concat(*[byte^R.Parent.S.STREAM[(residue+14+j)&15] for j, byte in enumerate(data[:2])])
        n = z3.ZeroExt(12, z3.Extract(15, 12, packed))
        scalar = packed&((z3.BitVecVal(1, 16)<<n)-1)
        prove('clear_half_decoder_residue_'+str(residue), z3.Or(z3.Extract(15, 0, v.read('w1')) != (scalar^0x7390)+14,
              *[a != b for a, b in zip(v.input_addresses, addresses)], v.read('w6') != 0x3a61,
              v.read('w16') != 0x4dc0), premises)
    o, p, c, q, end, opaque, transformed = z3.BitVecs('walk_o32 walk_p32 walk_c32 walk_q32 walk_end32 walk_opaque_count32 walk_transformed32', 32)
    def run(a, b, seeds=(), memory=()):
        v = Lift()
        for name, value in seeds:
            v.seed(name, value)
        for at, n, value in memory:
            mem(v, at, n, value)
        return v.run_block(a, b)
    v = run(*R.SPANS['cursor_initializer'], [('sp', F), ('w23', o-BIAS)])
    prove('original_cursor_is_record_start_plus20', z3.Or(len(v.stores) != 1,
          v.stores[0]['address'] != F+0x6c, v.stores[0]['value'] != o+20-BIAS))
    v = run(0x100333948, 0x1003339b8, [('sp', F), ('w16', p^0x8b3dc651)],
            [(F+0x9c, 4, 0x93f3cc4d), (F+0xa4, 4, 0x1bc3)])
    prove('initial_span_is_at_least20', v.read('w15') != z3.If(z3.UGE(p, 20), z3.BitVecVal(0xc94c, 32), z3.BitVecVal(0x1bc3, 32)))
    v = run(0x1003209ac, 0x1003209f0, [('w6', 0x3a61), ('w15', end+0xabc03b53), ('w1', transformed)])
    h = z3.Extract(15, 0, transformed-14)^0x7390
    prove('common_join_separates_enclosing_endpoint_and_count', z3.Or(v.read('w25') != end,
          z3.Extract(15, 0, v.read('w26')) != (h^0x7390), v.read('w16') != 0xffffffec,
          v.read('w15') != z3.If(h == 0, z3.BitVecVal(0x83da, 32), z3.BitVecVal(0x3a61, 32))))
    v = run(0x1003209f4, 0x1003209f8, [('sp', F)], [(F+0x6c, 4, c-BIAS)])
    prove('common_join_reloads_distinct_encoded_cursor', v.read('w15') != c-BIAS)
    v = run(0x1004bad90, 0x1004bade4, [('w16', 0xffffffec), ('w21', 0xffff9684), ('w24', BIAS), ('w15', c-BIAS)])
    prove('cursor_plus20_no_wrap_guard', z3.Or(v.read('w16') != z3.If(z3.ULE(c, 0xffffffeb),
          z3.BitVecVal(0x1bec, 32), z3.BitVecVal(0x1bc3, 32)), v.read('w1') != 0xc68b))
    v = run(0x10063b9bc, 0x10063ba20, [('w1', 0xc68b), ('w15', c-BIAS), ('w25', end)])
    prove('child_header_room_gate', v.read('w16') != z3.If(z3.UGT(c+20, end), z3.BitVecVal(0xc6dd, 32), z3.BitVecVal(0xc68b, 32)))
    v = run(0x100333920, 0x10033393c, [('w1', 0xc68b)])
    prove('child_reader_preparation_phase', z3.Or(v.read('w3') != 0xc4, v.read('w16') != 0xbff7, v.read('w17') != 0x25e0))
    flag = z3.BitVec('walk_flag32', 32)
    v = run(0x1005320f8, 0x10053214c,
            [('w16', 0xbff7), ('w3', 0xc4), ('x13', TABLE), ('x14', U), ('w15', c-BIAS), ('w24', BIAS)],
            [(TABLE+8*0xc4, 8, FIXUPS[TABLE+8*0xc4]['target']), (U+0x28, 4, flag)])
    prove('child_word_reader_flag_cursor_and_continuation', z3.Or(v.read('w22') != c, v.read('w2') != 0x602d,
          v.read('w6') != 0x602d, v.read('x27') != 0x1003fb284,
          v.read('w16') != z3.If(flag&4 == 0, z3.BitVecVal(0xbff7, 32), z3.BitVecVal(0xc00f, 32))))
    v = run(0x1003ec410, 0x1003ec414)
    prove('word_return_bridge_IA_modifier', v.read('x17') != 0x352e)
    v = run(0x1003fb284, 0x1003fb328, [('sp', F), ('w16', q^0x8b3dc651), ('w15', c-BIAS)],
            [(F+0x98, 4, 0x5c01a05e), (F+0xa0, 4, 0xa743)])
    nxt = c+q
    prove('child_positive_nonwrapping_advance', z3.Or(v.read('w16') != nxt+0xeb9b242f,
          v.read('w15') != z3.If(z3.UGT(nxt, c), z3.BitVecVal(0xb243, 32), z3.BitVecVal(0xa743, 32))))
    v = run(0x10031424c, 0x1003142d8, [('sp', F), ('w16', nxt+0xeb9b242f), ('w25', end)], [(F+0x74, 4, 0xca3b)])
    prove('child_endpoint_bound_and_next_cursor', z3.Or(v.read('w15') != nxt-BIAS, v.read('w3') != 0x3a47,
          v.read('w16') != z3.If(z3.UGT(nxt, end), z3.BitVecVal(0xca8a, 32), z3.BitVecVal(0xca3b, 32))))
    v = run(0x1003f0f58, 0x1003f1074, [('w3', 0x3a47), ('w26', opaque)])
    count = z3.Extract(15, 0, opaque)^0x7390
    following = z3.Extract(15, 0, v.read('w26'))^0x7390
    prove('all_upper_bits_count_decrement_and_loop_phase', z3.Or(following != count-1,
          v.read('w16') != 0xffffffec, v.read('w1') != 0x6993))
    prove('counted_loop_branch', v.read('w17') != z3.If(count == 1, z3.BitVecVal(0x3a47, 32), z3.BitVecVal(0x3a61, 32)))
    prove('nonzero_count_variant_strictly_decreases', z3.UGE(following, count), [count != 0])
    v = run(0x1004a86e8, 0x1004a8730, [('w1', 0x6993), ('w15', c-BIAS), ('w25', end)])
    prove('finish_requires_cursor_equals_enclosing_endpoint', v.read('w8') != z3.If(c == end, z3.BitVecVal(0xac30, 32), z3.BitVecVal(0x6993, 32)))
    for name, a, b, modifier in [('initial', 0x1003339bc, 0x1003339d0, 0xcb9a),
                                ('cursor', 0x1004bade8, 0x1004badf4, 0xcb9a),
                                ('header', 0x10063ba24, 0x10063ba30, 0x2712),
                                ('positive', 0x1003fb32c, 0x1003fb340, 0xf01d),
                                ('bound', 0x1003142dc, 0x1003142e8, 0x62c0),
                                ('finish', 0x1004a8734, 0x1004a8740, 0xfb0f)]:
        v = run(a, b)
        prove(name+'_dispatch_rebuilds_encoded_zero', z3.Or(v.read('w2') != 0x76d8ea80, v.read('x17') != modifier))
    # These arithmetic compositions are consequences of the source predicates.
    cap = z3.BitVec('walk_capacity32', 32)
    pre = [z3.UGE(p, 20), z3.UGT(o+p, o), z3.ULE(o+p, cap)]
    prove('admitted_span_contains_fixed_header_and_initial_cursor', z3.Or(z3.ULT(o+20, o),
          z3.UGT(o+20, o+p), z3.UGE(o+15, cap)), pre)
    prove('positive_child_advance_is_nonzero_and_bounded', z3.Or(q == 0, z3.UGT(q, end-c)),
          [z3.UGT(c+q, c), z3.ULE(c+q, end)])
    w = z3.BitVec('walk_packed_word32', 32)
    n = z3.LShR(w, 27)
    decoded = z3.If(n == 0, w, w&((z3.BitVecVal(1, 32)<<n)-1))
    prove('clear_word_decoder_unsigned_bound', z3.UGT(decoded, 0x7fffffff))
    half = z3.BitVec('walk_packed_half16', 16)
    n = z3.ZeroExt(12, z3.Extract(15, 12, half))
    decoded_half = half&((z3.BitVecVal(1, 16)<<n)-1)
    prove('clear_half_count_unsigned_bound', z3.UGT(decoded_half, 0x7fff))
    prove('clear_half_zero_width_decodes_zero', decoded_half != 0, [n == 0])
    return out


def walk(span, count, child_spans):
    """Scalar-only control model, O(count) time and O(1) auxiliary space."""
    if span < 20:
        return 'initial_minimum'
    if count == 0:
        return 'selected_coordinate'
    cursor, remaining = 20, count
    for q in child_spans:
        if cursor > 0xffffffeb:
            return 'cursor_wrap_guard'
        if cursor+20 > span:
            return 'child_header_room'
        nxt = (cursor+q)&0xffffffff
        if nxt <= cursor:
            return 'child_positive_advance'
        if nxt > span:
            return 'child_endpoint_bound'
        cursor = nxt
        remaining -= 1
        if remaining == 0:
            return 'selected_coordinate' if cursor == span else 'finish_equality'
    return 'incomplete_scalar_sequence'


def controls():
    specs = [('empty_minimum', 20, 0, [], 'selected_coordinate'),
             ('empty_with_extra_extent', 24, 0, [], 'selected_coordinate'),
             ('one_span', 40, 1, [20], 'selected_coordinate'),
             ('positive_short_first_span', 44, 2, [1, 23], 'selected_coordinate'),
             ('short_enclosing_header', 19, 0, [], 'initial_minimum'),
             ('nonzero_count_without_room', 20, 1, [20], 'child_header_room'),
             ('sum_alone_is_insufficient', 40, 2, [1, 19], 'child_header_room'),
             ('zero_child_span', 40, 1, [0], 'child_positive_advance'),
             ('child_exceeds_parent', 40, 1, [21], 'child_endpoint_bound'),
             ('final_underconsumption', 44, 1, [20], 'finish_equality')]
    out = []
    for label, span, count, children, expected in specs:
        actual = walk(span, count, children)
        assert actual == expected
        out.append({'label': label, 'enclosing_span_bytes': span, 'walk_count16': count, 'child_spans_bytes': children,
                    'result': actual, 'source_scalar_model_only': True, 'native_admission_established': False})
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': obligations(), 'scalar_controls': controls(),
            'clear_word_decoder_contract_established': True, 'clear_half_decoder_contract_established': True,
            'nonzero_walk_observed': False, 'alternate_word_decoder_contract_established': False,
            'native_schema_established': False, 'proof_cuts': 0, 'target_instruction_rewrites': 0,
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps({'source_proofs': len(a['source_proofs']), **a['independent_totals']}), flush=True)
