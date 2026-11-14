#!/usr/bin/env python3
"""Independent scalar-reader/update contracts, ring reductions and custody replay.
O(parent bytes + selected visits*32 + proof DAG) time/space, excluding solver
search; each query has a 30 s bound. No native target operation.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number, masks
from lskd_values_symbolic import mem, resize
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_append_fields as Fields
import recover_daemon_halfword_update as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py',
        'recover_daemon_append_fields.py']
SP = 0x680005fb70


def front(residue, high, base, first, second):
    v = Lift()
    offset = z3.Concat(high, z3.BitVecVal(residue, 4))
    v.seed('sp', SP)
    v.seed('w8', offset-0x8927158e)
    v.seed('x10', z3.ZeroExt(32, offset))
    protected = [(SP+0x268, 8), (0x6600060008, 8), (SP+0xf4, 4)]
    mem(v, SP+0x268, 8, 0x6600060008)
    mem(v, 0x6600060008, 8, base)
    mem(v, SP+0xf4, 4, 0xabb1)
    for key in ['D', 'E', 'K']:
        off, a, n = Fields.BANKS[key]
        mem(v, SP+off, 8, a)
        protected.extend([(SP+off, 8), (a, n)])
        for j, b in enumerate(IMAGE.read(a, n)):
            mem(v, a+j, 1, b)
    addresses = [base+z3.ZeroExt(32, offset), base+z3.ZeroExt(32, offset+1)]
    for a, b in zip(addresses, [first, second]):
        mem(v, a, 1, b)
    v.run_block(*R.SPANS['byte_unmask'])
    premises = [z3.UGE(a-start, n) for a in addresses for start, n in protected]
    return v, premises


def obligations():
    out, normalizations = [], []
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
    high = z3.BitVec('hu_offset_high28', 28)
    base = z3.BitVec('hu_buffer64', 64)
    first, second = z3.BitVecs('hu_first8 hu_second8', 8)
    for residue in range(16):
        v, premises = front(residue, high, base, first, second)
        m0, m1 = masks('half_writer', residue)
        expected = z3.Concat(first^m0, second^m1)^0x534c
        prove('original_byte_reader_inverse_residue_'+str(residue), z3.Or(
              z3.Concat(resize(v.read('w10'), 8), resize(v.read('w8'), 8)) != expected,
              v.read('w14') != 0xabb1), premises)
    x, y, s = z3.BitVecs('hu_x32 hu_y32 hu_shift32', 32)
    v = Lift()
    v.seed('w8', x)
    v.seed('w10', y)
    v.seed('w14', 0xabb1)
    v.run_block(*R.SPANS['assemble'])
    packed = z3.Concat(resize(y, 8), resize(x, 8))
    prove('original_assembly_and_internal_XOR', z3.Or(resize(v.read('w8'), 16) != packed^0x8cc9,
          resize(v.read('w9'), 16) != packed, v.read('x14') != 0xabb1))
    v = Lift()
    v.seed('w8', x)
    v.seed('w14', 0xabb1)
    v.run_block(*R.SPANS['count'])
    count = z3.ZeroExt(28, z3.Extract(15, 12, x^0x8cc9))
    prove('original_count_nibble_to_shift', z3.Or(v.read('w8') != 16-count, v.read('x14') != 0xabb1))
    v = Lift()
    v.seed('w9', x)
    v.seed('w8', s)
    v.seed('w14', 0xabb1)
    v.run_block(*R.SPANS['product_shift'])
    prove('original_masked_value_and_shifted_multiplier', z3.Or(v.read('w9') != ((z3.BitVecVal(0x433fd6d7, 32)<<(s&31))*(x&65535)),
          v.read('w8') != s, v.read('x14') != 0xabb1))
    v = Lift()
    v.seed('w9', x)
    v.seed('w14', 0xabb1)
    v.run_block(*R.SPANS['product_unmix'])
    prove('original_product_unmix_and_phase', z3.Or(v.read('w10') != ((x*0x7ce7)&0xfffe), v.read('w9') != 0x59aa))
    p = z3.BitVec('hu_packed16', 16)
    for n in range(16):
        shift = 16-n
        source = p*((0x433fd6d7 << shift)&65535)*0x7ce7
        target = p*((1 << shift)&65535)
        difference = z3.simplify(source-target, som=True)
        assert z3.is_bv_value(difference) and difference.as_long() == 0
        normalizations.append({'label': 'source_multiplier_cancellation_count_'+str(n), 'width_bits': 16,
            'count_nibble': n, 'shift': shift, 'source': source.sexpr(), 'target': target.sexpr(),
            'difference_normal_form': difference.sexpr(),
            'source_contracts': ['original_masked_value_and_shifted_multiplier', 'original_product_unmix_and_phase']})
        v = Lift()
        v.seed('w10', z3.ZeroExt(16, p << shift)&0xfffe)
        v.seed('w8', shift)
        v.seed('w9', 0x59aa)
        v.run_block(*R.SPANS['scalar_extract'])
        prove('original_scalar_extraction_count_'+str(n), z3.Or(
              v.read('w8') != z3.ZeroExt(16, p&((1 << n)-1))^0x7390,
              v.read('w16') != 0x7390, v.read('x9') != 0x59aa))
    v = Lift()
    v.seed('w8', x)
    v.seed('w9', 0x59aa)
    v.seed('sp', SP)
    v.seed('w16', 0x7390)
    v.run_block(*R.SPANS['increment_math'])
    prove('original_scalar_increment_preparation', z3.Or(
          v.read('w11') != z3.ZeroExt(16, resize(x, 16)^0x7390)-0x7390,
          v.read('x13') != z3.ZeroExt(48, resize(x, 16)), v.read('x16') != 0x7390))
    d = z3.BitVec('hu_old_scalar16', 16)
    frame = z3.BitVec('hu_frame64', 64)
    v = Lift()
    v.seed('sp', frame)
    v.seed('w11', z3.ZeroExt(16, d)-0x7390)
    v.run_block(*R.SPANS['store'])
    assert len(v.stores) == 1
    w = v.stores[0]
    prove('original_incremented_u32_cell_store', z3.Or(w['address'] != frame+0x2b4,
          w['value'] != z3.ZeroExt(16, d)+1, w['size_bytes'] != 4))
    v = Lift()
    v.seed('w13', z3.ZeroExt(16, d)^0x7390)
    v.seed('w16', 0x7390)
    v.seed('w9', 0x59aa)
    v.seed('w11', x)
    v.run_block(*R.SPANS['gate'])
    prove('original_zero_scalar_gate', z3.Or(v.read('w9') != z3.If(d == 0, z3.BitVecVal(0x6732, 32), z3.BitVecVal(0x59aa, 32)),
          v.read('w11') != x))
    for index, slot, target in [(0x59aa, R.SLOTS[0], 0x100a682e4), (0x6732, R.SLOTS[1], 0x100a6e76c)]:
        v = Lift()
        v.seed('w9', index)
        v.seed('x20', 0x101039ef0)
        v.seed('w11', x)
        mem(v, slot, 8, qword(slot))
        v.run_block(*R.SPANS['dispatch'])
        prove('original_scalar_dispatch_'+hex(index), z3.Or(v.read('x9') != target, v.read('x17') != 0xfd0f, v.read('w11') != x))
    auxiliary, width, scalar = z3.BitVecs('hu_auxiliary32 hu_width32 hu_scalar32', 32)
    encoded = resize((((auxiliary<<width)&0xfff)|(width<<12))+scalar, 16)
    decoded_count = z3.LShR(z3.ZeroExt(16, encoded), 12)
    decoded_scalar = z3.ZeroExt(16, encoded)&((z3.BitVecVal(1, 32)<<decoded_count)-1)
    prove('composed_writer_reader_scalar_inverse', decoded_scalar != scalar,
          [z3.UGE(width, 1), z3.ULE(width, 12), z3.ULT(scalar, z3.BitVecVal(1, 32)<<width)])
    wide = z3.ZeroExt(16, p)
    decoded = wide&((z3.BitVecVal(1, 32)<<z3.LShR(wide, 12))-1)
    prove('composed_reader_bound_preserves_increment_across_u16_read', z3.Or(z3.UGT(decoded, 32767),
          z3.ZeroExt(16, resize(decoded+1, 16)) != decoded+1))
    assert len(out) == 43 and len(normalizations) == 16
    return out, normalizations


def replay(e):
    polynomial, _, _ = R.parents()
    totals = Counter()
    for c in e['cases']:
        row = R.Buffer.unpack(polynomial['classes'][c['polynomial_class_index']]['interval_packed'])
        for s in c['slices']:
            lo, hi = s['start_visit'], s['end_visit_exclusive']
            v = Trace(s['reads'], s['writes'])
            for k, x in enumerate(s['entry']['registers31']):
                v.seed('x'+str(k), int(x, 16))
            v.seed('sp', int(s['entry']['SP'], 16))
            flags = int(s['entry']['NZCV'], 16)
            v.n, v.z, v.carry, v.overflow = [z3.BoolVal(bool(flags&(1 << b))) for b in [31, 30, 29, 28]]
            for j in range(lo, hi+1):
                f = row['source_frames'][j]
                assert f['Q_registers32'] == s['entry']['Q_registers32']
                for k in range(31):
                    assert number(v.read('x'+str(k))) == int(f['registers31'][k], 16)
                assert number(v.read('sp')) == int(f['SP'], 16)
                actual = [z3.simplify(x) for x in [v.n, v.z, v.carry, v.overflow]]
                assert all(z3.is_true(x) or z3.is_false(x) for x in actual)
                assert sum(int(z3.is_true(x)) << b for x, b in zip(actual, [31, 30, 29, 28])) == int(f['NZCV'], 16)
                totals.update(GP_SP_values_checked=32, NZCV_frames_checked=1)
                if j == hi:
                    break
                pc = int(row['source_visits'][j]['pc'], 16)
                assert row['source_visits'][j]['bytes_hex'] == IMAGE.read(pc, 4).hex()
                v.one(next(DEC.disasm(IMAGE.read(pc, 4), pc)))
                totals['source_visits_checked'] += 1
            assert v.ri == len(s['reads']) and v.wi == len(s['writes'])
            totals.update(read_events_checked=v.ri, write_events_checked=v.wi, slices_checked=1)
        assert c['slices'][1]['exit']['registers31'][9] == c['edge']['target']
        totals['logical_edges_checked'] += 1
    return dict(totals)


def controls():
    out = []
    def sat(label, assertions, **values):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*assertions)
        assert s.check() == z3.sat
        out.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), **values})
    d = z3.BitVec('hu_control_old16', 16)
    sat('largest_decodable_scalar_increment_still_fits_u16', [d == 32767,
        z3.ZeroExt(16, d)+1 == z3.ZeroExt(16, d+1)], packed16='0xffff',
        old_scalar16=32767, stored_u32=32768, later_read_u16=32768, native_admission_established=False)
    sat('largest_canonical_scalar_crosses_format_domain_after_increment', [d == 4095, z3.ZeroExt(16, d)+1 > 4095],
        old_scalar16=4095, new_scalar32=4096, new_source_count32=13, native_admission_established=False)
    v = Lift()
    v.seed('w13', 0x7390)
    v.seed('w16', 0x7390)
    v.seed('w9', 0x59aa)
    v.run_block(*R.SPANS['gate'])
    index = number(v.read('w9'))
    assert index == 0x6732
    x = z3.BitVec('hu_zero_gate_index32', 32)
    sat('zero_uses_the_other_dispatch_target', [x == index, x != 0x59aa], source_target='0x100a6e76c',
        nonzero_target='0x100a682e4', later_zero_path_effects_established=False)
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert R.extract() == e
    counts = replay(e)
    proofs, normalizations = obligations()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'parent_pins': R.PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': counts, 'source_proofs': proofs, 'source_queries_unsat': len(proofs),
            'ring_normalizations': normalizations, 'format_controls': controls(),
            'composition': {'reader_scalar16': '(BE16(stored_bytes XOR writer_masks) XOR 0x534c) AND ((1 << packed_count_nibble)-1)',
                'reader_W8': 'zero_extend32(decoded_scalar16) XOR 0x7390', 'incremented_cell32': 'zero_extend32(decoded_scalar16)+1',
                'later_scalar16': 'low16(incremented_cell32)', 'native_admission_bounds_established': False},
            'inherited_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'source_queries_unsat': result['source_queries_unsat'],
                      'ring_normalizations': len(result['ring_normalizations'])}), flush=True)
