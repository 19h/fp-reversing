#!/usr/bin/env python3
"""Independent halfword source contracts, retained replay and format controls.
O(parent bytes + selected visits*32 + proof DAG) time/space;
solver search is separate, bounded at 30 s/query. No native operation.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number
from lskd_values_symbolic import mem, resize
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_packed_halves as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py']


def packed(auxiliary, count, scalar):
    return resize((((auxiliary << (count&31))&0xfff)|(count<<12))+scalar, 16)


def obligations():
    out = []
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

    a = z3.BitVec('ph_auxiliary16', 16)
    x, n, k = z3.BitVecs('ph_x32 ph_count32 ph_scalar_raw32', 32)
    v = Lift()
    v.seed('w8', z3.ZeroExt(24, z3.Extract(15, 8, a)))
    v.seed('w9', z3.ZeroExt(24, z3.Extract(7, 0, a)))
    v.seed('w24', n)
    v.run_block(*R.SPANS['shift'])
    shifted = z3.ZeroExt(16, a) << (n&31)
    prove('original_big_endian_input_and_variable_shift', z3.Or(v.read('w8') != shifted, v.read('w9') != n&65535))
    v = Lift()
    v.seed('w8', x)
    v.seed('w25', 0x7a6302fa)
    v.run_block(*R.SPANS['mask'])
    prove('original_mask_low12_and_XOR_phase', v.read('w8') != ((x&0xfff)^0x0403c778))
    v = Lift()
    v.seed('w8', (x&0xfff)^0x0403c778)
    v.seed('w9', n&65535)
    v.run_block(*R.SPANS['pack'])
    base = (x&0xfff)|(n<<12)
    prove('original_count_pack_low16', resize(v.read('w8'), 16) != resize(base, 16))
    v = Lift()
    v.seed('w8', x)
    v.seed('w23', k)
    v.run_block(*R.SPANS['scalar_add'])
    prove('original_scalar_add_and_bias_low16', resize(v.read('w8'), 16) != resize(x+(k^0xdf8)+0x0f24, 16))
    v = Lift()
    v.seed('w8', x)
    v.run_block(*R.SPANS['final'])
    prove('original_final_complement_sum_low16', resize(-2-v.read('w8')-v.read('w10'), 16) != (resize(x-0x0f24, 16)^0x534c))
    b = resize((shifted&0xfff)|(n<<12), 16)
    d = resize(k^0xdf8, 16)
    composed = (b+d+0x0f24-0x0f24)^0x534c
    prove('composed_full_half_producer', composed != (packed(z3.ZeroExt(16, a), n, k^0xdf8)^0x534c))
    v = Lift()
    for i, value in R.PHASE.items():
        v.seed('x'+str(i), value)
    v.seed('w10', k)
    v.seed('w24', n)
    v.run_block(*R.SPANS['count_math'])
    decoded = (k&65535)^0xdf8
    prove('original_count_step_all_low16_and_phase_preservation', z3.Or(
          v.read('w24') != n+1, v.read('w11') != z3.LShR(decoded, 1)^0xdf8,
          v.read('w10') != z3.If(z3.ULT(decoded, 2), z3.BitVecVal(0x2997, 32), z3.BitVecVal(0x296e, 32)),
          *[v.read('x'+str(i)) != value for i, value in R.PHASE.items()]))
    for index, slot, target in [(0x296e, R.SLOTS[0], 0x100b787c8), (0x2997, R.SLOTS[1], 0x100b75148)]:
        v = Lift()
        v.seed('w10', index)
        v.seed('w11', x)
        v.seed('x20', R.PHASE[20])
        mem(v, slot, 8, qword(slot))
        v.run_block(*R.SPANS['count_dispatch'])
        prove('original_count_dispatch_'+hex(index), z3.Or(v.read('x12') != target,
              v.read('x10') != z3.ZeroExt(32, x), v.read('x17') != 0x1590))
    v = Lift()
    v.run_block(*R.SPANS['count_init'])
    prove('original_count_initializes_zero', v.read('x24') != 0)
    v = Lift()
    v.seed('w19', 0xe18)
    v.seed('w23', k)
    v.seed('w8', 0x296e)
    v.run_block(*R.SPANS['count_seed'])
    prove('original_count_phase_seed', z3.Or(v.read('x10') != z3.ZeroExt(32, k), v.read('x17') != 0x1590,
          *[v.read('x'+str(i)) != value for i, value in R.PHASE.items() if i != 20]))
    v = Lift()
    v.seed('w19', 0xe18)
    v.run_block(*R.SPANS['phase'])
    prove('original_half_mask_phase_seed', v.read('x25') != 0x7a6302fa)
    v = Lift()
    v.run_block(*R.SPANS['scalar_zero'])
    prove('original_zero_scalar_is_encoded_0xdf8', v.read('x23') != 0xdf8)
    sp = z3.BitVec('ph_SP64', 64)
    cell = z3.BitVec('ph_scalar_cell16', 16)
    v = Lift()
    v.seed('sp', sp)
    v.seed('w19', 0x7a6302fa)
    mem(v, sp+0x2b4, 2, cell)
    v.run_block(*R.SPANS['scalar_cell'])
    prove('original_scalar_cell_XOR_encoding', v.read('x23') != z3.ZeroExt(48, cell^0xdf8))
    saved = z3.BitVecs('ph_saved_X23 ph_saved_X24 ph_saved_X25 ph_saved_X26', 64)
    v = Lift()
    v.seed('sp', sp)
    for i, value in zip(range(23, 27), saved):
        v.seed('x'+str(i), value)
    v.run_block(*R.SPANS['save'])
    assert len(v.stores) == 4
    for i in range(23, 27):
        v.seed('x'+str(i), 0)
    v.run_block(*R.SPANS['restore'])
    prove('original_save_restore_identity_with_unchanged_cells', z3.Or(*[v.read('x'+str(i)) != value for i, value in zip(range(23, 27), saved)]))
    scalar = z3.BitVec('ph_width_scalar16', 16)
    for width in range(1, 17):
        premises = [z3.ULE(scalar, 1)] if width == 1 else [z3.UGE(scalar, 1 << (width-1))]
        if 1 < width < 16:
            premises.append(z3.ULT(scalar, 1 << width))
        bad = [z3.ULT(z3.LShR(scalar, j), 2) for j in range(width-1)]
        bad.append(z3.UGE(z3.LShR(scalar, width-1), 2))
        prove('complete_do_while_width_partition_'+str(width), z3.Or(*bad), premises)
    aux, width, scalar = z3.BitVecs('ph_format_aux32 ph_format_width32 ph_format_scalar32', 32)
    value = packed(aux, width, scalar)
    wide = z3.ZeroExt(16, value)
    scalar_mask = (z3.BitVecVal(1, 32)<<width)-1
    prove('canonical_format_scalar_count_auxiliary_inverse', z3.Or(
          value != resize(((aux<<width)&0xfff)|(width<<12)|scalar, 16), z3.LShR(wide, 12) != width,
          (wide&scalar_mask) != scalar, z3.LShR(wide&0xfff, width) != (aux&z3.LShR(z3.BitVecVal(0xfff, 32), width))),
          [z3.UGE(width, 1), z3.ULE(width, 12), z3.ULT(scalar, z3.BitVecVal(1, 32)<<width)])
    assert len(out) == 32
    return out


def replay(e):
    _, growth = R.parents()
    rows, totals = {}, Counter()
    for field in e['fields']:
        ci, ii = field['class_index'], field['interval_index']
        if (ci, ii) not in rows:
            rows[ci, ii] = R.Parent.Parent.unpack(growth['classes'][ci]['intervals'][ii]['interval_packed'])
        row = rows[ci, ii]
        for s in field['slices']+[x['slice'] for x in field['count_steps']]:
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
        for step in field['count_steps']:
            f, edge = step['slice']['exit'], step['edge']
            assert f['registers31'][12] == edge['target'] and f['registers31'][17] == edge['modifier']
            totals['logical_count_edges_checked'] += 1
        d, n = field['decoded_scalar16'], field['count32']
        value = int(field['packed16'], 16)
        assert value >> 12 == n and value&((1 << n)-1) == d
        assert (value&0xfff) >> n == int(field['retained_auxiliary_value'], 16)
        assert value^0x534c == int(field['writer']['values']['consumed16'], 16)
        totals.update(retained_field_decodes_checked=1, register_bridges_checked=len(field['register_bridge']))
    return dict(totals)


def controls():
    out = []
    def sat(label, assertions, **values):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*assertions)
        assert s.check() == z3.sat
        out.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), **values})
    zero = Lift()
    for i, value in R.PHASE.items():
        zero.seed('x'+str(i), value)
    zero.seed('w10', 0xdf8)
    zero.run_block(*R.SPANS['count_init'])
    zero.run_block(*R.SPANS['count_math'])
    n, index = number(zero.read('w24')), number(zero.read('w10'))
    assert n == 1 and index == 0x2997
    width = z3.BitVec('ph_zero_control_count32', 32)
    sat('zero_has_minimum_width_one', [width == n, width != 0], scalar16=0, source_count32=n, source_exit_index32=hex(index))
    x = z3.BitVec('ph_outside_control16', 16)
    value = number(packed(z3.BitVecVal(0, 32), z3.BitVecVal(13, 32), z3.BitVecVal(0x1000, 32)))
    sat('outside12bit_scalar_changes_count_field', [x == value, z3.LShR(x, 12) != 13],
        scalar16='0x1000', source_count32=13, packed16=hex(value), decoded_count16=value >> 12, admitted_native_input_established=False)
    a, b = z3.BitVecs('ph_auxiliary_control_A32 ph_auxiliary_control_B32', 32)
    sat('auxiliary_upper_bits_are_discarded', [a == 0, b == 0x8000, a != b,
        packed(a, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)) == packed(b, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))],
        scalar16=0, source_count32=1, auxiliary_A16='0x0', auxiliary_B16='0x8000', packed16='0x1000')
    be = packed(z3.BitVecVal(0x2fda, 32), z3.BitVecVal(2, 32), z3.BitVecVal(2, 32))
    le = packed(z3.BitVecVal(0xda2f, 32), z3.BitVecVal(2, 32), z3.BitVecVal(2, 32))
    sat('byte_order_changes_the_retained_field', [be != le], source_bytes_hex='2fda',
        big_endian_auxiliary16='0x2fda', little_endian_auxiliary16='0xda2f', source_packed16=hex(number(be)), reversed_packed16=hex(number(le)))
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert R.extract() == e
    counts = replay(e)
    proofs = obligations()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'parent_pins': R.PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': counts, 'source_proofs': proofs, 'source_queries_unsat': len(proofs),
            'format_controls': controls(), 'composition': {
                'producer_mixed16': 'u16(((((BE16(bytes)<<(count32&31))&0x0fff)|u16(count32<<12))+u16(raw_scalar32^0x0df8)))^0x534c',
                'consumed_sum': 'low16(-2-W8-W10)', 'required_W25': '0x7a6302fa',
                'width': 'max(1, bit_length(low16(raw_scalar32)^0x0df8))', 'canonical_scalar_max16': '0x0fff',
                'native_admission_bounds_established': False},
            'inherited_admissions_rerun': False, 'inherited_byte_writer_replay_rerun': False,
            'new_target_intervals': 0, 'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
            'native_target_executed': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'source_queries_unsat': result['source_queries_unsat']}), flush=True)
