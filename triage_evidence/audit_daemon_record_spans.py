#!/usr/bin/env python3
"""Independent span arithmetic, later word reader and selected source replay.
O(parent bytes + selected visits*32 + proof DAG) time/space. Solver search
is separate, with 30 s/query. No native operation or prior admission rerun.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_record_spans as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py']


class Reader(Lift):
    def __init__(self, data):
        super().__init__()
        self.inputs = dict(zip([0x100a44590, 0x100a445ec, 0x100a44644, 0x100a44698], data))
        self.input_addresses = []

    def load(self, address, n):
        if self.pc in self.inputs:
            assert n == 1
            self.input_addresses.append(address)
            return self.inputs[self.pc]
        return super().load(address, n)


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
    count, payload, p, raw = z3.BitVecs('rs_count32 rs_payload32 rs_old_header32 rs_raw_extent32', 32)
    v = Lift()
    v.seed('w8', count^0x8b3dc651)
    v.seed('w11', 0x4183)
    v.run_block(*R.SPANS['scale'])
    prove('original_count_scaled_by_four', z3.Or(v.read('w8') != (count<<2)^0x8b3dc651, v.read('w10') != 0xca23))
    v = Lift()
    v.seed('w8', payload^0x8b3dc651)
    v.seed('w10', 0xca23)
    v.run_block(R.SPANS['overhead'][0], 0x10077d1ac)
    prove('original_twenty_byte_span_overhead', v.read('w13') != (payload+20)^0x8b3dc651)
    sp = z3.BitVec('rs_frame64', 64)
    v = Lift()
    v.seed('sp', sp)
    v.seed('w13', payload)
    v.run_block(0x10077d1ac, 0x10077d1b4)
    assert len(v.stores) == 1
    prove('original_span_spill', z3.Or(v.stores[0]['address'] != sp+0x48cc,
          v.stores[0]['size_bytes'] != 4, v.stores[0]['value'] != payload))
    v = Lift()
    for name, value in {'sp': R.SP, 'w10': 0x493, 'w13': payload^0x8b3dc651, 'w11': 0}.items():
        v.seed(name, value)
    mem(v, R.SP+0x64a8, 4, p^0x8b3dc651)
    v.run_block(*R.SPANS['sum'])
    prove('original_old_header_plus_new_span', v.read('w12') != p+payload)
    a = z3.BitVec('rs_requested_header32', 32)
    v = Lift()
    for name, value in {'sp': R.LSP, 'w27': p^0x8b3dc651, 'w22': raw, 'w21': a}.items():
        v.seed(name, value)
    mem(v, R.LSP+0x19c, 4, 0x0ec513e8)
    v.run_block(*R.SPANS['later_growth_math'])
    prove('original_later_resize_generic_raw_count', v.read('w8') != raw+a-p)
    span = (count<<2)+20
    a = p+span
    prove('composed_first_resize_count_increment', raw+a-p+0xef133bef != raw+0xef133bef+span)
    packed = z3.BitVec('rs_packed32', 32)
    n = z3.LShR(packed, 27)
    scalar = z3.If(n == 0, packed, packed&((z3.BitVecVal(1, 32)<<n)-1))
    v = Lift()
    v.seed('w10', packed^0x8b3dc651)
    v.seed('w4', 0x8b3dc651)
    v.run_block(*R.SPANS['later_extract'])
    prove('original_later_decoder_scalar_extraction_including_zero_count', v.read('w8') != scalar)
    high = z3.BitVec('rs_offset_high28', 28)
    base = z3.BitVec('rs_buffer64', 64)
    data = [z3.BitVec('rs_input_byte'+str(j), 8) for j in range(4)]
    banks = [(0x278, 0x100f21190, 16), (0x270, 0x100fa38b0, 20), (0x280, 0x100ffc9e0, 17)]
    for residue in range(16):
        offset = z3.Concat(high, z3.BitVecVal(residue, 4))
        v = Reader(data)
        for name, value in {'sp': R.LSP, 'x10': base, 'w8': offset-0xbddaaacc, 'w4': 0x8b3dc651}.items():
            v.seed(name, value)
        protected = []
        for off, address, size in banks:
            mem(v, R.LSP+off, 8, address)
            protected.extend([(R.LSP+off, 8), (address, size)])
            for j, byte in enumerate(IMAGE.read(address, size)):
                mem(v, address+j, 1, byte)
        v.run_block(*R.SPANS['later_reader_math'])
        decoded = z3.Concat(*[b^R.S.STREAM[(residue+j)&15] for j, b in enumerate(data)])
        addresses = [base+z3.ZeroExt(32, offset+j) for j in range(4)]
        assert len(v.input_addresses) == 4
        prove('original_later_word_reader_common_mask_residue_'+str(residue), z3.Or(
              v.read('w10') != decoded^0x8b3dc651,
              *[actual != expected for actual, expected in zip(v.input_addresses, addresses)]),
              [z3.UGE(a-start, size) for a in addresses for start, size in protected])
    assert len(out) == 23
    return out


def replay(e):
    old, growth = R.parents()
    totals, current_key, row = Counter(), None, None
    for s in e['slices']:
        key = s['group'], s['class_index'], s['interval_index']
        if key != current_key:
            group, ci, ii = key
            packed = old['prefixes'][ci]['interval_packed'] if group == 'prefix' else (
                old['branches'][ci]['intervals'][ii]['interval_packed'] if group == 'branch' else growth['classes'][ci]['intervals'][ii]['interval_packed'])
            row = R.B.unpack(packed)
            current_key = key
        v = Trace(s['reads'], s['writes'])
        for k, value in enumerate(s['entry']['registers31']):
            v.seed('x'+str(k), int(value, 16))
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
            visit = row['source_visits'][j]
            pc = int(visit['pc'], 16)
            assert visit['bytes_hex'] == IMAGE.read(pc, 4).hex()
            ins = next(DEC.disasm(IMAGE.read(pc, 4), pc))
            assert not any(ins.reg_name(r).startswith(('v', 'q', 'd', 's')) and ins.reg_name(r) != 'sp'
                           for r in ins.regs_access()[0]+ins.regs_access()[1])
            v.one(ins)
            totals['source_visits_checked'] += 1
        assert v.ri == len(s['reads']) and v.wi == len(s['writes'])
        totals.update(read_events_checked=v.ri, write_events_checked=v.wi, slices_checked=1)
    return dict(totals)


def controls():
    rows = []
    for label, c, p, a, requested in [('interior_record_selected', 77, 20, 40, 97),
                                    ('root_scalar_substitution_changes_count', 77, 76, 40, 41)]:
        extent, header, operand = z3.BitVecs('rs_control_extent32 rs_control_header32 rs_control_operand32', 32)
        s = z3.Solver()
        s.add(extent == c, header == p, operand == a, extent+operand-header == requested)
        assert s.check() == z3.sat
        rows.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), 'old_extent32': c,
                     'old_header32': p, 'operand32': a, 'request32': requested, 'native_admission_established': False})
    return rows


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': obligations(), 'interpretation_controls': controls(),
            'universal_later_final_reencoding_established': False,
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
