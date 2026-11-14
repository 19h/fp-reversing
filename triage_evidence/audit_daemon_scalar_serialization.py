#!/usr/bin/env python3
"""Independent word reader/decoder contracts and selected source replay.
O(parent bytes + selected visits*32 + proof DAG) time/space; solver search
is separate with 30 s/query. No native operation or prior admission rerun.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, qword
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number
from lskd_values_symbolic import mem
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_scalar_serialization as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py']


class Reader(Lift):
    """Bind input bytes, while proving actual source addresses in each query."""
    def __init__(self, data):
        super().__init__()
        self.inputs = dict(zip([0x1008c6128, 0x1008c6184, 0x1008c61dc, 0x1008c6230], data))
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
    high = z3.BitVec('ss_offset_high28', 28)
    base = z3.BitVec('ss_buffer64', 64)
    data = [z3.BitVec('ss_byte'+str(j), 8) for j in range(4)]
    for residue in range(16):
        offset = z3.Concat(high, z3.BitVecVal(residue, 4))
        addresses = [base+z3.ZeroExt(32, offset+j) for j in range(4)]
        v = Reader(data)
        v.seed('sp', R.SP)
        v.seed('w8', offset-0xbddaaacc)
        v.seed('x9', base)
        v.seed('w10', 0x1305)
        mem(v, R.SP+0x9d8, 8, 0x101039ef0)
        mem(v, R.SLOTS[0], 8, qword(R.SLOTS[0]))
        protected = [(R.SP+0x9d8, 8), (R.SLOTS[0], 8)]
        for off, a, n in R.C.BANKS.values():
            mem(v, R.SP+off, 8, a)
            protected.extend([(R.SP+off, 8), (a, n)])
            for j, b in enumerate(IMAGE.read(a, n)):
                mem(v, a+j, 1, b)
        v.run_block(*R.SPANS['word_reader'])
        packed = z3.Concat(*[b^R.STREAM[(residue+j)&15] for j, b in enumerate(data)])
        assert len(v.input_addresses) == 4
        premises = [z3.UGE(a-start, n) for a in addresses for start, n in protected]
        prove('original_word_reader_common_mask_residue_'+str(residue), z3.Or(
              v.read('w9') != packed^0x8b3dc651, v.read('w8') != 0x8b3dc651,
              v.read('x10') != 0x10076c4b8, v.read('x17') != 0x1890,
              *[actual != expected for actual, expected in zip(v.input_addresses, addresses)]), premises)
    packed = z3.BitVec('ss_packed32', 32)
    n = z3.LShR(packed, 27)
    scalar = z3.If(n == 0, packed, packed&((z3.BitVecVal(1, 32)<<n)-1))
    v = Lift()
    v.seed('w9', packed^0x8b3dc651)
    v.seed('w8', 0x8b3dc651)
    v.run_block(*R.SPANS['decoder_math'])
    prove('original_word_decoder_including_zero_count', v.read('w20') != scalar^0x8b3dc651)
    prove('composed_word_decoder_unsigned_bound', z3.UGT(scalar, 0x7fffffff))
    frame = z3.BitVec('ss_frame64', 64)
    value = z3.BitVec('ss_stored32', 32)
    v = Lift()
    v.seed('sp', frame)
    v.seed('w20', value)
    v.run_block(*R.SPANS['word_store'])
    assert len(v.stores) == 1
    prove('original_decoded_word_spill', z3.Or(v.stores[0]['address'] != frame+0x64a8,
          v.stores[0]['size_bytes'] != 4, v.stores[0]['value'] != value))
    a, width, d = z3.BitVecs('ss_aux32 ss_width32 ss_scalar32', 32)
    produced = (((a<<width)&0x07ffffff)|(width<<27))+d
    produced_n = z3.LShR(produced, 27)
    inverse = z3.If(produced_n == 0, produced, produced&((z3.BitVecVal(1, 32)<<produced_n)-1))
    prove('composed_paired_word_scalar_inverse', inverse != d,
          [z3.UGE(width, 1), z3.ULE(width, 27), z3.ULT(d, z3.BitVecVal(1, 32)<<width)])
    assert len(out) == 20
    return out


def replay(e):
    old, _, _ = R.parents()
    totals = Counter()
    for c in e['prefixes']:
        row = R.B.unpack(old['prefixes'][c['prefix_class_index']]['interval_packed'])
        for s in c['slices']:
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
                v.one(next(DEC.disasm(IMAGE.read(pc, 4), pc)))
                totals['source_visits_checked'] += 1
            assert v.ri == len(s['reads']) and v.wi == len(s['writes'])
            totals.update(read_events_checked=v.ri, write_events_checked=v.wi, slices_checked=1)
        for item, s in zip(c['edges'], c['slices'][:2]):
            edge = item['edge']
            assert s['exit']['registers31'][item['target_register']] == edge['target']
            assert s['exit']['registers31'][17] == edge['modifier']
            totals['logical_edges_checked'] += 1
    return dict(totals)


def controls():
    rows = []
    for label, value, expected in [('zero_count_shift_wrap', 0x01234567, 0x01234567),
                                   ('maximum_decoder_result', 0xffffffff, 0x7fffffff)]:
        p = z3.BitVec('ss_control_packed32', 32)
        n = z3.LShR(p, 27)
        d = z3.If(n == 0, p, p&((z3.BitVecVal(1, 32)<<n)-1))
        s = z3.Solver()
        s.add(p == value, d == expected)
        assert s.check() == z3.sat
        rows.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), 'packed32': hex(value),
                     'decoded_scalar32': hex(expected), 'native_admission_established': False})
    return rows


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': obligations(), 'format_controls': controls(),
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
