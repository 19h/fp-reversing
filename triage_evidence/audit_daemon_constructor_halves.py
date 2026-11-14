#!/usr/bin/env python3
"""Independent constructor halfword contracts and selected source replay.
O(parent bytes + selected visits*32 + proof DAG) time/space, excluding solver
search. Queries have a 30 s bound. No native operation or admission rerun.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from audit_daemon_environment_outputs import DEC
from audit_daemon_append_fields import Lift, Trace, number, masks
from lskd_values_symbolic import mem, resize
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_constructor_halves as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py',
        'lskd_values_symbolic.py', 'recover_daemon_append_fields.py']


class Reader(Lift):
    """Bind the two symbolic bytes; prove their actual addresses in the query."""
    def __init__(self, first, second):
        super().__init__()
        self.inputs = {0x1007558b8: first, 0x100755924: second}
        self.input_addresses = []

    def load(self, address, n):
        if self.pc in self.inputs:
            assert n == 1
            self.input_addresses.append(address)
            return self.inputs[self.pc]
        return super().load(address, n)


def banks(v):
    protected = []
    for off, a, n in R.BANKS.values():
        mem(v, R.SP+off, 8, a)
        protected.extend([(R.SP+off, 8), (a, n)])
        for j, b in enumerate(IMAGE.read(a, n)):
            mem(v, a+j, 1, b)
    return protected


def obligations():
    proofs = []
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat, label
        s.add(z3.simplify(bad))
        result = s.check()
        assert result == z3.unsat, (label, str(result), s.reason_unknown())
        proofs.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    high = z3.BitVec('ch_offset_high28', 28)
    base = z3.BitVec('ch_buffer64', 64)
    first, second = z3.BitVecs('ch_first8 ch_second8', 8)
    encoded = z3.BitVec('ch_writer_input32', 32)
    for residue in range(16):
        offset = z3.Concat(high, z3.BitVecVal(residue, 4))
        addresses = [base+z3.ZeroExt(32, offset), base+z3.ZeroExt(32, offset+1)]
        v = Reader(first, second)
        v.seed('sp', R.SP)
        v.seed('w10', 0x9512)
        v.seed('w12', offset)
        v.seed('w9', offset << 1)
        v.seed('x21', 0x6600060000)
        protected = banks(v)+[(0x6600060008, 8)]
        mem(v, 0x6600060008, 8, base)
        v.run_block(R.SPANS['reader'][0], 0x1007559a0)
        m0, m1 = masks('half_writer', residue)
        packed = z3.Concat(first^m0, second^m1)^0x534c
        n = z3.ZeroExt(28, z3.Extract(15, 12, packed))
        scalar = z3.ZeroExt(16, packed)&((z3.BitVecVal(1, 32)<<n)-1)
        premises = [z3.UGE(address-start, length) for address in addresses for start, length in protected]
        assert len(v.input_addresses) == 2
        prove('original_constructor_reader_residue_'+str(residue), z3.Or(v.read('w9') != scalar, v.read('w10') != 0x9512,
              *[actual != expected for actual, expected in zip(v.input_addresses, addresses)]), premises)
        v = Lift()
        v.seed('sp', R.SP)
        v.seed('x10', base)
        v.seed('w11', offset)
        v.seed('w8', encoded)
        protected = banks(v)
        v.run_block(*R.SPANS['writer_math'])
        assert len(v.stores) == 2
        value = resize(encoded, 16)^0xdf8
        common_mixed = value^0x534c
        expected = [z3.Extract(15, 8, common_mixed)^m0, resize(common_mixed, 8)^m1]
        premises = [z3.UGE(address-start, length) for address in addresses for start, length in protected]
        prove('original_constructor_writer_residue_'+str(residue), z3.Or(*[
            z3.Or(w['address'] != address, w['value'] != byte, w['size_bytes'] != 1)
            for w, address, byte in zip(v.stores, addresses, expected)]), premises)
    a, n, k = z3.BitVecs('ch_auxiliary32 ch_width32 ch_scalar_key32', 32)
    v = Lift()
    v.seed('w8', a)
    v.seed('w9', a&255)
    v.run_block(*R.SPANS['auxiliary'])
    prove('original_constructor_auxiliary_identity', resize(v.read('w8'), 16) != resize(a, 16))
    v = Lift()
    v.seed('w8', a)
    v.seed('w21', n)
    v.run_block(*R.SPANS['shift'])
    prove('original_constructor_auxiliary_shift', resize(v.read('w8'), 16) != resize((((a&65535)<<(n&31))^0x318)&0xfff, 16))
    v = Lift()
    v.seed('w8', a&0xfff)
    v.seed('w21', n)
    v.run_block(*R.SPANS['pack'])
    prove('original_constructor_count_pack', resize(v.read('w8'), 16) != resize((a&0xfff)|(n<<12), 16)^0x8c27)
    v = Lift()
    v.seed('w8', a)
    v.seed('w20', k)
    v.run_block(*R.SPANS['scalar_add'])
    prove('original_constructor_scalar_add', resize(v.read('w8'), 16) != resize((a^0x8f3f)+((k^0xdf8)&65535)+0x92b, 16))
    v = Lift()
    v.seed('w8', a)
    v.run_block(*R.SPANS['producer_tail'])
    prove('original_constructor_producer_tail', resize(v.read('w8'), 16) != resize(a-0x92b, 16)^0xdf8)
    d = z3.BitVec('ch_decoded16', 16)
    wide = z3.ZeroExt(16, d)
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('w9', wide)
    mem(v, R.SP+0x9d0, 8, 0x6cf4)
    v.run_block(R.SPANS['zero_gate'][0], 0x1008c8884)
    assert len(v.stores) == 1
    prove('original_constructor_zero_gate_and_increment_interface', z3.Or(
          v.read('w14') != z3.If(d == 0, z3.BitVecVal(0xa085, 32), z3.BitVecVal(0xa05f, 32)),
          v.read('w8') != 0x7429, v.read('w10') != wide^0xe6eef3fb,
          v.read('w11') != 0xa05f, v.read('w12') != (wide<<1)&0x1e7f6, v.read('w13') != 0x7ff7cfe0,
          v.stores[0]['address'] != R.SP+0x868e, v.stores[0]['value'] != d))
    q, x, y, z = z3.BitVecs('ch_header_word32 ch_carry10 ch_carry12 ch_carry13', 32)
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('w11', 0xa05f)
    v.seed('w10', x)
    v.seed('w12', y)
    v.seed('w13', z)
    mem(v, R.SP+0x64a8, 4, q^0x8b3dc651)
    v.run_block(R.SPANS['zero_header_gate'][0], 0x10084dba4)
    prove('original_zero_route_unsigned_header_limit', z3.Or(
          v.read('w11') != z3.If(z3.ULT(q, 21), z3.BitVecVal(0xa05f, 32), z3.BitVecVal(0xbc52, 32)),
          v.read('w8') != 0x7429, v.read('w10') != x, v.read('w12') != y, v.read('w13') != z))
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('w8', 0x7429)
    v.seed('w10', wide^0xe6eef3fb)
    v.seed('w12', (wide<<1)&0x1e7f6)
    v.seed('w13', 0x7ff7cfe0)
    v.run_block(*R.SPANS['scalar_store'])
    assert len(v.stores) == 1
    prove('original_constructor_increment_encoded_cell', z3.Or(
          v.stores[0]['address'] != R.CELL, v.stores[0]['size_bytes'] != 4,
          v.stores[0]['value'] != (wide+1)^0x28e36a4a))
    v = Lift()
    v.seed('sp', R.SP)
    mem(v, R.CELL, 2, d)
    v.run_block(*R.SPANS['scalar_prepare'])
    prove('original_constructor_scalar_cell_to_producer_key', v.read('w20') != wide^0x67b2)
    p = z3.BitVec('ch_packed16', 16)
    pw = z3.ZeroExt(16, p)
    decoded = pw&((z3.BitVecVal(1, 32)<<z3.LShR(pw, 12))-1)
    cell = (decoded+1)^0x28e36a4a
    producer_d = (z3.ZeroExt(16, resize(cell, 16))^0x67b2^0xdf8)&65535
    prove('composed_constructor_reader_increment_width_bound', z3.Or(z3.UGT(decoded, 32767), producer_d != decoded+1))
    auxiliary, count, scalar = z3.BitVecs('ch_composed_aux32 ch_composed_count32 ch_composed_scalar32', 32)
    value = resize((((auxiliary<<count)&0xfff)|(count<<12))+scalar, 16)
    decoded_count = z3.LShR(z3.ZeroExt(16, value), 12)
    inverse = z3.ZeroExt(16, value)&((z3.BitVecVal(1, 32)<<decoded_count)-1)
    prove('composed_constructor_producer_scalar_inverse', inverse != scalar,
          [z3.UGE(count, 1), z3.ULE(count, 12), z3.ULT(scalar, z3.BitVecVal(1, 32)<<count)])
    assert len(proofs) == 43
    return proofs


def replay(e):
    parent = R.parents()
    totals = Counter()
    def cases():
        for p in e['prefixes']:
            yield p, R.B.unpack(parent['prefixes'][p['prefix_class_index']]['interval_packed'])
        for bi in sorted({f['branch_index'] for f in e['fields']}):
            row = R.B.unpack(parent['branches'][bi]['intervals'][1]['interval_packed'])
            for f in e['fields']:
                if f['branch_index'] == bi:
                    yield f, row
    for case, row in cases():
        for s in case['slices']:
            v = Trace(s['reads'], s['writes'])
            for k, value in enumerate(s['entry']['registers31']):
                v.seed('x'+str(k), int(value, 16))
            v.seed('sp', int(s['entry']['SP'], 16))
            flags = int(s['entry']['NZCV'], 16)
            v.n, v.z, v.carry, v.overflow = [z3.BoolVal(bool(flags&(1 << b))) for b in [31, 30, 29, 28]]
            for j in range(s['start_visit'], s['end_visit_exclusive']+1):
                frame = row['source_frames'][j]
                assert frame['Q_registers32'] == s['entry']['Q_registers32']
                for k in range(31):
                    assert number(v.read('x'+str(k))) == int(frame['registers31'][k], 16)
                assert number(v.read('sp')) == int(frame['SP'], 16)
                actual = [z3.simplify(t) for t in [v.n, v.z, v.carry, v.overflow]]
                assert all(z3.is_true(t) or z3.is_false(t) for t in actual)
                assert sum(int(z3.is_true(t)) << b for t, b in zip(actual, [31, 30, 29, 28])) == int(frame['NZCV'], 16)
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
        if 'edges' in case:
            for item, s in zip(case['edges'], case['slices'][1:3]):
                assert item['edge']['target'] in s['exit']['registers31']
                assert item['edge']['modifier'] == '0x62ce'
                totals['logical_edges_checked'] += 1
    return dict(totals)


def controls():
    rows = []
    for q, index in [(20, 0xa05f), (21, 0xbc52)]:
        x = z3.BitVec('ch_control_header32', 32)
        s = z3.Solver()
        s.add(x == q, z3.If(z3.ULT(x, 21), z3.BitVecVal(0xa05f, 32), z3.BitVecVal(0xbc52, 32)) == index)
        assert s.check() == z3.sat
        rows.append({'label': 'zero_header_boundary_'+str(q), 'result': 'sat', 'query': s.to_smt2(),
                     'decoded_word32': q, 'selected_index': hex(index), 'native_admission_established': False})
    return rows


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    result = {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
              'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
              'independent_totals': replay(e), 'source_proofs': obligations(), 'boundary_controls': controls(),
              'prior_admissions_rerun': False, 'new_target_intervals': 0,
              'new_guest_input_bytes': 0, 'new_API_return_premises': 0,
              'native_target_executed': False, 'full_goal_complete': False}
    return result


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
