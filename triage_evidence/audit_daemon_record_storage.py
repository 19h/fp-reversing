#!/usr/bin/env python3
"""Source-local alternate storage contracts and independent saved-cell replay.
O(receipt bytes + replay visits*32 + symbolic DAG) time/space, excluding solver
search (30 s/query). Universal normalizer lemmas justify explicit proof cuts;
cuts never modify target bytes, an IDB, a guest state or a retained journal.
"""
import json
import z3
from daemon_receive_tools import ROOT, SOURCE
from audit_daemon_append_fields import Lift, number
from audit_daemon_record_selection import replay
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_record_storage as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_record_selection.py', 'audit_daemon_environment_outputs.py',
        'lskd_values_symbolic.py', 'recover_daemon_return_bank_origins.py', 'daemon_cache_publication_model.py']


def word(address, cached):
    x, y = address & ~7, cached
    for j, k in enumerate(R.KEYS):
        x = (z3.RotateRight(x, 8)+y)^k
        if j < 7:
            y = x^z3.RotateRight(y, 61)
    return x


def index(address, mask):
    return z3.SignExt(32, ((z3.Extract(31, 0, address)&0xfffffff8)+0x1cecdea8)&mask)


class Reduced(Lift):
    """Apply only the separately proved universal XOR normalizer equations."""
    def __init__(self):
        super().__init__()
        self.cuts = []
        self.inputs = {}

    def one(self, ins):
        for a, b, reg, j in R.NORMALIZERS:
            if ins.address == a:
                self.inputs[a] = self.read(reg)
        super().one(ins)
        for a, b, reg, j in R.NORMALIZERS:
            if ins.address+4 == b:
                assert a in self.inputs
                self.write(reg, self.inputs[a]^R.KEYS[j])
                self.cuts.append({'start': hex(a), 'end_exclusive': hex(b), 'register': reg, 'round': j})


class Reader(Reduced):
    def __init__(self, values):
        super().__init__()
        self.values, self.loads = values, []

    def load(self, address, n):
        assert self.pc in self.values, hex(self.pc)
        expected_n, value = self.values[self.pc]
        assert n == expected_n
        self.loads.append((self.pc, address, n))
        return value if z3.is_bv(value) else z3.BitVecVal(value, 8*n)


def obligations():
    proofs, counts = [], {}
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat
        s.add(z3.simplify(bad))
        answer = s.check()
        assert answer == z3.unsat, (label, str(answer), s.reason_unknown())
        proofs.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    x, y, address = z3.BitVecs('storage_x64 storage_y64 storage_address64', 64)
    for a, b, reg, j in R.NORMALIZERS:
        v = Lift()
        for n, value in {reg: x, 'x4': R.KEYS[1], 'x9': R.KEYS[7]}.items():
            v.seed(n, value)
        v.run_block(a, b)
        prove('normalizer_'+hex(a), v.read(reg) != x^R.KEYS[j])
    for a, b, seeds, output in [(0x100495c88, 0x100495e84, {'x16': address&~7, 'x3': y}, 'x16'),
                               (0x100495eb0, 0x100495fe4, {'x1': address&~7, 'x16': y, 'x4': R.KEYS[1], 'x9': R.KEYS[7]}, 'x16')]:
        v = Reduced()
        for reg, value in seeds.items():
            v.seed(reg, value)
        v.run_block(a, b)
        assert len(v.cuts) == 8
        prove('composed_eight_round_word_'+hex(a), v.read(output) != word(address, y))
    base, table, off0, off1, cache0, cache1 = z3.BitVecs('storage_base64 storage_table64 storage_off064 storage_off164 storage_cache064 storage_cache164', 64)
    mask = z3.BitVec('storage_mask32', 32)
    raw0, raw1 = z3.BitVecs('storage_raw08 storage_raw18', 8)
    frame, u = 0x680005fa30, 0x6600060000
    values = {0x100495c44: (8, base), 0x100495c48: (8, off0), 0x100495c68: (4, mask),
              0x100495c6c: (8, 0x1010c8268), 0x100495c70: (8, table), 0x100495c84: (8, cache0),
              0x100495e8c: (1, raw0), 0x100495e94: (8, off1), 0x100495eac: (8, cache1), 0x100495ff4: (1, raw1)}
    v = Reader(values)
    for reg, value in {'w6': 0x6ce1, 'x14': u, 'sp': frame, 'x7': 0x1010c67d4}.items():
        v.seed(reg, value)
    v.run_block(0x100495c3c, 0x10049601c)
    assert len(v.cuts) == 16 and len(v.loads) == 10 and not v.stores
    a0, a1 = base+off0, base+off1
    expected = {0x100495c44: u, 0x100495c48: frame+0x58, 0x100495c68: 0x1010c67d4,
                0x100495c6c: frame+0xb0, 0x100495c70: 0x1010c8268,
                0x100495c84: table+index(a0, mask), 0x100495e8c: a0,
                0x100495e94: frame+0x50, 0x100495eac: table+index(a1, mask), 0x100495ff4: a1}
    prove('all_load_addresses_and_live_handover', z3.Or(*[at != expected[pc] for pc, at, n in v.loads],
          v.read('w6') != 0x3a61, v.read('w17') != 0x4dc0, v.read('x9') != 0x1010a1960))
    d0 = z3.Extract(7, 0, z3.LShR(word(a0, cache0), (a0&7)*8))^raw0
    d1 = z3.Extract(7, 0, z3.LShR(word(a1, cache1), (a1&7)*8))^raw1
    half = z3.Concat(d0, d1)
    prove('composed_decoded_halfword_transform', z3.Extract(15, 0, v.read('w1')) != (half^0x7390)+14)
    counts['reader_source_instructions'] = (0x10049601c-0x100495c3c)//4
    counts['reader_loads'] = len(v.loads)
    counts['reader_writes'] = len(v.stores)
    counts['proof_cuts'] = 32
    p, q = z3.BitVecs('storage_first32 storage_second32', 32)
    v = Lift()
    v.seed('w3', p)
    v.seed('w16', q)
    v.run_block(0x100495ffc, 0x10049601c)
    merged = (p << 8)|(q&255)
    prove('all_u32_merge_and_transform', v.read('w1') != (merged^0x7390)+14)
    h = z3.BitVec('storage_decoded16', 16)
    prove('transformed_comparison_iff_decoded_u16_zero', (((h^0x7390)+14) == 0x739e) != (h == 0))
    prove('mask255_index_bounds', z3.Or(z3.UGT(index(address, z3.BitVecVal(255, 32)), 248), index(address, z3.BitVecVal(255, 32))&7 != 0))
    prove('all_masks_preserve_index_alignment', index(address, mask)&7 != 0)
    prove('adjacent_bytes_same_cache_index_iff_same_aligned_word',
          (index(address, z3.BitVecVal(255, 32)) == index(address+1, z3.BitVecVal(255, 32))) != (address&7 != 7))
    o = z3.BitVec('storage_offset32', 32)
    v = Lift()
    v.seed('sp', frame)
    v.seed('w23', o-0x89271580)
    v.seed('w16', 0xbff7)
    v.run_block(*R.SPANS['saved_offsets'])
    saved0 = v.stores[0]['value']
    saved1 = v.stores[2]['value']
    prove('saved_offsets_are_successive_zero_extended_u32', z3.Or(
        saved0 != z3.ZeroExt(32, o+14), v.stores[1]['value'] != z3.ZeroExt(32, o+14),
        saved1 != z3.ZeroExt(32, o+15), v.stores[0]['address'] != frame+0x58,
        v.stores[1]['address'] != frame+0x60, v.stores[2]['address'] != frame+0x50))
    end = z3.BitVec('storage_record_end32', 32)
    v = Lift()
    for reg, value in {'w16': 0xffffffec, 'w21': 0xffff9684, 'w24': 0x89271580, 'w15': end-0x89271580}.items():
        v.seed(reg, value)
    v.run_block(0x1004bad90, 0x1004bade4)
    want = z3.If(z3.ULE(end, 0xffffffeb), z3.BitVecVal(0x1bec, 32), z3.BitVecVal(0x1bc3, 32))
    prove('mismatch_end_plus20_strictly_below_u32_limit', v.read('w16') != want)
    prove('mismatch_continue_condition_equivalence', z3.ULE(end, 0xffffffeb) != z3.ULT(z3.ZeroExt(32, end)+20, 1 << 32))
    v = Lift()
    v.run_block(0x1004bade8, 0x1004badf4)
    prove('mismatch_rebuilds_encoded_zero_and_IA_modifier', z3.Or(v.read('w2') != 0x76d8ea80, v.read('x17') != 0xcb9a))
    return proofs, counts


def controls():
    a = z3.BitVec('storage_control_address64', 64)
    h = z3.BitVec('storage_control_half16', 16)
    queries = [('zero_halfword_accepts', z3.And(h == 0, ((h^0x7390)+14) == 0x739e)),
               ('nonzero_halfword_rejects', z3.And(h == 1, ((h^0x7390)+14) != 0x739e)),
               ('arbitrary_mask_does_not_imply_bounds', z3.UGT(index(a, z3.BitVecVal(0xffffffff, 32)), 248)),
               ('mask1_cannot_destroy_index_alignment', index(a, z3.BitVecVal(1, 32))&7 != 0)]
    out = []
    for name, condition in queries:
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(condition)
        expected = z3.unsat if name.startswith('mask1') else z3.sat
        assert s.check() == expected
        out.append({'label': name, 'result': str(expected), 'query': s.to_smt2()})
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    proofs, counts = obligations()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': proofs, 'interpretation_controls': controls(),
            'composition_counts': counts, 'proof_cut_lemmas': 16, 'target_instruction_rewrites': 0,
            'alternate_path_observed': False, 'native_storage_admission_established': False,
            'same_keys_as_cached_consumer': False, 'complete_mismatch_result_established': False,
            'prior_admissions_rerun': False, 'new_target_intervals': 0, 'new_guest_input_bytes': 0,
            'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps({'source_proofs': len(a['source_proofs']), **a['independent_totals']}), flush=True)
