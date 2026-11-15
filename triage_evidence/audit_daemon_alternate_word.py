#!/usr/bin/env python3
"""Alternative u32 reader equations, saved-context ABI and source composition.
O(parent bytes + selected replay*32 + source DAG) time/space, excluding solver
search (30 s/query). Universal normalizer lemmas justify explicit proof cuts;
no source, guest, IDB or retained execution is rewritten or extended.
"""
import json
import z3
from daemon_receive_tools import ROOT, SOURCE, TABLE, FIXUPS
from audit_daemon_append_fields import Lift
from audit_daemon_record_selection import replay
from audit_daemon_record_storage import word, index
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_alternate_word as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_record_selection.py', 'audit_daemon_record_storage.py',
        'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py', 'recover_daemon_return_bank_origins.py']


class LemmaLift(Lift):
    """Collect every read-before-write premise used by a normalizer lemma."""
    def __init__(self, variable):
        super().__init__()
        self.variable, self.written, self.context = self.key(variable), set(), {}

    def read(self, name):
        value = super().read(name)
        if name not in ['xzr', 'wzr'] and self.key(name) not in self.written and self.key(name) != self.variable:
            assert z3.is_bv_value(z3.simplify(value)), name
            self.context[name] = z3.simplify(value).as_long()
        return value

    def write(self, name, value):
        super().write(name, value)
        self.written.add(self.key(name))


class Reduced(Lift):
    def __init__(self, contexts):
        super().__init__()
        self.cuts, self.inputs, self.cores, self.contexts = [], {}, [], contexts

    def one(self, ins):
        for j, (a, b, src, dest) in enumerate(R.NORMALIZERS):
            if ins.address == a:
                self.inputs[j] = self.read(src)
                for reg, value in self.contexts[j].items():
                    assert z3.is_true(z3.simplify(self.read(reg) == value)), (hex(a), reg)
        super().one(ins)
        for j, (a, b, src, dest) in enumerate(R.NORMALIZERS):
            if ins.address+4 == b:
                assert j in self.inputs
                self.write(dest, self.inputs[j]^R.normalizer_key(j))
                self.cuts.append({'lemma_start': hex(a), 'end_exclusive': hex(b), 'source_register': src,
                                  'destination_register': dest, 'context': {r: hex(v) for r, v in self.contexts[j].items()}})
        for end, reg in [(0x100357fa8, 'x16'), (0x100358134, 'x4'), (0x100358334, 'x4'), (0x100358558, 'x1')]:
            if ins.address+4 == end:
                self.cores.append(self.read(reg))


class Reader(Reduced):
    def __init__(self, values, contexts):
        super().__init__(contexts)
        self.values, self.loads = values, []

    def load(self, address, n):
        assert self.pc in self.values, hex(self.pc)
        size, value = self.values[self.pc]
        assert size == n
        self.loads.append((self.pc, address, n))
        return value if z3.is_bv(value) else z3.BitVecVal(value, 8*n)


def obligations():
    out, contexts = [], []
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat
        s.add(z3.simplify(bad))
        answer = s.check()
        assert answer == z3.unsat, (label, str(answer), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    x = z3.BitVec('alt_normalizer_input64', 64)
    for j, (a, b, src, dest) in enumerate(R.NORMALIZERS):
        v = LemmaLift(src)
        seeds = {'x19': R.KEYS[2], 'x8': R.KEYS[0] if j >= 24 else R.KEYS[4],
                 'x10': R.KEYS[5], 'x21': R.KEYS[6], 'x9': R.KEYS[7], 'x5': R.KEYS[1]}
        for reg, value in seeds.items():
            v.seed(reg, value)
        v.seed(src, x)
        v.run_block(a, b)
        prove('normalizer_'+hex(a), v.read(dest) != x^R.normalizer_key(j))
        contexts.append(v.context)
    c, mask = z3.BitVecs('alt_offset32 alt_table_mask32', 32)
    base, table, saved, incoming, key_input = z3.BitVecs('alt_base64 alt_table64 alt_saved_caller64 alt_incoming_caller64 alt_key_input64', 64)
    cache = [z3.BitVec('alt_cache'+str(j)+'64', 64) for j in range(4)]
    raw = [z3.BitVec('alt_raw'+str(j)+'8', 8) for j in range(4)]
    frame, u = 0x680005fa30, 0x6600060000
    values = {0x100357e2c: (8, base), 0x100357e6c: (4, mask), 0x100357e70: (8, table),
              0x100357e78: (8, cache[0]), 0x100357f04: (1, raw[0]),
              0x100357fdc: (8, cache[1]), 0x100357fe4: (1, raw[1]), 0x10035808c: (8, saved),
              0x100358154: (8, cache[2]), 0x10035832c: (1, raw[2]),
              0x100358360: (8, cache[3]), 0x100358588: (1, raw[3]),
              0x1003585c0: (8, FIXUPS[TABLE+8*0x602d]['target'])}
    v = Reader(values, contexts)
    protected = {reg: z3.BitVec('alt_preserved_'+reg+'64', 64) for reg in ['x11', 'x12', 'x25', 'x26', 'x27', 'x28']}
    for reg, value in {**protected, 'sp': frame, 'x14': u, 'x13': TABLE, 'w15': c-0x89271580,
                       'x22': z3.ZeroExt(32, c), 'w6': 0x602d, 'x7': 0x1010c67d4, 'x8': 0x1010c8268,
                       'x0': incoming, 'x10': key_input, 'x9': 0x1010a1960,
                       'w19': 0x89271582, 'w20': 0x89271583, 'w21': 0xffff9684}.items():
        v.seed(reg, value)
    v.run_block(0x100357e2c, 0x1003585c8)
    assert len(v.cuts) == 32 and len(v.cores) == 4 and len(v.loads) == 13 and not v.stores
    addresses = [base+z3.ZeroExt(32, c+j) for j in range(4)]
    expected = {0x100357e2c: u, 0x100357e6c: 0x1010c67d4, 0x100357e70: 0x1010c8268,
                0x100357e78: table+index(addresses[0], mask), 0x100357f04: addresses[0],
                0x100357fdc: table+index(addresses[1], mask), 0x100357fe4: addresses[1], 0x10035808c: frame+0xa8,
                0x100358154: table+index(addresses[2], mask), 0x10035832c: addresses[2],
                0x100358360: table+index(addresses[3], mask), 0x100358588: addresses[3],
                0x1003585c0: TABLE+8*0x602d}
    prove('all_thirteen_source_load_addresses', z3.Or(*[address != expected[pc] for pc, address, n in v.loads]))
    for j, core in enumerate(v.cores):
        prove('composed_eight_round_word_byte_'+str(j), core != word(addresses[j], cache[j])^(R.WHITENING if j == 3 else 0))
    decoded = [z3.Extract(7, 0, z3.LShR(word(addresses[j], cache[j]), (addresses[j]&7)*8))^raw[j] for j in range(4)]
    prove('composed_full_u32_output', v.read('w16') != z3.Concat(*decoded)^0x8b3dc651)
    prove('preserved_count_cursor_endpoint_and_dispatch_context', z3.Or(*[v.read(reg) != value for reg, value in protected.items()],
          v.read('sp') != frame, v.read('x13') != TABLE, v.read('x14') != u, v.read('w15') != c-0x89271580,
          v.read('w6') != 0x602d, v.read('x7') != 0x1010c67d4))
    prove('scratch_roundtrip_and_restored_phase_registers', z3.Or(v.read('x10') != key_input, v.read('x0') != saved,
          v.read('x9') != 0x1010a1960, v.read('x19') != 0x89271582, v.read('x20') != 0x89271583, v.read('x21') != 0xffff9684))
    prove('same_word_return_bridge_and_IA_modifier', z3.Or(v.read('x1') != 0x1003ec410, v.read('x17') != 0x143b))
    cuts = v.cuts
    address = z3.BitVec('alt_table_address64', 64)
    prove('mask255_bounds_all_four_cache_loads', z3.Or(z3.UGT(index(address, z3.BitVecVal(255, 32)), 248),
          index(address, z3.BitVecVal(255, 32))&7 != 0))
    prove('arbitrary_mask_preserves_eight_byte_alignment', index(address, mask)&7 != 0)
    shift = (x&7)*8
    y = z3.BitVec('alt_extract_word64', 64)
    prove('fourth_word_whitening_selects_byte_7e', z3.Extract(7, 0, z3.LShR(y^R.WHITENING, shift)) != z3.Extract(7, 0, z3.LShR(y, shift))^0x7e)
    b = [z3.BitVec('alt_decoded_byte'+str(j)+'8', 8) for j in range(4)]
    v = Lift()
    for reg, value in {'w16': z3.ZeroExt(24, b[0]), 'w30': z3.ZeroExt(24, b[1]), 'w22': z3.ZeroExt(24, b[2])}.items():
        v.seed(reg, value)
    v.run_block(0x100358560, 0x100358588)
    v.seed('w17', z3.ZeroExt(24, b[3]^0x7e))
    v.run_block(0x100358594, 0x1003585c0)
    prove('final_assembly_cancels_fourth_byte_whitening', v.read('w16') != z3.Concat(*b)^0x8b3dc651)
    return out, cuts


def controls():
    """Scalar interpretation checks only; no serialized target inputs."""
    address, saved, incoming = z3.BitVecs('alt_control_address64 alt_control_saved64 alt_control_incoming64', 64)
    b = [z3.BitVec('alt_control_byte'+str(j)+'8', 8) for j in range(4)]
    specs = [
        ('direct_word_can_have_high_bit', z3.Concat(*b) == z3.BitVecVal(0x80000000, 32), 'sat'),
        ('arbitrary_mask_does_not_establish_256_byte_table', z3.UGT(index(address, z3.BitVecVal(0xffffffff, 32)), 248), 'sat'),
        ('saved_caller_need_not_equal_current_scratch', saved != incoming, 'sat'),
        ('fourth_byte_whitening_cannot_be_omitted', z3.Concat(b[0], b[1], b[2], b[3]^0x7e) == z3.Concat(*b), 'unsat')]
    out = []
    for label, condition, expected in specs:
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(condition)
        assert str(s.check()) == expected
        out.append({'label': label, 'result': expected, 'query': s.to_smt2(),
                    'source_scalar_model_only': True, 'native_admission_established': False})
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e == R.extract()
    proofs, cuts = obligations()
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'independent_totals': replay(e), 'source_proofs': proofs, 'interpretation_controls': controls(),
            'proof_cut_lemmas': 32, 'proof_cut_applications': 32, 'proof_cut_contexts_verified': cuts,
            'alternative_word_decoder_contract_established': True,
            'alternative_word_observed': False, 'native_representation_admission_established': False,
            'target_instruction_rewrites': 0, 'prior_admissions_rerun': False, 'new_target_intervals': 0,
            'new_guest_input_bytes': 0, 'new_API_return_premises': 0, 'native_target_executed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps({'source_proofs': len(a['source_proofs']), **a['independent_totals']}), flush=True)
