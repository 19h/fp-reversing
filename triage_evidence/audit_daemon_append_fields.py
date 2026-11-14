#!/usr/bin/env python3
"""Independent selected-instruction replay and universal append-field codecs.
O(parent bytes + selected visits*32 + query DAG) time and
O(receipts + query DAG) space, excluding solver search; 30 s/query.
Pinned prior admissions qualify sharing; this audit does not rerun them.
"""
import json
from collections import Counter
import z3
from capstone.arm64 import ARM64_SFT_ASR, ARM64_OP_REG
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from audit_daemon_environment_outputs import DEC
from audit_daemon_state_table_mixing import Scalar
from lskd_values_symbolic import mem, resize
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_append_fields as R

DEPS = ['audit_daemon_state_table_mixing.py', 'audit_daemon_environment_outputs.py',
        'lskd_values_symbolic.py', 'recover_daemon_return_bank_origins.py']
MASK32 = (1 << 32)-1


class Lift(Scalar):
    def operand(self, ins, op, width):
        if op.shift.type == ARM64_SFT_ASR:
            assert op.type == ARM64_OP_REG and not op.ext
            return resize(self.read(ins.reg_name(op.reg)), width) >> op.shift.value
        return super().operand(ins, op, width)

    def one(self, ins):
        ops, kind = ins.operands, ins.mnemonic
        if kind == 'sxth':
            self.pc = ins.address
            self.write(ins.reg_name(ops[0].reg), z3.SignExt(16, resize(self.read(ins.reg_name(ops[1].reg)), 16)))
            return
        if kind in ['umull', 'sbfx', 'sbfiz']:
            self.pc = ins.address
            dest = ins.reg_name(ops[0].reg)
            n = self.width(dest)
            if kind == 'umull':
                assert n == 64
                value = z3.ZeroExt(32, resize(self.read(ins.reg_name(ops[1].reg)), 32))*z3.ZeroExt(32, resize(self.read(ins.reg_name(ops[2].reg)), 32))
            else:
                x = self.operand(ins, ops[1], n)
                k, w = ops[2].imm, ops[3].imm
                value = z3.SignExt(n-w, z3.Extract(k+w-1, k, x)) if kind == 'sbfx' else z3.SignExt(n-w, z3.Extract(w-1, 0, x)) << k
            self.write(dest, value)
            return
        return super().one(ins)


def number(x):
    x = z3.simplify(x)
    assert z3.is_bv_value(x), str(x)[:100]
    return x.as_long()


class Trace(Lift):
    def __init__(self, reads, writes):
        super().__init__()
        self.reads, self.writes = reads, writes
        self.ri = self.wi = 0

    def load(self, address, n):
        r = self.reads[self.ri]
        self.ri += 1
        assert (r['pc'], r['address'], r['size_bytes']) == (hex(self.pc), hex(number(address)), n)
        return z3.BitVecVal(int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little'), 8*n)

    def store(self, address, n, value, pc):
        w = self.writes[self.wi]
        self.wi += 1
        assert (w['pc'], w['address'], w['size_bytes']) == (hex(pc), hex(number(address)), n)
        assert number(resize(value, n*8)).to_bytes(n, 'little').hex() == w['after_hex']


class AliasedBytes(Scalar):
    """Concrete byte memory for the excluded output/table-alias control."""
    def __init__(self):
        super().__init__()
        self.bytes = {}
        for off, a, n in R.BANKS.values():
            for j, b in enumerate(a.to_bytes(8, 'little')):
                self.bytes[0x680005fb70+off+j] = b
            self.bytes.update({a+j: b for j, b in enumerate(IMAGE.read(a, n))})

    def load(self, address, n):
        a = number(address)
        return z3.BitVecVal(int.from_bytes(bytes(self.bytes[a+j] for j in range(n)), 'little'), 8*n)

    def store(self, address, n, value, pc):
        super().store(address, n, value, pc)
        a = number(address)
        self.bytes.update({a+j: b for j, b in enumerate(number(resize(value, 8*n)).to_bytes(n, 'little'))})


def replay(e):
    counts, out = Counter(), []
    occurrences = iter(e['occurrences'])
    for ci, ii, kind, lo, hi, row in R.slices(R.parents()):
        o = next(occurrences)
        assert (o['class_index'], o['interval_index'], o['kind'], o['start_visit'], o['end_visit_exclusive']) == (ci, ii, kind, lo, hi)
        v = Trace(o['reads'], o['writes'])
        for j, x in enumerate(o['entry']['registers31']):
            v.seed('x'+str(j), int(x, 16))
        v.seed('sp', int(o['entry']['SP'], 16))
        nzcv = int(o['entry']['NZCV'], 16)
        v.n, v.z, v.carry, v.overflow = [z3.BoolVal(bool(nzcv & (1 << bit))) for bit in [31, 30, 29, 28]]
        for j in range(lo, hi+1):
            f = row['source_frames'][j]
            assert f['Q_registers32'] == o['entry']['Q_registers32']
            actual_flags = 0
            for bit, x in zip([31, 30, 29, 28], [v.n, v.z, v.carry, v.overflow]):
                x = z3.simplify(x)
                assert z3.is_true(x) or z3.is_false(x)
                actual_flags |= int(z3.is_true(x)) << bit
            assert actual_flags == int(f['NZCV'], 16)
            for k in range(31):
                assert number(v.read('x'+str(k))) == int(f['registers31'][k], 16), (kind, j, k)
            assert number(v.read('sp')) == int(f['SP'], 16)
            counts.update(GP_SP_values_checked=32, NZCV_frames_checked=1)
            if j == hi:
                break
            visit = row['source_visits'][j]
            pc = int(visit['pc'], 16)
            assert visit['bytes_hex'] == IMAGE.read(pc, 4).hex()
            ins = next(DEC.disasm(IMAGE.read(pc, 4), pc))
            assert not any(ins.reg_name(r).startswith(('v', 'q', 'd', 's')) and ins.reg_name(r) != 'sp'
                           for r in ins.regs_access()[0]+ins.regs_access()[1])
            v.one(ins)
            counts['source_visits_checked'] += 1
        assert v.ri == len(o['reads']) and v.wi == len(o['writes'])
        counts.update(read_events_checked=v.ri, write_events_checked=v.wi, slices_checked=1)
        out.append({'class_index': ci, 'interval_index': ii, 'kind': kind, 'start_visit': lo,
                    'source_visits': hi-lo, 'reads': v.ri, 'writes': v.wi, 'all_checks_pass': True})
    assert next(occurrences, None) is None
    return out, dict(counts)


def masks(kind, offset):
    def b(bank, i):
        _, a, _ = R.BANKS[bank]
        return IMAGE.read(a+i, 1)[0]
    out = []
    for j in range(4 if kind == 'word_writer' else 2):
        k = (offset+j)&15
        if kind == 'word_writer' and j == 0:
            m = b('B', k)^b('C', k+3)^b('A', k+1)^(33*k)^0x12
        else:
            c = [0, 0x7e, 0x74, 0xff][j] if kind == 'word_writer' else [0x98, 0x87][j]
            m = b('D', k)^b('E', k+4)^b('K', k+1)^(31*k)^c
        out.append(m&255)
    return out


def seeded(kind, offset, base, word, second=None):
    v = Scalar()
    sp = 0x680005fb70
    v.seed('sp', sp)
    for off, a, _ in R.BANKS.values():
        mem(v, sp+off, 8, a)
    for _, a, n in R.BANKS.values():
        for j, b in enumerate(IMAGE.read(a, n)):
            mem(v, a+j, 1, b)
    if kind == 'word_writer':
        v.seed('x9', base)
        v.seed('w10', offset-0xae20ac2a)
        v.seed('w11', word)
    else:
        v.seed('x22', base)
        v.seed('w21', offset-0x8927158e)
        v.seed('w8', word)
        v.seed('w10', second)
    v.run_block(*R.SPANS[kind])
    return v


def protected_ranges(kind):
    keys = list(R.BANKS) if kind == 'word_writer' else ['D', 'E', 'K']
    return [(0x680005fb70+R.BANKS[k][0], 8) for k in keys]+[(R.BANKS[k][1], R.BANKS[k][2]) for k in keys]


def disjoint_outputs(kind, v):
    # Unsigned modular distance handles all u64 bases, including addition wrap.
    # These fixed source spans themselves do not wrap at the u64 boundary.
    return [z3.UGE(w['address']-a, n) for w in v.stores for a, n in protected_ranges(kind)]


def obligations():
    out = []
    def prove(label, bad, premises=(), **extra):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat
        s.add(z3.simplify(bad))
        result = s.check()
        assert result == z3.unsat, (label, str(result), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2(), **extra})
    high = z3.BitVec('append_offset_high28', 28)
    base = z3.BitVec('append_base64', 64)
    word, second = z3.BitVecs('append_word32 append_second32', 32)
    for kind in ['word_writer', 'half_writer']:
        for residue in range(16):
            offset = z3.Concat(high, z3.BitVecVal(residue, 4))
            v = seeded(kind, offset, base, word, second)
            ms = masks(kind, residue)
            value = word if kind == 'word_writer' else -2-word-second
            width = len(ms)
            expected = [resize(z3.LShR(value, 8*(width-1-j)), 8)^ms[j] for j in range(width)]
            assert len(v.stores) == width
            bad = []
            for j, (w, byte) in enumerate(zip(v.stores, expected)):
                bad.extend([w['address'] != base+z3.ZeroExt(32, offset+j), w['size_bytes'] != 1, w['value'] != byte])
            decoded = z3.Concat(*[w['value']^ms[j] for j, w in enumerate(v.stores)])
            bad.append(decoded != resize(value, width*8))
            prove(kind+'_all_inputs_offset_residue_'+str(residue), z3.Or(*bad),
                  premises=disjoint_outputs(kind, v),
                  protected_read_spans=[{'address': hex(a), 'size_bytes': n} for a, n in protected_ranges(kind)],
                  partition_low_bits=4, residue=residue, symbolic_offset_high_bits=28,
                  symbolic_base_bits=64, source_span=[hex(x) for x in R.SPANS[kind]])
    raw = z3.BitVec('append_array_raw32', 32)
    v = Scalar()
    v.seed('w11', raw)
    v.seed('x5', R.Parent.B.U)
    mem(v, R.Parent.B.U+8, 8, R.Parent.H)
    v.run_block(*R.SPANS['array_mixer'])
    prove('array_element_all_u32_mixed_value', v.read('w11') != ((raw+0xb69f7313)^0xe4b5bf34))
    for kind in ['packed_word_caller_a', 'packed_word_caller_b']:
        v = Scalar()
        v.seed('w11', raw)
        v.run_block(*R.SPANS[kind])
        prove(kind+'_all_u32_XOR', v.read('w11') != raw^0x25e3467a)
    return out


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert R.extract() == e
    rows, counts = replay(e)
    proofs = obligations()
    controls = []
    base = z3.BitVec('append_control_base64', 64)
    word = z3.BitVec('append_control_word32', 32)
    for label, offset, wrong in [('reversed_byte_order', 0, 'endian'), ('signed_offset_extension', 0x80000000, 'signed')]:
        v = seeded('word_writer', z3.BitVecVal(offset, 32), base, word)
        ms = masks('word_writer', offset)
        bad = v.stores[0]['value'] != resize(word, 8)^ms[0] if wrong == 'endian' else v.stores[0]['address'] != base+z3.SignExt(32, z3.BitVecVal(offset, 32))
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*disjoint_outputs('word_writer', v))
        s.add(word == 0x11223344, base == R.Parent.H)
        s.add(bad)
        assert s.check() == z3.sat
        m = s.model()
        controls.append({'label': label, 'wrong_contract_rejected': True, 'result': 'sat', 'query': s.to_smt2(),
                         'word32': hex(m.eval(word, model_completion=True).as_long()),
                         'base64': hex(m.eval(base, model_completion=True).as_long()), 'offset32': hex(offset)})
    alias = AliasedBytes()
    alias_base = R.BANKS['D'][1]+1
    for name, value in {'sp': 0x680005fb70, 'x9': alias_base, 'w10': (-0xae20ac2a)&MASK32, 'w11': 0}.items():
        alias.seed(name, value)
    alias.run_block(*R.SPANS['word_writer'])
    actual = bytes(number(w['value']) for w in alias.stores)
    nominal = bytes(masks('word_writer', 0))
    assert actual != nominal and number(alias.stores[0]['address']) == R.BANKS['D'][1]+1
    s = z3.Solver()
    observed = z3.BitVec('append_alias_observed32', 32)
    s.add(observed == int.from_bytes(actual, 'big'), observed != int.from_bytes(nominal, 'big'))
    assert s.check() == z3.sat
    controls.append({'label': 'output_bank_alias_requires_disjointness_premise', 'wrong_contract_rejected': True,
                     'result': 'sat', 'query': s.to_smt2(), 'word32': '0x0', 'base64': hex(alias_base), 'offset32': '0x0',
                     'actual_stores_hex': actual.hex(), 'fixed_bank_formula_hex': nominal.hex()})
    fields = []
    for o in e['occurrences']:
        kind = o['kind']
        if kind not in ['word_writer', 'half_writer']:
            continue
        value = o['values']
        sp = int(o['entry']['SP'], 16)
        for r in o['reads']:
            a, n = int(r['address'], 16), r['size_bytes']
            if n == 8:
                bank = next((x for x in R.BANKS.values() if sp+x[0] == a), None)
                assert bank is not None and int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little') == bank[1]
            else:
                assert n == 1 and any(b <= a < b+length for _, b, length in R.BANKS.values())
                assert r['bytes_hex'] == IMAGE.read(a, 1).hex()
        offset = value['offset32']
        n = int(value['mixed32' if kind == 'word_writer' else 'consumed16'], 16)
        width = 4 if kind == 'word_writer' else 2
        raw = n.to_bytes(width, 'big')
        encoded = bytes(b^m for b, m in zip(raw, masks(kind, offset)))
        assert encoded.hex() == ''.join(w['after_hex'] for w in o['writes'])
        assert [w['address'] for w in o['writes']] == [hex((int(value['base'], 16)+((offset+j)&MASK32))&((1<<64)-1)) for j in range(width)]
        assert all(not a <= int(w['address'], 16) < a+n for w in o['writes'] for a, n in protected_ranges(kind))
        fields.append({'class_index': o['class_index'], 'interval_index': o['interval_index'], 'kind': kind,
                       'offset32': offset, 'value_hex': raw.hex(), 'mask_hex': bytes(masks(kind, offset)).hex(),
                       'encoded_hex': encoded.hex(), 'all_checks_pass': True})
    return {'scope': __doc__, 'generator_sha256': sha(R.__file__), 'auditor_sha256': sha(__file__),
            'source_sha256': sha(SOURCE), 'parent_pins': R.PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'selected_replays': rows, 'independent_totals': counts, 'field_codec_checks': fields,
            'source_proofs': proofs, 'source_queries_unsat': len(proofs), 'wrong_contract_controls': controls,
            'inherited_admissions_rerun': False, 'inherited_nonnull_branch_members': 304,
            'general_packed_word_producer_reduction_established': False,
            'native_target_executed': False, 'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'independent_totals': result['independent_totals'], 'source_queries_unsat': result['source_queries_unsat']}), flush=True)
