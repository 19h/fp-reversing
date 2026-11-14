#!/usr/bin/env python3
"""Independent constructor extent/header contracts and selected source replay.
O(parent bytes + selected visits*32 + proof DAG) time/space; solver search
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
import recover_daemon_constructor_extent as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_environment_outputs.py', 'lskd_values_symbolic.py']


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
    p, q, a, raw = z3.BitVecs('ce_old_header32 ce_saved_header32 ce_operand32 ce_raw_extent32', 32)
    v = Lift()
    for name, value in {'sp': R.SP, 'w14': 0x6cf4, 'w20': p^0x8b3dc651, 'w8': raw}.items():
        v.seed(name, value)
    mem(v, R.SP+0x312c, 4, a)
    v.run_block(*R.SPANS['growth'])
    assert len(v.stores) == 1
    prove('original_generic_raw_extent_update', z3.Or(v.stores[0]['address'] != R.SP+0x3b80,
          v.stores[0]['size_bytes'] != 4, v.stores[0]['value'] != raw+a-p))
    v = Lift()
    for name, value in {'w25': 0x5f29, 'w26': 0x9717, 'w9': 0x37ee, 'w12': 0xef1233cf, 'w8': raw}.items():
        v.seed(name, value)
    v.run_block(*R.SPANS['malloc_head'])
    v.run_block(*R.SPANS['malloc_tail'])
    prove('original_malloc_count_zero_extended_u32', v.read('x0') != z3.ZeroExt(32, raw+0xef133bef))
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('w20', p^0x8b3dc651)
    mem(v, R.SP+0x9d0, 8, 0x6cf4)
    mem(v, R.SP+0x312c, 4, a)
    mem(v, R.SP+0x70b4, 4, q^0x8b3dc651)
    v.run_block(*R.SPANS['header_inputs'])
    prove('original_header_input_reductions', z3.Or(v.read('w8') != a,
          v.read('w11') != p+0x74c239af, v.read('w12') != q+0x74c239af))
    u, t = z3.BitVecs('ce_header_intermediate_u32 ce_header_intermediate_t32', 32)
    v = Lift()
    for name, value in {'w8': a, 'w11': u, 'w12': t}.items():
        v.seed(name, value)
    v.run_block(*R.SPANS['header_tail'])
    prove('original_header_tail', v.read('w23') != (a+u-t)^0x8b3dc651)
    new_header = a+(p+0x74c239af)-(q+0x74c239af)
    extent = raw+0xef133bef
    new_extent = raw+a-p+0xef133bef
    prove('composed_header_agreement_and_gap_preservation', z3.Or(new_header != a,
          new_extent-new_header != extent-p), [p == q])
    aux, n, key, word = z3.BitVecs('ce_aux_raw32 ce_count32 ce_scalar_key32 ce_intermediate_word32', 32)
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('w19', aux)
    mem(v, R.SP+0xab2c, 4, n)
    v.run_block(*R.SPANS['producer_prefix'])
    packed_high = (((aux^0x6703cce9)<<(n&31))&0x07ffffff)|(n<<27)
    prove('original_earlier_producer_prefix', v.read('w8') != packed_high+0xe0d06e54)
    v = Lift()
    v.seed('sp', R.SP)
    v.seed('x13', R.SP+0x9000)
    v.seed('w8', word)
    mem(v, R.SP+0xab28, 4, key)
    v.run_block(*R.SPANS['producer_add'])
    prove('original_earlier_producer_scalar_add', v.read('w8') != word+(key^0x8b3dc651)+0x7d9e4176)
    quotient = z3.BitVec('ce_eliminated_quotient32', 32)
    v = Lift()
    v.seed('w11', quotient)
    v.seed('w15', word)
    v.run_block(*R.SPANS['quotient_cancel'])
    prove('original_quotient_independent_cancellation', v.read('w11') != word<<8)
    # The four omitted quotient-generation instructions only write X11.
    skipped = list(DEC.disasm(IMAGE.read(0x100618b5c, 16), 0x100618b5c))
    assert len(skipped) == 4 and all(i.reg_name(i.operands[0].reg) in ['w11', 'x11'] for i in skipped)
    assert [i.mnemonic for i in skipped] == ['mov', 'movk', 'umull', 'lsr']
    v = Lift()
    v.seed('w8', word)
    v.run_block(R.SPANS['producer_final'][0], 0x100618b5c)
    tail = Lift()
    for name in ['w8', 'w9', 'w10', 'w12', 'w15']:
        tail.seed(name, v.read(name))
    tail.seed('w11', v.read('w15')<<8)
    tail.run_block(0x100618b80, R.SPANS['producer_final'][1])
    prove('composed_original_earlier_producer_final', tail.read('w12') != (word-0x5e6eafca)^0xc12b4f72)
    v = Lift()
    v.seed('w12', word^0xc12b4f72)
    v.run_block(*R.SPANS['caller_xor'])
    prove('original_earlier_caller_normalization', v.read('w12') != word^0xe4b5bf34)
    d = z3.BitVec('ce_decoded_scalar32', 32)
    packed = packed_high+d
    decoded_n = z3.LShR(packed, 27)
    inverse = z3.If(decoded_n == 0, packed, packed&((z3.BitVecVal(1, 32)<<decoded_n)-1))
    prove('composed_earlier_producer_canonical_inverse', inverse != d,
          [z3.UGE(n, 1), z3.ULE(n, 27), z3.ULT(d, z3.BitVecVal(1, 32)<<n)])
    high = z3.BitVec('ce_offset_high28', 28)
    base = z3.BitVec('ce_buffer64', 64)
    banks = {'B': (0x3e8, 0x100e36310, 16), 'C': (0x3e0, 0x100f2f6b0, 19),
             'A': (0x3d8, 0x100ed2440, 17), 'D': (None, 0x100f21190, 16),
             'E': (None, 0x100fa38b0, 20), 'K': (None, 0x100ffc9e0, 17)}
    for residue in range(16):
        offset = z3.Concat(high, z3.BitVecVal(residue, 4))
        v = Lift()
        for name, value in {'sp': R.SP, 'x16': R.SP+0x8000, 'x9': base,
                            'w11': offset-0xae20ac2a, 'w12': word^0xe4b5bf34,
                            'x3': banks['D'][1], 'x1': banks['E'][1], 'x0': banks['K'][1]}.items():
            v.seed(name, value)
        protected = [(R.SP+0x9220, 8)]
        for off, address, size in banks.values():
            protected.append((address, size))
            if off is not None:
                mem(v, R.SP+off, 8, address)
                protected.append((R.SP+off, 8))
            for j, byte in enumerate(IMAGE.read(address, size)):
                mem(v, address+j, 1, byte)
        v.run_block(*R.SPANS['writer_math'])
        assert len(v.stores) == 5
        scratch, *stores = v.stores
        bad = [scratch['address'] != R.SP+0x9220, scratch['size_bytes'] != 8, scratch['value'] != base]
        for j, w in enumerate(stores):
            expected = z3.Extract(31-8*j, 24-8*j, word)^R.S.STREAM[(residue+j)&15]
            bad.extend([w['address'] != base+z3.ZeroExt(32, offset+j), w['size_bytes'] != 1, w['value'] != expected])
        premises = [z3.UGE(w['address']-start, size) for w in stores for start, size in protected]
        prove('original_earlier_word_writer_common_mask_residue_'+str(residue), z3.Or(*bad), premises)
    assert len(out) == 27
    return out


def replay(e):
    old = R.parents()
    totals = Counter()
    for group, packed in [(e['prefixes'], lambda c: old['prefixes'][c['prefix_class_index']]['interval_packed']),
                           (e['branches'], lambda c: old['branches'][c['branch_index']]['intervals'][0]['interval_packed'])]:
        for c in group:
            row = R.B.unpack(packed(c))
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
    for label, c, p, q, a, expected_n, expected_d in [
            ('nonunit_gap_preserved', 24, 20, 20, 56, 60, 56),
            ('unequal_header_copies_change_published_scalar', 21, 20, 21, 56, 57, 55)]:
        extent, header, saved, operand = z3.BitVecs('ce_control_extent32 ce_control_header32 ce_control_saved32 ce_control_operand32', 32)
        s = z3.Solver()
        s.add(extent == c, header == p, saved == q, operand == a,
              extent+operand-header == expected_n, operand+header-saved == expected_d)
        assert s.check() == z3.sat
        rows.append({'label': label, 'result': 'sat', 'query': s.to_smt2(), 'old_extent32': c,
                     'old_header32': p, 'saved_header32': q, 'operand32': a,
                     'new_extent32': expected_n, 'new_header32': expected_d, 'native_admission_established': False})
    return rows


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
