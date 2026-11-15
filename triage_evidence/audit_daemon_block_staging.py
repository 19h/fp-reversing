#!/usr/bin/env python3
"""Independent staging replay, descriptor contracts and bounded byte controls.
O(receipts + selected visits*32 + word rows + proof DAG + byte controls)
time/space; solver search additional, 30 s/query. No native operation.
"""
import json
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, TABLE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_alternative_fill import Source
from audit_daemon_append_fields import number
from audit_daemon_record_input_origin import replay
from recover_daemon_record_banks import instruction
import recover_daemon_block_staging as R

DEPS = ['audit_daemon_record_input_origin.py', 'audit_daemon_append_fields.py',
        'audit_daemon_alternative_fill.py', 'audit_daemon_state_table_mixing.py', 'lskd_values_symbolic.py']


def key_record(r): return (z3.Extract(31, 0, r)^0xb5da7ac1)*0x5de29be3
def pre_decode(d): return z3.Extract(31, 0, d)^0x966e5812
def pre_encode(d): return ((z3.Extract(31, 0, d)^0x94a3d320)|6)^0x02cd8b34
def key_decode(d): return pre_decode(d)*0x592e2f77
def key_encode(d): return pre_encode(d)*0x592e2f77


def obligations(e):
    out = []
    def prove(label, bad, premises=()):
        s = z3.Solver(); s.set(timeout=30000); s.add(*premises); assert s.check() == z3.sat
        s.add(z3.simplify(bad)); result = s.check(); assert result == z3.unsat, (label, str(result))
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    r, sp, src, dst = z3.BitVecs('staging_R64 staging_wrapperSP64 staging_src64 staging_dst64', 64)
    d = sp+16; encoded = z3.BitVec('staging_record_control32', 32)
    v = Source({0x100427c84: (4, encoded), 0x100427c8c: (8, src), 0x100427c90: (8, dst)})
    v.seed('sp', sp); v.seed('x19', r)
    v.run_block(0x100427c4c, 0x100427c80)
    normalized = z3.Extract(31, 0, r)^0xb5da7ac1
    prove('source_record_prekey_normalizer_before_constant_multiply', v.read('w15') != normalized)
    v.write('w15', normalized)  # Qualified by the immediately preceding lemma.
    v.run_block(0x100427c80, 0x100427cd0)
    prove('source_descriptor_prekey_normalizer_before_constant_multiply', v.read('w1') != pre_encode(d))
    v.write('w1', pre_encode(d))  # Qualified before the source MUL at cd0.
    v.run_block(0x100427cd0, 0x100427ce8)
    assert len(v.loads) == len(v.stores) == 3
    expected = (encoded^key_record(r))+0xc906f030
    prove('all_pointer_bits_wrapper_fields_and_reencoded_control', z3.Or(
        *[a != want for (pc, a, n), want in zip(v.loads, [r+24, r+16, r])],
        *[z3.Or(s['address'] != a, s['size_bytes'] != n, s['value'] != value)
          for s, (a, n, value) in zip(v.stores, [(d+12, 4, expected^key_encode(d)), (d, 8, src), (d+16, 8, dst)])]))
    raw, descriptor = z3.BitVec('staging_descriptor_control32', 32), z3.BitVec('staging_D64', 64)
    g0, g1 = z3.BitVecs('staging_decode_controller032 staging_decode_controller132', 32)
    l, rr = z3.BitVecs('staging_decode_bankL8 staging_decode_bankR8', 8)
    w = Source({0x1004115b0: (4, raw), 0x1004115b4: (4, g0), 0x1004115b8: (4, g1),
                0x1004115d4: (1, l), 0x1004115e8: (1, rr)})
    for name, value in {'x28': descriptor, 'x0': descriptor, 'x23': 0x1010b6000,
                        'x15': 0x1010c4000, 'w8': 0xa6, 'w9': 0x0a5cd4cf}.items(): w.seed(name, value)
    w.run_block(0x100411584, 0x1004115ac)
    prove('source_decoder_prekey_normalizer_before_constant_multiply', w.read('w10') != pre_decode(descriptor))
    w.write('w10', pre_decode(descriptor))
    w.run_block(0x1004115ac, 0x1004115f0)
    prove('all_descriptor_pointer_bits_dispatch_decoder', z3.Or(w.loads[0][1] != descriptor+12,
        w.read('w10') != (raw^key_decode(descriptor))))
    root, selected = z3.BitVecs('staging_dispatch_root64 staging_dispatch_target64', 64)
    dispatch = Source({0x10041160c: (8, selected)}); dispatch.seed('x24', root); dispatch.seed('w10', raw)
    dispatch.run_block(*R.SPANS['dispatch_load'])
    prove('dispatch_load_uses_signed_u32_index_and_eight_byte_stride', z3.Or(
        dispatch.loads[0][1] != root+z3.SignExt(32, raw)*8, dispatch.read('x13') != selected))
    prove('encoder_decoder_prekey_equality_iff_bits_one_two_clear',
        (pre_encode(descriptor) == pre_decode(descriptor)) != ((descriptor&6) == 0))
    x = z3.BitVec('staging_multiply_input32', 32); inverse = pow(0x592e2f77, -1, 1 << 32)
    assert (0x592e2f77*inverse) % (1 << 32) == 1
    prove('all_u32_constant_multiply_has_verified_left_inverse', (x*0x592e2f77)*inverse != x)
    f = z3.Function('staging_f', z3.BitVecSort(32), z3.BitVecSort(32))
    g = z3.Function('staging_g', z3.BitVecSort(32), z3.BitVecSort(32))
    y = z3.BitVec('staging_other_input32', 32)
    prove('equal_images_iff_equal_inputs_under_left_inverse',
        (f(x) == f(y)) != (x == y), [g(f(x)) == x, g(f(y)) == y])
    ke, kd, desired = z3.BitVecs('staging_encode_key32 staging_decode_key32 staging_desired_index32', 32)
    prove('wrapper_decoder_composition_given_certified_key_equality', ((desired^ke)^kd) != desired, [ke == kd])
    c = z3.BitVec('staging_count64', 64); byte, a, b, cc = z3.BitVecs('staging_input8 staging_A8 staging_B8 staging_C8', 8)
    pa, pb, pc, offa, offc, table = z3.BitVecs('staging_PA64 staging_PB64 staging_PC64 staging_offA64 staging_offC64 staging_table64', 64)
    ia, ic = z3.BitVecs('staging_pool_indexA32 staging_pool_indexC32', 32)
    target = z3.BitVec('staging_input_target64', 64)
    vals = {0x10004e954: (1, byte), 0x10004e968: (8, pa), 0x10004e96c: (8, pc),
            0x10004e988: (1, a), 0x10004e990: (1, b), 0x10004e994: (1, cc), 0x10004e9b8: (8, target)}
    v = Source(vals)
    seeds = {'x3': c, 'x13': src, 'x11': dst, 'x14': offa, 'x2': offc, 'x19': pb,
             'w7': ia, 'w17': ic, 'w4': 0x6f, 'w5': 0x43, 'w6': 0x3f2, 'w10': 0x81f7,
             'x24': table, 'x25': 0x1010a1960}
    for n, x in seeds.items(): v.seed(n, x)
    v.run_block(0x10004e950, 0x10004e9bc)
    v.run_block(0x10004e9bc, 0x10004e9cc)
    i = c-1; value = byte^z3.Extract(7, 0, i*0x6f)^a^b^cc^0x43
    loads = {0x10004e954: src+i, 0x10004e968: 0x1010a1960+z3.ZeroExt(32, (ia&255)+0x2ad)*8,
             0x10004e96c: 0x1010a1960+z3.ZeroExt(32, (ic&255)+0xaf5)*8,
             0x10004e988: pa+i+offa, 0x10004e990: pb, 0x10004e994: pc+c+offc,
             0x10004e9b8: table+z3.ZeroExt(32, z3.If(i == 0, z3.BitVecVal(0x8205, 32), z3.BitVecVal(0x81f7, 32)))*8}
    prove('all_u64_input_tail_addresses_mask_and_exit_choice', z3.Or(
        *[addr != loads[at] for at, addr, n in v.loads], v.stores[0]['address'] != dst+i,
        v.stores[0]['value'] != value, v.stores[0]['size_bytes'] != 1, v.read('x20') != i,
        v.read('x7') != target, v.read('x3') != i, v.read('x17') != 0x8425))
    prove('positive_input_rank_decreases_without_underflow', z3.Or(z3.UGE(i, c), z3.ZeroExt(1, i) != z3.ZeroExt(1, c)-1), [c != 0])
    # Full output body keeps its recorded controller/pool context; four data
    # bytes, input/output bases, descriptor and descending index are symbolic.
    sample = e['cases'][0]['stages']['output'][0]['source_chunk']; supplied = {}
    for read_event in sample['reads']:
        at = int(read_event['pc'], 16); assert at not in supplied
        supplied[at] = (read_event['size_bytes'], int.from_bytes(bytes.fromhex(read_event['bytes_hex']), 'little'))
    supplied.update({0x100085b08: (8, dst), 0x100085b10: (1, byte),
                     0x100085bbc: (1, a), 0x100085bd0: (1, b), 0x100085be0: (1, cc)})
    output_target = z3.BitVec('staging_output_target64', 64)
    supplied[0x100085c0c] = (8, output_target)
    v = Source(supplied); frame = sample['frames'][0]
    for j, x in enumerate(frame['registers31']): v.seed('x'+str(j), int(x, 16))
    v.seed('sp', int(frame['SP'], 16)); v.seed('x28', descriptor); v.seed('x8', c); v.seed('x10', src+15)
    v.run_block(0x100085b08, 0x100085c0c)
    choice = v.read('w17')
    v.run_block(0x100085c0c, 0x100085c18)
    assert len(v.stores) == 1
    position = c+15
    prove('full_output_body_arbitrary_bytes_and_descending_addresses', z3.Or(
        v.loads[0][1] != descriptor+16, v.loads[1][1] != src+position,
        v.stores[0]['address'] != dst+position,
        v.stores[0]['value'] != (byte^a^b^cc^z3.Extract(7, 0, position*0x17)^0xd8),
        choice != z3.If(c == z3.BitVecVal((1 << 64)-15, 64), z3.BitVecVal(0x6799, 32), z3.BitVecVal(0x3808, 32)),
        v.loads[-1][1] != TABLE+z3.ZeroExt(32, choice)*8, v.read('x8') != c-1,
        v.read('x0') != output_target, v.read('x17') != 0x3b84))
    # The modulo-negative range is expressed by its decoded nonnegative j.
    prove('sixteen_position_output_rank_and_terminal_condition', z3.Or(
        z3.UGT(position, 15), (position == 0) != (c == z3.BitVecVal((1 << 64)-15, 64))),
        [z3.ULE(c+16, 16), z3.UGE(c+16, 1)])
    v = Source(); v.run_block(*R.SPANS['staging_count'])
    prove('dispatch_setup_supplies_exactly_sixteen_input_bytes', v.read('x3') != 16)
    return out


def controls():
    rows = []
    for low in range(16):
        d = 0x680005fb20+low; phase = 0x81f7
        enc = number(key_encode(z3.BitVecVal(d, 64))); dec = number(key_decode(z3.BitVecVal(d, 64)))
        after = (phase^enc)^dec; assert (after == phase) == ((d&6) == 0)
        rows.append({'descriptor': hex(d), 'bits_one_two_clear': (d&6) == 0,
                     'encoded_control32': hex(phase^enc), 'decoded_index32': hex(after), 'roundtrip_matches': after == phase})
    c = z3.BitVecVal(0x680005fb20, 64); relocated = z3.BitVecVal(0x680005fb30, 64)
    raw = 0x81f7^number(key_decode(c)); wrong = raw^number(key_decode(relocated)); assert wrong != 0x81f7
    return {'alignment_cases': rows, 'relocation_without_rekey_counterexample': {
        'original_descriptor': hex(number(c)), 'relocated_descriptor': hex(number(relocated)),
        'copied_raw_control32': hex(raw), 'wrong_decoded_index32': hex(wrong), 'expected_index32': '0x81f7'}}


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); totals = Counter(); classes = []
    old = json.loads(read(ROOT/'daemon_record_input_origin_checks.json'))
    for c, parent in zip(e['cases'], old['cases']):
        assert c['class_index'] == parent['class_index']
        chunks = c['descriptor_chunks']+[x['source_chunk'] for k in c['stages'].values() for x in k]
        for chunk in chunks: totals.update(replay(chunk))
        original = parent['chunks'][-1]; observed = []
        for r in original['reads']:
            at = int(r['pc'], 16); a = int(r['address'], 16)
            if not (0x10010eabc <= at <= 0x1001112bc and r['size_bytes'] == 4 and 'known_mask_hex' not in r): continue
            ins = instruction(at)
            if not ins.operands[1].mem.index: continue
            hits = [b for b in R.BANKS if b <= a < b+1024]; assert len(hits) == 1
            assert IMAGE.read(a, 4).hex() == r['bytes_hex']
            observed.append({'read': r, 'bank_base': hex(hits[0]), 'index': (a-hits[0])//4})
        assert observed == c['core_word_table_reads']; totals['core_table_reads_checked'] += len(observed)
        for kind, stages in c['stages'].items():
            mask = bytes.fromhex(c['mask16_hex'][kind]); assert len(mask) == 16
            windows = c['mask_windows'][kind]
            for window in windows:
                assert IMAGE.read(int(window['base'], 16), 16).hex() == window['bytes_hex'] and window['extent_bytes'] == 16
                totals['immutable_mask_window_bytes_checked'] += 16
            for x in stages:
                p = x['position']; coefficient, constant = (111, 67) if kind == 'input' else (23, 216)
                prediction = coefficient*p ^ constant
                for r in x['bank_reads']:
                    raw = IMAGE.read(int(r['address'], 16), 1); assert raw.hex() == r['bytes_hex']; prediction ^= raw[0]
                    totals['original_mask_bank_bytes_checked'] += 1
                assert mask[p] == x['mask_byte'] == prediction&255
                decoded = [bytes.fromhex(w['bytes_hex'])[p] for w in windows]
                assert mask[p] == (decoded[0]^decoded[1]^decoded[2]^(coefficient*p)^constant)&255
                for b in range(256):
                    assert ((b^mask[p])^mask[p]) == b; totals['mask_byte_involution_controls'] += 1
        values = {k: bytes.fromhex(v) for k, v in c['vectors'].items()}
        for before, after, kind in [('external_input16_hex', 'staged_input16_hex', 'input'),
                                    ('core_output16_hex', 'external_output16_hex', 'output')]:
            assert bytes(a^b for a, b in zip(values[before], bytes.fromhex(c['mask16_hex'][kind]))) == values[after]
        classes.append({'class_index': c['class_index'], 'all_checks_pass': True})
    for key, bank in e['word_banks'].items():
        raw = IMAGE.read(int(key, 16), 1024); assert raw.hex() == bank['bytes_hex'] and bank['extent_bytes'] == 1024
        totals['immutable_word_bytes_checked'] += len(raw)
    slots = {int(x['slot'], 16) for x in e['dispatch']}
    fixups = verify_original_fixups(slots)
    proofs = obligations(e)
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'extractor_sha256': sha(ROOT/('recover_'+R.P+'.py')),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'classes': classes,
            'independent_totals': dict(totals), 'original_fixups': fixups, 'source_proofs': proofs,
            'source_queries_unsat': len(proofs), 'controls': controls(), 'native_API_executed': False,
            'certified_rewrites': [{'pc': hex(pc), 'register': reg, 'qualifying_proof': name} for pc, reg, name in [
                (0x100427c80, 'w15', 'source_record_prekey_normalizer_before_constant_multiply'),
                (0x100427cd0, 'w1', 'source_descriptor_prekey_normalizer_before_constant_multiply'),
                (0x1004115ac, 'w10', 'source_decoder_prekey_normalizer_before_constant_multiply')]],
            'derived_key_equivalence': {'condition': '(D & 6) == 0', 'domain': 'all u64 D; u32 keys',
                'multiplier32': '0x592e2f77', 'inverse32': hex(pow(0x592e2f77, -1, 1 << 32)),
                'qualifying_proofs': ['encoder_decoder_prekey_equality_iff_bits_one_two_clear',
                    'all_u32_constant_multiply_has_verified_left_inverse', 'equal_images_iff_equal_inputs_under_left_inverse']},
            'native_daemon_kext_pairing_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    e = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps({'independent_totals': e['independent_totals'], 'source_queries_unsat': e['source_queries_unsat']}), flush=True)
