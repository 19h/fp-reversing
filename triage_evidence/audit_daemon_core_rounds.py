#!/usr/bin/env python3
"""Certify the source round-composition cuts and an independent round-state model.
O(source DAG + proof DAG + 1024 finite rows + 64*(DAG + 9*16)) time/space;
solver search additional, 30 s/query. The pinned parent lift/admissions remain
dependencies. No native target, API, IPC, PAC or IDB action.
"""
import json
from collections import Counter
from functools import reduce
from hashlib import sha256
from operator import xor
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_core_lookup as Core
import daemon_core_lookup_kernel as Kernel
from audit_daemon_core_affine import reference, apply
import recover_daemon_core_rounds as R

DEPS = ['recover_daemon_core_lookup.py', 'daemon_core_lookup_kernel.py', 'audit_daemon_core_affine.py',
        'audit_daemon_alternative_fill.py', 'audit_daemon_append_fields.py', 'lskd_values_symbolic.py']


def xtime(x): return ((x << 1) ^ (0x1b if x & 128 else 0)) & 255


def expanded(seed, sbox):
    data = bytearray(seed); rc = 1
    while len(data) < 176:
        at = len(data); temp = list(data[-4:])
        if at % 16 == 0:
            temp = [sbox[temp[1]], sbox[temp[2]], sbox[temp[3]], sbox[temp[0]]]
            temp[0] ^= rc; rc = xtime(rc)
        data.extend(data[at-16+j] ^ temp[j] for j in range(4))
    return [bytes(data[j:j+16]) for j in range(0, 176, 16)]


def reference_indices(case, data, affine, sbox):
    """Byte-array state, independently arranged ShiftRows and xtime columns."""
    enc = affine['mixcolumns']['row_encoder_columns8']
    tables = {t['mixcolumns_factor']['input_row']: t for t in affine['main_tables']}
    state = list(data); result = {}; states = [bytes(state).hex()]
    for layer in range(1, 11):
        rows = [r for r in case['word_reads'] if r['round'] == layer]
        for r in rows:
            p, row = r['input_offset'], r['row']
            if layer < 10:
                value = state[p] ^ r['effective_sbox_input_xor8'] ^ tables[row]['factor']['input_xor8']
                result[r['ordinal']] = apply(enc[row], value)
            else: result[r['ordinal']] = apply(enc[row], state[p]) ^ r['encoded_state_xor8']
        if layer == 10: break
        key = bytes.fromhex(case['offsets9_hex'][layer-1])
        for p in range(16): state[p] = sbox[state[p] ^ key[p]]
        shifted = [None]*16
        for row in range(4):
            values = state[row::4]; values = values[row:]+values[:row]
            shifted[row::4] = values
        for col in range(4):
            values = shifted[4*col:4*col+4]; total = reduce(xor, values)
            state[4*col:4*col+4] = [values[row] ^ total ^ xtime(values[row] ^ values[(row+1) % 4]) for row in range(4)]
        states.append(bytes(state).hex())
    return result, states


def audit():
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); assert evidence == R.build()
    affine = json.loads(read(ROOT/'daemon_core_affine_checks.json'))
    parents = json.loads(read(ROOT/'daemon_core_lookup_checks.json'))
    tables = {t['bank']: t for t in affine['main_tables']}; sbox = reference()
    assert sbox.hex() == affine['reference']['table256_hex']
    # Published FIPS 197-upd1 Appendix A.1 anchors the independent schedule convention.
    known = expanded(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'), sbox)
    assert known[1].hex() == 'a0fafe1788542cb123a339392a6c7605'
    assert known[10].hex() == 'd014f9a8c9ee2589e13f0cc8b6630ca6'
    totals = Counter(reference_sbox_values_checked=256, NIST_schedule_checkpoints=2)
    proofs, vectors = [], []
    for table in affine['main_tables']:
        raw = IMAGE.read(int(table['bank'], 16), 1024); row = table['mixcolumns_factor']['input_row']
        for x in range(256):
            i = apply(table['input_columns8'], x); word = int.from_bytes(raw[4*i:4*i+4], 'little')
            assert word == table['word256_LE'][i]
            if row == 0: actual = word ^ (word >> 2) ^ (word >> 6)
            elif row == 1:
                rotated = ((word << 14) | (word >> 18)) & 0xffffffff
                actual = rotated ^ ((rotated << 3) & 0xe19e3e68)
            else: actual = word ^ i
            v = sbox[x ^ table['factor']['input_xor8']]; products = {1: v, 2: xtime(v), 3: xtime(v) ^ v}
            wanted = bytes(apply(affine['mixcolumns']['row_encoder_columns8'][r], products[affine['mixcolumns']['matrix4x4'][r][row]]) for r in range(4))
            assert actual == int.from_bytes(wanted, 'big') ^ table['mixcolumns_factor']['normalized_bias32']
            totals['original_normalized_table_rows_checked'] += 1
    for case, parent in zip(evidence['cases'], parents['cases']):
        model = Core.Model(parent['source_chunk']).run(); rows = {r['ordinal']: r for r in case['word_reads']}
        assert set(rows) == {j for j, r in enumerate(model.lookups) if r['unit_bytes'] == 4}
        for layer in range(1, 11):
            selected = [r for r in rows.values() if r['round'] == layer]
            assert len(selected) == 16 and sorted(r['input_offset'] for r in selected) == list(range(16))
            if layer < 10:
                assert all(tables[r['bank']]['mixcolumns_factor']['input_row'] == r['row'] for r in selected)
                expected_key = bytes(r['effective_sbox_input_xor8'] for r in sorted(selected, key=lambda r: r['input_offset']))
                assert expected_key.hex() == case['offsets9_hex'][layer-1]
            else: assert len({r['bank'] for r in selected}) == 4 and len({(r['bank'], r['row']) for r in selected}) == 4
        beta = reduce(xor, (t['mixcolumns_factor']['normalized_bias32'] for t in tables.values()))
        for j, record in rows.items():
            source = model.lookups[j]; row = record['row']; assert row == record['input_offset'] % 4
            assert (source['pc'], source['base']) == (record['pc'], record['bank'])
            if record['round'] == 1:
                original = affine['cases'][0]['initial_indices'][j-16]
                assert original['effective_first_sbox_input_xor8'] == record['effective_sbox_input_xor8']
                continue
            deps = record['contributions']; assert len(deps) == len(set(deps)) == 4 and max(deps) < j
            col = record['input_offset']//4
            assert sorted(rows[k]['row'] for k in deps) == list(range(4))
            assert all(rows[k]['round'] == record['round']-1 and (rows[k]['input_offset']//4-rows[k]['row']) % 4 == col for k in deps)
            terms = []
            for k in deps:
                previous = model.lookups[k]; value = previous['value']; previous_row = rows[k]['row']
                if previous_row == 0: term = value ^ z3.LShR(value, 2) ^ z3.LShR(value, 6)
                elif previous_row == 1:
                    rotated = z3.RotateLeft(value, 14); term = rotated ^ ((rotated << 3) & 0xe19e3e68)
                else: term = value ^ z3.Extract(31, 0, previous['index'])
                terms.append(term)
            selected_byte = z3.Extract(31-row*8, 24-row*8, reduce(xor, terms))
            expected = z3.ZeroExt(56, selected_byte) ^ record['source_xor8']
            solver = z3.SolverFor('QF_BV'); solver.set(timeout=30000); assert solver.check() == z3.sat
            solver.add(source['index'] != expected); answer = solver.check()
            assert answer == z3.unsat, (j, str(answer), solver.reason_unknown())
            label = str(case['class_index'])+'_'+record['pc']+'_round_index'
            proofs.append({'label': label, 'class_index': case['class_index'], 'ordinal': j,
                           'pc': record['pc'], 'round': record['round'], 'premises_nonvacuous': True,
                           'arbitrary_lookup_returns': True, 'result': 'unsat', 'query': solver.to_smt2()})
            residual = record['source_xor8'] ^ ((beta >> (24-8*row)) & 255)
            assert residual == record['encoded_state_xor8']
            if record['round'] <= 9:
                t = tables[record['bank']]; inverse = {apply(t['input_columns8'], x): x for x in range(256)}
                assert inverse[residual] ^ t['factor']['input_xor8'] == record['effective_sbox_input_xor8']
            totals['structural_composition_records_checked'] += 1
        schedule = case['AES128_prefix_schedule']; seed = bytes.fromhex(schedule['backderived_seed16_hex']); keys = expanded(seed, sbox)
        assert [k.hex() for k in keys] == schedule['expanded11_hex']
        assert schedule['source_matched_expansion_indices'] == list(range(1, 9)) and schedule['source_unestablished_expansion_indices'] == [9, 10]
        for j in range(1, 9): assert keys[j].hex() == case['offsets9_hex'][j]
        assert bytes(x ^ y for x, y in zip(seed, bytes.fromhex(case['offsets9_hex'][0]))).hex() == schedule['input_whitening16_hex']
        direct = expanded(bytes.fromhex(case['offsets9_hex'][0]), sbox)
        for r in case['AES128_direct_schedule_candidate']['comparisons']:
            assert r['actual_hex'] == case['offsets9_hex'][r['round_offset_index']]
            assert r['expanded_hex'] == direct[r['round_offset_index']].hex()
            assert r['equal'] == (r['actual_hex'] == r['expanded_hex']) == False
        totals.update(source_matched_expanded_vectors_checked=8, direct_seed_mismatches_checked=8)
        inputs = [bytes.fromhex(case['retained_input16_hex']), bytes(16), bytes([255])*16, bytes(range(16))]
        inputs += [sha256(b'core-rounds-input-'+str(j).encode()).digest()[:16] for j in range(28)]
        for data in inputs:
            actual, accesses = Kernel.transform(parent, data)
            independent, states = reference_indices(case, data, affine, sbox)
            proposed, proposed_states = R.prefix(case, data, affine)
            assert independent == proposed and states == proposed_states
            for j, value in independent.items():
                read_at = accesses[j]; source = model.lookups[j]
                assert read_at['pc'] == source['pc'] and int(read_at['address'], 16) == int(source['base'], 16)+4*value
                totals['word_indices_compared'] += 1
            if data.hex() == case['retained_input16_hex']:
                assert actual.hex() == parent['expected_output16_hex'] and states == case['retained_canonical_states10_hex']
                assert {str(k): v for k, v in independent.items()} == case['retained_word_indices']
            vectors.append({'class_index': case['class_index'], 'input16_hex': data.hex(),
                            'indices_sha256': sha256(bytes(independent[k] for k in sorted(independent))).hexdigest(),
                            'state9_hex': states[-1], 'DAG_output16_hex': actual.hex()})
            totals.update(vector_comparisons=1, canonical_states_compared=10)
        print(json.dumps({'class_index': case['class_index'], 'source_proofs': 144, 'vector_comparisons': 32}), flush=True)
    assert len(proofs) == 288 and len({p['label'] for p in proofs}) == 288
    assert evidence['cases'][0]['word_reads'] == evidence['cases'][1]['word_reads']
    totals['source_queries_unsat'] = len(proofs)
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'generator_sha256': sha(ROOT/'recover_daemon_core_rounds.py'),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'independent_totals': dict(totals),
            'source_proofs': proofs, 'vector_comparisons': vectors,
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'transform_algorithm_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    evidence = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence['independent_totals']), flush=True)
