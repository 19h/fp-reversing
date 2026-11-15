#!/usr/bin/env python3
"""Recover source composition of the nine main substitution/column layers.
O(source DAG + candidate groups * DAG + fixed byte domains) time/space;
solver search additional, 30 s/query. No native target, IPC, PAC or IDB action.
"""
import json
from collections import Counter
from functools import reduce
from operator import xor
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_append_fields import number
import recover_daemon_core_lookup as Core
import recover_daemon_core_affine as Affine

P = 'daemon_core_rounds'
PINS = {'daemon_core_lookup_checks.json': '5661e892920d52fac2029d2bbc4b3189c884caa839dd93552c268eed293689c9',
        'daemon_core_lookup_audit.json': '39495d6ba9b37d1113d3d7ceba4c8ec317baec96f1ed1277ec7d4344df87d460',
        'daemon_core_affine_checks.json': 'd46e946d6acca5be5f2a599544bde0dae5a755b2b8a2011a244ac2865be09c8f',
        'daemon_core_affine_audit.json': 'ec0188120431ee0d83f7bc606e4122197f3a5ae97d0a5703656411ae663418e6'}
DEPS = ['recover_daemon_core_lookup.py', 'recover_daemon_core_affine.py', 'daemon_receive_tools.py',
        'audit_daemon_append_fields.py', 'audit_daemon_alternative_fill.py', 'lskd_values_symbolic.py']


def normalized(model, ordinal, tables):
    r = model.lookups[ordinal]; y = r['value']; index = z3.Extract(31, 0, r['index'])
    kind = tables[r['base']]['mixcolumns_factor']['normalizer']
    if kind == 'xor_index': return y ^ index
    if kind == 'right_xorshift': return y ^ z3.LShR(y, 2) ^ z3.LShR(y, 6)
    assert kind == 'rotate_xorshift'
    rotated = z3.RotateRight(y, 18)
    return rotated ^ ((rotated << 3) & 0xe19e3e68)


def equation(model, record, tables):
    combined = reduce(xor, (normalized(model, j, tables) for j in record['contributions']))
    row = record['row']
    byte = z3.Extract(31-8*row, 24-8*row, combined)
    return z3.ZeroExt(56, byte) ^ record['source_xor8']


def discover(model, initial, tables):
    records = {16+j: {'ordinal': 16+j, 'pc': r['pc'], 'bank': r['bank'], 'round': 1,
                     'input_offset': r['input_offset'], 'row': r['input_offset'] % 4,
                     'source_xor8': r['bias8'], 'effective_sbox_input_xor8': r['effective_first_sbox_input_xor8']}
               for j, r in enumerate(initial)}
    names = {r['name']: j for j, r in enumerate(model.lookups)}
    beta = reduce(xor, (t['mixcolumns_factor']['normalized_bias32'] for t in tables.values()))
    for j, r in enumerate(model.lookups):
        if j < 32 or r['unit_bytes'] != 4: continue
        mentioned = {names[str(v)] for v in Core.variables(r['index']) if str(v) in names}
        groups = {}
        for k, v in records.items():
            if v['bank'] in tables:
                groups.setdefault((v['round'], (v['input_offset']//4-v['row']) % 4), []).append(k)
        found = []
        for (previous_round, col), deps in sorted(groups.items(), reverse=True):
            if len(deps) != 4 or not set(deps) <= mentioned: continue
            assert sorted(records[k]['row'] for k in deps) == list(range(4))
            rows = [tables[r['base']]['mixcolumns_factor']['input_row']] if r['base'] in tables else range(4)
            for row in rows:
                trial = {'row': row, 'contributions': deps, 'source_xor8': 0}
                delta = z3.simplify(r['index'] ^ equation(model, trial, tables))
                value = number(z3.substitute(delta, *[(v, z3.BitVecVal(0, v.size())) for v in Core.variables(delta)]))
                solver = z3.SolverFor('QF_BV'); solver.set(timeout=30000); solver.add(delta != value)
                result = solver.check(); assert result in [z3.sat, z3.unsat], (j, str(result))
                if result == z3.unsat: found.append((previous_round+1, col, row, deps, value))
            if found: break
        assert len(found) == 1, (j, found)
        rnd, col, row, deps, bias = found[0]; assert 0 <= bias < 256
        encoded_bias = bias ^ ((beta >> (24-8*row)) & 255)
        record = {'ordinal': j, 'pc': r['pc'], 'bank': r['base'], 'round': rnd, 'row': row,
                  'input_offset': 4*col+row, 'contributions': deps, 'source_xor8': bias,
                  'encoded_state_xor8': encoded_bias}
        if r['base'] in tables:
            t = tables[r['base']]
            inverse = next(x for x in range(256) if Affine.linear(t['input_columns8'], x) == encoded_bias)
            record['effective_sbox_input_xor8'] = inverse ^ t['factor']['input_xor8']
        records[j] = record
    out = list(records.values())
    assert len(out) == 160 and Counter(r['round'] for r in out) == Counter({r: 16 for r in range(1, 11)})
    assert all(sorted(r['input_offset'] for r in out if r['round'] == rnd) == list(range(16)) for rnd in range(1, 11))
    assert all((r['bank'] in tables) == (r['round'] <= 9) for r in out)
    return out


def schedule128(key, sbox):
    """FIPS 197-upd1 Algorithm 2, AES-128 candidate expansion only."""
    words = [list(key[j:j+4]) for j in range(0, 16, 4)]; rc = 1
    for j in range(4, 44):
        temp = words[j-1][:]
        if j % 4 == 0:
            temp = [sbox[x] for x in temp[1:]+temp[:1]]; temp[0] ^= rc
            rc = Affine.gf_multiply(rc, 2)
        words.append([x ^ y for x, y in zip(words[j-4], temp)])
    return [bytes(sum(words[j:j+4], [])) for j in range(0, 44, 4)]


def seed_from_first_expanded(value, sbox):
    words = [list(value[j:j+4]) for j in range(0, 16, 4)]; previous = [None]*4
    for j in [3, 2, 1]: previous[j] = [x ^ y for x, y in zip(words[j], words[j-1])]
    temp = [sbox[x] for x in previous[3][1:]+previous[3][:1]]; temp[0] ^= 1
    previous[0] = [x ^ y for x, y in zip(words[0], temp)]
    return bytes(sum(previous, []))


def prefix(case, data, affine):
    """Independent-state form through all word-read indices; final words unconsumed.
    O(9*16) fixed-field operations and O(10*16) retained indices/states.
    """
    assert len(data) == 16
    state = bytes(data); sbox = bytes.fromhex(affine['reference']['table256_hex'])
    by_row = {t['mixcolumns_factor']['input_row']: t for t in affine['main_tables']}
    indexes, states = {}, [state.hex()]
    for rnd in range(1, 11):
        rows = [r for r in case['word_reads'] if r['round'] == rnd]
        for r in rows:
            x = state[r['input_offset']]; t = by_row[r['row']]
            if rnd <= 9:
                argument = x ^ r['effective_sbox_input_xor8'] ^ t['factor']['input_xor8']
                index = Affine.linear(t['input_columns8'], argument)
            else: index = Affine.linear(t['input_columns8'], x) ^ r['encoded_state_xor8']
            indexes[r['ordinal']] = index
        if rnd == 10: break
        nonlinear = [None]*16
        for r in rows: nonlinear[r['input_offset']] = sbox[state[r['input_offset']] ^ r['effective_sbox_input_xor8']]
        shifted = [nonlinear[4*((col+row) % 4)+row] for col in range(4) for row in range(4)]
        state = bytes(reduce(xor, (Affine.gf_multiply(affine['mixcolumns']['matrix4x4'][row][k], shifted[4*col+k])
                                 for k in range(4))) for col in range(4) for row in range(4))
        states.append(state.hex())
    return indexes, states


def build():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    old = json.loads(read(ROOT/'daemon_core_lookup_checks.json'))
    affine = json.loads(read(ROOT/'daemon_core_affine_checks.json')); cases = []
    for parent, initial in zip(old['cases'], affine['cases']):
        model = Core.Model(parent['source_chunk']).run(); rows = discover(model, initial['initial_indices'], {t['bank']: t for t in affine['main_tables']})
        case = {'class_index': parent['class_index'], 'word_reads': rows,
                'offsets9_hex': [bytes(r['effective_sbox_input_xor8'] for r in sorted(rows, key=lambda r: r['input_offset']) if r['round'] == rnd).hex()
                                 for rnd in range(1, 10)],
                'terminal_encoded_xor16_hex': bytes(r['encoded_state_xor8'] for r in sorted(rows, key=lambda r: r['input_offset']) if r['round'] == 10).hex()}
        expected = schedule128(bytes.fromhex(case['offsets9_hex'][0]), bytes.fromhex(affine['reference']['table256_hex']))
        case['AES128_direct_schedule_candidate'] = {'premise': 'First offset vector is the AES-128 seed, same state byte convention, no additional round re-encoding.',
            'comparisons': [{'round_offset_index': j, 'actual_hex': key, 'expanded_hex': expected[j].hex(), 'equal': key == expected[j].hex()}
                            for j, key in enumerate(case['offsets9_hex']) if j],
            'claim': 'Finite test of this direct schedule representation only.'}
        seed = seed_from_first_expanded(bytes.fromhex(case['offsets9_hex'][1]), bytes.fromhex(affine['reference']['table256_hex']))
        expanded = schedule128(seed, bytes.fromhex(affine['reference']['table256_hex']))
        assert all(expanded[j].hex() == key for j, key in enumerate(case['offsets9_hex']) if j)
        case['AES128_prefix_schedule'] = {'backderived_seed16_hex': seed.hex(),
            'expanded11_hex': [v.hex() for v in expanded],
            'source_matched_expansion_indices': list(range(1, 9)),
            'source_unestablished_expansion_indices': [9, 10],
            'input_whitening16_hex': bytes(x ^ y for x, y in zip(seed, bytes.fromhex(case['offsets9_hex'][0]))).hex(),
            'scope': 'Nine substitution/ShiftRows/MixColumns layers match the AES-128 prefix on a whitened staged input, before round-9 AddRoundKey. Predicted final keys and terminal semantics are not source-established.'}
        case['retained_input16_hex'] = parent['entry_input16_hex']
        indices, states = prefix(case, bytes.fromhex(parent['entry_input16_hex']), affine)
        case['retained_word_indices'] = {str(k): v for k, v in indices.items()}; case['retained_canonical_states10_hex'] = states
        cases.append(case)
    assert cases[0]['word_reads'] == cases[1]['word_reads']
    counts = {'retained_contexts': 2, 'word_read_records': 320, 'source_composition_identities': 288,
              'main_substitution_mix_layers_per_context': 9, 'main_word_reads_per_context': 144,
              'terminal_word_indices_per_context': 16, 'offset_vectors_per_context': 9,
              'new_target_intervals': 0, 'new_root_bytes': 0}
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'cases': cases,
            'verified_counts': counts, 'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'transform_algorithm_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    evidence = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence['verified_counts']), flush=True)
