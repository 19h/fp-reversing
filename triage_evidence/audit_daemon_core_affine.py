#!/usr/bin/env python3
"""Certify source byte projections, all finite codecs and S-box fit witnesses.
O(parent bytes + source lift/DAG + codec rows + candidate witness rows
+ positive fit rows + reference field arithmetic + query DAG) time/space;
solver search additional, 30 s/query. Prior complete core admissions/replay
are pinned rather than rerun. No native target, IPC, PAC or IDB action.
"""
import json
import struct
from collections import Counter
from functools import reduce
from operator import xor
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_append_fields import number
import recover_daemon_core_lookup as Core
import recover_daemon_core_affine as R

DEPS = ['recover_daemon_core_lookup.py', 'audit_daemon_append_fields.py',
        'audit_daemon_alternative_fill.py', 'lskd_values_symbolic.py', 'capture_daemon_core_affine_reference.py']


def apply(columns, value):
    return reduce(xor, (column for bit, column in enumerate(columns) if value >> bit & 1), 0)


def reference():
    def multiply(a, b):
        result = 0
        for bit in range(8):
            if b & 1: result ^= a
            a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255; b >>= 1
        return result
    result = []
    for x in range(256):
        value, base, exponent = 1, x, 254
        while exponent:
            if exponent & 1: value = multiply(value, base)
            base = multiply(base, base); exponent >>= 1
        result.append(value ^ reduce(xor, (((value << j) | (value >> (8-j))) & 255 for j in range(1, 5)), 0) ^ 0x63)
    return bytes(result)


def audit():
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); assert e == R.build()
    old = json.loads(read(ROOT/'daemon_core_lookup_checks.json'))
    sbox = reference(); inverse = bytes(sbox.index(x) for x in range(256))
    assert sbox.hex() == e['reference']['table256_hex'] and len(set(sbox)) == 256
    assert e['reference']['capture_tool_sha256'] == sha(ROOT/'capture_daemon_core_affine_reference.py')
    totals = Counter(reference_sbox_values_checked=256); proofs = []
    for case, parent in zip(e['cases'], old['cases']):
        model = Core.Model(parent['source_chunk']).run()
        assert sorted(r['input_offset'] for r in case['initial_indices']) == list(range(16))
        for j, r in enumerate(case['initial_indices']):
            source = model.lookups[16+j]; x = model.inputs[r['input_offset']]
            prefix, = [p for p in model.lookups[:16] if Core.variables(p['index']) == [x]]
            allowed = {str(x), prefix['name']}
            reduced = z3.simplify(z3.substitute(source['index'], *[
                (v, z3.BitVecVal(0, v.size())) for v in Core.variables(source['index']) if str(v) not in allowed]))
            assert reduced.sexpr() == r['source_reduced_index'] and prefix['index'].sexpr() == r['prefix_source_index']
            assert (source['pc'], source['base'], prefix['pc'], prefix['base']) == (r['pc'], r['bank'], r['prefix_pc'], r['prefix_bank'])
            solver = z3.Solver(); solver.set(timeout=30000); assert solver.check() == z3.sat
            solver.add(source['index'] != reduced); answer = solver.check()
            assert answer == z3.unsat, (j, str(answer), solver.reason_unknown())
            label = str(case['class_index'])+'_'+r['pc']+'_two_byte_projection'
            proofs.append({'label': label, 'class_index': case['class_index'], 'pc': r['pc'],
                           'allowed_variables': sorted(allowed), 'premises_nonvacuous': True,
                           'result': 'unsat', 'query': solver.to_smt2()})
            bank = IMAGE.read(int(prefix['base'], 16), 256)
            for value in range(256):
                index = number(z3.substitute(prefix['index'], (x, z3.BitVecVal(value, 8))))
                assert index == value ^ r['prefix_index_xor8']
                actual = number(z3.substitute(reduced, (x, z3.BitVecVal(value, 8)),
                                (prefix['value'], z3.BitVecVal(bank[index], 8))))
                assert actual == r['map256'][value] == apply(r['columns8'], value) ^ r['bias8']
                totals.update(prefix_source_rows_checked=1, projected_source_rows_checked=1, affine_map_rows_checked=1)
            assert len({apply(r['columns8'], v) for v in range(256)}) == 256
            totals['bijective_byte_codecs_checked'] += 1
            print(json.dumps({'source_proof': label, 'result': 'unsat', 'finite_rows': 256}), flush=True)
    patterns = Counter()
    for table in e['main_tables']:
        raw = IMAGE.read(int(table['bank'], 16), 1024)
        words = [int.from_bytes(raw[j:j+4], 'little') for j in range(0, 1024, 4)]
        assert words == table['word256_LE']; totals['original_word_rows_checked'] += 256
        matrix = table['input_columns8']
        assert len({apply(matrix, x) for x in range(256)}) == 256
        domain = {(c['reference'], c['extended'], c['input_xor8']) for c in table['candidates']}
        assert domain == {(name, ext, delta) for name in ['forward', 'inverse'] for ext in [False, True] for delta in range(256)}
        for c in table['candidates']:
            ref = sbox if c['reference'] == 'forward' else inverse; delta = c['input_xor8']; ext = c['extended']
            def feature(x): return ref[x ^ delta] | (x << 8 if ext else 0) | (1 << (16 if ext else 8))
            if c['fits']:
                assert len(c['feature_columns32']) == c['feature_rank'] == (17 if ext else 9)
                for x in range(256): assert words[apply(matrix, x)] == apply(c['feature_columns32'], feature(x))
                totals['positive_factor_rows_checked'] += 256; patterns[(c['reference'], ext)] += 1
            else:
                witness = c['witness_inputs']; assert len(witness) == len(set(witness)) and all(0 <= x < 256 for x in witness)
                assert reduce(xor, (feature(x) for x in witness), 0) == 0
                residual = reduce(xor, (words[apply(matrix, x)] for x in witness), 0)
                assert residual == c['output_XOR32'] != 0
                totals['rejection_witness_terms_checked'] += len(witness)
            totals['factor_candidates_checked'] += 1
        factor = table['factor']; assert factor['sbox_embedding_rank'] == 8
        assert all(apply(factor['sbox_left_inverse_columns8'], apply(factor['sbox_columns32'], x)) == x for x in range(256))
        for x in range(256):
            corrected = words[apply(matrix, x)] ^ apply(factor['input_columns32'], x) ^ factor['bias32']
            assert corrected == apply(factor['sbox_columns32'], sbox[x ^ factor['input_xor8']])
            assert apply(factor['sbox_left_inverse_columns8'], corrected) == sbox[x ^ factor['input_xor8']]
        totals['decoded_sbox_rows_checked'] += 256
    assert patterns == Counter({('forward', False): 2, ('forward', True): 4})
    # Independently construct the encoded forward MixColumns contribution.
    mc = e['mixcolumns']; assert mc['matrix4x4'] == [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    assert all(mc['row_encoder_columns8'][r['input_offset'] % 4] == r['columns8'] for c in e['cases'] for r in c['initial_indices'])
    def xtime(x): return ((x << 1) ^ (0x1b if x & 128 else 0)) & 255
    for table in e['main_tables']:
        f = table['mixcolumns_factor']; row = f['input_row']
        for x in range(256):
            index = apply(table['input_columns8'], x); word = table['word256_LE'][index]
            byte = sbox[x ^ table['factor']['input_xor8']]
            products = {1: byte, 2: xtime(byte), 3: xtime(byte) ^ byte}
            encoded = [apply(mc['row_encoder_columns8'][r], products[mc['matrix4x4'][r][row]]) for r in range(4)]
            target = int.from_bytes(bytes(encoded), 'big') ^ f['normalized_bias32']
            if f['normalizer'] == 'xor_index': actual = word ^ index
            elif f['normalizer'] == 'right_xorshift': actual = word ^ (word >> 2) ^ (word >> 6)
            else:
                assert f['normalizer'] == 'rotate_xorshift'
                rotated = ((word << 14) | (word >> 18)) & 0xffffffff
                actual = rotated ^ ((rotated << 3) & 0xe19e3e68)
            assert actual == target
            totals['encoded_mixcolumns_rows_checked'] += 1
    factors = {r['bank']: r['factor'] for r in e['main_tables']}
    for case in e['cases']:
        effective = [None]*16
        for r in case['initial_indices']:
            f = factors[r['bank']]
            for x in range(256):
                encoded = apply(r['columns8'], x) ^ r['bias8']
                decoded = next(v for v in range(256) if apply(r['columns8'], v) == encoded)
                assert decoded ^ f['input_xor8'] == x ^ r['effective_first_sbox_input_xor8']
                totals['first_sbox_argument_rows_checked'] += 1
            effective[r['input_offset']] = r['effective_first_sbox_input_xor8']
        assert bytes(effective).hex() == case['effective_first_sbox_input_xor16_hex']
    # Check the load-command fields directly, independently of the extractor walk.
    image = SOURCE.read_bytes(); mapping, = e['original_window_mapping']; at = int(mapping['command_file_offset'], 16)
    assert struct.unpack_from('<I', image, at)[0] == 0x19
    assert image[at+8:at+24].rstrip(b'\0') == b'__TEXT'
    assert struct.unpack_from('<II', image, at+56) == (5, 5)
    va, extent = struct.unpack_from('<QQ', image, at+24)
    assert set(mapping['windows']) == set(old['cases'][0]['graph']['windows'])
    assert all(va <= int(a, 16) and int(a, 16)+256*old['cases'][0]['graph']['windows'][a]['unit_bytes'] <= va+extent for a in mapping['windows'])
    assert len(proofs) == 32
    totals.update(source_projection_queries_unsat=32, original_protection_windows_checked=16)
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'generator_sha256': sha(ROOT/'recover_daemon_core_affine.py'),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'independent_totals': dict(totals),
            'source_queries_unsat': len(proofs), 'source_proofs': proofs,
            'factor_matches': [{'reference': name, 'extended': ext, 'banks': n} for (name, ext), n in sorted(patterns.items())],
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False,
            'transform_algorithm_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    a = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a, indent=2)+'\n')
    print(json.dumps(a['independent_totals']), flush=True)
