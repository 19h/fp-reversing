#!/usr/bin/env python3
"""Initial core byte codecs and finite AES S-box factorizations.
Fixed source/data domains; O(parent bytes + source lift/DAG + 32*256 value
checks + 4*2*2*256*256*17 elimination steps) time, linear receipt storage.
No native execution, new root admission, PAC or IDB modification.
"""
import json
import struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_append_fields import number
import recover_daemon_core_lookup as Core

P = 'daemon_core_affine'
ORDER = [5, 10, 0, 4, 9, 14, 3, 13, 15, 8, 1, 2, 7, 12, 6, 11]
PINS = {'daemon_core_lookup_checks.json': '5661e892920d52fac2029d2bbc4b3189c884caa839dd93552c268eed293689c9',
        'daemon_core_lookup_audit.json': '39495d6ba9b37d1113d3d7ceba4c8ec317baec96f1ed1277ec7d4344df87d460',
        'daemon_core_affine_reference.json': '7fe2e9953f620e6d7c210f177197cb8d4b537ade926bdba7d8085969aaf49553'}
DEPS = ['recover_daemon_core_lookup.py', 'daemon_receive_tools.py', 'audit_daemon_append_fields.py',
        'audit_daemon_alternative_fill.py', 'lskd_values_symbolic.py', 'capture_daemon_core_affine_reference.py']


def linear(columns, x):
    value = 0
    for j, v in enumerate(columns):
        if x >> j & 1: value ^= v
    return value


def rank(columns):
    basis = {}
    for value in columns:
        while value:
            bit = value.bit_length()-1
            if bit not in basis: basis[bit] = value; break
            value ^= basis[bit]
    return len(basis)


def left_inverse(columns):
    basis = {}
    for j, value in enumerate(columns):
        tag = 1 << j
        while value:
            bit = value.bit_length()-1
            if bit not in basis: basis[bit] = (value, tag); break
            x, y = basis[bit]; value ^= x; tag ^= y
    assert len(basis) == 8
    def decode(value):
        out = 0
        for bit, (x, y) in sorted(basis.items(), reverse=True):
            if value >> bit & 1: value ^= x; out ^= y
        return out
    inverse = [decode(1 << j) for j in range(32)]
    assert all(linear(inverse, linear(columns, x)) == x for x in range(256))
    return inverse


def projection(model, j):
    row = model.lookups[16+j]; p = ORDER[j]; input_byte = model.inputs[p]
    prefix = next(r for r in model.lookups[:16] if Core.variables(r['index']) == [input_byte])
    keep = {str(input_byte), prefix['name']}
    reduced = z3.simplify(z3.substitute(row['index'], *[
        (v, z3.BitVecVal(0, v.size())) for v in Core.variables(row['index']) if str(v) not in keep]))
    return row, prefix, input_byte, reduced


def codecs(model):
    out = []
    for j in range(16):
        row, prefix, x, reduced = projection(model, j)
        raw = IMAGE.read(int(prefix['base'], 16), 256)
        indices = [number(z3.substitute(prefix['index'], (x, z3.BitVecVal(v, 8)))) for v in range(256)]
        assert all(v == (i ^ indices[0]) for i, v in enumerate(indices))
        values = [number(z3.substitute(reduced, (x, z3.BitVecVal(v, 8)),
                        (prefix['value'], z3.BitVecVal(raw[indices[v]], 8)))) for v in range(256)]
        bias = values[0]; columns = [values[1 << bit] ^ bias for bit in range(8)]
        assert all(value == bias ^ linear(columns, i) for i, value in enumerate(values))
        assert max(values) <= 255 and rank(columns) == 8
        out.append({'read_ordinal': j, 'pc': row['pc'], 'bank': row['base'], 'input_offset': ORDER[j],
                    'prefix_pc': prefix['pc'], 'prefix_bank': prefix['base'], 'prefix_index_xor8': indices[0],
                    'prefix_source_index': prefix['index'].sexpr(), 'source_reduced_index': reduced.sexpr(),
                    'map256': values, 'columns8': columns, 'bias8': bias, 'rank': 8})
    return out


def fit(features, outputs):
    """GF(2) row elimination with a retained contradiction-combination witness."""
    basis = {}
    for i, (a, b) in enumerate(zip(features, outputs)):
        witness = 1 << i
        while a:
            bit = a.bit_length()-1
            if bit not in basis: basis[bit] = (a, b, witness); break
            x, y, w = basis[bit]; a ^= x; b ^= y; witness ^= w
        else:
            if b: return {'fits': False, 'witness_inputs': [j for j in range(256) if witness >> j & 1],
                          'output_XOR32': b}
    width = max(features).bit_length(); assert len(basis) == width
    columns = []
    for bit in range(width):
        a = 1 << bit; b = 0
        while a:
            x, y, witness = basis[a.bit_length()-1]; a ^= x; b ^= y
        columns.append(b)
    assert all(linear(columns, f) == y for f, y in zip(features, outputs))
    return {'fits': True, 'feature_rank': width, 'feature_columns32': columns}


def features(reference, delta, extended):
    return [reference[x ^ delta] | (x << 8 if extended else 0) | (1 << (16 if extended else 8)) for x in range(256)]


def gf_multiply(a, b):
    value = 0
    for j in range(8):
        if b & 1: value ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255; b >>= 1
    return value


def normalize(kind, word, index):
    if kind == 'rotate_xorshift':
        value = ((word >> 18) | (word << 14)) & 0xffffffff
        return value ^ ((value << 3) & 0xe19e3e68)
    if kind == 'right_xorshift': return word ^ (word >> 2) ^ (word >> 6)
    assert kind == 'xor_index'
    return word ^ index


def mixcolumns(factored, rows, sbox):
    encoders = {}
    for r in rows:
        row = r['input_offset'] % 4
        if row in encoders: assert encoders[row] == r['columns8']
        encoders[row] = r['columns8']
    matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    by_row = {0: 'right_xorshift', 1: 'rotate_xorshift', 2: 'xor_index', 3: 'xor_index'}
    for t in factored:
        source_rows = {r['input_offset'] % 4 for r in rows if r['bank'] == t['bank']}; row, = source_rows
        kind = by_row[row]; bias = normalize(kind, t['factor']['bias32'], 0)
        for x in range(256):
            index = linear(t['input_columns8'], x); byte = sbox[x ^ t['factor']['input_xor8']]
            expected = int.from_bytes(bytes(linear(encoders[r], gf_multiply(matrix[r][row], byte)) for r in range(4)), 'big')
            assert normalize(kind, t['word256_LE'][index], index) == expected ^ bias
        t['mixcolumns_factor'] = {'input_row': row, 'normalizer': kind,
                                  'normalized_bias32': bias, 'rows_checked': 256}
    return {'row_encoder_columns8': [encoders[r] for r in range(4)],
            'matrix4x4': matrix, 'field_polynomial': '0x11b',
            'word_byte_order': 'row 0 is bits31..24; row 3 is bits7..0', 'rows_checked': 1024}


def tables(rows, sbox):
    inverse = bytes(sbox.index(j) for j in range(256)); out = []
    for bank in dict.fromkeys(r['bank'] for r in rows):
        same = [r for r in rows if r['bank'] == bank]; columns = same[0]['columns8']
        assert all(r['columns8'] == columns for r in same) and len(same) == 4
        raw = IMAGE.read(int(bank, 16), 1024)
        words = [int.from_bytes(raw[j:j+4], 'little') for j in range(0, 1024, 4)]
        encoded = [words[linear(columns, x)] for x in range(256)]
        candidates = []
        for extended in [False, True]:
            for name, reference in [('forward', sbox), ('inverse', inverse)]:
                for delta in range(256):
                    result = fit(features(reference, delta, extended), encoded)
                    candidates.append({'reference': name, 'input_xor8': delta, 'extended': extended, **result})
        matches = [c for c in candidates if c['fits'] and c['extended']]
        assert len(matches) == 1 and matches[0]['reference'] == 'forward'
        match = matches[0]; coeff = match['feature_columns32']
        out.append({'bank': bank, 'input_columns8': columns, 'input_rank': 8, 'word256_LE': words,
                    'candidates': candidates, 'factor': {'input_xor8': match['input_xor8'],
                        'sbox_columns32': coeff[:8], 'input_columns32': coeff[8:16], 'bias32': coeff[16],
                        'sbox_left_inverse_columns8': left_inverse(coeff[:8]),
                        'sbox_embedding_rank': rank(coeff[:8]), 'input_correction_rank': rank(coeff[8:16])}})
    return out


def mapping(windows):
    data = SOURCE.read_bytes(); at = 32; hits = []
    for j in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            name = data[at+8:at+24].split(b'\0')[0].decode(); va, extent = struct.unpack_from('<QQ', data, at+24)
            selected = [a for a, r in windows.items() if va <= int(a, 16) and int(a, 16)+256*r['unit_bytes'] <= va+extent]
            if selected:
                maximum, initial = struct.unpack_from('<II', data, at+56)
                hits.append({'segment': name, 'command_file_offset': hex(at), 'maxprot': maximum,
                             'initprot': initial, 'windows': sorted(selected)})
        at += size
    assert len(hits) == 1 and hits[0]['segment'] == '__TEXT' and hits[0]['maxprot'] == hits[0]['initprot'] == 5
    assert len(hits[0]['windows']) == 16
    return hits


def build():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    old = json.loads(read(ROOT/'daemon_core_lookup_checks.json'))
    reference = json.loads(read(ROOT/'daemon_core_affine_reference.json')); sbox = bytes.fromhex(reference['table256_hex'])
    cases = []
    for case in old['cases']:
        model = Core.Model(case['source_chunk']).run(); rows = codecs(model)
        cases.append({'class_index': case['class_index'], 'initial_indices': rows})
    assert cases[0]['initial_indices'] == cases[1]['initial_indices']
    factored = tables(cases[0]['initial_indices'], sbox); factors = {r['bank']: r for r in factored}
    mix = mixcolumns(factored, cases[0]['initial_indices'], sbox)
    for c in cases:
        effective = [None]*16
        for row in c['initial_indices']:
            factor = factors[row['bank']]['factor']; matrix = row['columns8']
            inverse_bias = next(x for x in range(256) if linear(matrix, x) == row['bias8'])
            row['effective_first_sbox_input_xor8'] = inverse_bias ^ factor['input_xor8']
            effective[row['input_offset']] = row['effective_first_sbox_input_xor8']
        c['effective_first_sbox_input_xor16_hex'] = bytes(effective).hex()
    counts = {'retained_contexts': 2, 'source_projection_candidates': 32, 'codec_rows': 32,
              'codec_input_values_checked': 8192, 'main_banks': 4, 'main_bank_word_rows': 1024,
              'factor_candidates': sum(len(t['candidates']) for t in factored),
              'factor_matches': sum(c['fits'] for t in factored for c in t['candidates']),
              'encoded_mixcolumns_rows': 1024,
              'reference_sbox_values': 256, 'new_target_intervals': 0, 'new_root_bytes': 0}
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'parent_pins': PINS, 'reference': reference,
            'cases': cases, 'main_tables': factored, 'mixcolumns': mix,
            'original_window_mapping': mapping(old['cases'][0]['graph']['windows']),
            'verified_counts': counts, 'native_API_executed': False,
            'native_daemon_kext_pairing_established': False, 'transform_algorithm_established': False,
            'full_goal_complete': False}


if __name__ == '__main__':
    e = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(e, indent=2)+'\n')
    print(json.dumps(e['verified_counts']), flush=True)
