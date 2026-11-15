#!/usr/bin/env python3
"""Terminal tables, final byte decoders and the complete conditional core cipher.
O(parent bytes + source DAG + 2048*256*9 elimination + 32*256 evaluations)
time, linear receipt storage. No native target, IPC, PAC or IDB operation.
"""
import json
from functools import reduce
from operator import xor
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_append_fields import number
import recover_daemon_core_lookup as Core
import recover_daemon_core_affine as Affine
import recover_daemon_core_rounds as Rounds

P = 'daemon_core_cipher'
PINS = {'daemon_core_lookup_checks.json': '5661e892920d52fac2029d2bbc4b3189c884caa839dd93552c268eed293689c9',
        'daemon_core_lookup_audit.json': '39495d6ba9b37d1113d3d7ceba4c8ec317baec96f1ed1277ec7d4344df87d460',
        'daemon_core_affine_checks.json': 'd46e946d6acca5be5f2a599544bde0dae5a755b2b8a2011a244ac2865be09c8f',
        'daemon_core_affine_audit.json': 'ec0188120431ee0d83f7bc606e4122197f3a5ae97d0a5703656411ae663418e6',
        'daemon_core_rounds_checks.json': '483171e5eac9b0986b2df25160bbacb803fa78f364766e169f897cb9ff765e5d',
        'daemon_core_rounds_audit.json': '959f187b700cd067d5b2e8d63f93d6813bb1d06f7da1318d1fd058caf5763949',
        'daemon_block_staging_checks.json': 'f544501de6a7ceefa17c5bba23a8f1de5137bbf8cd53d812e66b8e5e5a0e00a6'}
DEPS = ['recover_daemon_core_lookup.py', 'recover_daemon_core_affine.py', 'recover_daemon_core_rounds.py',
        'daemon_core_cipher_kernel.py', 'daemon_receive_tools.py', 'audit_daemon_append_fields.py',
        'audit_daemon_alternative_fill.py', 'lskd_values_symbolic.py']


def normalize(row, index, word):
    if row == 0: return (word ^ (word << 2)) & 0xffffffff
    if row == 1: return (word + (index ^ 0x27) + 0x494ca6e5) & 0xffffffff
    if row == 2: return word ^ index
    assert row == 3
    z = index ^ 0x85
    correction = z ^ ((z-((2*z+0x2ae) & 0x308)+0xa70652db) & 0xffffffff)
    return word ^ correction


def factors(case, affine):
    sbox = bytes.fromhex(affine['reference']['table256_hex']); inverse = bytes(sbox.index(j) for j in range(256))
    result = []
    for row in range(4):
        bank, = {r['bank'] for r in case['word_reads'] if r['round'] == 10 and r['row'] == row}
        columns = affine['mixcolumns']['row_encoder_columns8'][row]; raw = IMAGE.read(int(bank, 16), 1024)
        words = [int.from_bytes(raw[j:j+4], 'little') for j in range(0, 1024, 4)]
        outputs = [normalize(row, Affine.linear(columns, x), words[Affine.linear(columns, x)]) for x in range(256)]
        candidates = []
        for name, reference in [('forward', sbox), ('inverse', inverse)]:
            for delta in range(256):
                fit = Affine.fit(Affine.features(reference, delta, False), outputs)
                candidates.append({'reference': name, 'input_xor8': delta, **fit})
        match, = [r for r in candidates if r['fits']]
        assert match['reference'] == 'forward'
        assert match['feature_columns32'][:8] == [v << (24-row*8) for v in columns]
        result.append({'row': row, 'bank': bank, 'input_columns8': columns, 'word256_LE': words,
                       'candidates': candidates, 'input_xor8': match['input_xor8'],
                       'normalized_bias32': match['feature_columns32'][8], 'output_columns32': match['feature_columns32'][:8]})
    return result


def bvlinear(columns, value):
    return reduce(xor, (z3.If(z3.Extract(j, j, value) == 1, z3.BitVecVal(v, 8), z3.BitVecVal(0, 8)) for j, v in enumerate(columns)))


def terminal_cuts(model, case, tables, affine):
    main = {t['bank']: t for t in affine['main_tables']}; by_row = {t['row']: t for t in tables}
    rows = [r for r in case['word_reads'] if r['round'] == 10]
    symbols = {r['ordinal']: z3.BitVec('terminal_sbox_%03d_8' % r['ordinal'], 8) for r in rows}
    pairs = []
    for r in rows:
        j, row = r['ordinal'], r['row']; table = by_row[row]
        index = z3.Extract(31, 0, Rounds.equation(model, r, main))
        norm = (z3.ZeroExt(24, bvlinear(table['input_columns8'], symbols[j])) << (24-row*8)) ^ table['normalized_bias32']
        if row == 0: raw = reduce(xor, (norm << (2*k) for k in range(16)))
        elif row == 1: raw = norm-(index ^ 0x27)-0x494ca6e5
        elif row == 2: raw = norm ^ index
        else:
            z = index ^ 0x85
            raw = norm ^ z ^ (z-(((z << 1)+0x2ae) & 0x308)+0xa70652db)
        pairs.append((model.lookups[j]['value'], z3.simplify(raw)))
    return rows, symbols, pairs


def final_bytes(model, case, tables, affine):
    terminal, symbols, pairs = terminal_cuts(model, case, tables, affine)
    by_name = {r['name']: j for j, r in enumerate(model.lookups)}; result = []
    for output in model.output:
        returned, = Core.variables(output['value']); j = by_name[str(returned)]; source = model.lookups[j]
        p = output['offset']; input_position = 4*((p//4+p % 4) % 4)+p % 4
        previous, = [r for r in terminal if r['input_offset'] == input_position]
        table = tables[p % 4]; symbol = symbols[previous['ordinal']]
        candidate = z3.ZeroExt(56, bvlinear(table['input_columns8'], symbol))
        full = z3.simplify(z3.substitute(source['index'], *pairs)); delta = full ^ candidate
        bias = number(z3.substitute(delta, *[(v, z3.BitVecVal(0, v.size())) for v in Core.variables(delta)]))
        assert 0 <= bias < 256
        post = [number(z3.substitute(output['value'], (returned, z3.BitVecVal(v, 8)))) for v in range(256)]
        assert len(set(post)) == 256
        raw = IMAGE.read(int(source['base'], 16), 256)
        decoded = [post[raw[Affine.linear(table['input_columns8'], v) ^ bias]] for v in range(256)]
        offset = decoded[0]; assert all(y == (x ^ offset) for x, y in enumerate(decoded)), (p, decoded)
        result.append({'output_offset': p, 'store_pc': output['pc'], 'byte_ordinal': j, 'byte_pc': source['pc'],
                       'byte_bank': source['base'], 'input_position': input_position, 'terminal_ordinal': previous['ordinal'],
                       'index_xor8': bias, 'source_store_expression': output['value'].sexpr(),
                       'post_store_map256': post, 'original_byte_bank256_hex': raw.hex(),
                       'decoded_map256': decoded, 'final_xor8': offset})
    assert len(result) == 16 and sorted(r['output_offset'] for r in result) == list(range(16))
    return result


def build():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    parent = json.loads(read(ROOT/'daemon_core_lookup_checks.json'))
    affine = json.loads(read(ROOT/'daemon_core_affine_checks.json'))
    rounds = json.loads(read(ROOT/'daemon_core_rounds_checks.json'))
    staging = json.loads(read(ROOT/'daemon_block_staging_checks.json'))
    tables = factors(rounds['cases'][0], affine); cases = []
    for core, prefix, staged in zip(parent['cases'], rounds['cases'], staging['cases']):
        model = Core.Model(core['source_chunk']).run(); decoders = final_bytes(model, prefix, tables, affine)
        final = bytes(r['final_xor8'] for r in sorted(decoders, key=lambda r: r['output_offset']))
        terminal_key = [None]*16
        for r in prefix['word_reads']:
            if r['round'] != 10: continue
            table = tables[r['row']]; inverse = next(x for x in range(256) if Affine.linear(table['input_columns8'], x) == r['encoded_state_xor8'])
            terminal_key[r['input_offset']] = inverse ^ table['input_xor8']
        schedule = prefix['AES128_prefix_schedule']
        assert bytes(terminal_key).hex() == schedule['expanded11_hex'][9]
        core_input = bytes.fromhex(schedule['input_whitening16_hex'])
        core_output = bytes(x ^ y for x, y in zip(final, bytes.fromhex(schedule['expanded11_hex'][10])))
        masks = staged['mask16_hex']
        contract = {'key16_hex': schedule['backderived_seed16_hex'],
                    'core_input_xor16_hex': core_input.hex(), 'core_output_xor16_hex': core_output.hex(),
                    'core_formula': 'B = AES128_encrypt_K(A XOR core_input_xor16) XOR core_output_xor16',
                    'external_input_xor16_hex': bytes(x ^ y for x, y in zip(core_input, bytes.fromhex(masks['input']))).hex(),
                    'external_output_xor16_hex': bytes(x ^ y for x, y in zip(core_output, bytes.fromhex(masks['output']))).hex(),
                    'external_formula': 'T = AES128_encrypt_K(S_serialized[2:18] XOR external_input_xor16) XOR external_output_xor16',
                    'scope': 'Conditional 16-byte component and established staging only. Native traffic pairing, key-object lineage and any multi-block protocol mode remain unknown.'}
        cases.append({'class_index': core['class_index'], 'decoders': decoders,
                      'source_round9_key16_hex': bytes(terminal_key).hex(), 'final_xor16_hex': final.hex(),
                      'contract': contract, 'retained_vectors': staged['vectors']})
    assert cases[0]['decoders'] == cases[1]['decoders'] and cases[0]['contract'] == cases[1]['contract']
    counts = {'retained_contexts': 2, 'terminal_word_banks': 4, 'terminal_word_rows': 1024,
              'factor_candidates': 2048, 'factor_matches': 4, 'source_final_index_identities': 32,
              'source_univariate_store_cuts': 32, 'post_store_rows': 8192, 'decoded_output_rows': 8192,
              'source_round9_key_bytes': 32, 'new_target_intervals': 0, 'new_root_bytes': 0}
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'tables': tables, 'cases': cases, 'verified_counts': counts,
            'conditional_core_cipher_established': True, 'native_API_executed': False,
            'native_daemon_kext_pairing_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    evidence = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence['verified_counts']), flush=True)
