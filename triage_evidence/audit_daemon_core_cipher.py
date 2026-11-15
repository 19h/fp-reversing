#!/usr/bin/env python3
"""Certify terminal embeddings, output consumers and complete block semantics.
O(source DAG + proof DAG + finite witness rows + 136*DAG) time/space;
solver search additional, 30 s/query. Host OpenSSL is a reference only;
no native daemon/kext, API/IPC, hardware PAC or IDB action.
"""
import json
import subprocess
import shutil
from collections import Counter
from functools import reduce
from hashlib import sha256
from operator import xor
from pathlib import Path
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_append_fields import number
from audit_daemon_core_affine import reference, apply
import recover_daemon_core_lookup as Core
import recover_daemon_core_rounds as Rounds
import daemon_core_lookup_kernel as DAG
import daemon_core_cipher_kernel as Kernel
import recover_daemon_core_cipher as R

DEPS = ['recover_daemon_core_lookup.py', 'recover_daemon_core_rounds.py', 'audit_daemon_core_affine.py',
        'daemon_core_lookup_kernel.py', 'daemon_core_cipher_kernel.py', 'audit_daemon_alternative_fill.py',
        'audit_daemon_append_fields.py', 'lskd_values_symbolic.py']


def symbolic_byte(matrix, value):
    bits = [z3.ZeroExt(7, z3.Extract(bit, bit, value)) for bit in range(8)]
    return reduce(xor, (z3.If(bit == 0, z3.BitVecVal(0, 8), z3.BitVecVal(column, 8)) for bit, column in zip(bits, matrix)))


def original_word(table, index, byte):
    row = table['row']; norm = (apply(table['input_columns8'], byte) << (24-8*row)) ^ table['normalized_bias32']
    if row == 0: return reduce(xor, (norm << shift for shift in range(0, 32, 2))) & 0xffffffff
    if row == 1: return (norm-0x494ca6e5-(index ^ 0x27)) & 0xffffffff
    if row == 2: return norm ^ index
    part = index ^ 0x85; adjusted = (part+0xa70652db-((2*part+0x2ae) & 0x308)) & 0xffffffff
    return norm ^ part ^ adjusted


def table_normalized(row, index, word):
    if row == 0: return (word ^ (4*word)) & 0xffffffff
    if row == 1: return (word+0x494ca6e5+(index ^ 39)) & 0xffffffff
    if row == 2: return word ^ index
    part = index ^ 133
    return word ^ part ^ ((part+0xa70652db-((2*part+686) & 776)) & 0xffffffff)


def embeddings(model, case, evidence, affine):
    symbols, substitutions = {}, []
    main = {t['bank']: t for t in affine['main_tables']}
    for r in case['word_reads']:
        if r['round'] != 10: continue
        j, row = r['ordinal'], r['row']; table = evidence['tables'][row]
        value = z3.BitVec('terminal_sbox_%03d_8' % j, 8); symbols[j] = value
        index = z3.Extract(31, 0, Rounds.equation(model, r, main))
        normalized = (z3.ZeroExt(24, symbolic_byte(table['input_columns8'], value)) << (24-8*row)) ^ table['normalized_bias32']
        if row == 0: raw = reduce(xor, (normalized << shift for shift in range(0, 32, 2)))
        elif row == 1: raw = normalized-0x494ca6e5-(index ^ 0x27)
        elif row == 2: raw = normalized ^ index
        else:
            part = index ^ 0x85
            raw = normalized ^ part ^ (part+0xa70652db-(((part << 1)+0x2ae) & 0x308))
        substitutions.append((model.lookups[j]['value'], z3.simplify(raw)))
    return symbols, substitutions


def prove(label, case, pc, bad):
    solver = z3.SolverFor('QF_BV'); solver.set(timeout=30000); assert solver.check() == z3.sat
    solver.add(bad); result = solver.check()
    assert result == z3.unsat, (label, str(result), solver.reason_unknown())
    return {'label': str(case['class_index'])+'_'+label, 'class_index': case['class_index'], 'pc': pc,
            'premises_nonvacuous': True, 'result': 'unsat', 'query': solver.to_smt2()}


def openssl(key, blocks):
    command = ['openssl', 'enc', '-aes-128-ecb', '-K', key.hex(), '-nopad', '-nosalt']
    run = subprocess.run(command, input=b''.join(blocks), capture_output=True, check=True)
    assert not run.stderr and len(run.stdout) == 16*len(blocks)
    return [run.stdout[j:j+16] for j in range(0, len(run.stdout), 16)]


def audit():
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); assert evidence == R.build()
    affine = json.loads(read(ROOT/'daemon_core_affine_checks.json'))
    rounds = json.loads(read(ROOT/'daemon_core_rounds_checks.json'))
    parents = json.loads(read(ROOT/'daemon_core_lookup_checks.json'))
    staging = json.loads(read(ROOT/'daemon_block_staging_checks.json'))
    sbox = reference(); inverse = bytes(sbox.index(j) for j in range(256)); assert sbox == Kernel.SBOX
    totals = Counter(reference_sbox_values_checked=256); proofs, vectors = [], []
    for table in evidence['tables']:
        row = table['row']; raw = IMAGE.read(int(table['bank'], 16), 1024)
        words = [int.from_bytes(raw[j:j+4], 'little') for j in range(0, 1024, 4)]
        assert words == table['word256_LE'] and table['input_columns8'] == affine['mixcolumns']['row_encoder_columns8'][row]
        assert table['output_columns32'] == [v << (24-8*row) for v in table['input_columns8']]
        assert {(c['reference'], c['input_xor8']) for c in table['candidates']} == {(name, delta) for name in ['forward', 'inverse'] for delta in range(256)}
        for candidate in table['candidates']:
            ref = sbox if candidate['reference'] == 'forward' else inverse; delta = candidate['input_xor8']
            feature = [ref[x ^ delta] | 256 for x in range(256)]
            output = [table_normalized(row, apply(table['input_columns8'], x), words[apply(table['input_columns8'], x)]) for x in range(256)]
            if candidate['fits']:
                assert candidate['reference'] == 'forward' and delta == table['input_xor8'] and candidate['feature_rank'] == 9
                assert all(apply(candidate['feature_columns32'], f) == y for f, y in zip(feature, output))
                totals['positive_factor_rows_checked'] += 256
            else:
                witness = candidate['witness_inputs']; assert len(witness) == len(set(witness))
                assert reduce(xor, (feature[j] for j in witness), 0) == 0
                assert reduce(xor, (output[j] for j in witness), 0) == candidate['output_XOR32'] != 0
                totals['rejection_witness_terms_checked'] += len(witness)
            totals['factor_candidates_checked'] += 1
        for x in range(256):
            index = apply(table['input_columns8'], x); value = sbox[x ^ table['input_xor8']]
            assert original_word(table, index, value) == words[index]
            totals['original_terminal_embedding_rows_checked'] += 1
    known_input = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
    known_key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    known_output = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')
    assert Kernel.encrypt(known_input, known_key) == openssl(known_key, [known_input])[0] == known_output
    totals['NIST_complete_cipher_checkpoints'] += 1
    for case, prefix, parent, staged in zip(evidence['cases'], rounds['cases'], parents['cases'], staging['cases']):
        model = Core.Model(parent['source_chunk']).run(); main = {t['bank']: t for t in affine['main_tables']}
        symbols, substitutions = embeddings(model, prefix, evidence, affine)
        for record in prefix['word_reads']:
            if record['round'] != 10: continue
            j = record['ordinal']; table = evidence['tables'][record['row']]
            expected = Rounds.equation(model, record, main)
            proofs.append(prove('terminal_index_'+str(j), case, record['pc'], model.lookups[j]['index'] != expected))
            inverse_matrix = {apply(table['input_columns8'], x): x for x in range(256)}
            key_byte = inverse_matrix[record['encoded_state_xor8']] ^ table['input_xor8']
            assert key_byte == bytes.fromhex(case['source_round9_key16_hex'])[record['input_offset']]
            totals['source_round9_key_bytes_checked'] += 1
        outputs = {r['offset']: r for r in model.output}
        assert len(case['decoders']) == 16
        for record in case['decoders']:
            p, j = record['output_offset'], record['byte_ordinal']; source = model.lookups[j]; output = outputs[p]
            assert (source['pc'], source['base'], output['pc']) == (record['byte_pc'], record['byte_bank'], record['store_pc'])
            assert record['input_position'] == 4*((p//4+p % 4) % 4)+p % 4
            terminal, = [r for r in prefix['word_reads'] if r['ordinal'] == record['terminal_ordinal']]
            assert terminal['input_offset'] == record['input_position'] and terminal['round'] == 10
            substituted = z3.simplify(z3.substitute(source['index'], *substitutions))
            matrix = affine['mixcolumns']['row_encoder_columns8'][p % 4]
            expected = z3.ZeroExt(56, symbolic_byte(matrix, symbols[record['terminal_ordinal']])) ^ record['index_xor8']
            proof = prove('final_byte_index_'+str(j), case, source['pc'], substituted != expected)
            proof['terminal_outputs_independent_u8'] = True; proof['terminal_literal_embedding_rows_complete'] = True
            proofs.append(proof)
            returned, = Core.variables(output['value']); assert str(returned) == source['name']
            assert output['value'].sexpr() == record['source_store_expression']
            post = [number(z3.substitute(output['value'], (returned, z3.BitVecVal(x, 8)))) for x in range(256)]
            assert post == record['post_store_map256'] and len(set(post)) == 256
            bank = IMAGE.read(int(source['base'], 16), 256); assert bank.hex() == record['original_byte_bank256_hex']
            for x in range(256):
                value = post[bank[apply(matrix, x) ^ record['index_xor8']]]
                assert value == record['decoded_map256'][x] == x ^ record['final_xor8']
            totals.update(univariate_source_store_rows_checked=256, final_decoder_rows_checked=256)
        contract = case['contract']; key = bytes.fromhex(contract['key16_hex']); keys = Kernel.expand(key)
        assert keys[9].hex() == case['source_round9_key16_hex']
        final = bytes(r['final_xor8'] for r in sorted(case['decoders'], key=lambda r: r['output_offset']))
        assert final.hex() == case['final_xor16_hex']
        assert bytes(x ^ y for x, y in zip(final, keys[10])).hex() == contract['core_output_xor16_hex']
        assert contract['core_input_xor16_hex'] == prefix['AES128_prefix_schedule']['input_whitening16_hex']
        for kind in ['input', 'output']:
            core_mask = bytes.fromhex(contract['core_'+kind+'_xor16_hex']); staged_mask = bytes.fromhex(staged['mask16_hex'][kind])
            assert bytes(x ^ y for x, y in zip(core_mask, staged_mask)).hex() == contract['external_'+kind+'_xor16_hex'] == '98'*16
        inputs = [bytes.fromhex(parent['entry_input16_hex']), bytes(16), bytes([255])*16, bytes(range(16))]
        inputs += [sha256(b'core-cipher-input-'+str(j).encode()).digest()[:16] for j in range(64)]
        whitened = [bytes(x ^ y for x, y in zip(data, bytes.fromhex(contract['core_input_xor16_hex']))) for data in inputs]
        references = openssl(key, whitened)
        for data, encrypted in zip(inputs, references):
            actual, accesses = DAG.transform(parent, data); expected = Kernel.transform(contract, data)
            host = bytes(x ^ y for x, y in zip(encrypted, bytes.fromhex(contract['core_output_xor16_hex'])))
            assert actual == expected == host and len(accesses) == 192
            external_input = bytes(x ^ y for x, y in zip(data, bytes.fromhex(staged['mask16_hex']['input'])))
            external_output = bytes(x ^ y for x, y in zip(actual, bytes.fromhex(staged['mask16_hex']['output'])))
            assert Kernel.transform(contract, external_input, external=True) == external_output
            if data.hex() == parent['entry_input16_hex']:
                assert actual.hex() == case['retained_vectors']['core_output16_hex']
                assert external_output.hex() == case['retained_vectors']['external_output16_hex']
            vectors.append({'class_index': case['class_index'], 'core_input16_hex': data.hex(),
                            'core_output16_hex': actual.hex(), 'host_AES16_hex': encrypted.hex(),
                            'external_input16_hex': external_input.hex(), 'external_output16_hex': external_output.hex()})
            totals.update(complete_block_vectors_checked=1, core_output_bytes_compared=16, external_output_bytes_compared=16)
        print(json.dumps({'class_index': case['class_index'], 'source_queries_unsat': 32, 'complete_block_vectors': 68}), flush=True)
    assert len(proofs) == len({p['label'] for p in proofs}) == 64 and len(vectors) == 136
    totals.update(source_queries_unsat=64, host_OpenSSL_blocks_checked=137)
    host_binary = Path(shutil.which('openssl'))
    host_reference = {'program': 'openssl', 'version': subprocess.check_output(['openssl', 'version'], text=True).strip(),
                      'binary_sha256': sha(host_binary), 'AES_reference_command': 'openssl enc -aes-128-ecb -K KEY_HEX -nopad -nosalt',
                      'blocks_checked': 137, 'scope': 'Independent host block-encryption reference; no target protocol mode or native daemon execution inferred.'}
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'generator_sha256': sha(ROOT/'recover_daemon_core_cipher.py'),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'independent_totals': dict(totals),
            'source_proofs': proofs, 'vector_comparisons': vectors, 'host_reference': host_reference,
            'conditional_core_cipher_established': True, 'native_API_executed': False,
            'native_daemon_kext_pairing_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    evidence = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence['independent_totals']), flush=True)
