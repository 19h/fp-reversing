#!/usr/bin/env python3
"""Source serializer/formatter composition, byte epochs and independent format checks.
O(selected source visits*32 + proof DAG + 196*source slices + 608 exports)
time/space; solver search additional, 30 s/query. Host crypto is a reference;
no native daemon/kext, target IPC, root admission, PAC or IDB operation.
"""
import json
import subprocess
from collections import Counter
from hashlib import sha256
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_alternative_fill import Source
from audit_daemon_append_fields import number
from recover_daemon_record_banks import instruction
import audit_daemon_record_input_origin as OriginAudit
import recover_daemon_record_input_origin as Origin
import daemon_core_cipher_kernel as Cipher
import daemon_state_splice_kernel as Kernel
import recover_daemon_state_splice as R

DEPS = ['audit_daemon_record_input_origin.py', 'recover_daemon_record_input_origin.py',
        'audit_daemon_alternative_fill.py', 'audit_daemon_append_fields.py', 'daemon_core_cipher_kernel.py',
        'daemon_state_splice_kernel.py', 'recover_daemon_record_banks.py', 'lskd_values_symbolic.py']


def serializer(words, frame):
    values, slices = [None]*20, []
    for j, word in enumerate(words):
        v = Source({0x100be0454: (4, word)})
        for name, value in {'x13': frame+0x3cc+4*j, 'x1': frame+0x1cc,
                            'w11': (4*j-0xd3286d1e) & 0xffffffff, 'w12': 0xd3286d1e}.items(): v.seed(name, value)
        v.run_block(0x100be0454, 0x100be04e4)
        for store, k in zip(v.stores, [0, 2, 1, 3]): values[4*j+k] = store['value']
        slices.append(v)
    assert all(x is not None for x in values)
    return values, slices


def formatter(serialized, transformed, frame, output, table, phase, target):
    local = dict(zip(Origin.MAP, serialized[:2]+transformed+serialized[18:]))
    values = {0x100aaa370: (8, output), 0x100aaa3d8: (8, target)}
    for pc in range(0x100aaa324, 0x100aaa3e0, 4):
        ins = instruction(pc)
        if ins.mnemonic == 'ldrb': values[pc] = (1, local[ins.operands[1].mem.disp])
    v = Source(values)
    for name, value in {'sp': frame, 'x20': table, 'w22': phase}.items(): v.seed(name, value)
    v.run_block(0x100aaa324, 0x100aaa3e0)
    return v


def obligations():
    proofs = []
    def prove(label, bad):
        solver = z3.SolverFor('QF_UFBV'); solver.set(timeout=30000); assert solver.check() == z3.sat
        solver.add(z3.simplify(bad)); answer = solver.check(); assert answer == z3.unsat, (label, str(answer))
        proofs.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': solver.to_smt2()})
    words = [z3.BitVec('splice_W%d_32' % j, 32) for j in range(5)]
    frame, output, table, target = z3.BitVecs('splice_F64 splice_O64 splice_table64 splice_target64', 64)
    phase = z3.BitVec('splice_phase32', 32)
    decoded = [z3.Extract(31-8*k, 24-8*k, w ^ 0xf4f92df7) for w in words for k in range(4)]
    serialized, slices = serializer(words, frame)
    wrong = []
    for j, v in enumerate(slices):
        wrong.append(v.loads[0][1] != frame+0x414+4*j)
        for store, k in zip(v.stores, [0, 2, 1, 3]):
            wrong.extend([store['address'] != frame+0x1cc+4*j+k, store['value'] != decoded[4*j+k] ^ 0x98])
    prove('source_five_word_serialization_and_twenty_addresses', z3.Or(*wrong))
    enc = z3.Function('splice_fixed_AES128_K', z3.BitVecSort(128), z3.BitVecSort(128))
    source_block = enc(z3.Concat(*[b ^ 0x98 for b in serialized[2:18]]))
    transformed = [z3.Extract(127-8*j, 120-8*j, source_block) ^ 0x98 for j in range(16)]
    v = formatter(serialized, transformed, frame, output, table, phase, target)
    canonical_block = enc(z3.Concat(*decoded[2:18]))
    canonical = decoded[:2]+[z3.Extract(127-8*j, 120-8*j, canonical_block) for j in range(16)]+decoded[18:]
    assert len(v.stores) == 20 and len(v.loads) == 22
    prove('source_formatter_composes_middle_AES_and_XOR98', z3.Or(*[
        z3.Or(s['address'] != output+k, s['value'] != canonical[k] ^ 0x98, s['size_bytes'] != 1)
        for s, k in zip(v.stores, range(19, -1, -1))]))
    expected = {pc: frame+instruction(pc).operands[1].mem.disp for pc in range(0x100aaa324, 0x100aaa3e0, 4) if instruction(pc).mnemonic == 'ldrb'}
    expected.update({0x100aaa370: frame+0x90, 0x100aaa3d8: table+z3.SignExt(32, phase)*8})
    prove('formatter_addresses_status_and_outgoing_continuation', z3.Or(
        *[address != expected[pc] for pc, address, size in v.loads], v.read('x9') != target,
        v.read('w8') != 0x8b3dc651, v.read('w21') != phase ^ 0x221b, v.read('x17') != 0xc6fe))
    plain = [w ^ 0xf4f92df7 for w in words]
    split = z3.Concat(z3.Extract(15, 0, plain[0]), plain[1], plain[2], plain[3], z3.Extract(31, 16, plain[4]))
    prove('AES_middle_block_crosses_first_and_last_word_halves', z3.Or(
        z3.Concat(*decoded[2:18]) != split, z3.Concat(*decoded[:2]) != z3.Extract(31, 16, plain[0]),
        z3.Concat(*decoded[18:]) != z3.Extract(15, 0, plain[4])))
    return proofs


def host_blocks(key, blocks, decrypt=False):
    args = ['openssl', 'enc', '-aes-128-ecb', '-K', key.hex(), '-nopad', '-nosalt']
    if decrypt: args.append('-d')
    result = subprocess.run(args, input=b''.join(blocks), capture_output=True, check=True)
    assert not result.stderr and len(result.stdout) == 16*len(blocks)
    return [result.stdout[j:j+16] for j in range(0, len(result.stdout), 16)]


def audit():
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); assert evidence == R.build()
    origins = json.loads(read(ROOT/'daemon_record_input_origin_checks.json'))
    cipher = json.loads(read(ROOT/'daemon_core_cipher_checks.json'))
    banks = json.loads(read(ROOT/'daemon_record_banks_checks.json')); totals = Counter()
    for case, old in zip(evidence['cases'], origins['cases']):
        for chunk in case['source_chunks']: totals.update(OriginAudit.replay(chunk))
        for row, epoch in zip(old['word_origins'], case['word_epochs']):
            raw = bytes.fromhex(row['reader']['bytes_hex']); assert int.from_bytes(raw, 'little') == int(epoch['encoded32'], 16)
            assert epoch['writer_visit'] < epoch['reader_visit']
            for part in row['origins']:
                writer = part['writer']; assert writer['pc'] == epoch['writer_pc'] and writer['source_visit_index'] == epoch['writer_visit']
                assert int(writer['address'], 16)+part['writer_byte'] == int(row['reader']['address'], 16)+part['reader_byte']
                assert bytes.fromhex(writer['after_hex'])[part['writer_byte']] == raw[part['reader_byte']]
                totals['word_epoch_bytes_checked'] += 1
        reuse = case['state_reuse_events']; base = int(old['frame_F'], 16)+0x414
        assert len(reuse) == 20 and {int(r['address'], 16) for r in reuse} == set(range(base, base+20))
        assert all(r['size_bytes'] == 1 and r['pc'] == '0x100a66654' and
                   old['word_reads'][-1]['source_visit_index'] < r['source_visit_index'] < old['calls'][0]['source_visit_index'] for r in reuse)
        totals['state_reuse_bytes_checked'] += 20
        pointer = case['output_pointer_origins']; assert len(pointer['origins']) == 8
        assert int(pointer['reader']['address'], 16) == int(case['frame_F'], 16)+0x90
        for row in pointer['origins']:
            writer = row['writer']; assert writer['pc'] == '0x100a5e2d8'
            assert writer['source_visit_index'] < pointer['reader']['source_visit_index']
            assert int(writer['address'], 16)+row['writer_byte'] == int(pointer['reader']['address'], 16)+row['reader_byte']
            assert bytes.fromhex(writer['after_hex'])[row['writer_byte']] == bytes.fromhex(pointer['reader']['bytes_hex'])[row['reader_byte']]
            totals['output_pointer_epoch_bytes_checked'] += 1
        assert int.from_bytes(bytes.fromhex(pointer['reader']['bytes_hex']), 'little') == int(case['output_base'], 16)
        assert len(case['encoded_words5']) == 5
        plain = b''.join((w ^ 0xf4f92df7).to_bytes(4, 'big') for w in case['encoded_words5'])
        assert plain.hex() == case['decoded20_hex'] and plain[2:18].hex() == case['AES_plaintext16_hex']
        assert Kernel.encode(case['encoded_words5'], bytes.fromhex(case['key16_hex'])).hex() == case['record_input20_hex']
    assert len(banks['frontiers']) == 608
    for row in banks['frontiers']:
        assert row['three_bank_fields_defined'] is False and row['native_execution'] is False
        assert all(row['input20_hex'] == c['record_input20_hex'] for c in evidence['cases'])
        totals['retained_frontier_exports_checked'] += 1
    # Independently assemble the twenty-byte reference using host AES blocks.
    base_words = evidence['cases'][0]['encoded_words5']; key = bytes.fromhex(evidence['cases'][0]['key16_hex'])
    inputs = [base_words, [0]*5, [0xffffffff]*5, [0x00010203+0x04040404*j for j in range(5)]]
    for bit in range(160):
        words = base_words[:]; words[bit//32] ^= 1 << (bit % 32); inputs.append(words)
    inputs += [[int.from_bytes(sha256(b'state-splice-'+str(j).encode()).digest()[4*k:4*k+4], 'little') for k in range(5)] for j in range(32)]
    assert len(inputs) == 196
    plains = [b''.join((w ^ 0xf4f92df7).to_bytes(4, 'big') for w in words) for words in inputs]
    blocks = host_blocks(key, [p[2:18] for p in plains]); restored = host_blocks(key, blocks, decrypt=True)
    assert restored == [p[2:18] for p in plains]
    vectors = []; original = Kernel.encode(base_words, key); frame = 0x680005fb60; destination = 0x680006c5b0
    for words, plain, block in zip(inputs, plains, blocks):
        reference = bytes(x ^ 0x98 for x in plain[:2]+block+plain[18:])
        assert Kernel.encode(words, key) == reference
        source_bytes, serializers = serializer(words, frame)
        serialized = bytes(number(x) for x in source_bytes)
        assert serialized == bytes(x ^ 0x98 for x in plain)
        transformed = Cipher.transform(cipher['cases'][0]['contract'], serialized[2:18], external=True)
        formatter_run = formatter(list(serialized), list(transformed), frame, destination, 0x101039ef0, 0x7aa5, 0x100a653cc)
        result = bytearray(20)
        for store in formatter_run.stores:
            at = number(store['address'])-destination; assert 0 <= at < 20
            result[at] = number(store['value'])
        assert bytes(result) == reference
        vectors.append({'encoded_words5': words, 'plain20_hex': plain.hex(), 'AES_ciphertext16_hex': block.hex(), 'record_input20_hex': reference.hex()})
        totals.update(complete_format_vectors_checked=1, source_serializer_words_checked=5,
                      source_formatter_bytes_checked=20, host_AES_roundtrip_blocks_checked=1)
    edge_bits = middle_bits = 0
    for bit, vector in enumerate(vectors[4:164]):
        word, offset = divmod(bit, 32); byte_position = 4*word+3-offset//8
        value = bytes.fromhex(vector['record_input20_hex'])
        if byte_position < 2 or byte_position >= 18:
            assert value[2:18] == original[2:18]
            assert sum((x ^ y).bit_count() for x, y in zip(value, original)) == 1; edge_bits += 1
        else:
            assert value[:2]+value[18:] == original[:2]+original[18:] and value[2:18] != original[2:18]; middle_bits += 1
    assert (edge_bits, middle_bits) == (32, 128)
    totals.update(edge_bit_controls_checked=edge_bits, middle_bit_controls_checked=middle_bits)
    alias_controls = OriginAudit.alias_controls(); assert len(alias_controls) == 2
    proofs = obligations(); assert len(proofs) == 4
    totals.update(source_queries_unsat=4, formatter_alias_controls_checked=2)
    return {'scope': __doc__, 'auditor_sha256': sha(__file__), 'generator_sha256': sha(ROOT/'recover_daemon_state_splice.py'),
            'checks_sha256': sha(ROOT/(R.P+'_checks.json')), 'source_sha256': sha(SOURCE),
            'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'independent_totals': dict(totals),
            'source_proofs': proofs, 'format_vectors': vectors, 'alias_controls': alias_controls,
            'host_reference': {'program': 'openssl', 'version': subprocess.check_output(['openssl', 'version'], text=True).strip(),
                'encrypt_blocks': 196, 'decrypt_blocks': 196, 'scope': 'Independent single-block host reference, no target protocol mode inferred.'},
            'conditional_state_format_established': True, 'digest_message_identity_established': False,
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    evidence = audit(); (ROOT/(R.P+'_audit.json')).write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence['independent_totals']), flush=True)
