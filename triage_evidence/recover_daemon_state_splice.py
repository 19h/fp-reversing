#!/usr/bin/env python3
"""Compose the source serializer, conditional AES wrapper and twenty-byte splice.
O(pinned bytes + selected source chunks + 608 exports) time/space.
No new target interval, root byte, native API/IPC, PAC or IDB operation.
"""
import json
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_block_staging import subchunk
import daemon_state_splice_kernel as Kernel

P = 'daemon_state_splice'
PINS = {'daemon_record_input_origin_checks.json': '450d52130015a8ae1e0f033db234be880051d9071b9f478cc93e9778bce7a12e',
        'daemon_record_input_origin_audit.json': '3fc418ed9272a785fbea01bef58a11a625b4c748dbab9d2fd3b04f8d4fb84363',
        'daemon_core_cipher_checks.json': '5fff08a8f1e2748a344a86ac84e0533e9a0cb690234dde77e07cafc6dee7dc71',
        'daemon_core_cipher_audit.json': '90c46d9e6c06598e84d8f7e754e907eaa809306f74016bd5612ae3bdf32696f5',
        'daemon_record_banks_checks.json': '50000b634bd81018868350c194f60e49992dded73a2a6996764f0af345c40f48'}
DEPS = ['daemon_state_splice_kernel.py', 'daemon_core_cipher_kernel.py', 'recover_daemon_block_staging.py',
        'recover_daemon_record_input_origin.py', 'daemon_receive_tools.py']


def build():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    origin = json.loads(read(ROOT/'daemon_record_input_origin_checks.json'))
    cipher = json.loads(read(ROOT/'daemon_core_cipher_checks.json'))
    banks = json.loads(read(ROOT/'daemon_record_banks_checks.json')); cases = []
    for old, core in zip(origin['cases'], cipher['cases']):
        assert old['class_index'] == core['class_index']
        contract = core['contract']; assert contract['external_input_xor16_hex'] == contract['external_output_xor16_hex'] == '98'*16
        key = bytes.fromhex(contract['key16_hex']); words = [int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little') for r in old['word_reads']]
        decoded = b''.join((x ^ 0xf4f92df7).to_bytes(4, 'big') for x in words)
        serialized = bytes(b ^ 0x98 for b in decoded)
        encrypted = Kernel.encrypt(decoded[2:18], key); output = Kernel.encode(words, key)
        assert serialized.hex() == old['serialized20_hex']
        assert bytes(b ^ 0x98 for b in encrypted).hex() == old['transform_output16_hex']
        assert output.hex() == old['record_input20_hex']
        chunk = old['chunks'][-1]; lo = next(j for j, v in enumerate(chunk['visits']) if v['pc'] == '0x100aaa324')
        hi = next(j for j, v in enumerate(chunk['visits']) if v['pc'] == '0x100aaa3e0')+1
        formatter = subchunk(chunk, lo, hi, 'state_splice_formatter')
        selected = [c for c in old['chunks'] if c['kind'] in ['serialize_word', 'serialized_word_last_writer', 'saved_output_pointer']]+[formatter]
        epochs = []
        for j, row in enumerate(old['word_origins']):
            assert row['reader'] == old['word_reads'][j] and len(row['origins']) == 4
            writer, = {r['writer']['source_visit_index'] for r in row['origins']}
            pc, = {r['writer']['pc'] for r in row['origins']}
            epochs.append({'word_index': j, 'address': row['reader']['address'], 'encoded32': hex(words[j]),
                           'decoded32': hex(words[j] ^ 0xf4f92df7), 'writer_pc': pc, 'writer_visit': writer,
                           'reader_visit': row['reader']['source_visit_index']})
        assert len(old['state_word_later_writes']) == 20
        cases.append({'class_index': old['class_index'], 'key16_hex': key.hex(), 'encoded_words5': words,
                      'decoded_words5': [x ^ 0xf4f92df7 for x in words], 'decoded20_hex': decoded.hex(),
                      'AES_plaintext16_hex': decoded[2:18].hex(), 'AES_ciphertext16_hex': encrypted.hex(),
                      'serialized20_hex': serialized.hex(), 'record_input20_hex': output.hex(),
                      'word_epochs': epochs, 'source_chunks': selected,
                      'frame_F': old['frame_F'], 'outer_frame_K': old['outer_frame_K'], 'output_base': old['output_base'],
                      'state_reuse_events': old['state_word_later_writes'],
                      'output_pointer_origins': old['output_pointer_origins']})
    assert len(banks['frontiers']) == 608
    assert all(r['input20_hex'] == c['record_input20_hex'] and r['three_bank_fields_defined'] is False
               for r in banks['frontiers'] for c in cases)
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS}, 'cases': cases,
            'format_contract': 'P=BE32(W0 XOR f4f92df7)||...||BE32(W4 XOR f4f92df7); O=(P[0:2]||AES128_K(P[2:18])||P[18:20]) XOR 98 repeated20',
            'verified_counts': {'retained_contexts': 2, 'source_chunks': 24,
                'source_visits': sum(len(p['visits']) for c in cases for p in c['source_chunks']),
                'word_epochs': 10, 'state_reuse_byte_stores': 40, 'retained_frontier_values_checked': 608,
                'new_target_intervals': 0, 'new_root_bytes': 0},
            'conditional_state_format_established': True, 'digest_message_identity_established': False,
            'native_API_executed': False, 'native_daemon_kext_pairing_established': False, 'full_goal_complete': False}


if __name__ == '__main__':
    evidence = build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence['verified_counts']), flush=True)
