#!/usr/bin/env python3
"""Fresh complete-component audit and exact publication custody.
O(receipts + source DAGs + audit + owned bytes + proof DAG) time/space;
solver search additional. No native target, IDB action or history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_core_cipher as R
import audit_daemon_core_cipher as A

PREVIOUS = 'da1fd6e126e636a816fde6d18322c5b7b8a65f26'
BASELINE_SHA = '77867234b76abb2a852a2a1732c01a9eee9ae710950552fdb92bbbb1137ec59d'
CHECKS_SHA = '5fff08a8f1e2748a344a86ac84e0533e9a0cb690234dde77e07cafc6dee7dc71'
AUDIT_SHA = '90c46d9e6c06598e84d8f7e754e907eaa809306f74016bd5612ae3bdf32696f5'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_block_staging_report.md', 'daemon_core_lookup_report.md', 'daemon_core_affine_report.md',
           'daemon_core_rounds_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_core_cipher_report.md', 'triage_evidence/recover_daemon_core_cipher.py',
         'triage_evidence/audit_daemon_core_cipher.py', 'triage_evidence/daemon_core_cipher_kernel.py',
         'triage_evidence/verify_daemon_core_cipher_publication.py',
         'triage_evidence/daemon_core_cipher_checks.json', 'triage_evidence/daemon_core_cipher_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_core_cipher_checks.json', 'triage_evidence/daemon_core_cipher_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_contexts': 2, 'terminal_word_banks': 4, 'terminal_word_rows': 1024,
          'factor_candidates': 2048, 'factor_matches': 4, 'source_final_index_identities': 32,
          'source_univariate_store_cuts': 32, 'post_store_rows': 8192, 'decoded_output_rows': 8192,
          'source_round9_key_bytes': 32, 'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'reference_sbox_values_checked': 256, 'rejection_witness_terms_checked': 10660,
          'factor_candidates_checked': 2048, 'positive_factor_rows_checked': 1024,
          'original_terminal_embedding_rows_checked': 1024, 'NIST_complete_cipher_checkpoints': 1,
          'source_round9_key_bytes_checked': 32, 'univariate_source_store_rows_checked': 8192,
          'final_decoder_rows_checked': 8192, 'complete_block_vectors_checked': 136,
          'core_output_bytes_compared': 2176, 'external_output_bytes_compared': 2176,
          'source_queries_unsat': 64, 'host_OpenSSL_blocks_checked': 137}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); audit = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = audit.pop('source_proofs'), fresh.pop('source_proofs')
    assert audit == fresh and evidence['verified_counts'] == COUNTS and audit['independent_totals'] == TOTALS
    assert evidence['source_sha256'] == audit['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == 64
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        solver = z3.SolverFor('QF_BV'); solver.set(timeout=30000); solver.add(*p); assert solver.check() == z3.unsat
    audit['source_proofs'] = old_proofs
    assert len({p['label'] for p in old_proofs}) == 64
    report = read(BASE/'daemon_core_cipher_report.md')
    assert all('| CC'+str(j)+' |' in report and '| CC-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    assert len(set(evidence['tables'][3]['word256_LE'])) == 203 and '203 distinct words' in report
    for case in evidence['cases']:
        assert case['source_round9_key16_hex'] in report and case['final_xor16_hex'] in report
        for field in ['key16_hex', 'core_input_xor16_hex', 'core_output_xor16_hex', 'external_input_xor16_hex', 'external_output_xor16_hex']:
            assert case['contract'][field] in report
        for r in case['decoders']:
            line = f"| {r['output_offset']} | `{r['byte_pc']}` | `{r['byte_bank']}` | `{r['index_xor8']:02x}` | `{r['final_xor8']:02x}` | `{r['store_pc']}` |"
            assert line in report
    assert audit['host_reference']['binary_sha256'] in report
    hygiene(evidence); hygiene(audit)
    for receipt in [evidence, audit]:
        assert receipt['conditional_core_cipher_established'] is True
        for field in ['native_API_executed', 'native_daemon_kext_pairing_established', 'full_goal_complete']: assert receipt[field] is False
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_core_cipher_report.md' in read(BASE/p)
    return evidence, audit


def publication(evidence, audit):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9076 and len(after) == 9083
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', evidence['verified_counts']), ('static_scope', evidence['scope']),
                       ('independent_checks', audit['independent_totals']), ('source_queries_unsat', 64),
                       ('contract', evidence['cases'][0]['contract']), ('host_reference', audit['host_reference']),
                       ('conditional_core_cipher_established', True)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 559
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 559,
                      'original_inputs_preserved': 3, **COUNTS, **TOTALS,
                      'conditional_core_cipher_established': True, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
