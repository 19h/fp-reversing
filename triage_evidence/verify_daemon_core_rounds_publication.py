#!/usr/bin/env python3
"""Fresh nine-layer audit and exact publication custody.
O(receipts + source DAGs + audit + owned bytes + proof DAG) time/space;
solver search additional. No native operation, IDB action or history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_core_rounds as R
import audit_daemon_core_rounds as A

PREVIOUS = '69578fdfc1489a8ebe3b2838a65eaa1bcbc27b8d'
BASELINE_SHA = '6dec16b8b74770804cf2ece9b3175a52ecdac25ce9e6ee0839fd408b21f3da84'
CHECKS_SHA = '483171e5eac9b0986b2df25160bbacb803fa78f364766e169f897cb9ff765e5d'
AUDIT_SHA = '959f187b700cd067d5b2e8d63f93d6813bb1d06f7da1318d1fd058caf5763949'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_block_staging_report.md', 'daemon_core_lookup_report.md', 'daemon_core_affine_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_core_rounds_report.md', 'triage_evidence/recover_daemon_core_rounds.py',
         'triage_evidence/audit_daemon_core_rounds.py', 'triage_evidence/verify_daemon_core_rounds_publication.py',
         'triage_evidence/daemon_core_rounds_checks.json', 'triage_evidence/daemon_core_rounds_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_core_rounds_checks.json', 'triage_evidence/daemon_core_rounds_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_contexts': 2, 'word_read_records': 320, 'source_composition_identities': 288,
          'main_substitution_mix_layers_per_context': 9, 'main_word_reads_per_context': 144,
          'terminal_word_indices_per_context': 16, 'offset_vectors_per_context': 9,
          'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'reference_sbox_values_checked': 256, 'NIST_schedule_checkpoints': 2,
          'original_normalized_table_rows_checked': 1024, 'structural_composition_records_checked': 288,
          'source_matched_expanded_vectors_checked': 16, 'direct_seed_mismatches_checked': 16,
          'word_indices_compared': 10240, 'vector_comparisons': 64, 'canonical_states_compared': 640,
          'source_queries_unsat': 288}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); audit = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = audit.pop('source_proofs'), fresh.pop('source_proofs')
    assert audit == fresh and evidence['verified_counts'] == COUNTS and audit['independent_totals'] == TOTALS
    assert evidence['source_sha256'] == audit['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == 288
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['arbitrary_lookup_returns'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        solver = z3.SolverFor('QF_BV'); solver.set(timeout=30000); solver.add(*p); assert solver.check() == z3.unsat
    audit['source_proofs'] = old_proofs
    assert len({p['label'] for p in old_proofs}) == 288
    assert evidence['cases'][0]['word_reads'] == evidence['cases'][1]['word_reads']
    report = read(BASE/'daemon_core_rounds_report.md')
    assert all('| CR'+str(j)+' |' in report and '| CR-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for case in evidence['cases']:
        assert all(v in report for v in case['offsets9_hex']) and case['terminal_encoded_xor16_hex'] in report
        assert all(case['AES128_prefix_schedule'][k] in report for k in ['backderived_seed16_hex', 'input_whitening16_hex'])
        for rnd in range(1, 11):
            rows = [r for r in case['word_reads'] if r['round'] == rnd]
            assert rows[0]['pc'] in report and rows[-1]['pc'] in report
    hygiene(evidence); hygiene(audit)
    for receipt in [evidence, audit]:
        for field in ['native_API_executed', 'native_daemon_kext_pairing_established', 'transform_algorithm_established', 'full_goal_complete']:
            assert receipt[field] is False
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_core_rounds_report.md' in read(BASE/p)
    return evidence, audit


def publication(evidence, audit):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9070 and len(after) == 9076
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', evidence['verified_counts']), ('static_scope', evidence['scope']),
                       ('independent_checks', audit['independent_totals']), ('source_queries_unsat', 288),
                       ('offset_vectors', evidence['cases'][0]['offsets9_hex']),
                       ('prefix_schedule', evidence['cases'][0]['AES128_prefix_schedule']),
                       ('terminal_encoded_xor16_hex', evidence['cases'][0]['terminal_encoded_xor16_hex'])]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 558
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 558,
                      'original_inputs_preserved': 3, **COUNTS, **TOTALS,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
