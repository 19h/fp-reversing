#!/usr/bin/env python3
"""Fresh codec/factor audit and exact publication custody.
O(receipts + source DAGs + finite audit + owned bytes + proof DAG) time/space;
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
import recover_daemon_core_affine as R
import audit_daemon_core_affine as A

PREVIOUS = 'd31296965abe9f0e164b67f96b732ce8fbff94e1'
BASELINE_SHA = '65ffa49bf888dbd77e32c73a9f76c08d675be1ea7880077f4eed15766205eda9'
CHECKS_SHA = 'd46e946d6acca5be5f2a599544bde0dae5a755b2b8a2011a244ac2865be09c8f'
AUDIT_SHA = 'ec0188120431ee0d83f7bc606e4122197f3a5ae97d0a5703656411ae663418e6'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_block_staging_report.md', 'daemon_core_lookup_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_core_affine_report.md', 'triage_evidence/recover_daemon_core_affine.py',
         'triage_evidence/audit_daemon_core_affine.py', 'triage_evidence/capture_daemon_core_affine_reference.py',
         'triage_evidence/verify_daemon_core_affine_publication.py', 'triage_evidence/daemon_core_affine_reference.json',
         'triage_evidence/daemon_core_affine_checks.json', 'triage_evidence/daemon_core_affine_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_core_affine_reference.json',
            'triage_evidence/daemon_core_affine_checks.json', 'triage_evidence/daemon_core_affine_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_contexts': 2, 'source_projection_candidates': 32, 'codec_rows': 32,
          'codec_input_values_checked': 8192, 'main_banks': 4, 'main_bank_word_rows': 1024,
          'factor_candidates': 4096, 'factor_matches': 6, 'encoded_mixcolumns_rows': 1024,
          'reference_sbox_values': 256, 'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'reference_sbox_values_checked': 256, 'prefix_source_rows_checked': 8192,
          'projected_source_rows_checked': 8192, 'affine_map_rows_checked': 8192,
          'bijective_byte_codecs_checked': 32, 'original_word_rows_checked': 1024,
          'rejection_witness_terms_checked': 25942, 'factor_candidates_checked': 4096,
          'positive_factor_rows_checked': 1536, 'decoded_sbox_rows_checked': 1024,
          'encoded_mixcolumns_rows_checked': 1024, 'first_sbox_argument_rows_checked': 8192,
          'source_projection_queries_unsat': 32, 'original_protection_windows_checked': 16}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = a.pop('source_proofs'), fresh.pop('source_proofs')
    assert a == fresh and e['verified_counts'] == COUNTS and a['independent_totals'] == TOTALS
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == a['source_queries_unsat'] == 32
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        solver = z3.Solver(); solver.set(timeout=30000); solver.add(*p); assert solver.check() == z3.unsat
    a['source_proofs'] = old_proofs
    assert len({p['label'] for p in old_proofs}) == 32
    assert e['cases'][0]['initial_indices'] == e['cases'][1]['initial_indices']
    assert sha(ROOT/(R.P+'_reference.json')) == R.PINS[R.P+'_reference.json']
    report = read(BASE/'daemon_core_affine_report.md')
    assert all('| CA'+str(j)+' |' in report and '| CA-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    assert e['reference']['PDF_sha256'] in report and R.PINS[R.P+'_reference.json'] in report
    banks = dict(zip([r['bank'] for r in e['main_tables']], 'ABCD'))
    for c in e['cases']:
        assert c['effective_first_sbox_input_xor16_hex'] in report
        for r in c['initial_indices']:
            expected = f"| {r['read_ordinal']} | `{r['pc']}` | {r['input_offset']} | {banks[r['bank']]} | `{r['bias8']:02x}` | `{r['effective_first_sbox_input_xor8']:02x}` |"
            assert expected in report
    hygiene(e); hygiene(a)
    for receipt in [e, a]:
        for field in ['native_API_executed', 'native_daemon_kext_pairing_established',
                      'transform_algorithm_established', 'full_goal_complete']: assert receipt[field] is False
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_core_affine_report.md' in read(BASE/p)
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9062 and len(after) == 9070
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', e['verified_counts']), ('static_scope', e['scope']),
                       ('independent_checks', a['independent_totals']), ('source_queries_unsat', 32),
                       ('factor_matches', a['factor_matches']), ('mixcolumns', e['mixcolumns']),
                       ('original_window_mapping', e['original_window_mapping']),
                       ('reference_PDF_sha256', e['reference']['PDF_sha256'])]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 557
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 557,
                      'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 32,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
