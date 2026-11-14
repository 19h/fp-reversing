#!/usr/bin/env python3
"""Fresh alternate-reader contracts, custody and exact publication verification.
O(receipt bytes + selected replay + owned bytes + proof DAG) time/space,
excluding solver search. No native operation or history rewrite.
"""
import contextlib
import io
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_record_storage as R
import audit_daemon_record_storage as A

PREVIOUS = '36e3b2e5238c900b1a8cd46fe918f47ee5cdb3a9'
BASELINE_SHA = '725c28c9a0d2d1f15cf9daaf38f8af9ea75b0fbbd02d06d1a3c1f29a1049168a'
CHECKS_SHA = '08dd5c2d5d3c14efd4ec744f35267c1d9f879d2a93c3d4ea8ca68f3c22e31337'
AUDIT_SHA = '1be9029f3b67f0d543db412982617378cae7064ff4a9ade39f503b4da5f0eac4'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md',
           'daemon_record_selection_report.md', 'daemon_cache_publication_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_record_storage_report.md', 'triage_evidence/recover_daemon_record_storage.py',
         'triage_evidence/audit_daemon_record_storage.py', 'triage_evidence/verify_daemon_record_storage_publication.py',
         'triage_evidence/daemon_record_storage_checks.json', 'triage_evidence/daemon_record_storage_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_record_storage_checks.json', 'triage_evidence/daemon_record_storage_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'helper_cases': 6, 'saved_cells_checked': 24, 'saved_bytes_checked': 168, 'last_writer_instructions': 24,
          'preparation_slices': 6, 'dispatch_routes': 7, 'source_instructions': 296, 'normalizers': 16}
INDEPENDENT = {'GP_SP_values_checked': 5376, 'NZCV_frames_checked': 168, 'source_visits_checked': 138,
               'read_events_checked': 0, 'write_events_checked': 48, 'slices_checked': 30}
COMPOSITION = {'reader_source_instructions': 248, 'reader_loads': 10, 'reader_writes': 0, 'proof_cuts': 32}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, n in [('source_proofs', 29), ('interpretation_controls', 4)]:
        before, after = old.pop(key), fresh.pop(key)
        assert len(before) == len(after) == n
        for x, y in zip(before, after):
            a, b = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
            assert x == y and len(a) == len(b) > 0
            assert all(canonical_expression(c) == canonical_expression(d) for c, d in zip(a, b))
            s = z3.Solver()
            s.set(timeout=30000)
            s.add(*a)
            assert str(s.check()) == x['result']
    assert old == fresh
    a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256'] == a['generator_sha256'] == sha(R.__file__)
    assert a['auditor_sha256'] == sha(A.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert a['dependencies'] == {p: sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE)
    for r in e['source_spans']:
        start, end = int(r['start'], 16), int(r['end_exclusive'], 16)
        assert r['bytes_hex'] == IMAGE.read(start, end-start).hex()
    assert e['verified_counts'] == COUNTS and a['independent_totals'] == INDEPENDENT
    assert a['composition_counts'] == COMPOSITION and a['proof_cut_lemmas'] == 16
    assert a['target_instruction_rewrites'] == 0
    assert not any(a[k] for k in ['alternate_path_observed', 'native_storage_admission_established',
                                 'same_keys_as_cached_consumer', 'complete_mismatch_result_established'])
    assert [c['result'] for c in a['interpretation_controls']] == ['sat', 'sat', 'sat', 'unsat']
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report = read(BASE/'daemon_record_storage_report.md')
    assert all('| STO'+str(j)+' |' in report for j in range(1, 7))
    assert all('| STO-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    for j, key in enumerate(R.KEYS):
        assert f'| {j} | `0x{key:016x}` |' in report
    assert '| Four constructor-prefix classes | 1 B | 15 B | 16 B | 21 B | No |' in report
    assert '| Two later growth classes | 57 B | 71 B | 72 B | 77 B | No |' in report
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8977 and len(after) == 8983
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']
        assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip():
            assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', COUNTS), ('static_scope', e['scope']), ('independent_checks', INDEPENDENT),
                       ('composition_checks', COMPOSITION), ('source_queries_unsat', 29), ('interpretation_controls', 4), ('new_target_intervals', 0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 543
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES:
        assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 543,
          'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 29, 'interpretation_controls': 4,
          'new_target_intervals': 0, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
