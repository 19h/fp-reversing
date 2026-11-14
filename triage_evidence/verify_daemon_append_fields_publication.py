#!/usr/bin/env python3
"""Fresh field-codec audit, source proofs and exact publication delta.
O(receipt bytes + selected replay + owned bytes + proof DAG) time;
O(receipts + proof DAG) space, excluding solver search. No history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_append_fields as R
import audit_daemon_append_fields as A

PREVIOUS = 'b1c088a565facb1ca0e7046020b0f2839d57c26d'
BASELINE_SHA = '74ad48e4f784669b6fc98e0390a79ac980eba9d3b354d0f67a77ed750e232d3f'
CHECKS_SHA = 'bac22d45750863b7d3bce0993bc891b70a60f43548907c1135a64f89c50e91f7'
AUDIT_SHA = 'a79919e954824d1e1716e3298b455d6f8f03966cfc5ef6242c80d97dad903049'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_descriptor_growth_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_append_fields_report.md', 'triage_evidence/recover_daemon_append_fields.py',
         'triage_evidence/audit_daemon_append_fields.py', 'triage_evidence/verify_daemon_append_fields_publication.py',
         'triage_evidence/daemon_append_fields_checks.json', 'triage_evidence/daemon_append_fields_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_append_fields_checks.json', 'triage_evidence/daemon_append_fields_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    fresh = A.audit()
    for key, expected in [('source_proofs', z3.unsat), ('wrong_contract_controls', z3.sat)]:
        before, after = old.pop(key), fresh.pop(key)
        assert len(before) == len(after) == (35 if expected == z3.unsat else 3)
        for x, y in zip(before, after):
            a, b = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
            assert x == y and len(a) == len(b) > 0
            assert all(canonical_expression(c) == canonical_expression(d) for c, d in zip(a, b))
            s = z3.Solver()
            s.set(timeout=30000)
            s.add(*a)
            assert s.check() == expected
    assert old == fresh
    a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256'] == a['generator_sha256'] == sha(R.__file__)
    assert a['auditor_sha256'] == sha(A.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert a['dependencies'] == {p: sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE)
    assert e['verified_counts'] == {'slices': 30, 'selected_visits': 4018, 'selected_reads': 210, 'selected_writes': 40}
    assert a['independent_totals'] == {'GP_SP_values_checked': 129536, 'NZCV_frames_checked': 4048,
        'source_visits_checked': 4018, 'read_events_checked': 210, 'write_events_checked': 40, 'slices_checked': 30}
    assert len(a['field_codec_checks']) == 12 and len(e['producer_writer_joins']) == 6
    assert e['inherited_nonnull_branch_members'] == a['inherited_nonnull_branch_members'] == 304
    assert not a['inherited_admissions_rerun'] and not a['general_packed_word_producer_reduction_established']
    assert e['new_target_intervals'] == e['new_guest_input_bytes'] == e['new_API_return_premises'] == 0
    assert not e['native_target_executed'] and not a['native_target_executed']
    assert not e['full_goal_complete'] and not a['full_goal_complete']
    report = read(BASE/'daemon_append_fields_report.md')
    assert all('| AF'+str(j)+' |' in report for j in range(1, 6))
    assert all('| AF-A'+str(j)+':' in report for j in range(1, 5))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    hygiene(e)
    hygiene(a)
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8917 and len(after) == 8923
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
    for key, value in [('increment_checks', e['verified_counts']), ('static_scope', e['scope']),
                       ('independent_checks', a['independent_totals']), ('source_queries_unsat', 35),
                       ('inherited_admissions_rerun', False)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 533
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 533,
                      'original_inputs_preserved': 3, **e['verified_counts'], 'source_queries_unsat': 35,
                      'inherited_admissions_rerun': False, 'new_target_intervals': 0,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
