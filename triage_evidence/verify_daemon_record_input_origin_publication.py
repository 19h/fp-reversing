#!/usr/bin/env python3
"""Fresh extraction/replay/proofs, exact publication delta and path hygiene.
O(parent receipts + selected replay + owned bytes + proof DAG) time/space,
excluding solver search. No target API, IDB action or history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_record_input_origin as R
import audit_daemon_record_input_origin as A

PREVIOUS = 'f41d5b3fc52dcb06df5380307ac9bf0e17734089'
BASELINE_SHA = 'cf14bb4aee15f32c2e2278de97731af59214e3a66ebb162c07a7df46d135eb2e'
CHECKS_SHA = '450d52130015a8ae1e0f033db234be880051d9071b9f478cc93e9778bce7a12e'
AUDIT_SHA = '3fc418ed9272a785fbea01bef58a11a625b4c748dbab9d2fd3b04f8d4fb84363'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_record_extension_report.md', 'daemon_record_banks_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_record_input_origin_report.md', 'triage_evidence/recover_daemon_record_input_origin.py',
         'triage_evidence/audit_daemon_record_input_origin.py', 'triage_evidence/verify_daemon_record_input_origin_publication.py',
         'triage_evidence/daemon_record_input_origin_checks.json', 'triage_evidence/daemon_record_input_origin_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_record_input_origin_checks.json', 'triage_evidence/daemon_record_input_origin_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_classes': 2, 'selected_chunks': 24, 'source_visits': 10808, 'read_events': 2156,
          'write_events': 332, 'selected_read_bytes': 9070, 'last_writer_byte_links': 3960,
          'retained_frontier_value_matches': 608, 'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'source_visits': 10808, 'GP_SP_values': 346624, 'NZCV_frames': 10832, 'reads': 2156,
          'writes': 332, 'chunks': 24, 'logical_edges': 82, 'logical_PAC_prologues': 4,
          'conditional_branches': 4, 'last_writer_bytes_checked': 3960,
          'incoming_or_image_bytes_separate': 5110, 'snapshot_bytes': 120}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e == R.build()
    fresh = A.audit(); original_proofs = a.pop('source_proofs'); fresh_proofs = fresh.pop('source_proofs')
    assert a == fresh and e['verified_counts'] == COUNTS and a['independent_totals'] == TOTALS
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(original_proofs) == len(fresh_proofs) == a['source_queries_unsat'] == 6
    for old, new in zip(original_proofs, fresh_proofs):
        x, y = dict(old), dict(new)
        p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        s = z3.Solver(); s.set(timeout=30000); s.add(*p); assert s.check() == z3.unsat
    a['source_proofs'] = original_proofs; hygiene(e); hygiene(a)
    for receipt in [e, a]:
        for field in ['native_API_executed', 'native_daemon_kext_pairing_established',
                      'digest_message_or_algorithm_established', 'transform_algorithm_established', 'full_goal_complete']:
            assert receipt[field] is False
    assert [x['snapshot_splice_matches'] for x in a['alias_controls']] == [True, False]
    report = read(BASE/'daemon_record_input_origin_report.md')
    assert all('| RI'+str(j)+' |' in report and '| RI-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    assert CHECKS_SHA in report and AUDIT_SHA in report
    for c in e['cases']:
        assert all(c[k] in report for k in ['serialized20_hex', 'middle_input16_hex', 'transform_output16_hex', 'record_input20_hex'])
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_record_input_origin_report.md' in read(BASE/p)
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9043 and len(after) == 9049
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', e['verified_counts']), ('static_scope', e['scope']),
                       ('independent_checks', a['independent_totals']), ('source_queries_unsat', 6),
                       ('alias_controls', a['alias_controls'])]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 554
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 554,
                      'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 6,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
