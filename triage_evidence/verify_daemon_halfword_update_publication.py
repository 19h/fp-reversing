#!/usr/bin/env python3
"""Fresh halfword reader/update contracts, custody and publication checks.
O(receipt bytes + selected replay + owned bytes + proof DAG) time/space,
excluding solver search. No native operation or history rewrite.
"""
import contextlib
import io
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_halfword_update as R
import audit_daemon_halfword_update as A

PREVIOUS = 'ae992051db5a6eebf451451f71f3f1cdb32a0ec1'
BASELINE_SHA = 'c84c088294f9990f901b61d4676b38656ee6b21bdbbc8b7a84cccf97ab061ece'
CHECKS_SHA = '5f53bea42c88b3bdc516321e318f4ca5da94c4e2a6eff64e51c12b349726f9d4'
AUDIT_SHA = '8a981f149dc127d4079eaeed525a90630b14712cea3c24c12119ac3f287e7883'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_packed_halves_report.md', 'daemon_descriptor_polynomial_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_halfword_update_report.md', 'triage_evidence/recover_daemon_halfword_update.py',
         'triage_evidence/audit_daemon_halfword_update.py', 'triage_evidence/verify_daemon_halfword_update_publication.py',
         'triage_evidence/daemon_halfword_update_checks.json', 'triage_evidence/daemon_halfword_update_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_halfword_update_checks.json', 'triage_evidence/daemon_halfword_update_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'selected_slices': 12, 'selected_visits': 656, 'selected_reads': 60, 'selected_writes': 8,
          'polynomial_classes': 4, 'parent_exports': 152, 'exported_cell_bytes': 608,
          'growth_field_joins': 2, 'inherited_nonnull_members': 304, 'retained_logical_edges': 4}
INDEPENDENT = {'GP_SP_values_checked': 21376, 'NZCV_frames_checked': 668, 'source_visits_checked': 656,
               'read_events_checked': 60, 'write_events_checked': 8, 'slices_checked': 12, 'logical_edges_checked': 4}



def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, expected, n in [('source_proofs', z3.unsat, 43), ('format_controls', z3.sat, 3)]:
        before, after = old.pop(key), fresh.pop(key)
        assert len(before) == len(after) == n
        for x, y in zip(before, after):
            a, b = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
            assert x == y and len(a) == len(b) > 0
            assert all(canonical_expression(c) == canonical_expression(d) for c, d in zip(a, b))
            s = z3.Solver()
            s.set(timeout=30000)
            s.add(*a)
            assert s.check() == expected
    assert old == fresh and len(old['ring_normalizations']) == 16
    assert {r['count_nibble'] for r in old['ring_normalizations']} == set(range(16))
    for r in old['ring_normalizations']:
        assert r['width_bits'] == 16 and r['difference_normal_form'] == '#x0000'
    a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256'] == a['generator_sha256'] == sha(R.__file__)
    assert a['auditor_sha256'] == sha(A.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert a['dependencies'] == {p: sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE)
    for r in e['source_spans']:
        start, end = int(r['start'], 16), int(r['end_exclusive'], 16)
        assert r['bytes_hex'] == IMAGE.read(start, end-start).hex()
    assert e['original_fixups'] == verify_original_fixups(R.SLOTS)
    assert e['verified_counts'] == COUNTS and a['independent_totals'] == INDEPENDENT
    assert not a['inherited_admissions_rerun']
    assert not a['composition']['native_admission_bounds_established']
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete']
        hygiene(x)
    report = read(BASE/'daemon_halfword_update_report.md')
    assert all('| HU'+str(j)+' |' in report for j in range(1, 6))
    assert all('| HU-A'+str(j)+':' in report for j in range(1, 6))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8935 and len(after) == 8941
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
                       ('source_queries_unsat', 43), ('ring_normalizations', 16), ('format_controls', 3), ('new_target_intervals', 0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 536
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 536,
        'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 43, 'ring_normalizations': 16, 'format_controls': 3,
        'new_target_intervals': 0, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
