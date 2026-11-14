#!/usr/bin/env python3
"""Fresh packed-word contracts, exact ring proof and publication verification.
O(receipt bytes + selected replay + owned bytes + proof DAG) time/space,
excluding solver search. No native target operation or history rewrite.
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
import recover_daemon_packed_words as R
import audit_daemon_packed_words as A

PREVIOUS = 'fa968ee61cd8d8df3dc6a45f789deb8413062492'
BASELINE_SHA = '6a08d92221dd4f9fea57069bdf4ba0cd23f14243f094c6b2a1db5e55d788414b'
CHECKS_SHA = 'e8d3a4ffe60b0a28944a5d4a47227f6d313c609e00ab8dcc304c38fc00734554'
AUDIT_SHA = 'fc68105796266bb76dbf92fa3c8efc35fed3d970b4bd6aa11ed08aedd4bd2aaa'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_append_fields_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_packed_words_report.md', 'triage_evidence/recover_daemon_packed_words.py',
         'triage_evidence/audit_daemon_packed_words.py', 'triage_evidence/verify_daemon_packed_words_publication.py',
         'triage_evidence/daemon_packed_words_checks.json', 'triage_evidence/daemon_packed_words_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_packed_words_checks.json', 'triage_evidence/daemon_packed_words_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, expected, n in [('source_proofs', z3.unsat, 50), ('format_controls', z3.sat, 3)]:
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
    assert old == fresh and len(old['ring_normalizations']) == 1
    for n in old['ring_normalizations']:
        assert n['width_bits'] == 27 and n['difference_normal_form'] == '#b'+'0'*27
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
    assert e['verified_counts'] == {'fields': 6, 'count_iterations': 26, 'count_branches': 26,
        'selected_slices': 44, 'selected_visits': 518, 'selected_reads': 26, 'selected_writes': 12}
    assert a['independent_totals'] == {'GP_SP_values_checked': 17984, 'NZCV_frames_checked': 562,
        'source_visits_checked': 518, 'read_events_checked': 26, 'write_events_checked': 12,
        'slices_checked': 44, 'logical_count_edges_checked': 26, 'retained_field_decodes_checked': 6}
    assert not a['inherited_admissions_rerun'] and not a['inherited_producer_replay_rerun']
    assert a['quotient_cut']['seeded_tail_inputs'] == ['W8', 'W9', 'W10', 'W11']
    assert not a['quotient_cut']['target_execution_modified']
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete']
        hygiene(x)
    assert not a['composition']['native_admission_bounds_established']
    report = read(BASE/'daemon_packed_words_report.md')
    assert all('| PW'+str(j)+' |' in report for j in range(1, 6))
    assert all('| PW-A'+str(j)+':' in report for j in range(1, 6))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8923 and len(after) == 8929
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
                       ('independent_checks', a['independent_totals']), ('source_queries_unsat', 50),
                       ('ring_normalizations', 1), ('format_controls', 3), ('new_target_intervals', 0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 534
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 534,
        'original_inputs_preserved': 3, **e['verified_counts'], 'source_queries_unsat': 50,
        'ring_normalizations': 1, 'format_controls': 3, 'new_target_intervals': 0,
        'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
