#!/usr/bin/env python3
"""Fresh storage-selector contracts, byte custody and publication verification.
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
import recover_daemon_storage_flag as R
import audit_daemon_storage_flag as A

PREVIOUS = '6d9be7fb2f6c54e6cb28bdec4c4ede9b453ae896'
BASELINE_SHA = '325e6f47bce30918e533dc7cf4d2ae7f4d71d92dc096dd36e27abdb7abebc562'
CHECKS_SHA = '25dde28ce42bfe2840e4cf9c8887ac969bd7a660f333e59925bf38aa553f50e0'
AUDIT_SHA = 'd064264e74e129f32aef403fa8328b288500e0bdff16e5439da6de9b22b82740'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md',
           'daemon_state_container_construction_report.md', 'daemon_constructor_gate_report.md',
           'daemon_alternate_word_report.md', 'daemon_record_storage_report.md', 'daemon_record_walk_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_storage_flag_report.md', 'triage_evidence/recover_daemon_storage_flag.py',
         'triage_evidence/audit_daemon_storage_flag.py', 'triage_evidence/verify_daemon_storage_flag_publication.py',
         'triage_evidence/daemon_storage_flag_checks.json', 'triage_evidence/daemon_storage_flag_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_storage_flag_checks.json', 'triage_evidence/daemon_storage_flag_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'constructor_cases': 76, 'byte_phase_snapshots': 456, 'object_views': 608,
          'object_field_values_checked': 1824, 'object_bytes_checked': 12160, 'persistence_rows': 606,
          'persistence_visits': 1620162, 'source_instructions': 135, 'replay_slices': 312,
          'dispatch_routes': 8, 'text_words_scanned': 3712490, 'direct_STRB_candidates': 6, 'direct_LDRB_candidates': 3}
INDEPENDENT = {'GP_SP_values_checked': 167296, 'Q_values_checked': 167296, 'NZCV_frames_checked': 5228,
               'source_visits_checked': 4916, 'read_events_checked': 700, 'write_events_checked': 240, 'slices_checked': 312}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, n in [('source_proofs', 16)]:
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
    assert a['proof_cuts'] == a['target_instruction_rewrites'] == 0
    assert a['conditional_selector_custody_established']
    assert not any(a[k] for k in ['native_epoch_join_established', 'alternate_constructor_completion_established', 'new_port_emission_established'])
    assert len(a['scalar_controls']) == 8
    assert all(c['source_scalar_model_only'] and not c['native_admission_established'] for c in a['scalar_controls'])
    assert len(e['cases']) == 76 and len(e['phase_snapshots']) == 456 and len(e['object_views']) == 608
    assert all(c['selected_flag_byte'] == 1 and c['pointed_word32'] == 6 and c['tag32'] == '0x4e40e176' for c in e['cases'])
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    for rows in e['direct_displacement_census']['candidates'].values():
        for row in rows:
            assert row['context_bytes_hex'] == IMAGE.read(int(row['context_start'], 16), 36).hex()
    report = read(BASE/'daemon_storage_flag_report.md')
    assert all('| FLG'+str(j)+' |' in report for j in range(1, 7))
    assert all('| FLG-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    for route in e['routes']:
        assert f"| `{route['index32']}` | `{route['target']}` | `{route['IA_modifier']}` |" in report
    assert '| Initializer | 76 | 0 | T=`0x6600050000` | `0xd299e642` |' in report
    assert '| Successful later growth | 304 | 0 | H-buffer=`0x6600080000` | `0xd299e642` |' in report
    for p in CHANGED:
        if p.endswith('_report.md') or p.endswith('_status.md'):
            assert 'daemon_storage_flag_report.md' in read(BASE/p)
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8995 and len(after) == 9001
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
                       ('source_queries_unsat', 16), ('scalar_controls', 8), ('new_target_intervals', 0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 546
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 546,
          'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 16, 'scalar_controls': 8,
          'new_target_intervals': 0, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
