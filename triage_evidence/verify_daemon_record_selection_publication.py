#!/usr/bin/env python3
"""Fresh record selection proof, custody and publication verification.
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
import recover_daemon_record_selection as R
import audit_daemon_record_selection as A

PREVIOUS = 'e4c889813a2699064481c19b848adfc756e65140'
BASELINE_SHA = '33b209fe6a985ab759678812f944efdb675074471d9fd85fa16862afc1f2de53'
CHECKS_SHA = '21a7744f9ad61f2a00d2f83941f9af190040427a655ae24507300386eb4b5108'
AUDIT_SHA = '174b389bf7f0f11595520d7b8f9360afe69cb506a0efcb0b73235edc5ac7e3bd'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md',
           'daemon_constructor_buffer_report.md', 'daemon_resize_callers_report.md', 'daemon_constructor_gate_report.md', 'daemon_descriptor_growth_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_record_selection_report.md', 'triage_evidence/recover_daemon_record_selection.py',
         'triage_evidence/audit_daemon_record_selection.py', 'triage_evidence/verify_daemon_record_selection_publication.py',
         'triage_evidence/daemon_record_selection_checks.json', 'triage_evidence/daemon_record_selection_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_record_selection_checks.json', 'triage_evidence/daemon_record_selection_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'journals_scanned': 58, 'journal_visits_scanned': 2044454, 'default_overlapping_write_events': 44, 'selected_slices': 118, 'selected_visits': 2848, 'selected_reads': 316, 'selected_writes': 66, 'helper_classes': 6, 'initializer_classes': 4, 'checked_exports': 608, 'export_words_checked': 1824, 'dispatch_routes': 13, 'exact_store_candidates': 1, 'text_words_scanned': 3712490}
INDEPENDENT = {'GP_SP_values_checked': 94912, 'NZCV_frames_checked': 2966, 'source_visits_checked': 2848, 'read_events_checked': 316, 'write_events_checked': 66, 'slices_checked': 118}



def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, expected, n in [('source_proofs', z3.unsat, 16), ('interpretation_controls', z3.sat, 4)]:
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
    assert len(e['exports']) == 608 and len(e['helper_classes']) == 6 and len(e['default_initializers']) == 4
    assert not any(a[k] for k in ['general_word_decoder_contract_established', 'general_half_decoder_contract_established', 'earlier_default_word_epoch_established'])
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report = read(BASE/'daemon_record_selection_report.md')
    for helper in e['helper_classes']:
        o, extent = helper['selected_offset_bytes'], helper['extent_bytes']
        raw = ''.join(r['bytes_hex'] for r in helper['buffer_reads'][:4])
        half = ''.join(r['bytes_hex'] for r in helper['buffer_reads'][4:])
        name = 'T' if helper['group'] == 'prefix' else 'H'
        assert f'| {name} / {extent} B | {o} | `{raw}` | 20 B | {o+20} B | {o+14} | `{half}` | 0 |' in report
    assert all('| SEL'+str(j)+' |' in report for j in range(1, 7))
    assert all('| SEL-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8971 and len(after) == 8977
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
                       ('source_queries_unsat', 16), ('interpretation_controls', 4), ('new_target_intervals', 0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 542
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 542,
        'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 16, 'interpretation_controls': 4,
        'new_target_intervals': 0, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
