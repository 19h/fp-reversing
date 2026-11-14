#!/usr/bin/env python3
"""Fresh private resize caller proof, custody and publication verification.
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
import recover_daemon_resize_callers as R
import audit_daemon_resize_callers as A

PREVIOUS = 'e143b124eded834340c1019c5779422be1af918a'
BASELINE_SHA = '7fe786f394c8a8eba8657d6065e155a2d1543ef8593e326d6f2396197f008532'
CHECKS_SHA = '421f899bf25a3ac563aa923545423c65aa6c2cb19ffa5ccc45aa928bb2049ac1'
AUDIT_SHA = '727dcee019edfe6bf0f49e8f3f89e138839f7b23eca502cbdf859a452d0faa3e'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md',
           'daemon_constructor_buffer_report.md', 'daemon_record_spans_report.md', 'daemon_descriptor_growth_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_resize_callers_report.md', 'triage_evidence/recover_daemon_resize_callers.py',
         'triage_evidence/audit_daemon_resize_callers.py', 'triage_evidence/verify_daemon_resize_callers_publication.py',
         'triage_evidence/daemon_resize_callers_checks.json', 'triage_evidence/daemon_resize_callers_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_resize_callers_checks.json', 'triage_evidence/daemon_resize_callers_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'selected_slices': 146, 'selected_visits': 1450, 'selected_reads': 200, 'selected_writes': 114, 'caller_classes': 2, 'caller_record_reads': 20, 'caller_record_bytes_read': 108, 'checked_exports': 304, 'export_words_checked': 2128}
INDEPENDENT = {'GP_SP_values_checked': 51072, 'NZCV_frames_checked': 1596, 'source_visits_checked': 1450, 'read_events_checked': 200, 'write_events_checked': 114, 'slices_checked': 146}



def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, expected, n in [('source_proofs', z3.unsat, 16), ('interpretation_controls', z3.sat, 3)]:
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
    assert len(e['exports']) == 304 and len(e['classes']) == 2
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report = read(BASE/'daemon_resize_callers_report.md')
    for field in e['classes'][0]['caller_record_fields']:
        off, r = field['offset_bytes'], field['read']
        if off in [0x10, 0x20]:
            continue
        value = int.from_bytes(bytes.fromhex(r['bytes_hex']), 'little')
        assert f"| `0x{off:02x}` | {r['size_bytes']} | `{hex(value)}` |" in report
    assert all('| RC'+str(j)+' |' in report for j in range(1, 7))
    assert all('| RC-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8965 and len(after) == 8971
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
                       ('source_queries_unsat', 16), ('interpretation_controls', 3), ('new_target_intervals', 0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 541
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 541,
        'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 16, 'interpretation_controls': 3,
        'new_target_intervals': 0, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    publication(*receipts())
