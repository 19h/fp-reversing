#!/usr/bin/env python3
"""Fresh source-contract and exact publication-delta verification.
O(source + profiles + terminal bytes + owned bytes + query DAG) time;
O(largest receipt + terminal byte map + query DAG) space, excluding solver
search complexity. No native target operation or history rewrite executes.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_constructor_descriptor as R

PREVIOUS = '877010da53b2d9380d8ab7a803d25176f5f93971'
BASELINE_SHA = '6ca691558c6372bd2a0b83ab5646ffb339b4465d363a700d8e8610cddca112d4'
CHECKS_SHA = '9d044ed5285d1fb392fb01eb10e016b19d8ba312435793760e28376c9bc50d3f'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_constructor_buffer_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_constructor_descriptor_report.md',
         'triage_evidence/recover_daemon_constructor_descriptor.py',
         'triage_evidence/verify_daemon_constructor_descriptor_publication.py',
         'triage_evidence/daemon_constructor_descriptor_checks.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_constructor_descriptor_checks.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    old = json.loads(read(ROOT/(R.P+'_checks.json')))
    fresh = R.build()
    # Compare regenerated symbolic expressions structurally, independently of
    # harmless SMT pretty-printer ordering; all other receipt fields are exact.
    aa, bb = old.pop('source_proofs'), fresh.pop('source_proofs')
    assert old == fresh
    assert len(aa) == len(bb) == 8
    for retained, current in zip(aa, bb):
        x, y = z3.parse_smt2_string(retained.pop('query')), z3.parse_smt2_string(current.pop('query'))
        assert retained == current and retained['premises_nonvacuous'] and retained['result'] == 'unsat'
        assert len(x) == len(y) > 0
        assert all(canonical_expression(a) == canonical_expression(b) for a, b in zip(x, y))
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*x)
        assert s.check() == z3.unsat
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['new_guest_execution_intervals'] == 0 and not e['native_API_executed'] and not e['full_goal_complete']
    assert not e['initializer_to_current_caller_epoch_join_established']
    assert not e['feedback_store_destination_join_established'] and not e['native_daemon_kext_pairing_established']
    report = read(BASE/'daemon_constructor_descriptor_report.md')
    assert all('| CD'+str(j)+' |' in report for j in range(1, 5))
    assert all('| CD-A'+str(j)+':' in report for j in range(1, 6))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    hygiene(e)
    return e


def main():
    e = receipts()
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before = {r['path']: r for r in old['files']}
    after = {r['path']: r for r in new['files']}
    assert len(before) == 8887 and len(after) == 8891
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for row in new['inputs_preserved']:
        p = row['path']
        assert sha(BASE/p) == row['sha256'] and size(BASE/p) == row['size_bytes']
        # The ignored original C file is filesystem-preserved, never staged.
        tracked = git('ls-files', '--', p).decode().strip()
        if tracked:
            assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == row['sha256']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    assert new['validation'][R.P+'_increment_checks'] == e['verified_counts']
    assert new['validation'][R.P+'_static_scope'] == e['scope']
    assert new['validation']['reports'] == old['validation']['reports']+1 == 527
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
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after),
                      'reports': 527, 'original_inputs_preserved': 3,
                      **e['verified_counts'], 'new_guest_execution_intervals': 0,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    main()
