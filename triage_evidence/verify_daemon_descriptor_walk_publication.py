#!/usr/bin/env python3
"""Fresh complete walk-prefix replay and exact publication verification.
O(receipt bytes + replay/admissions + owned bytes + query DAG) time;
O(receipts+parent maps+largest interval+query DAG) space, excluding solver
search complexity. No native target operation or history rewrite executes.
"""
import json
from collections import Counter
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE, FIXUPS
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_daemon_constructor_buffer_publication import packed_hygiene
import recover_daemon_descriptor_walk as R
import replay_daemon_descriptor_walk as A

PREVIOUS = '0e061c939e48b5e1e37988e644608116fc147de2'
BASELINE_SHA = '2ebd756d009eac311cca5b6d686eb14d184f49824d296f5269558b559d050338'
CHECKS_SHA, REPLAY_SHA = 'f11399df1f9b98d5b06ee61996c335d749a33b14ad764fe442cc47a03c419a50', 'd09df40f234c9391aaaade51e397f69dbcc536063f4738fdaade624822ade023'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_feedback_callers_report.md', 'daemon_constructor_descriptor_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_descriptor_walk_report.md', 'triage_evidence/recover_daemon_descriptor_walk.py',
         'triage_evidence/replay_daemon_descriptor_walk.py', 'triage_evidence/verify_daemon_descriptor_walk_publication.py',
         'triage_evidence/daemon_descriptor_walk_checks.json', 'triage_evidence/daemon_descriptor_walk_replay.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_descriptor_walk_checks.json', 'triage_evidence/daemon_descriptor_walk_replay.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_replay.json')) == REPLAY_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    replay = json.loads(read(ROOT/(R.P+'_replay.json')))
    fresh = json.loads(json.dumps(A.audit()))
    old_proofs, new_proofs = replay.pop('source_proofs'), fresh.pop('source_proofs')
    assert replay == fresh and len(old_proofs) == len(new_proofs) == 6
    for old, new in zip(old_proofs, new_proofs):
        x, y = z3.parse_smt2_string(old.pop('query')), z3.parse_smt2_string(new.pop('query'))
        assert old == new and old['premises_nonvacuous'] and old['result'] == 'unsat'
        assert len(x) == len(y) > 0 and all(canonical_expression(a) == canonical_expression(b) for a, b in zip(x, y))
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*x)
        assert s.check() == z3.unsat
    replay = json.loads(read(ROOT/(R.P+'_replay.json')))
    assert e['generator_sha256'] == replay['generator_sha256'] == sha(R.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert e['source_sha256'] == replay['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    counts = Counter()
    pcs, used = set(), set()
    assert len(e['classes']) == 4 and sorted(len(c['member_cohort_indices']) for c in e['classes']) == [8, 8, 68, 68]
    for c in e['classes']:
        row = R.unpack(c['interval_packed'])
        counts.update(R.B.rc(row))
        for v in row['source_visits']:
            pc = int(v['pc'], 16)
            assert v['bytes_hex'] == IMAGE.read(pc, 4).hex()
            pcs.add(pc)
        used.update(int(r['address'], 16) for r in row['source_reads'] if int(r['address'], 16) in FIXUPS)
    assert e['source_words'] == [{'start': hex(pc), 'bytes_hex': IMAGE.read(pc, 4).hex()} for pc in sorted(pcs)]
    assert e['source_fixups'] == R.B.APIParent.API.Parent.fixups(used)
    assert e['verified_counts'] == replay['verified_counts'] == {'incoming_parents': 152, 'representative_classes': 4,
        'terminal_exports': 152, 'new_root_bytes_per_parent': 8, 'combined_conditional_root_bytes_per_parent': 104, **counts}
    assert len(e['coverage']) == 152 and {c['cohort_index'] for c in e['coverage']} == set(range(152))
    assert counts['source_visits'] == 1532 and replay['source_queries_unsat'] == 6
    assert not e['native_API_executed'] and not e['initializer_to_current_caller_join_established']
    assert e['descriptor_bytes_supplied'] == 0 and not e['full_goal_complete'] and not replay['full_goal_complete']
    assert not e['native_daemon_kext_pairing_established'] and not replay['native_API_executed']
    report = read(BASE/'daemon_descriptor_walk_report.md')
    assert all('| DW'+str(j)+' |' in report for j in range(1, 6))
    assert all('| DW-A'+str(j)+':' in report for j in range(1, 6))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    packed_hygiene(e)
    hygiene(replay)
    return e, replay


def main():
    e, replay = receipts()
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8899 and len(after) == 8905
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
                       ('replay_checks', replay['independent_totals']), ('admissions', replay['admissions']),
                       ('source_queries_unsat', 6)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 530
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES:
        assert not (BASE/p).exists()
    for p in OWNED:
        if p == 'triage_evidence/daemon_descriptor_walk_checks.json.zst':
            packed_hygiene(json.loads(read(BASE/p[:-4])))
        else:
            path_hygiene((BASE/p).read_bytes())
            path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 530,
                      'original_inputs_preserved': 3, **e['verified_counts'], 'source_queries_unsat': 6,
                      'max_source_node_visits_in_phase': 19, 'descriptor_bytes_supplied': 0,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    main()
