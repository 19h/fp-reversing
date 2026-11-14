#!/usr/bin/env python3
"""Fresh full polynomial-frontier replay and exact publication verification.
O(receipt bytes + replay/admissions + owned bytes + proof DAG) time;
O(receipts+parent maps+largest interval+proof DAG) space, excluding solver
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
import recover_daemon_descriptor_polynomial as R
import replay_daemon_descriptor_polynomial as A

PREVIOUS = 'a57ea8145654aa9e80fe85628c66bb567e4f27b0'
BASELINE_SHA = '05c9b379d07579db45e705cffafad11c1b597e09cd7d7c82c3f1ad47b0363375'
CHECKS_SHA = 'a43e977f7a9b786f44427b67e8152ba8e64ad940014c6cf821a800b9479b60c6'
REPLAY_SHA = '7acd16ed49134447d3588f8c2d4a00b0adfb0cd734217f8b939af82d03fd954c'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_descriptor_walk_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_descriptor_polynomial_report.md', 'triage_evidence/recover_daemon_descriptor_polynomial.py',
         'triage_evidence/replay_daemon_descriptor_polynomial.py', 'triage_evidence/verify_daemon_descriptor_polynomial_publication.py',
         'triage_evidence/daemon_descriptor_polynomial_checks.json', 'triage_evidence/daemon_descriptor_polynomial_replay.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_descriptor_polynomial_checks.json', 'triage_evidence/daemon_descriptor_polynomial_replay.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_replay.json')) == REPLAY_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    replay = json.loads(read(ROOT/(R.P+'_replay.json')))
    fresh = json.loads(json.dumps(A.audit()))
    old_proofs, new_proofs = replay.pop('source_proofs'), fresh.pop('source_proofs')
    assert replay == fresh and len(old_proofs) == len(new_proofs) == 9
    for old, new in zip(old_proofs, new_proofs):
        x, y = z3.parse_smt2_string(old.pop('query')), z3.parse_smt2_string(new.pop('query'))
        assert old == new and old['premises_nonvacuous'] and old['result'] == 'unsat'
        assert len(x) == len(y) > 0 and all(canonical_expression(a) == canonical_expression(b) for a, b in zip(x, y))
        solver = z3.Solver()
        solver.set(timeout=30000)
        solver.add(*x)
        assert solver.check() == z3.unsat
    replay = json.loads(read(ROOT/(R.P+'_replay.json')))
    assert e['generator_sha256'] == replay['generator_sha256'] == sha(R.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert replay['replayer_sha256'] == sha(A.__file__)
    assert replay['replayer_dependencies'] == {p: sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256'] == replay['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    counts = Counter()
    pcs, used = set(), set()
    assert len(e['classes']) == 4 and sorted(len(c['member_cohort_indices']) for c in e['classes']) == [8, 8, 68, 68]
    for c in e['classes']:
        row = R.unpack(c['interval_packed'])
        counts.update(R.B.rc(row))
        assert Counter(x['kind'] for x in row['logical_edges']) == {'braa': 98, 'blraa': 1, 'retab': 1}
        for v in row['source_visits']:
            pc = int(v['pc'], 16)
            assert v['bytes_hex'] == IMAGE.read(pc, 4).hex()
            pcs.add(pc)
        used.update(int(r['address'], 16) for r in row['source_reads'] if int(r['address'], 16) in FIXUPS)
    assert e['source_words'] == [{'start': hex(pc), 'bytes_hex': IMAGE.read(pc, 4).hex()} for pc in sorted(pcs)]
    assert e['source_fixups'] == R.B.APIParent.API.Parent.fixups(used)
    assert e['verified_counts'] == replay['verified_counts'] == {'incoming_parents': 152, 'representative_classes': 4,
        'terminal_exports': 152, 'new_node_bytes_per_parent': 12, 'inherited_conditional_root_bytes_per_parent': 104,
        'combined_conditional_entry_bytes_per_parent': 116, **counts}
    assert len(e['coverage']) == 152 and {c['cohort_index'] for c in e['coverage']} == set(range(152))
    assert counts['source_visits'] == 20604 and replay['source_queries_unsat'] == 9
    assert replay['exact_ring_normalizations'] == len(replay['source_normalizations']) == 7
    assert all(n['difference_normal_form'] == '#x00000000' for n in replay['source_normalizations'])
    assert not e['native_API_executed'] and not e['initializer_to_current_caller_join_established']
    assert e['node_gap_bytes_supplied'] == 0 and not e['malloc_return_supplied']
    assert not e['full_goal_complete'] and not replay['full_goal_complete']
    assert not e['native_daemon_kext_pairing_established'] and not replay['native_API_executed']
    report = read(BASE/'daemon_descriptor_polynomial_report.md')
    assert all('| DP'+str(j)+' |' in report for j in range(1, 6))
    assert all('| DP-A'+str(j)+':' in report for j in range(1, 6))
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
    assert len(before) == 8905 and len(after) == 8911
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
                       ('source_queries_unsat', 9), ('exact_ring_normalizations', 7)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 531
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES:
        assert not (BASE/p).exists()
    for p in OWNED:
        if p == 'triage_evidence/daemon_descriptor_polynomial_checks.json.zst':
            packed_hygiene(json.loads(read(BASE/p[:-4])))
        else:
            path_hygiene((BASE/p).read_bytes())
            path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 531,
                      'original_inputs_preserved': 3, **e['verified_counts'], 'source_queries_unsat': 9,
                      'exact_ring_normalizations': 7, 'pending_malloc_bytes': 77,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__':
    main()
