#!/usr/bin/env python3
"""Fresh complete growth replay and exact publication verification.
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
import recover_daemon_descriptor_growth as R
import replay_daemon_descriptor_growth as A

PREVIOUS = '882455e101f1954a91ba4240298445ce11f6a04a'
BASELINE_SHA = '2decde9cba233259683d908f7d5858c935e2c5035bba2215b98d0bfcee31bfd6'
CHECKS_SHA = 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2'
REPLAY_SHA = 'bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'foundational_triage_report.md', 'corefp_client_paths_report.md',
           'daemon_descriptor_polynomial_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_descriptor_growth_report.md', 'triage_evidence/recover_daemon_descriptor_growth.py',
         'triage_evidence/replay_daemon_descriptor_growth.py', 'triage_evidence/verify_daemon_descriptor_growth_publication.py',
         'triage_evidence/daemon_descriptor_growth_checks.json', 'triage_evidence/daemon_descriptor_growth_replay.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_descriptor_growth_checks.json', 'triage_evidence/daemon_descriptor_growth_replay.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_replay.json')) == REPLAY_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    replay = json.loads(read(ROOT/(R.P+'_replay.json')))
    fresh = json.loads(json.dumps(A.audit()))
    old_proofs, new_proofs = replay.pop('source_proofs'), fresh.pop('source_proofs')
    assert replay == fresh and len(old_proofs) == len(new_proofs) == 3
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
    assert len(e['classes']) == 4 and sorted(len(c['members']) for c in e['classes']) == [32, 32, 272, 272]
    assert sum(len(c['intervals']) for c in e['classes']) == 10
    edge_kinds = Counter()
    for c in e['classes']:
        for item in c['intervals']:
            row = R.unpack(item['interval_packed'])
            counts.update(R.B.rc(row))
            edge_kinds.update(x['kind'] for x in row['logical_edges'])
            for v in row['source_visits']:
                pc = int(v['pc'], 16)
                assert v['bytes_hex'] == IMAGE.read(pc, 4).hex()
                pcs.add(pc)
            used.update(int(r['address'], 16) for r in row['source_reads'] if int(r['address'], 16) in FIXUPS)
    assert edge_kinds == {'braa': 10530, 'blraa': 64, 'retab': 40, 'ret': 28}
    assert e['source_words'] == [{'start': hex(pc), 'bytes_hex': IMAGE.read(pc, 4).hex()} for pc in sorted(pcs)]
    assert e['source_fixups'] == R.B.APIParent.API.Parent.fixups(used)
    assert e['verified_counts'] == replay['verified_counts'] == {'incoming_parents': 152, 'branch_classes': 4,
        'terminal_exports': 608, 'ABI_patterns': 2, 'malloc_return_cases': 2, 'new_payload_bytes_supplied': 0,
        'new_root_bytes_supplied': 0, 'fresh_owner_extent_bytes': 77, **counts}
    assert len(e['coverage']) == 608 and counts['source_visits'] == 247506
    assert replay['source_queries_unsat'] == 3 and replay['independent_totals']['CAS_value_transitions_checked'] == 2
    for ci in [0, 1]:
        row = R.unpack(e['classes'][ci]['intervals'][1]['interval_packed'])
        rr = [r for r in row['source_reads'] if r['pc'] == '0x1003adb90']
        ww = [w for w in row['source_writes'] if w['pc'] == '0x1003adb90']
        assert len(rr) == len(ww) == 1 and rr[0]['address'] == ww[0]['address'] == '0x1010b5de0'
        assert rr[0]['bytes_hex'] == '965d0000' and ww[0]['after_hex'] == 'ef940a00'
    assert {r['address'] for r in replay['pending_import_fixups']['records']} == {'0x10109ff30', '0x10109ff58'}
    assert not e['native_API_executed'] and not e['initializer_to_current_caller_join_established']
    assert not e['full_goal_complete'] and not replay['full_goal_complete']
    assert not e['native_daemon_kext_pairing_established'] and not replay['native_API_executed']
    report = read(BASE/'daemon_descriptor_growth_report.md')
    assert all('| DG'+str(j)+' |' in report for j in range(1, 6))
    assert all('| DG-A'+str(j)+':' in report for j in range(1, 6))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8))
    packed_hygiene(e)
    hygiene(replay)
    return e, replay


def publication(e, replay):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 8911 and len(after) == 8917
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
                       ('replay_checks', replay['independent_totals']), ('admissions', replay['admissions']), ('source_queries_unsat', 3)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 532
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES:
        assert not (BASE/p).exists()
    for p in OWNED:
        if p == 'triage_evidence/daemon_descriptor_growth_checks.json.zst':
            packed_hygiene(json.loads(read(BASE/p[:-4])))
        else:
            path_hygiene((BASE/p).read_bytes())
            path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 532,
                      'original_inputs_preserved': 3, **e['verified_counts'], 'source_queries_unsat': 3,
                      'success_tail_bytes_defined_by_source': 20, 'next_pending_malloc_bytes': 97,
                      'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


def main():
    publication(*receipts())


if __name__ == '__main__':
    main()
