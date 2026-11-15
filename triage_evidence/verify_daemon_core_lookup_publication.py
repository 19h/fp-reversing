#!/usr/bin/env python3
"""Fresh extraction/audit and exact publication custody for the core graph.
O(receipts + source replay/vectors + DAGs + owned bytes + proof DAG) time/space;
solver search additional. No native operation, IDB action or history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_core_lookup as R
import audit_daemon_core_lookup as A

PREVIOUS = 'a22d44238ee79bc5e895cca2719497a6c6f579de'
BASELINE_SHA = '8e88aa52cafc9927aae9a20f45f5890713b8fdcfeb53625502e50af1253bc015'
CHECKS_SHA = '5661e892920d52fac2029d2bbc4b3189c884caa839dd93552c268eed293689c9'
AUDIT_SHA = '39495d6ba9b37d1113d3d7ceba4c8ec317baec96f1ed1277ec7d4344df87d460'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_record_input_origin_report.md', 'daemon_block_staging_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_core_lookup_report.md', 'triage_evidence/recover_daemon_core_lookup.py',
         'triage_evidence/audit_daemon_core_lookup.py', 'triage_evidence/daemon_core_lookup_kernel.py',
         'triage_evidence/verify_daemon_core_lookup_publication.py',
         'triage_evidence/daemon_core_lookup_checks.json', 'triage_evidence/daemon_core_lookup_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_core_lookup_checks.json', 'triage_evidence/daemon_core_lookup_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_contexts': 2, 'source_visits': 5122, 'lookup_nodes': 384,
          'input_byte_reads': 32, 'output_byte_stores': 32, 'fixed_read_value_cells': 148,
          'address_and_exit_conditions': 676, 'expression_nodes': 28014}
TOTALS = {'source_visits': 5122, 'logical_edges': 2, 'GP_SP_values': 163968, 'NZCV_frames': 5124,
          'reads': 600, 'writes': 72, 'chunks': 2, 'immutable_window_bytes_checked': 20480,
          'retained_graph_lookup_reads_checked': 384, 'source_vector_runs': 156, 'source_vector_visits': 399360,
          'graph_vector_runs': 156, 'source_graph_lookup_values_checked': 29952,
          'source_vector_output_bytes_checked': 2496}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = a.pop('source_proofs'), fresh.pop('source_proofs')
    assert a == fresh and e['verified_counts'] == COUNTS and a['independent_totals'] == TOTALS
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == a['source_queries_unsat'] == 14
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        s = z3.Solver(); s.set(timeout=30000); s.add(*p); assert s.check() == z3.unsat
    a['source_proofs'] = old_proofs
    assert sum(p['conditions'] for p in old_proofs) == 676
    assert len({p['label'] for p in old_proofs}) == 14
    assert e['cases'][0]['graph'] == e['cases'][1]['graph'] and a['identical_retained_context_graphs']
    g = e['cases'][0]['graph']; assert len(g['nodes']) == 14007 and len(g['lookups']) == 192 and len(g['windows']) == 16
    assert len(a['original_fixups']['records']) == 21
    hygiene(e); hygiene(a)
    for receipt in [e, a]:
        for field in ['native_API_executed', 'native_daemon_kext_pairing_established',
                      'transform_algorithm_established', 'full_goal_complete']: assert receipt[field] is False
    report = read(BASE/'daemon_core_lookup_report.md')
    assert all('| CL'+str(j)+' |' in report and '| CL-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    assert a['controls']['nonaffine_counterexample']['four_output_XOR16_hex'] in report
    assert a['controls']['corrupted_literal_table_control']['changed_output16_hex'] in report
    for c in e['cases']:
        assert c['entry_input16_hex'] in report and c['expected_output16_hex'] in report
        for b in c['graph']['windows']: assert b in report
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_core_lookup_report.md' in read(BASE/p)
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9055 and len(after) == 9062
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', e['verified_counts']), ('static_scope', e['scope']),
                       ('independent_checks', a['independent_totals']), ('source_queries_unsat', 14),
                       ('identical_retained_context_graphs', True), ('controls', a['controls'])]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 556
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 556,
                      'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 14,
                      'source_vector_runs': 156, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
