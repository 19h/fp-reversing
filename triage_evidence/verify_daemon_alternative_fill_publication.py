#!/usr/bin/env python3
"""Fresh alternative-fill equations, retained zero stores and publication audit.
O(receipt bytes + selected replay + owned bytes + proof DAG) time/space,
excluding solver search. No target operation or Git-history rewrite.
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
import recover_daemon_alternative_fill as R
import audit_daemon_alternative_fill as A

PREVIOUS = '4b0b9d413d42a60d68ad734a0bdf4edae6f32ed9'
BASELINE_SHA = '01074f59e0248dfc4517bb164e03b823667e305a5703371f3f443976d25e3000'
CHECKS_SHA = '83ec71770a279faee2fa7016756b2449354a0e9722c03233b412a7d157cba662'
AUDIT_SHA = '62a06536904a4b39ecb2c9242e25919c9463c98752699d4409e39df73316938c'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md',
           'daemon_state_allocation_cascade_report.md', 'daemon_constructor_gate_report.md',
           'daemon_alternate_word_report.md', 'daemon_record_storage_report.md', 'daemon_storage_flag_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_alternative_fill_report.md', 'triage_evidence/recover_daemon_alternative_fill.py',
         'triage_evidence/audit_daemon_alternative_fill.py', 'triage_evidence/verify_daemon_alternative_fill_publication.py',
         'triage_evidence/daemon_alternative_fill_checks.json', 'triage_evidence/daemon_alternative_fill_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_alternative_fill_checks.json', 'triage_evidence/daemon_alternative_fill_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'source_instructions': 342, 'source_spans': 13, 'dispatch_routes': 14, 'allocator_bank_rows': 512,
          'retained_clear_snapshots': 76, 'saved_cells_checked': 684, 'zero_store_replay_slices': 76}
INDEPENDENT = {'GP_SP_values_checked': 7296, 'Q_values_checked': 7296, 'NZCV_frames_checked': 228,
               'source_visits_checked': 152, 'read_events_checked': 0, 'write_events_checked': 152, 'slices_checked': 76}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, n in [('source_proofs', 21), ('scalar_controls', 10)]:
        before, after = old.pop(key), fresh.pop(key)
        assert len(before) == len(after) == n
        for x, y in zip(before, after):
            if 'query' in x:
                a, b = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
                assert len(a) == len(b) > 0
                assert all(canonical_expression(c) == canonical_expression(d) for c, d in zip(a, b))
                s = z3.Solver();s.set(timeout=30000);s.add(*a)
                assert str(s.check()) == x['result']
            assert x == y
    assert old == fresh
    a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256'] == a['generator_sha256'] == sha(R.__file__)
    assert a['auditor_sha256'] == sha(A.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert a['dependencies'] == {p: sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE)
    for row in e['source_spans']:
        start, end = int(row['start'], 16), int(row['end_exclusive'], 16)
        assert row['bytes_hex'] == IMAGE.read(start, end-start).hex()
    assert e['verified_counts'] == COUNTS and a['independent_totals'] == INDEPENDENT
    assert a['proof_cut_lemmas'] == a['proof_cut_applications'] == len(a['proof_cut_contexts_verified']) == 3
    assert a['target_instruction_rewrites'] == 0
    assert a['alternative_allocation_and_fill_contract_established']
    assert not any(a[k] for k in ['alternative_constructor_completion_established', 'alternative_branch_observed',
                                  'native_cache_epoch_established', 'new_port_emission_established'])
    assert all(c['source_scalar_model_only'] and not c['native_admission_established'] for c in a['scalar_controls'])
    assert len(e['retained_clear_snapshots']) == len(e['slices']) == 76
    for b in e['allocator_banks']:
        left,right = bytes.fromhex(b['left256_hex']),bytes.fromhex(b['right256_hex'])
        key,c = int(b['key'],16),int(b['constant'],16)
        assert [x^right[left[x]^key] for x in range(256)] == b['outputs256'] == [c]*256
        assert b['target'] == 'libSystem/_malloc' and b['index'] == '0xcc0d'
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report = read(BASE/'daemon_alternative_fill_report.md')
    assert all('| AF'+str(j)+' |' in report for j in range(1,7))
    assert all('| AF-A'+str(j)+':' in report for j in range(1,8))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8))
    for route in e['routes']:
        assert f"| `{route['index32']}` | `{route['target']}` | `{route['IA_modifier']}` |" in report
    assert 'decimal 13 (`0x0d`)' in report and '0x8b3dc651' in report
    assert 'subsequent header writes, complete constructor publication and native admission remain unknown' in report
    for p in CHANGED:
        if p.endswith('_report.md') or p.endswith('_status.md'):
            assert 'daemon_alternative_fill_report.md' in read(BASE/p)
    return e,a


def publication(e,a):
    raw = zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old,new = json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after = ({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before) == 9001 and len(after) == 9007
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for row in new['inputs_preserved']:
        p = row['path']
        assert sha(BASE/p) == row['sha256'] and size(BASE/p) == row['size_bytes']
        if git('ls-files','--',p).decode().strip():
            assert sha256(git('show',PREVIOUS+':'+p)).hexdigest() == row['sha256']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',INDEPENDENT),
                       ('source_queries_unsat',21),('scalar_controls',10),('proof_cut_contexts',3),('new_target_intervals',0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 547
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES:
        assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta = set(git('diff','--name-only',PREVIOUS).decode().splitlines()) | set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta == OWNED,delta ^ OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':547,
        'original_inputs_preserved':3,**COUNTS,'source_queries_unsat':21,'scalar_controls':10,
        'proof_cut_contexts':3,'new_target_intervals':0,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':
    publication(*receipts())
