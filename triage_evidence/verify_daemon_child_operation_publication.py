#!/usr/bin/env python3
"""Fresh child-operation source/replay/proof and exact publication verifier.
O(receipt bytes + selected replay*32 + owned bytes + proof DAG) time/space,
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
import recover_daemon_child_operation as R
import audit_daemon_child_operation as A

PREVIOUS='ab6ceb0ab613df48a7c6df3d8eef5082296ed6bf'
BASELINE_SHA='d2bf6ef607730d65aa573b227e894ed30bba716fccf9a18cb13947dc8f9cfc8b'
CHECKS_SHA='7d7029404ffe048fff50a8ea402b9f07eb6b27bd0874ce9c5ca45f6358cbc383'
AUDIT_SHA='c6012aa59d69647d190356f3825e99a72e09a9b1abc579a30cb6c594aac4182a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md',
    'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
    'daemon_alternative_header_report.md','daemon_constructor_gate_report.md','daemon_constructor_buffer_report.md',
    'daemon_storage_flag_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_child_operation_report.md','triage_evidence/recover_daemon_child_operation.py',
    'triage_evidence/audit_daemon_child_operation.py','triage_evidence/verify_daemon_child_operation_publication.py',
    'triage_evidence/daemon_child_operation_checks.json','triage_evidence/daemon_child_operation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_child_operation_checks.json','triage_evidence/daemon_child_operation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans':13,'source_instructions':264,'dispatch_routes':16,'selected_replay_slices':36,
        'retained_clear_views':4,'saved_cells_checked':32}
INDEPENDENT={'GP_SP_values_checked':29184,'Q_values_checked':29184,'NZCV_frames_checked':912,
    'source_visits_checked':876,'logical_authenticated_edges_checked':36,'read_events_checked':112,
    'write_events_checked':52,'slices_checked':36}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));old=json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
    before,after=old.pop('source_proofs'),fresh.pop('source_proofs');assert len(before)==len(after)==18
    for x,y in zip(before,after):
        a,b=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert len(a)==len(b)>0 and all(canonical_expression(c)==canonical_expression(d) for c,d in zip(a,b))
        s=z3.Solver();s.set(timeout=30000);s.add(*a);assert str(s.check())==x['result']=='unsat'
        assert x==y and x['premises_nonvacuous']
    assert old==fresh
    a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert e['dependencies']=={p:sha(ROOT/p) for p in R.DEPS}
    assert a['dependencies']=={p:sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)
    for row in e['source_spans']:
        start,end=int(row['start'],16),int(row['end_exclusive'],16)
        assert row['bytes_hex']==IMAGE.read(start,end-start).hex()
    assert e['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(a['scalar_controls'])==8 and a['proof_cuts']==a['target_instruction_rewrites']==0
    assert a['conditional_child_prelude_contract_established']
    assert not any(a[k] for k in ['alternative_execution_observed','native_epoch_join_established','new_port_emission_established'])
    assert all(c['source_scalar_model_only'] and not c['native_admission_established'] for c in a['scalar_controls'])
    assert len(e['retained_views'])==4 and all(v['root_260_defined_bytes']==0 for v in e['retained_views'])
    for x in [e,a]:
        assert x['new_target_intervals']==x['new_guest_input_bytes']==x['new_API_return_premises']==0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report=read(BASE/'daemon_child_operation_report.md')
    assert all('| CO'+str(j)+' |' in report for j in range(1,7))
    assert all('| CO-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8))
    for route in e['routes']:
        assert f"| `{route['index32']}` | `{route['target']}` | `{route['IA_modifier']}` |" in report
    assert all(s in report for s in ['98 99 98 99','0xec2d0e54','0x76657273','0x8b3dc651','SP+0x260'])
    assert 'no execution witness' in report and 'daemon-kext transaction pairing' in report
    for p in CHANGED:
        if p.endswith(('_report.md','_status.md')):assert 'daemon_child_operation_report.md' in read(BASE/p)
    return e,a


def publication(e,a):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9013 and len(after)==9019
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:
        p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',INDEPENDENT),
                      ('source_queries_unsat',18),('scalar_controls',8),('new_target_intervals',0)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==549
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':549,
        'original_inputs_preserved':3,**COUNTS,'source_queries_unsat':18,'scalar_controls':8,
        'independent_checks':INDEPENDENT,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
