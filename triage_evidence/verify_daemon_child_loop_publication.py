#!/usr/bin/env python3
"""Fresh child-loop source/replay/proof and exact publication verifier.
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
import recover_daemon_child_loop as R
import audit_daemon_child_loop as A

PREVIOUS='a700f3992357f95867086494ffc7165d06da389f'
BASELINE_SHA='4f24cf55264d6cc953c52b1c5be4cfb3f4c11e2490ac935e1882e6513585d0c1'
CHECKS_SHA='55f0e7548b603b7191495e9749e947106717bd70677eeb341188553beb77463c'
AUDIT_SHA='8ef19fe4cc3ab3b666d4bb6c19153cb2c52b96833e9fe86e0cd1e1d13a3b0912'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','foundational_triage_report.md','interface_abi_report.md',
    'obfuscated_routines_report.md','mach_ports_report.md','corefp_client_paths_report.md',
    'daemon_child_payload_report.md','daemon_child_operation_report.md','daemon_constructor_buffer_report.md',
    'daemon_record_spans_report.md','daemon_record_selection_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_child_loop_report.md','triage_evidence/recover_daemon_child_loop.py',
    'triage_evidence/audit_daemon_child_loop.py','triage_evidence/verify_daemon_child_loop_publication.py',
    'triage_evidence/daemon_child_loop_checks.json','triage_evidence/daemon_child_loop_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_child_loop_checks.json','triage_evidence/daemon_child_loop_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans':12,'source_instructions':161,'dispatch_routes':13,'selected_replay_slices':152,
    'loop_sequences':8,'fresh_custody_links':80,'inherited_fields':32}
INDEPENDENT={'GP_SP_values_checked':78336,'Q_values_checked':78336,'NZCV_frames_checked':2448,
    'source_visits_checked':2296,'logical_authenticated_edges_checked':136,'read_events_checked':424,
    'write_events_checked':72,'slices_checked':152}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));old=json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
    before,after=old.pop('source_proofs'),fresh.pop('source_proofs');assert len(before)==len(after)==17
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
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    for row in e['source_spans']:
        start,end=int(row['start'],16),int(row['end_exclusive'],16)
        assert row['bytes_hex']==IMAGE.read(start,end-start).hex()
    assert e['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(a['scalar_controls'])==20 and a['proof_cuts']==a['target_instruction_rewrites']==0
    assert a['conditional_loop_output_status_contract_established']
    assert not any(a[k] for k in ['arbitrary_body_termination_established','native_epoch_join_established','new_port_emission_established'])
    assert all(c['source_scalar_model_only'] and not c['native_admission_established'] for c in a['scalar_controls'])
    assert len(e['loop_sequences'])==8 and len(e['fresh_custody_links'])==80 and len(e['inherited_fields'])==32
    assert all(v['body_indices32']==[0,1,2,3] and v['gate_indices32']==[0,1,2,3,4] for v in e['loop_sequences'])
    for x in [e,a]:
        assert x['new_target_intervals']==x['new_guest_input_bytes']==x['new_API_return_premises']==0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report=read(BASE/'daemon_child_loop_report.md')
    assert all('| CL'+str(j)+' |' in report for j in range(1,7))
    assert all('| CL-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8))
    for route in e['routes']:
        assert f"| `{route['index32']}` | `{route['target']}` | `{route['IA_modifier']}` |" in report
    assert all(s in report for s in ['0x76d8ea95','0x8b3dc651','0x1009a1574','0x100957a58','0x69746772','0x100000000','SP+0x8d8c'])
    assert 'without an execution witness' in report and 'daemon-kext' in report
    for p in CHANGED:
        if p.endswith(('_report.md','_status.md')):assert 'daemon_child_loop_report.md' in read(BASE/p)
    return e,a


def publication(e,a):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9025 and len(after)==9031
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:
        p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',INDEPENDENT),
                      ('source_queries_unsat',17),('scalar_controls',20),('new_target_intervals',0)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==551
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':551,
        'original_inputs_preserved':3,**COUNTS,'source_queries_unsat':17,'scalar_controls':20,
        'independent_checks':INDEPENDENT,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
