#!/usr/bin/env python3
"""Fresh source extraction, projection replay, SMT and exact publication audit.
O(receipts + projections + text words + exports + owned bytes + proof DAG)
time/space, excluding solver search. No target operation or history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_record_banks as R
import audit_daemon_record_banks as A

PREVIOUS='12547a0c0094ecf908d7db6df166e2adc5fa1bf2'
BASELINE_SHA='c6622e118a64e86ddba87743fc9a3d71d2d86646cf2a0f419929f6e4142647c9'
CHECKS_SHA='50000b634bd81018868350c194f60e49992dded73a2a6996764f0af345c40f48'
AUDIT_SHA='c22bc57d3c84cde88ea1b5e1a8097d5ba20b23a58fe1004b1f7c653a307098fd'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','foundational_triage_report.md','interface_abi_report.md',
         'obfuscated_routines_report.md','mach_ports_report.md','corefp_client_paths_report.md',
         'daemon_record_extension_report.md','daemon_child_loop_report.md',
         'daemon_constructor_bank_origins_report.md','daemon_shared_roots_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_record_banks_report.md','triage_evidence/recover_daemon_record_banks.py',
       'triage_evidence/audit_daemon_record_banks.py','triage_evidence/verify_daemon_record_banks_publication.py',
       'triage_evidence/daemon_record_banks_checks.json','triage_evidence/daemon_record_banks_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_record_banks_checks.json','triage_evidence/daemon_record_banks_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    fresh=A.audit()
    old_proofs=a.pop('source_proofs');fresh_proofs=fresh.pop('source_proofs')
    assert a==fresh and e==R.build()
    assert len(old_proofs)==len(fresh_proofs)==a['source_queries_unsat']==10
    for old,new in zip(old_proofs,fresh_proofs):
        x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    a['source_proofs']=old_proofs
    hygiene(e);hygiene(a)
    for x in [e,a]:
        assert not x['native_API_executed'] and not x['native_daemon_kext_pairing_established']
        assert not x['initializer_to_current_caller_join_established'] and not x['full_goal_complete']
    report=read(BASE/'daemon_record_banks_report.md')
    assert all('| RB'+str(j)+' |' in report for j in range(1,7))
    assert all('| RB-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8))
    assert CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x10084fe0c','0x10084fcc4','SP+0x390','SP+0x398','SP+0x3a0','165','184','608']:
        assert word in report,word
    for p in CHANGED:
        if p.endswith(('_report.md','_status.md')):assert 'daemon_record_banks_report.md' in read(BASE/p)
    return e,a


def publication(e,a):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9037 and len(after)==9043
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),
        ('independent_checks',a['independent_totals']),('source_queries_unsat',10),('finite_controls',a['finite_controls'])]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==553
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':553,
        'original_inputs_preserved':3,**e['verified_counts'],'source_queries_unsat':10,
        'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
