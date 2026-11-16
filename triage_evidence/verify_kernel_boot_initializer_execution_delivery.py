#!/usr/bin/env python3
"""Rebuild full private boot execution/replay, proofs and publication custody.
Linear source/memory/corpus/page/artifact work; SMT search separate.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_kernel_boot_initializer_execution as R
import audit_kernel_boot_initializer_execution as A
PREVIOUS='5f58609b96d8eaa1dbb6c6bb24bd7184547ff886'
BASELINE_SHA='e3f4f56fbe5a6d51ac6a35fad393246700545a44a3dd6a3123cbc7b2c065419b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_fixup_projection_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_boot_initializer_execution_report.md',*[('triage_evidence/'+name+'_kernel_boot_initializer_execution.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_boot_initializer_execution_delivery.py','triage_evidence/kernel_boot_initializer_execution_checks.json','triage_evidence/kernel_boot_initializer_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_boot_initializer_execution_checks.json','triage_evidence/kernel_boot_initializer_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
TOTALS={'source_queries_unsat':24,'proof_instruction_instances':135,'proof_distinct_PCs':95,'full_private_boot_executions':1,'source_visits':43400376,'executed_source_PCs':738,'source_reads':4664940,'source_writes':1548546,'fixup_stores':1036413,'zero_slide_stores':511000,'published_global_words':8,'original_call_entries':365,'mapped_image_pages':4967,'changed_source_controls':2,'loop_contractions':0,'native_target_executions':0,'continuous_startup_visits_added':0}
def receipts():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit();x,y=dict(a),dict(fresh);old,new=x.pop('source_proofs'),y.pop('source_proofs');assert x==y
 assert len(old)==len(new)==24
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(left,right))
 assert e['verified_counts']=={'functions':4,'source_words':861,'source_bytes':3444,'root_segments':9,'published_global_words':8,'published_global_bytes':64} and a['independent_totals']==TOTALS
 report=read(BASE/'kernel_boot_initializer_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| BE-A'+str(j)+':' in report
 for p in [R.P+'_checks.json',R.P+'_audit.json']:assert sha(ROOT/p) in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_boot_initializer_execution_report.md' in read(BASE/p)
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 assert not any(a[k] for k in ['native_target_executed','hardware_PAC_executed','full_goal_complete']) and a['prior_continuous_startup_case_unchanged']
 print(json.dumps({'source_rebuilt':True,'source_queries_rebuilt':24,'complete_private_boot_rebuilt_and_replayed':True,'source_visits_per_execution':43400376,'mutations_rebuilt':2,'all_final_pages_rechecked':4967,'prior_continuous_state_unchanged':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9605 and len(after)==9613 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals']),('independent_replay_checks',a['independent_replay_totals'])]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==637 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':637,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':e,a=receipts();publication(e,a)
