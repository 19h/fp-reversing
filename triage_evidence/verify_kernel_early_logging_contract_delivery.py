#!/usr/bin/env python3
"""Rebuild logging source/proofs/CPU controls and verify exact publication.
O(artifact bytes + query DAG + finite CPU cases); SMT search separate.
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
import recover_kernel_early_logging_contract as R
import audit_kernel_early_logging_contract as A
PREVIOUS='2dd73bd2fe7d28e3c9fd6ee45610d20662c42fa4'
BASELINE_SHA='bdf284d1d04b342c746967bbb4e40fc1f19750a448193927dff83b473e34c13d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_longterm_bootstrap_execution_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_early_logging_contract_report.md',*[('triage_evidence/'+name+'_kernel_early_logging_contract.py') for name in ['recover','audit']],'triage_evidence/verify_kernel_early_logging_contract_delivery.py','triage_evidence/kernel_early_logging_contract_checks.json','triage_evidence/kernel_early_logging_contract_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_early_logging_contract_checks.json','triage_evidence/kernel_early_logging_contract_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
def receipts():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.build()
 x,y=dict(a),dict(fresh);old,new=x.pop('source_proofs'),y.pop('source_proofs');assert x==y
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(left,right))
 assert len(old)==len(new)==5 and a['independent_totals']=={'source_queries_unsat':5,'proof_instruction_instances':27,'proved_source_PCs':18,'linked_edges':22,'CPU_source_cut_cases':96,'CPU_source_visits':864,'rejected_NOP_controls':2,'continuous_bootstrap_visits_added':0,'native_target_executions':0,'new_system_register_values':0}
 assert e['verified_counts']=={'functions':7,'words':1752,'bytes':7008,'prior_bodies_preserved':2,'records':9,'pointer_slots':4}
 report=read(BASE/'kernel_early_logging_contract_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| EL-A'+str(j)+':' in report
 for p in [R.P+'_checks.json',R.P+'_audit.json']:assert sha(ROOT/p) in report
 assert e['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe' and e['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 print(json.dumps({'source_rebuilt':True,'source_queries_rebuilt':5,'fresh_CPU_source_cut_cases':96,'NOP_controls_rebuilt':2,'continuous_bootstrap_advanced':False}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9567 and len(after)==9573 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals'])]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==632 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':632,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':e,a=receipts();publication(e,a)
