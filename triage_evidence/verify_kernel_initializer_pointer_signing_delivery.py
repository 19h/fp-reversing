#!/usr/bin/env python3
"""Rebuild module-pointer proofs/CPU controls and verify publication scope.
Linear artifact/source/journal/RAM work; SMT search separate.
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
import recover_kernel_initializer_pointer_signing as R
import audit_kernel_initializer_pointer_signing as A
PREVIOUS='ae45d42d1f2ace8c0f754316edf120d9fb481963'
BASELINE_SHA='1ab689a5cc712f18d66eadab9ace57a124dff9ce5b9297f0e762fc2a44045d5b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_collection_header_publication_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_initializer_pointer_signing_report.md',*[('triage_evidence/'+name+'_kernel_initializer_pointer_signing.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_initializer_pointer_signing_delivery.py','triage_evidence/kernel_initializer_pointer_signing_checks.json','triage_evidence/kernel_initializer_pointer_signing_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_initializer_pointer_signing_checks.json','triage_evidence/kernel_initializer_pointer_signing_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
def receipts():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit();x,y=dict(a),dict(fresh);old,new=x.pop('source_proofs'),y.pop('source_proofs');assert x==y
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(left,right))
 assert len(old)==len(new)==21 and e['verified_counts']=={'functions':2,'source_words':314,'source_bytes':1256,'headers':363,'fileset_images':362,'pointer_tables':674,'pointer_slots':6362,'pointer_bytes':50896,'fairplay_tables':2,'fairplay_pointer_slots':6,'fairplay_callback_source_words':75,'fairplay_class_initializers':3}
 assert a['independent_totals']=={'components':29,'source_visits':311801,'source_queries_unsat':21,'proof_instruction_instances':159,'proof_distinct_PCs':159,'semantic_assertions':14004,'original_collection_segment_calls':1845,'original_collection_pointer_stores':6362,'fairplay_pointer_stores':6,'changed_source_controls':3,'module_callback_invocations':0,'native_target_executions':0,'continuous_startup_visits_added':0}
 report=read(BASE/'kernel_initializer_pointer_signing_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| IP-A'+str(j)+':' in report
 for p in [R.P+'_checks.json',R.P+'_audit.json']:assert sha(ROOT/p) in report
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 print(json.dumps({'source_rebuilt':True,'source_queries_rebuilt':21,'CPU_cases_replayed':29,'mutations_rebuilt':3,'prior_continuous_state_unchanged':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9589 and len(after)==9597 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals']),('independent_replay_checks',a['independent_replay_totals'])]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==635 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':635,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':e,a=receipts();publication(e,a)
