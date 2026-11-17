#!/usr/bin/env python3
"""Rebuild actual early-main pointer signing, proofs and publication custody.
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
import recover_kernel_main_pointer_signing as R
import audit_kernel_main_pointer_signing as A
PREVIOUS='df623ab36afaa38edef040e84c2154623c8f1e71'
BASELINE_SHA='16cee91c7f87098909ce3686949932d074a0d6ee138266d6f33f9c8f09a05a2d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_logging_handoff_report.md','kernel_initializer_pointer_signing_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_main_pointer_signing_report.md',*[('triage_evidence/'+name+'_kernel_main_pointer_signing.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_main_pointer_signing_delivery.py','triage_evidence/kernel_main_pointer_signing_checks.json','triage_evidence/kernel_main_pointer_signing_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_main_pointer_signing_checks.json','triage_evidence/kernel_main_pointer_signing_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
def receipts():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit();x,y=dict(a),dict(fresh)
 for key,n in [('source_proofs',9),('retained_signing_proofs',21),('retained_logging_proofs',5)]:
  old,new=x.pop(key),y.pop(key);assert len(old)==len(new)==n
  for p,q in zip(old,new):
   p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(left,right))
 assert x==y and a['independent_totals']['source_visits']==821831 and a['independent_totals']['inserted_original_helper_visits']==306644
 assert a['independent_totals']['pointer_stores']==6362 and a['independent_totals']['segment_calls']==1845
 assert a['independent_totals']['character_callbacks']==94 and a['independent_totals']['remaining_API_models']==2
 assert all(q['whole_walker_return_checkpoint_matches_positive'] for q in a['negative_source_controls'])
 report=read(BASE/'kernel_main_pointer_signing_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| MP-A'+str(j)+':' in report
 for p in [R.P+'_checks.json',R.P+'_audit.json']:assert sha(ROOT/p) in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_main_pointer_signing_report.md' in read(BASE/p)
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 assert not any(a[k] for k in ['native_target_executed','hardware_PAC_executed','matched_FairPlay_transaction_established','full_goal_complete'])
 print(json.dumps({'source_rebuilt':True,'new_source_queries_rebuilt':9,'retained_signing_queries_rebuilt':21,'retained_logging_queries_rebuilt':5,'continuous_main_case_rebuilt_and_replayed':True,'source_visits':821831,'mutations_rebuilt':2,'modeled_predecessor_preserved':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9621 and len(after)==9629 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals']),('independent_replay_checks',a['independent_replay_totals'])]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==639 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':639,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':e,a=receipts();publication(e,a)
