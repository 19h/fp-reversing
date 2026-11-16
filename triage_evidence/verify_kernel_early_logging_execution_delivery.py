#!/usr/bin/env python3
"""Rebuild source/proof/formula receipts and verify compressed publication.
The producer retains full fresh replay and two original-word controls.
O(source, journal and RAM bytes); interval sorting and SMT search separate.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from audit_kernel_early_logging_contract import source_proofs
from replay_kernel_early_logging_execution import oracle,preservation,hydrate,publication_row
import recover_kernel_early_logging_execution as R
import audit_kernel_early_logging_execution as A
PREVIOUS='04d142b7f40da25418208855f5d12abf7b65795f'
BASELINE_SHA='738c2d648b29f720b94e06461de5b739f47f9d867c5b2f9e50b0a57535b8d474'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_early_logging_contract_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_early_logging_execution_report.md',*[('triage_evidence/'+name+'_kernel_early_logging_execution.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_early_logging_execution_delivery.py','triage_evidence/kernel_early_logging_execution_checks.json','triage_evidence/kernel_early_logging_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_early_logging_execution_checks.json','triage_evidence/kernel_early_logging_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
def receipts():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 assert a['generator_sha256']==sha(A.__file__) and a['probe_sha256']==sha(ROOT/'probe_kernel_early_logging_execution.py') and a['replay_sha256']==sha(ROOT/'replay_kernel_early_logging_execution.py') and a['checks_sha256']==sha(ROOT/(R.P+'_checks.json'))
 proofs,coverage=source_proofs(e);assert coverage==a['proof_coverage'] and len(proofs)==len(a['retained_source_proofs_rebuilt'])==5
 for p,q in zip(a['retained_source_proofs_rebuilt'],proofs):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(left,right))
 assert e['verified_counts']=={'functions':200,'words':16695,'bytes':66780,'prior_bodies_preserved':195,'added_functions':5,'new_mutable_regions':5,'new_mutable_bytes':131113}
 im=Image();assert im.k.read(0xfffffe0007f8b528,8)==bytes(8) and im.k.sha256==a['kernel_collection_sha256']==e['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(a['components'])==1;row=a['components'][0];assert publication_row(hydrate(row,im),im)==row and row['independent_oracle']==oracle(row,e) and a['prior_published_frontier_preservation']==preservation(row,im)
 t=a['independent_totals'];assert t['source_visits']==510723 and t['additional_journal_visits']==3909 and t['proved_block_transitions']==1 and t['contracted_original_words']==9 and t['character_callbacks']==47 and t['logging_calls_returned']==7 and t['changed_source_controls']==2 and t['callbacks_returned']==1029
 assert t['new_system_register_values']==t['new_callback_result_models']==t['call_frame_epochs']==t['native_target_executions']==0
 assert row['independent_replay']==a['independent_replay_totals'] and row['independent_replay']['source_visits_checked']==len(row['source_visits']) and len(row['API_models'])==3
 for c in a['negative_controls']:assert c['all_initial_fields_match'] and c['oracle_rejection'][0]=='early_logging_contract' and c['boundary']['pc']=='0xfffffe000c48fc98' and not c['full_control_journal_retained']
 report=read(BASE/'kernel_early_logging_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| LE-A'+str(j)+':' in report
 for p in [R.P+'_checks.json',R.P+'_audit.json']:assert sha(ROOT/p) in report
 assert a['conditional_early_logging_execution_contract_established'] and not any(a[k] for k in ['native_target_executed','native_console_emission_established','matched_FairPlay_transaction_established','full_goal_complete'])
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 print(json.dumps({'source_rebuilt':True,'retained_queries_rebuilt':5,'formulas_rebuilt':1,'producer_full_replay_visits':510723,'producer_mutation_controls':2,'prior_frontier_exact':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9573 and len(after)==9581 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals']),('independent_replay_checks',a['independent_replay_totals'])]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==633 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':633,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':e,a=receipts();publication(e,a)
