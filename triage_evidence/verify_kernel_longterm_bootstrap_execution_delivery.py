#!/usr/bin/env python3
"""Verify timer source/formula receipts and explicit publication scope.
The producer runs fresh CPU replay and mutations; delivery verifies immutable
receipts, rederives source obligations/formulas and checks archive publication.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_kernel_longterm_bootstrap_execution as R
import audit_kernel_longterm_bootstrap_execution as A
from replay_kernel_longterm_bootstrap_execution import oracle,B

PREVIOUS='604c755ed8f8ab0ec1adac742a5062acfdb2bc83'
BASELINE_SHA='547d7d1afb924205a24fcbc893e0e1abba06ac2a4ac0e5a7cc6ea0888c3ecb01'
CHECKS_SHA='785c05b0bdfa098e792e8c1c6e56579a0304b54c3857b76857ff37713ea3f5e7'
AUDIT_SHA='be5fde2e0f53519f66b2a76faeede082e0072f932a4a94956469933669aea379'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_lock_bootstrap_execution_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_longterm_bootstrap_execution_report.md',*[('triage_evidence/'+name+'_kernel_longterm_bootstrap_execution.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_longterm_bootstrap_execution_delivery.py','triage_evidence/kernel_longterm_bootstrap_execution_checks.json','triage_evidence/kernel_longterm_bootstrap_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_longterm_bootstrap_execution_checks.json','triage_evidence/kernel_longterm_bootstrap_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 assert a['generator_sha256']==sha(A.__file__) and a['probe_sha256']==sha(ROOT/'probe_kernel_longterm_bootstrap_execution.py') and a['replay_sha256']==sha(ROOT/'replay_kernel_longterm_bootstrap_execution.py') and a['checks_sha256']==CHECKS_SHA
 fresh,coverage=A.source_proofs(e);assert a['proof_coverage']==coverage and len(fresh)==len(a['source_proofs'])==5 and a['integer_reciprocal_bounds']==A.reciprocal_bounds()
 for old,new in zip(a['source_proofs'],fresh):
  x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat';assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 t=a['independent_totals'];assert t['components']==3 and t['completed_timer_initializers']==2 and t['logging_system_register_frontiers']==1 and t['source_queries_unsat']==5 and t['integer_reciprocal_bounds']==4 and t['callbacks_returned_per_case']==1029 and t['changed_source_controls']==2
 assert t['new_system_register_values']==t['new_callback_result_models']==t['call_frame_epochs']==t['native_target_executions']==0
 assert e['verified_counts']=={'captured_functions':195,'captured_words':16244,'captured_bytes':64976,'matched_prior_functions':188,'added_functions':7,'timer_initializer_words':311,'records':4,'strings':2}
 assert a['kernel_collection_sha256']==e['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe' and e['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 im=Image()
 for index,c in enumerate(a['components']):
  assert B.B.B.publication_row(B.B.B.hydrate(c,im),im)==c and c['independent_oracle']==oracle(c,e) and len(c['API_models'])==3 and len(c['callback_entries'])==len(c['callback_returns'])==1029 and 'epochs' not in c and c['source_word_mutated_to_NOP'] is None
  assert [r['phase_u32'] for r in c['callback_entries']]==[1]*392+[2]*10+[3]*627 and c['independent_replay']['source_visits_checked']==len(c['source_visits'])
  visited={v['pc'] for v in c['source_visits']};assert hex(R.CPU) not in visited and '0xfffffe000c62a46c' not in visited and '0xfffffe000c48faf4' not in visited
  if index<2:assert c['longterm_initializer_returned'] and c['boundary']['pc']==hex(R.STOP)
  else:assert not c['longterm_initializer_returned'] and c['boundary']['pc']=='0xfffffe000c48faf4' and c['logging_system_register_frontier']['register']=='daif' and c['original_printf_calls'][0]['u64_vararg_at_SP']==1
 assert a['prior_published_checkpoint_preservation']==A.preservation(a['components'][0],im)
 for c in a['negative_controls']:assert c['all_initial_fields_match'] and c['oracle_rejection'][0]=='longterm_contract' and c['boundary']['pc']==hex(R.STOP) and not c['full_control_journal_retained']
 report=read(BASE/'kernel_longterm_bootstrap_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| LT'+str(j)+' |' in report and '| LT-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bd65030','0xfffffe000bd650bc','0xfffffe000c48faf4','DAIF','233136191799']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_longterm_bootstrap_execution_report.md' in read(BASE/p)
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 assert a['conditional_kernel_longterm_bootstrap_execution_contract_established'] and not any(a[n] for n in ['native_target_executed','hardware_PAC_executed','matched_FairPlay_transaction_established','full_goal_complete'])
 print(json.dumps({'source_and_formula_receipts_match':True,'source_queries_rebuilt':5,'reciprocal_bounds_rebuilt':4,'case_formulas_rebuilt':3,'producer_fresh_replays_retained':3,'producer_mutation_controls_retained':2,'prior_published_boundary_preserved':True,'native_target_executed':False}),flush=True);return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9559 and len(after)==9567 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals']),('independent_replay_checks',a['independent_replay_totals']),('source_queries_unsat',5),('integer_reciprocal_bounds',4),('conditional_kernel_longterm_bootstrap_execution_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==631 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':631,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':e,a=receipts();publication(e,a)
