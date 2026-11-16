#!/usr/bin/env python3
"""Rebuild the finite lock report and check its explicit publication scope.
Linear source/journal/RAM work; interval sorting and SMT search separate.
"""
import contextlib,io,json
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_kernel_lock_bootstrap_execution as R
import audit_kernel_lock_bootstrap_execution as A
from replay_kernel_lock_bootstrap_execution import B

PREVIOUS='08cb9427aee14788c5b63ae26c06239ab2d58aff'
BASELINE_SHA='81a4df7aae1ffb306286eb3d3b01718b05a9c7b4c3636a1b41149a4d5b02bb0c'
CHECKS_SHA='7cff5ee38d8420d37223f05a841758feafa59279fce25f7321391a5518e26a29'
AUDIT_SHA='9093e22d92869a1bbb8be69f77e796dcfe57f23a6ef6754673a7f526ea32af75'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_timeout_execution_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_lock_bootstrap_execution_report.md',*[('triage_evidence/'+name+'_kernel_lock_bootstrap_execution.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_lock_bootstrap_execution_delivery.py','triage_evidence/kernel_lock_bootstrap_execution_checks.json','triage_evidence/kernel_lock_bootstrap_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_lock_bootstrap_execution_checks.json','triage_evidence/kernel_lock_bootstrap_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 assert len(a['source_proofs'])==len(fresh['source_proofs'])==5
 for old,new in zip(a['source_proofs'],fresh['source_proofs']):
  x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat';assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert {k:v for k,v in a.items() if k!='source_proofs'}=={k:v for k,v in fresh.items() if k!='source_proofs'},('audit_rebuild_fields',[k for k in a if k!='source_proofs' and a[k]!=fresh[k]])
 t=a['independent_totals'];assert t['components']==2 and t['source_visits']==965589 and t['lock_semantic_checks']==8896 and t['static_checks']==2750 and t['phase_three_callbacks_per_case']==627 and t['callbacks_returned_per_case']==1029 and t['new_callback_result_models']==t['call_frame_epochs']==t['native_target_executions']==0
 assert a['kernel_collection_sha256']==e['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe' and e['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['verified_counts']['captured_functions']==188 and e['verified_counts']['captured_words']==15533 and e['verified_counts']['captured_bytes']==62132
 im=Image();assert im.k.read(0xfffffe00070b0587,9)==b'longterm\0' and im.k.read(0xfffffe000ca87248,5)==b'lcks\0'
 for c in a['components']:
  assert B.B.publication_row(B.B.hydrate(c,im),im)==c and len(c['API_models'])==3 and len(c['callback_entries'])==len(c['callback_returns'])==1029 and 'epochs' not in c and c['source_word_mutated_to_NOP'] is None
  assert [r['phase_u32'] for r in c['callback_entries']]==[1]*392+[2]*10+[3]*627
  assert c['boundary']['pc']==hex(R.STOP) and c['boundary']['kind']=='before_original_post_lock_timeout_wait_queue_initializer_BL' and c['phase_three_callbacks_executed'] and not c['native_phase_three_completed']
  visited={v['pc'] for v in c['source_visits']};assert hex(R.FRONTIER) not in visited and '0xfffffe000c62a46c' not in visited and all(hex(x) not in visited for x in [0xfffffe000bceb394,0xfffffe000bd55878,0xfffffe000bd57a48])
 assert a['prior_published_checkpoint_preservation']['exact_match'] and a['prior_published_checkpoint_preservation']['known_original_page_hashes_exact_match']
 for c in a['negative_controls']:assert c['all_initial_fields_match'] and c['oracle_rejection'][0]=='lock_contract' and c['boundary']['pc']==hex(R.STOP) and not c['full_control_journal_retained']
 report=read(BASE/'kernel_lock_bootstrap_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| LK'+str(j)+' |' in report and '| LK-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'965589','8896','0xfffffe000c62d68c','0xfffffe000bd06270','0xfffffe000c639e3c','0xfffffe000bd64ea4']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_lock_bootstrap_execution_report.md' in read(BASE/p)
 for obj in [e,a]:hygiene(obj);nested_hygiene(obj)
 assert a['conditional_kernel_lock_bootstrap_execution_contract_established'] and not any(a[n] for n in ['native_target_executed','hardware_PAC_executed','matched_FairPlay_transaction_established','full_goal_complete'])
 print(json.dumps({'fresh_source_and_audit_match':True,'components_rebuilt':2,'source_queries_rebuilt':5,'source_mutations_rejected':2,'prior_published_boundary_preserved':True,'native_target_executed':False}),flush=True);return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new]);assert len(before)==9551 and len(after)==9559 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),('independent_checks',a['independent_totals']),('independent_replay_checks',a['independent_replay_totals']),('source_queries_unsat',5),('conditional_kernel_lock_bootstrap_execution_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==630 and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':630,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':e,a=receipts();publication(e,a)
