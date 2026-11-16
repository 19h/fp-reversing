#!/usr/bin/env python3
"""Rebuild finite timeout contracts and verify owned publication.
Linear source/journal/RAM construction; timeline O(J log J), SMT separate.
"""
import contextlib,io,json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from kernel_vm_mig_tools import Image
import recover_kernel_timeout_execution as R
import audit_kernel_timeout_execution as A
from replay_kernel_timeout_execution import B

PREVIOUS='b9122ec1662539e93292767bd03a7ae56a170b1a'
BASELINE_SHA='d35b80699a088c9e3ac59c6f0310913b0dce990a1714a6dc45556108de761d81'
CHECKS_SHA='15e506a970376a31855eac50f79e3734b80dd509e33908f008d0b20b57c5926d'
AUDIT_SHA='aa9e723c2dbd885fd59a3712fcda0f052dcb519742b1d437ab2abc3ae80872de'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_environment_publication_report.md','kernel_platform_environment_execution_report.md','kernel_boot_option_execution_report.md','kernel_secure_dt_execution_report.md','kernel_cpu_topology_handoff_report.md','kernel_bootstrap_state_composition_report.md','kernel_vm_mig_report.md','kernel_startup_registry_abi_report.md','kernel_tunable_batch_execution_report.md','kernel_uuid_formatter_execution_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_timeout_execution_report.md',*[('triage_evidence/'+name+'_kernel_timeout_execution.py') for name in ['recover','probe','replay','audit']],'triage_evidence/verify_kernel_timeout_execution_delivery.py','triage_evidence/kernel_timeout_execution_checks.json','triage_evidence/kernel_timeout_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_timeout_execution_checks.json','triage_evidence/kernel_timeout_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 184, 'captured_words': 14962, 'captured_bytes': 59848, 'matched_prior_functions': 179, 'added_functions': 5, 'timeout_registrations': 10, 'timeout_descriptors': 9, 'strings': 11, 'shared_timeout_words': 495, 'opaque_words_preserved': 5}
TOTALS={'source_queries_unsat': 12, 'retained_formatter_queries_rebuilt': 16, 'proved_source_PCs': 42, 'proof_instruction_instances': 42, 'linked_edge_obligations': 30, 'components': 6, 'source_visits': 3098687, 'executed_source_PCs': 5158, 'changed_source_controls': 2, 'independent_semantic_checks': 59467, 'static_contracts': 216, 'original_API_entries': 42121, 'original_API_returns': 42109, 'original_registry_callbacks_returned': 2412, 'callbacks_returned_per_case': 402, 'phase_two_callbacks_per_case': 10, 'timeout_descriptor_publications_per_case': 9, 'helper_calls_checked': 736, 'mutable_region_count_per_case': 216, 'mutable_region_bytes_per_case': 142085, 'callback_output_and_final_global_bytes_compared': 853716, 'private_nonstack_bytes_checked': 6265344, 'call_frame_epochs': 0, 'new_callback_result_models': 0, 'native_target_executions': 0}
REPLAY={'source_visits_checked': 3098687, 'logical_PAC_steps_checked': 30680, 'writes_checked': 364861, 'write_bytes_checked': 2829833, 'logical_effects_checked': 28935, 'declared_API_models_checked': 18, 'reads_checked': 748304, 'read_bytes_checked': 3854812, 'whole_checkpoint_private_bytes_checked': 88080384, 'whole_checkpoint_image_bytes_checked': 2795520, 'whole_checkpoint_additional_image_bytes_checked': 231264, 'whole_checkpoint_registry_image_bytes_checked': 7268544, 'whole_checkpoint_phase_one_bytes_checked': 328896, 'whole_checkpoint_timeout_bytes_checked': 5256, 'callback_entries_checked': 2412, 'callback_output_bytes_checked': 29766, 'callback_returns_checked': 2412, 'checkpoint_eager_original_page_bytes_checked': 675840, 'formatter_checkpoint_eager_original_page_bytes_checked': 311296, 'phase_two_eager_original_page_bytes_checked': 122880, 'final_boundaries_checked': 6, 'whole_private_bytes_checked': 6291456, 'whole_image_page_bytes_checked': 3936256, 'vector_registers_checked': 192, 'original_API_entries_and_returns_checked': 42109, 'unfinished_original_API_entries_checked': 12}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 for key,count in [('source_proofs',12),('retained_source_proofs_rebuilt',16)]:
  assert len(a[key])==len(fresh[key])==count
  for old,new in zip(a[key],fresh[key]):
   x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 excluded={'source_proofs','retained_source_proofs_rebuilt'}
 assert {k:v for k,v in a.items() if k not in excluded}=={k:v for k,v in fresh.items() if k not in excluded},('audit_rebuild_fields',[k for k in a if k not in excluded and a[k]!=fresh[k]])
 assert e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 preservation=a['prior_published_checkpoint_preservation'];assert preservation['exact_match'] and preservation['known_original_page_hashes_exact_match'] and preservation['prior_audit_sha256']=='3892702cfa3e18cb80d59df513986d50a0d1f7cab5b2258b86ffcc2cdd885ef7'
 image=Image()
 for address,text in [(0xfffffe000704e1fa,'machine.c'),(0xfffffe000704e3df,'machine_timeout_init_with_suffix')]:assert image.k.read(address,len(text)+1)==text.encode()+b'\0'
 assert len(e['timeout_registrations'])==10 and len(e['timeout_descriptors'])==9 and all(d['filter_pointer'] is None and d['divisor_u64']==0 for d in e['timeout_descriptors'])
 assert len(a['components'])==6
 for c in a['components']:
  assert B.publication_row(B.hydrate(c,image),image)==c and c['source_word_mutated_to_NOP'] is None and 'epochs' not in c
  assert len(c['API_models'])==3 and c['entry_PC']=='0xfffffe000c639a40' and len(c['initial_system'])==11 and len(c['unfinished_API_entry_indices'])==2
  assert len(c['callback_entries'])==len(c['callback_returns'])==402 and [r['phase_u32'] for r in c['callback_entries']]==[1]*392+[2]*10
  assert c['phase_three_dispatch_boundary']=={'cursor':'0xfffffe000cbec780','phase_u32':3,'rank_u32':0,'target':'0xfffffe000c62d618','argument':'0x0'} and c['boundary']['pc']==hex(R.DISPATCH) and c['boundary']['kind']=='before_first_phase_three_callback_BLRAA'
  assert len(c['original_API_entries'])==len(c['original_API_returns'])+2 and c['phase_two_entry_checkpoint']['registers31'][0]=='0xfffffe000ca94260'
  assert c['independent_oracle']['produced_timebase_frequency_word']==24000000 and len(c['independent_oracle']['timeout_results'])==10 and c['independent_oracle']['phase_three_callback_invoked'] is False
  assert c['independent_oracle']['timeout_results'][-1]['max_wfe_value_published'] is False
  for name in R.TRUE:assert c[name] is True
 first=[c['independent_oracle']['timeout_results'][0]['published_u64'] for c in a['components']];assert first==[1440000,144,1848000,336000,1440000,(1<<64)-1]
 for r in a['components'][4]['independent_oracle']['timeout_results'][1:9]:assert r['disabled_by_watchdog'] and r['published_u64']==0
 visited={v['pc'] for c in a['components'] for v in c['source_visits']};assert '0xfffffe000c62d618' not in visited and '0xfffffe000c62a46c' not in visited
 for c in a['negative_controls']:assert c['all_initial_fields_match'] and not c['full_control_journal_retained'] and c['control_journal_rebuilt_by_delivery_verifier'] and c['boundary']['pc']==hex(R.DISPATCH) and c['oracle_rejection']
 report=read(BASE/'kernel_timeout_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| TO'+str(j)+' |' in report and '| TO-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'machine_timeout_init_with_suffix','0xfffffe000bd10fbc','0xfffffe000bd10cf0','0xfffffe000cbec780',str(TOTALS['source_visits']),str(TOTALS['independent_semantic_checks'])]:assert item in report
 for path in CHANGED:
  if path.endswith('.md'):assert 'kernel_timeout_execution_report.md' in read(BASE/path)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_timeout_execution_contract_established']
  for name in R.FALSE:assert obj[name] is False
 for name in R.TRUE:assert a[name] is True
 print(json.dumps({'fresh_source_and_audit_match':True,'source_queries_rebuilt':12,'retained_queries_rebuilt':16,'components_rebuilt':6,'diagnostic_strings_checked':2,'changed_source_controls_rejected':2,'prior_published_boundary_preserved':True,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9543 and len(after)==9551 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),('source_queries_unsat',12),('retained_source_queries_rebuilt',16),('conditional_kernel_timeout_execution_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==629 and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':629,'original_inputs_preserved':3,'analyst_paths_absent':True,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
