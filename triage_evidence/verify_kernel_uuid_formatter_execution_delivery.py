#!/usr/bin/env python3
"""Rebuild finite formatter/startup contracts and verify owned publication.
Linear owned/source/formula/journal/RAM construction; timeline O(J log J).
SMT search separate. No native target execution or IDB access.
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
import recover_kernel_uuid_formatter_execution as R
import audit_kernel_uuid_formatter_execution as A
from replay_kernel_uuid_formatter_execution import B

PREVIOUS='a909ff6e7f17f53ac6f8a4b2b35f07b9434b68e0'
BASELINE_SHA='4917cf778838f48bf8a18c0cffd7b2924e5420247d45768141b79d12bb7076ac'
CHECKS_SHA='6d4284002d8bb69ffdeaac36a5588470302f2dac59aa5b5eccef5641273320b4'
AUDIT_SHA='3892702cfa3e18cb80d59df513986d50a0d1f7cab5b2258b86ffcc2cdd885ef7'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_environment_publication_report.md','kernel_platform_environment_execution_report.md','kernel_boot_option_execution_report.md','kernel_secure_dt_execution_report.md','kernel_cpu_topology_handoff_report.md','kernel_bootstrap_state_composition_report.md','kernel_vm_mig_report.md','kernel_startup_registry_abi_report.md','kernel_tunable_batch_execution_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_uuid_formatter_execution_report.md',*[('triage_evidence/'+name+'_kernel_uuid_formatter_execution.py') for name in ['recover','probe','replay','audit']],'triage_evidence/probe_kernel_uuid_formatter_cases.py','triage_evidence/verify_kernel_uuid_formatter_execution_delivery.py','triage_evidence/kernel_uuid_formatter_execution_checks.json','triage_evidence/kernel_uuid_formatter_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_uuid_formatter_execution_checks.json','triage_evidence/kernel_uuid_formatter_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 179, 'captured_words': 14369, 'captured_bytes': 57476, 'matched_prior_functions': 176, 'added_functions': 3, 'formatter_wrapper_words': 25, 'output_callback_words': 12, 'format_engine_words': 858, 'authenticated_engine_call_sites': 24, 'conversion_dispatch_slots': 121, 'conversion_dispatch_targets': 18, 'per_CPU_object_descriptors': 4, 'per_CPU_object_registrations': 8, 'opaque_words_preserved': 5}
TOTALS={'source_queries_unsat': 16, 'retained_batch_queries_rebuilt': 14, 'proved_source_PCs': 62, 'proof_instruction_instances': 65, 'linked_edge_obligations': 49, 'main_components': 4, 'direct_formatter_components': 21, 'source_visits': 1640960, 'main_source_visits': 1570532, 'direct_source_visits': 70428, 'executed_source_PCs': 4584, 'changed_source_controls': 2, 'main_semantic_checks': 25348, 'direct_formatter_checks': 2826, 'static_contracts': 318, 'original_registry_callbacks_returned': 1568, 'phase_one_callbacks_returned_per_case': 392, 'formatted_results': 25, 'formatter_byte_output_calls': 900, 'main_API_entries': 24995, 'main_API_returns': 24987, 'direct_API_entries_and_returns': 798, 'direct_nonstack_bytes_checked': 21928704, 'direct_guarded_output_bytes_checked': 2688, 'main_callback_output_and_final_global_bytes_compared': 568976, 'main_nonstack_private_bytes_checked': 4176896, 'call_frame_epochs': 0, 'new_callback_result_models': 0, 'native_target_executions': 0}
REPLAY={'source_visits_checked': 1640960, 'logical_PAC_steps_checked': 14592, 'writes_checked': 228296, 'write_bytes_checked': 1786375, 'logical_effects_checked': 19856, 'declared_API_models_checked': 13, 'reads_checked': 415857, 'read_bytes_checked': 2371290, 'whole_checkpoint_private_bytes_checked': 54525952, 'whole_checkpoint_image_bytes_checked': 1730560, 'whole_checkpoint_additional_image_bytes_checked': 141328, 'whole_checkpoint_registry_image_bytes_checked': 4441888, 'whole_checkpoint_phase_one_bytes_checked': 200992, 'callback_entries_checked': 1568, 'callback_output_bytes_checked': 19040, 'callback_returns_checked': 1568, 'checkpoint_eager_original_page_bytes_checked': 356352, 'formatter_checkpoint_eager_original_page_bytes_checked': 122880, 'final_boundaries_checked': 25, 'whole_private_bytes_checked': 26214400, 'whole_image_page_bytes_checked': 3043328, 'vector_registers_checked': 800, 'original_API_entries_and_returns_checked': 25785, 'unfinished_original_API_entries_checked': 8}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 for key,count in [('source_proofs',16),('retained_source_proofs_rebuilt',14)]:
  assert len(a[key])==len(fresh[key])==count
  for old,new in zip(a[key],fresh[key]):
   x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 excluded={'source_proofs','retained_source_proofs_rebuilt'}
 assert {k:v for k,v in a.items() if k not in excluded}=={k:v for k,v in fresh.items() if k not in excluded},('audit_rebuild_fields',[k for k in a if k not in excluded and a[k]!=fresh[k]])
 assert e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 preservation=a['prior_published_checkpoint_preservation'];assert preservation['exact_match'] and preservation['prior_audit_sha256']=='b5d76eafcca226e7db156a08598b5266b178f6f106394739eff322ac18788b1a'
 assert [f['start'] for f in e['functions'][-3:]]==[hex(R.FORMAT),hex(R.EMIT),hex(R.ENGINE)]
 assert {r['phase_u32'] for r in e['per_CPU_object_registrations']}=={1,7} and all(r['rank_u32']==0xffffffff for r in e['per_CPU_object_registrations'])
 for obj in e['per_CPU_objects']:
  rows=[r for r in e['per_CPU_object_registrations'] if r['object_address']==obj['address']];assert len(rows)==2 and {r['phase_u32'] for r in rows}=={1,7}
 assert len(e['conversion_dispatch']['entries'])==121 and len(bytes.fromhex(e['digit_table']['bytes_hex']))==33
 assert e['optional_capability_record']['callback_pointer'] is None
 image=Image();all_rows=a['components']+a['direct_components'];assert sum('original_logical_page_sha256' in p for c in all_rows for p in c['initial_image_pages'])==6
 for c in all_rows:
  assert B.publication_row(B.hydrate(c,image),image)==c and c['source_word_mutated_to_NOP'] is None and 'epochs' not in c
  assert len(c['original_API_entries'])==len(c['original_API_returns'])+len(c['unfinished_API_entry_indices'])
  assert c['independent_oracle']['formatter_contracts']['formats'][0]['attempted_bytes']==36
 for c,visits,models in zip(a['components'],[310947,485766,325129,448690],[3,3,4,3]):
  assert len(c['source_visits'])==visits and len(c['API_models'])==models and c['entry_PC']=='0xfffffe000c639a40'
  assert len(c['initial_system'])==11 and len(c['final_image_globals'])==208 and len(c['callback_entries'])==len(c['callback_returns'])==392
  assert c['boundary']['pc']==hex(R.PHASE2_CALL) and len(c['unfinished_API_entry_indices'])==2
  assert c['formatter_return_checkpoint']['registers31'][0]=='0x24' and c['formatter_call_boundary']['PC']=='0xfffffe000c48ef98'
  assert c['phase_two_dispatch_boundary']=={'cursor':'0xfffffe000cbec690','phase_u32':2,'rank_u32':0,'target':'0xfffffe000bd12f7c','argument':'0xfffffe000ca94260'}
  for name in R.TRUE:assert c[name] is True
  f=c['independent_oracle']['formatter_contracts']['formats'][0];assert f['expected_text']=='9B65BD6E-027B-34D1-A22B-AC03DCCFFC84' and f['stored_character_bytes']==36 and f['capacity_bytes']==37 and f['NUL_stored']
 assert len(a['direct_components'])==21
 for c in a['direct_components']:
  n=c['configuration']['capacity_bytes'];assert not c['API_models'] and not c['unfinished_API_entry_indices'] and len(c['original_API_entries'])==38
  assert c['boundary']['kind']=='original_formatter_returned' and c['boundary']['registers31'][0]=='0x24' and c['boundary']['SP']==c['entry_SP']
  f=c['independent_oracle']['formatter_contracts']['formats'][0];assert f['capacity_bytes']==n and f['stored_character_bytes']==min(36,max(0,n-1)) and f['NUL_stored']==bool(n)
  if n==0:assert f['destination']=='0x0' and all(int(r['address'],16)>=4096 for r in c['source_reads']+c['source_writes'])
 assert {c['configuration']['capacity_bytes'] for c in a['direct_components']}=={0,1,2,17,36,37,38}
 visited={v['pc'] for c in all_rows for v in c['source_visits']};assert '0xfffffe000bd12f7c' not in visited and '0xfffffe000c62a46c' not in visited
 assert all(c['phase_u32']==1 for row in a['components'] for c in row['callback_entries'])
 for c in a['negative_controls']:assert c['all_initial_fields_match'] and not c['full_control_journal_retained'] and c['control_journal_rebuilt_by_delivery_verifier'] and c['oracle_rejection']
 report=read(BASE/'kernel_uuid_formatter_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| UF'+str(j)+' |' in report and '| UF-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'1640960','25348','318','70428','142012','0xfffffe000c630370','0xfffffe000c300430','0xfffffe000c300404']:assert item in report
 for path in CHANGED:
  if path.endswith('.md'):assert 'kernel_uuid_formatter_execution_report.md' in read(BASE/path)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_uuid_formatter_execution_contract_established']
  for name in R.FALSE:assert obj[name] is False
 for name in R.TRUE:assert a[name] is True
 print(json.dumps({'fresh_source_and_audit_match':True,'source_queries_rebuilt':16,'retained_queries_rebuilt':14,'main_components_rebuilt':4,'direct_components_rebuilt':21,'main_semantic_checks':25348,'direct_formatter_checks':2826,'static_contracts':318,'changed_source_controls_rejected':2,'prior_published_boundary_preserved':True,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9534 and len(after)==9543 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),('source_queries_unsat',16),('retained_source_queries_rebuilt',14),('conditional_kernel_uuid_formatter_execution_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==628 and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':628,'original_inputs_preserved':3,'analyst_paths_absent':True,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
