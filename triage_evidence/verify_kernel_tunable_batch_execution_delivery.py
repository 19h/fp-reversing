#!/usr/bin/env python3
"""Rebuild finite source/contracts/replay and verify owned publication.
O(owned bytes+source+formula DAG+journals+RAM) construction/space;
API timeline O(J log J), SMT search separate. No native target or IDB access.
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
import recover_kernel_tunable_batch_execution as R
import audit_kernel_tunable_batch_execution as A
from replay_kernel_tunable_batch_execution import hydrate,publication_row
from kernel_vm_mig_tools import Image

PREVIOUS='d8139a5d9000328fa251091977c9b8eda20ad962'
BASELINE_SHA='3a18b42d4669157c5a0d6d439fcf2f34b2bfb4bbc526c01c728d891d18e64e74'
CHECKS_SHA='64d81d258a9d33b11b067a168df96a0f7c7d9b393691e21ff448629059a521b0'
AUDIT_SHA='b5d76eafcca226e7db156a08598b5266b178f6f106394739eff322ac18788b1a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_environment_publication_report.md','kernel_platform_environment_execution_report.md','kernel_boot_option_execution_report.md','kernel_secure_dt_execution_report.md','kernel_cpu_topology_handoff_report.md','kernel_bootstrap_state_composition_report.md','kernel_vm_mig_report.md','kernel_startup_registry_abi_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_tunable_batch_execution_report.md',*[('triage_evidence/'+name+'_kernel_tunable_batch_execution.py') for name in ['recover','probe','replay','audit']], 'triage_evidence/verify_kernel_tunable_batch_execution_delivery.py','triage_evidence/kernel_tunable_batch_execution_checks.json','triage_evidence/kernel_tunable_batch_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_tunable_batch_execution_checks.json','triage_evidence/kernel_tunable_batch_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 176, 'captured_words': 13474, 'captured_bytes': 53896, 'matched_prior_functions': 156, 'phase_one_callback_targets': 16, 'option_descriptors': 237, 'per_CPU_pointer_arguments': 101, 'indexed_descriptors': 17, 'SFI_handler_bodies': 17, 'option_shapes': {'4,0,0': 110, '8,0,0': 44, '1,0,0': 4, '1,1,0': 67, '128,0,1': 1, '2,0,0': 8, '17,0,1': 1, '5,0,1': 1, '256,0,1': 1}, 'strings': 27, 'MachO_load_commands': 29, 'opaque_words_preserved': 5}
TOTALS={'source_queries_unsat': 14, 'retained_registry_queries_rebuilt': 14, 'proved_source_PCs': 104, 'proof_instruction_instances': 116, 'linked_edge_obligations': 102, 'components': 3, 'source_visits': 1105249, 'executed_source_PCs': 4176, 'changed_source_controls': 2, 'independent_semantic_checks': 16127, 'static_contracts': 1222, 'original_API_entries': 18535, 'original_API_returns': 18523, 'original_registry_callbacks_returned': 1104, 'registry_callbacks_returned_per_case': 368, 'registry_callback_entries_per_case': 369, 'mutable_region_count_per_case': 208, 'mutable_region_bytes_per_case': 142012, 'callback_output_and_final_global_bytes_compared': 439608, 'private_nonstack_bytes_checked': 3132672, 'call_frame_epochs': 0, 'new_callback_result_models': 0, 'native_target_executions': 0}
REPLAY={'source_visits_checked': 1105249, 'logical_PAC_steps_checked': 10272, 'writes_checked': 164114, 'write_bytes_checked': 1293802, 'logical_effects_checked': 14068, 'declared_API_models_checked': 10, 'reads_checked': 294487, 'read_bytes_checked': 1735009, 'whole_checkpoint_private_bytes_checked': 34603008, 'whole_checkpoint_image_bytes_checked': 1098240, 'whole_checkpoint_additional_image_bytes_checked': 86724, 'whole_checkpoint_registry_image_bytes_checked': 2725704, 'whole_checkpoint_phase_one_bytes_checked': 123336, 'callback_entries_checked': 1107, 'callback_output_bytes_checked': 13584, 'callback_returns_checked': 1104, 'checkpoint_eager_original_page_bytes_checked': 172032, 'final_boundaries_checked': 3, 'whole_private_bytes_checked': 3145728, 'whole_image_page_bytes_checked': 1798144, 'vector_registers_checked': 96, 'original_API_entries_and_returns_checked': 18523, 'unfinished_original_API_entries_checked': 12}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 # Assertion arguments are tuples in Python and arrays in the JSON receipt.
 # Compare the exact serialized representation without changing their values.
 for control in fresh['negative_controls']:control['oracle_rejection']=list(control['oracle_rejection'])
 for key in ['source_proofs','retained_source_proofs_rebuilt']:
  assert len(a[key])==len(fresh[key])==14
  for old,new in zip(a[key],fresh[key]):
   x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 excluded={'source_proofs','retained_source_proofs_rebuilt'}
 assert {k:v for k,v in a.items() if k not in excluded}=={k:v for k,v in fresh.items() if k not in excluded},('audit_rebuild_fields',[k for k in a if k not in excluded and a[k]!=fresh[k]])
 assert e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert a['prior_published_checkpoint_preservation']['exact_match'] and a['prior_published_checkpoint_preservation']['prior_audit_sha256']=='3bec297b43e93af8f51535729e74a4b97afcc305762daadc6780b0fb256fca1a'
 assert {o['selector_u32'] for o in e['indexed_descriptors']}==set(range(1,18))
 for o in e['indexed_descriptors']:
  handler=o['pointers'][0];assert handler['auth']==1 and handler['diversity']=='0xd507' and handler['address_diversity']==handler['key']==0
  assert all(p['auth']==0 for p in o['pointers'][1:])
 image=Image();assert sum('original_logical_page_sha256' in p for c in a['components'] for p in c['initial_image_pages'])==4
 for c,visits,models in zip(a['components'],[305828,479411,320010],[3,3,4]):
  assert publication_row(hydrate(c,image),image)==c
  assert len(c['source_visits'])==visits and len(c['API_models'])==models and c['source_word_mutated_to_NOP'] is None and 'epochs' not in c
  assert c['entry_PC']=='0xfffffe000c639a40' and len(c['initial_system'])==11 and len(c['final_image_globals'])==208
  assert len(c['callback_entries'])==369 and len(c['callback_returns'])==368 and c['boundary']['pc']==hex(R.STOP)
  assert len(c['original_API_entries'])==len(c['original_API_returns'])+len(c['unfinished_API_entry_indices']) and len(c['unfinished_API_entry_indices'])==4
  o=c['independent_oracle'];assert not o['formatter_output_executed'] and o['formatter_expected_text']=='9B65BD6E-027B-34D1-A22B-AC03DCCFFC84'
  assert o['completed_family_histogram'][hex(R.OPTION)]==237 and o['completed_family_histogram'][hex(R.ADJUST)]==87 and o['completed_family_histogram'][hex(R.INDEXED)]==17
 visited={v['pc'] for c in a['components'] for v in c['source_visits']};assert not visited&set(e['SFI_handler_targets']+e['SFI_shared_targets']+[hex(R.FORMAT),hex(R.B.INIT),hex(R.STOP)])
 for c in a['negative_controls']:assert c['all_initial_fields_match'] and not c['full_control_journal_retained'] and c['boundary']['pc']==hex(R.STOP)
 report=read(BASE/'kernel_tunable_batch_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| TB'+str(j)+' |' in report and '| TB-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'1105249','16127','1222','18535','18523','142012','0xfffffe000c630370','0xfffffe000c48ef98','0xfffffe000c62a46c']:assert item in report
 for path in CHANGED:
  if path.endswith('.md'):assert 'kernel_tunable_batch_execution_report.md' in read(BASE/path)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_tunable_batch_execution_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'source_queries_rebuilt':14,'retained_queries_rebuilt':14,'private_components_rebuilt':3,'independent_semantic_checks':16127,'static_contracts':1222,'changed_source_controls_rejected':2,'prior_published_boundary_preserved':True,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9526 and len(after)==9534 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),('source_queries_unsat',14),('retained_source_queries_rebuilt',14),('conditional_kernel_tunable_batch_execution_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==627 and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':627,'original_inputs_preserved':3,'analyst_paths_absent':True,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
