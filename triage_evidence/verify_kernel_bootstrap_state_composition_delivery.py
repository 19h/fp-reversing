#!/usr/bin/env python3
"""Rebuild source, nonvacuous proofs, private cases and exact owned publication.
O(owned bytes+source+formula DAG+journals+RAM) construction/space; SMT search
separate. No native target, IDB or history mutation.
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
import recover_kernel_bootstrap_state_composition as R
import audit_kernel_bootstrap_state_composition as A

PREVIOUS='8778311aa4bf2df952011b7801e1f0ca0af3eb63'
BASELINE_SHA='24613cfddbc7a5de87ad60d86a23e57f492d393fc7dcf1b02808a4ab632b0d4e'
CHECKS_SHA='69a2cd26f90adf9b35c6a048772d5e36e66e4175c4ab6c041c11e0c3cdc62f4a'
AUDIT_SHA='b8a611019e85f0a0aa225907fadb7f52e6e4aee481f1b36bd326c9d51db359cf'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_environment_publication_report.md','kernel_platform_environment_execution_report.md','kernel_boot_option_execution_report.md','kernel_secure_dt_execution_report.md','kernel_cpu_topology_handoff_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_bootstrap_state_composition_report.md',*[('triage_evidence/'+name+'_kernel_bootstrap_state_composition.py') for name in ['recover','probe','replay','audit']], 'triage_evidence/verify_kernel_bootstrap_state_composition_delivery.py','triage_evidence/kernel_bootstrap_state_composition_checks.json','triage_evidence/kernel_bootstrap_state_composition_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_bootstrap_state_composition_checks.json','triage_evidence/kernel_bootstrap_state_composition_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':31,'captured_words':4265,'captured_bytes':17060,'matched_prior_functions':31,'captured_strings':60,'literal_blocks':4,'initialized_data_blocks':7,'pointer_fixups':3,'opaque_words_preserved':5}
TOTALS={'source_composition_queries_unsat':11,'retained_source_queries_rebuilt':54,'proved_composition_source_PCs':60,'composition_instruction_instances':70,'composition_linked_edge_obligations':59,'components':9,'source_visits':315563,'executed_source_PCs':2439,'changed_source_controls':5,'independent_semantic_checks':12302,'completed_admitted_CPU_records':26,'source_enumeration_returns':6,'source_post_helper_returns':5,'source_thread_setups':5,'preserved_prior_zero_page_failures':1,'call_frame_epochs':0,'generic_initializer_calls':0,'selector0e_declared_returns':26,'original_API_entries':5557,'original_API_returns':5553,'whole_mutable_checkpoint_bytes_checked':729840,'private_nonstack_bytes_checked':9398016,'copy_contract_destination_bytes_checked':26519}
REPLAY={'source_visits_checked':315563,'logical_PAC_steps_checked':3637,'writes_checked':24858,'write_bytes_checked':188456,'logical_effects_checked':209,'declared_API_models_checked':44,'reads_checked':60471,'read_bytes_checked':275341,'whole_checkpoint_private_bytes_checked':39845888,'whole_checkpoint_image_bytes_checked':1264640,'whole_checkpoint_additional_image_bytes_checked':64240,'final_boundaries_checked':9,'whole_private_bytes_checked':9437184,'whole_image_page_bytes_checked':1462272,'vector_registers_checked':288,'original_API_entries_and_returns_checked':5553,'unfinished_original_API_entries_checked':4}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 for key,count in [('source_proofs',11),('retained_source_proofs_rebuilt',54)]:
  old_queries,new_queries=a[key],fresh[key];assert len(old_queries)==len(new_queries)==count
  for old,new in zip(old_queries,new_queries):
   x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 excluded={'source_proofs','retained_source_proofs_rebuilt'}
 assert {k:v for k,v in a.items() if k not in excluded}=={k:v for k,v in fresh.items() if k not in excluded}
 assert e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for addr in R.ADDITIONS:assert e['exact_symbols'][hex(addr)]==[]
 assert [int(p['target'],16) for p in e['pointer_fixups']]==[R.K.ARRAY,R.K.CLUSTERS,R.K.SLOT]
 data={d['address']:d for d in e['initialized_data']};page=bytes.fromhex(data['0xfffffe0007ef8000']['logical_hex']);assert page[0xe98:0xe9c]==bytes.fromhex('02000000')
 forbidden={i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']};visited={v['pc'] for c in a['components'] for v in c['source_visits']};assert not forbidden&visited and hex(R.B.E.GENERIC) not in visited and hex(R.T.WRAPPER) not in visited
 coverage={c['start']:c for c in a['executed_function_coverage']}
 for addr,captured,executed in [(R.K.ENUM,969,588),(R.K.SCALAR,64,33),(R.K.SETTER,13,13),(R.T.POST,34,34),(R.T.WRAPPER,15,0)]:assert coverage[hex(addr)]=={'start':hex(addr),'captured_words':captured,'executed_unique_PCs':executed}
 preservation=a['prior_published_checkpoint_preservation']
 for flag in ['exact_match','additional_logical_system_inputs_declared','paired_initial_image_difference_is_only_original_topology_page','paired_pre_enumeration_source_and_registers_and_private_RAM_identical','additional_demand_mapped_pages_match_original_logical_image']:assert preservation[flag]
 for c in a['components']:
  assert c['entry_PC']==hex(R.B.E.MAIN) and 'epochs' not in c and c['source_word_mutated_to_NOP'] is None
  assert c['initial_vectors']==['0x0']*32 and len(c['final_vectors'])==32 and len(c['initial_system'])==10
  assert all(int(m['pc'],16) in A.CPU.B.LEAVES or int(m['pc'],16)==R.T.WRAPPER for m in c['API_models'])
  assert c['original_platform_return']['PC']=='0xfffffe000c639b9c' and c['pre_enumeration_checkpoint']['PC']=='0xfffffe000c639cb8' and len(c['final_image_globals'])==14
  assert len(c['original_API_entries'])==len(c['original_API_returns'])+len(c['unfinished_API_entry_indices'])
 byname={c['configuration']['label']:c for c in a['components']}
 assert byname['prior_zero_page_stops_before_null_record_store']['boundary']['pc']=='0xfffffe000be83324'
 assert byname['initialized_page_default_thread']['independent_oracle']['post_helper_control']==2
 assert byname['sixteen_CPUs_running_last']['independent_oracle']['selected_boot_ordinal']==15
 assert byname['post_helper_control4_diagnostic']['boundary']['pc']==hex(R.K.PANIC)
 report=read(BASE/'kernel_bootstrap_state_composition_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| SC'+str(j)+' |' in report and '| SC-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'315563','12302','5557','5553','729840','9398016','26519','39845888','1264640','64240','9437184','1462272','36492','0xfffffe000be83324','0xfffffe000c639dd8']:assert item in report
 for path in CHANGED:
  if path.endswith('.md'):assert 'kernel_bootstrap_state_composition_report.md' in read(BASE/path)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_bootstrap_state_composition_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'composition_queries_rebuilt_and_resolved':11,'retained_queries_rebuilt_and_resolved':54,'private_components_rebuilt':9,'independent_semantic_checks':12302,'changed_source_controls_rejected':5,'continuous_source_thread_setups':5,'prior_published_handoff_preserved':True,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9510 and len(after)==9518 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),('source_composition_queries_unsat',11),('retained_source_queries_rebuilt',54),('conditional_kernel_bootstrap_state_composition_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==625
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':625,'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
