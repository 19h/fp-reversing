#!/usr/bin/env python3
"""Rebuild source/contracts/replay and verify exact owned publication.
O(owned bytes+source+registry+formula DAG+journals+RAM) construction/space;
SMT search separate. No native target, IDB or history mutation.
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
import recover_kernel_startup_registry_abi as R
import audit_kernel_startup_registry_abi as A

PREVIOUS='6ef4dacea6976621a14eccebfed5ae9fad07f072'
BASELINE_SHA='8ef150ad358efb7758e5431ccf07aa4b1749471cc489689abe622be46aa1fb46'
CHECKS_SHA='45762fcf5f360ac4e3e96dcf34900c775f96748cd9e2974f0c69c48226881812'
AUDIT_SHA='3bec297b43e93af8f51535729e74a4b97afcc305762daadc6780b0fb256fca1a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_environment_publication_report.md','kernel_platform_environment_execution_report.md','kernel_boot_option_execution_report.md','kernel_secure_dt_execution_report.md','kernel_cpu_topology_handoff_report.md','kernel_bootstrap_state_composition_report.md','kernel_vm_mig_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_startup_registry_abi_report.md',*[('triage_evidence/'+name+'_kernel_startup_registry_abi.py') for name in ['recover','probe','replay','audit']], 'triage_evidence/verify_kernel_startup_registry_abi_delivery.py','triage_evidence/kernel_startup_registry_abi_checks.json','triage_evidence/kernel_startup_registry_abi_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_startup_registry_abi_checks.json','triage_evidence/kernel_startup_registry_abi_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':156,'captured_words':13275,'captured_bytes':53100,'matched_bootstrap_functions':31,'registry_records':3519,'registry_bytes':84456,'unique_callbacks':115,'null_arguments':88,'phase_name_slots':20,'named_phases':17,'registered_callback_words':6589,'tunable_descriptors':22,'opaque_words_preserved':5}
TOTALS={'source_queries_unsat':14,'retained_bootstrap_queries_rebuilt':11,'proved_source_PCs':56,'proof_instruction_instances':64,'linked_edge_obligations':50,'components':3,'source_visits':753522,'executed_source_PCs':3565,'changed_source_controls':2,'independent_semantic_checks':4892,'static_registry_checks':21492,'registry_records':3519,'unique_callback_targets':115,'tunable_descriptors':22,'original_API_entries':13646,'original_API_returns':13640,'original_registry_callbacks_returned':3,'trace_records':6,'whole_mutable_checkpoint_bytes_checked':2061660,'private_nonstack_bytes_checked':3132672,'call_frame_epochs':0,'native_target_executions':0}
REPLAY={'source_visits_checked':753522,'logical_PAC_steps_checked':994,'writes_checked':126311,'write_bytes_checked':1007329,'logical_effects_checked':12700,'declared_API_models_checked':9,'reads_checked':208983,'read_bytes_checked':1326879,'whole_checkpoint_private_bytes_checked':31457280,'whole_checkpoint_image_bytes_checked':998400,'whole_checkpoint_additional_image_bytes_checked':77088,'whole_checkpoint_registry_image_bytes_checked':2422848,'final_boundaries_checked':3,'whole_private_bytes_checked':3145728,'whole_image_page_bytes_checked':1036288,'vector_registers_checked':96,'original_API_entries_and_returns_checked':13640,'unfinished_original_API_entries_checked':6}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 for key,count in [('source_proofs',14),('retained_source_proofs_rebuilt',11)]:
  assert len(a[key])==len(fresh[key])==count
  for old,new in zip(a[key],fresh[key]):
   x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 excluded={'source_proofs','retained_source_proofs_rebuilt'}
 assert {k:v for k,v in a.items() if k not in excluded}=={k:v for k,v in fresh.items() if k not in excluded}
 assert e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert a['independent_registry_contracts']['pointer_records_independently_decoded']==7056 and a['prior_published_checkpoint_preservation']['exact_match']
 assert e['MIG_initializer_registration']['argument_pointer'] is None and e['MIG_initializer_registration']['phase_name']=='mach_ipc'
 assert not any(c['exact_symbols'] for c in e['callback_inventory'])
 expected=[('00000000',[125,3]),('07000000',[125,3]),('0d000000',[125,6])]
 for c,(value,ratio) in zip(a['components'],expected):
  assert c['entry_PC']=='0xfffffe000c639a40' and 'epochs' not in c and c['source_word_mutated_to_NOP'] is None
  assert len(c['initial_system'])==11 and len(c['final_image_globals'])==37 and c['boundary']['pc']=='0xfffffe000c63037c'
  assert c['independent_oracle']['first_callback']['final_hex']==value and c['independent_oracle']['reduced_ratio_words']==ratio
  assert len(c['original_API_entries'])==len(c['original_API_returns'])+len(c['unfinished_API_entry_indices']) and len(c['API_models'])==3
  assert [c['original_API_entries'][j]['PC'] for j in c['unfinished_API_entry_indices']]==[hex(R.SORT),hex(R.DISPATCH)]
 visited={v['pc'] for c in a['components'] for v in c['source_visits']};forbidden={i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']};assert not visited&forbidden and '0xfffffe000c62a46c' not in visited
 report=read(BASE/'kernel_startup_registry_abi_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| SR'+str(j)+' |' in report and '| SR-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'753522','21492','4892','13646','13640','2061660','3132672','0xfffffe000c630370','0xfffffe000c63037c','0xfffffe000c62a46c']:assert item in report
 for path in CHANGED:
  if path.endswith('.md'):assert 'kernel_startup_registry_abi_report.md' in read(BASE/path)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_startup_registry_abi_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'new_source_queries_rebuilt':14,'retained_queries_rebuilt':11,'private_components_rebuilt':3,'independent_semantic_checks':4892,'static_registry_checks':21492,'changed_source_controls_rejected':2,'prior_published_handoff_preserved':True,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9518 and len(after)==9526 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),('source_queries_unsat',14),('retained_source_queries_rebuilt',11),('conditional_kernel_startup_registry_abi_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==626 and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':626,'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
