#!/usr/bin/env python3
"""Seal original IORPC OOL binary emission, wrapper dispatch and modeled VM/parser evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='iorpc_ool_serialization'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='ee86cd41557bee98065de6d1efb368747dd908857ddc58edd4056f0dd9b19126';m=json.loads(prior.read_text());assert len(m['files'])==6005;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5999 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'exact_prior_actor_transfers_checked': 20, 'parser_body_unexecuted_cases_checked': 20, 'original_two_descriptor_builder_checked': 1, 'original_nullable_dictionary_type_adapter_reply_checked': 1, 'API_declared_SetProperties_handler_result': 1, 'original_remote_two_descriptor_frames_checked': 13, 'independent_binary_byte_and_OOL_extent_oracles_checked': 12, 'index_data_D4_cases_checked': 10, 'API_declared_queue_lookup_model': 13, 'API_declared_port_reference_copy_model': 13, 'API_declared_port_lock_no_effect_model': 18, 'API_declared_port_unlock_no_effect_model': 18, 'API_declared_serializer_collection_allocation': 46, 'API_declared_memo_array_initialization': 24, 'API_declared_serializer_VM_allocation': 12, 'API_declared_index_data_initialization': 10, 'API_declared_serialized_object_reference': 102, 'API_declared_private_memory_copy': 56, 'API_declared_serialized_VM_copyin': 12, 'source_adapter_reply_transfers_and_validation_checked': 2, 'API_declared_SetProperties_transport': 4, 'API_declared_port_send_release_model': 10, 'API_declared_queue_release_model': 4, 'nullable_OOL_without_serializer_checked': 1, 'source_error_and_moved_cleanup_field_cases_checked': 2, 'exact_packet_and_emitted_byte_consumer_transfers_checked': 5, 'original_wrapper_D3_D4_parser_dispatch_checked': 5, 'source_consumer_deallocation_and_slot_clearing_checked': 3, 'API_declared_object_reference_no_effect_model': 15, 'API_declared_serialized_VM_copyout': 5, 'API_declared_strcmp_result': 5, 'API_declared_binary_parser_object': 3, 'API_declared_serialized_mapping_deallocation': 3, 'unexecuted_parser_frontiers_checked': 2, 'optional_index_NULL_D3_cases_checked': 2, 'API_declared_optional_index_allocation_NULL': 2, 'cases': 20, 'functions': 168, 'captured_instructions': 14631, 'serialization_slots': 57, 'recaptured_binding_records': 92, 'unique_binding_slots': 91}
 assert len(prof['cases'])==20 and sum(len(r['source_visits'])for r in prof['cases'])==31054 and sum(len(r['API_models'])for r in prof['cases'])==376
 assert totals=={'source_visits_checked': 31054, 'logical_authentication_steps_checked': 1573, 'writes_checked': 5331, 'write_bytes_checked': 39854, 'reads_checked': 8117, 'read_bytes_checked': 57819, 'logical_indirect_edges_checked': 797, 'rpc_frames_checked': 14, 'final_boundaries_checked': 20, 'final_objects_checked': 3860, 'final_source_globals_checked': 40, 'final_environment_globals_checked': 80, 'final_RPC_buffers_checked': 20, 'final_registry_globals_checked': 120, 'final_serialization_globals_checked': 40, 'invoke_frames_checked': 1, 'SetProperties_handler_frames_checked': 1, 'declared_API_models_checked': 376, 'logical_return_steps_checked': 351, 'remote_frames_checked': 13, 'queue_lookup_frames_checked': 13, 'port_copy_frames_checked': 13, 'conversion_packet_frames_checked': 21, 'conversion_frames_checked': 21, 'object_conversion_frames_checked': 73, 'port_lock_frames_checked': 36, 'serialization_frames_checked': 96, 'declared_model_memory_effects_checked': 163, 'declared_model_write_bytes_checked': 5416, 'serialization_VM_frames_checked': 32, 'object_reference_frames_checked': 117, 'serialization_byte_frames_checked': 17, 'serialization_records_checked': 12, 'transport_frames_checked': 13, 'release_frames_checked': 14, 'serialization_parser_frames_checked': 10}
 for obj in [src,prof,checks]:
  for key in ['native_object_port_registry_effects_executed','native_registry_or_platform_effects_executed','native_port_objects_observed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','native_remote_transport_executed','native_serialized_VM_or_parser_effects_executed','hardware_PAC_executed','native_IPC_executed']:assert obj[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']+src['iorpc_slots']+src['remote_slots']+src['object_conversion_slots']+src['serialization_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| OS'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6005,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':92,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original SetProperties builder/adapter, binary writer D3/D4 bytes, OOL descriptor publication, exact inverse byte transfer, parser-entry dispatch and conditional slot cleanup. VM/collection/reference/transport/parser outcomes remain models; native ownership, parser correctness and FairPlay continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', OS1-OS8, original source/fixups, prior actor snapshots, exact binary bytes and descriptor extents, D3/D4 wrapper dispatch, parser frontiers and conditional conversion/cleanup oracles, independent A64 read/write/branch replay and preserved globals, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':92,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
