#!/usr/bin/env python3
"""Seal original binary parser, collection reconstruction, filter and adapter evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='iorpc_binary_parser'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='98635a587dc44ac60fa0536c09219ca95d45fee92112e53766a9c3979dc55d29';m=json.loads(prior.read_text());assert len(m['files'])==6018;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6012 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'exact_prior_actor_transfers_checked': 19, 'whole_parser_result_model_removed_cases_checked': 19, 'source_dictionary_fields_and_buffer_accounting_checked': 19, 'empty_dictionary_round_trips_checked': 2, 'original_parser_and_collection_bodies_executed_cases_checked': 17, 'source_reference_table_and_root_return_checked': 17, 'source_D4_dictionary_index_skip_without_value_read_checked': 15, 'original_inverse_publishes_actual_parser_root_and_clears_descriptors_checked': 9, 'API_declared_port_lock_no_effect_model': 9, 'API_declared_object_reference_no_effect_model': 27, 'API_declared_port_unlock_no_effect_model': 9, 'API_declared_port_send_release_model': 9, 'API_declared_serialized_VM_copyout': 9, 'API_declared_strcmp_result': 19, 'API_declared_parser_dictionary_allocation': 17, 'API_declared_parser_typed_buffer_allocation': 31, 'API_declared_parser_bookkeeping_allocation': 32, 'API_declared_parser_bookkeeping_free': 32, 'API_declared_serialized_mapping_deallocation': 9, 'semantic_key_payload_and_source_dictionary_pair_round_trips_checked': 17, 'original_dictionary_key_value_and_count_stores_checked': 15, 'API_declared_parser_symbol_intern': 15, 'API_declared_parser_data_allocation': 15, 'API_declared_parser_zero_byte_copy': 1, 'API_declared_parser_object_reference': 64, 'API_declared_private_memory_copy': 14, 'exact_reconstructed_object_snapshot_transfers_checked': 2, 'reconstructed_global_snapshot_transfers_checked': 28, 'original_adapter_accepts_source_reconstructed_dictionary_checked': 2, 'API_declared_SetProperties_handler_result': 2, 'separate_parser_component_options_and_error_slot_checked': 8, 'dictionary_filter_low_three_bit_options_checked': 8, 'source_authenticated_filter_ABI_edges_checked': 4, 'API_declared_parser_filter_passthrough': 4, 'cases': 19, 'functions': 191, 'captured_instructions': 17506, 'parser_instructions': 882, 'binary_parser_binding_records': 18, 'recaptured_binding_records': 110, 'unique_binding_slots': 109}
 assert len(prof['cases'])==19 and sum(len(r['source_visits'])for r in prof['cases'])==15189 and sum(len(r['API_models'])for r in prof['cases'])==318
 assert totals=={'conversion_packet_frames_checked': 9, 'conversion_frames_checked': 9, 'source_visits_checked': 15189, 'logical_authentication_steps_checked': 543, 'writes_checked': 2261, 'write_bytes_checked': 17072, 'reads_checked': 2859, 'read_bytes_checked': 20833, 'object_conversion_frames_checked': 18, 'port_lock_frames_checked': 18, 'declared_API_models_checked': 318, 'logical_indirect_edges_checked': 208, 'object_reference_frames_checked': 27, 'logical_return_steps_checked': 106, 'release_frames_checked': 9, 'serialization_VM_frames_checked': 18, 'declared_model_memory_effects_checked': 187, 'declared_model_write_bytes_checked': 20550, 'serialization_parser_frames_checked': 34, 'binary_parser_frames_checked': 94, 'serialization_byte_frames_checked': 17, 'binary_parser_allocation_frames_checked': 127, 'binary_parser_return_frames_checked': 17, 'final_boundaries_checked': 19, 'final_objects_checked': 3857, 'final_source_globals_checked': 38, 'final_environment_globals_checked': 76, 'final_RPC_buffers_checked': 19, 'final_registry_globals_checked': 114, 'final_serialization_globals_checked': 38, 'binary_parser_symbol_frames_checked': 15, 'binary_parser_reference_frames_checked': 64, 'invoke_frames_checked': 2, 'binary_parser_handler_frames_checked': 2, 'SetProperties_handler_frames_checked': 2, 'binary_parser_filter_frames_checked': 4}
 for obj in [src,prof,checks]:
  for key in ['native_object_port_registry_effects_executed','native_registry_or_platform_effects_executed','native_port_objects_observed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','native_remote_transport_executed','native_serialized_VM_or_parser_effects_executed','native_binary_parser_executed','hardware_PAC_executed','native_IPC_executed']:assert obj[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']+src['iorpc_slots']+src['remote_slots']+src['object_conversion_slots']+src['serialization_slots']+src['binary_parser_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| BP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6018,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'binding_records_recaptured':110,'unique_binding_slots':109,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original complete binary parser, dictionary/data initialization and insertion, finite D3/D4 field round trips, actual root publication, reconstructed adapter state transfers and dictionary filter ABI. Lower allocation/extents, intern/reference/copy/VM/filter/handler outcomes remain models; native ownership, arbitrary graphs and a FairPlay caller remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', BP1-BP8, original source/fixups, prior actor snapshots, exact emitted bytes, original collection stores and actual parser roots, two reconstructed consumer handoffs and low-three-bit callback options, independent A64 read/write/branch replay and preserved globals, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'binding_records_recaptured':110,'unique_binding_slots':109,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
