#!/usr/bin/env python3
"""Seal original IORPC object/port converters, IOMachPort registry and ownership-mode evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='iorpc_object_conversion'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='a56eed88b75c57c2274dbb4ae5f3fde0ad56d6509b05b5c138186978e1b64a20';m=json.loads(prior.read_text());assert len(m['files'])==5992;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5986 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'exact_actor_snapshot_transfers_checked': 16, 'source_port_counter_images_checked': 16, 'original_registry_miss_constructor_and_publication_checked': 1, 'original_converter_entries_executed_checked': 23, 'source_exported_port_descriptor_frames_checked': 9, 'API_declared_queue_lookup_model': 9, 'API_declared_port_reference_copy_model': 9, 'API_declared_IOMachPort_allocation_model': 1, 'API_declared_object_reference_no_effect_model': 8, 'API_declared_port_aux_allocation_model': 1, 'API_declared_typed_port_creation_model': 1, 'API_declared_port_lock_no_effect_model': 12, 'API_declared_port_unlock_no_effect_model': 12, 'API_declared_kernel_transport_model': 8, 'API_declared_port_send_release_model': 11, 'API_declared_queue_release_model': 8, 'former_conversion_models_removed_cases_checked': 16, 'source_registry_global_transfers_checked': 90, 'registry_allocation_free_cases_checked': 15, 'unmoved_request_actual_descriptor_cleanup_checked': 1, 'moved_request_descriptor_preserved_checked': 1, 'consume_mode_object_release_checked': 1, 'nullable_object_export_checked': 1, 'independent_restore_release_mode_cases_checked': 4, 'source_wrapper_to_object_reference_sequences_checked': 2, 'same_hash_collision_traversal_checked': 1, 'conditional_NULL_port_result_caller_case_checked': 1, 'API_declared_object_port_NULL_model': 1, 'cases': 16, 'functions': 110, 'captured_instructions': 9642, 'object_conversion_slots': 4, 'recaptured_bindings': 35}
 assert len(prof['cases'])==16 and sum(len(r['source_visits'])for r in prof['cases'])==6288 and sum(len(r['API_models'])for r in prof['cases'])==81
 assert totals=={'source_visits_checked': 6288, 'logical_authentication_steps_checked': 200, 'writes_checked': 1442, 'write_bytes_checked': 11033, 'reads_checked': 1668, 'read_bytes_checked': 12040, 'logical_indirect_edges_checked': 71, 'rpc_frames_checked': 9, 'remote_frames_checked': 9, 'queue_lookup_frames_checked': 9, 'declared_API_models_checked': 81, 'port_copy_frames_checked': 9, 'conversion_packet_frames_checked': 23, 'conversion_frames_checked': 23, 'object_conversion_frames_checked': 47, 'object_allocation_frames_checked': 3, 'declared_model_memory_effects_checked': 16, 'declared_model_write_bytes_checked': 1100, 'object_reference_frames_checked': 8, 'logical_return_steps_checked': 92, 'port_lock_frames_checked': 24, 'transport_frames_checked': 9, 'release_frames_checked': 19, 'final_boundaries_checked': 16, 'final_objects_checked': 2768, 'final_source_globals_checked': 32, 'final_environment_globals_checked': 112, 'final_RPC_buffers_checked': 16, 'final_registry_globals_checked': 96}
 for obj in [src,prof,checks]:
  for key in ['native_object_port_registry_effects_executed','native_registry_or_platform_effects_executed','native_port_objects_observed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','native_remote_transport_executed','hardware_PAC_executed','native_IPC_executed']:assert obj[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']+src['iorpc_slots']+src['remote_slots']+src['object_conversion_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| OC'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5992,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':35,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original selected port/zero-reference converters, IOMachPort construction/hash miss/hit/collision, descriptor publication, source counter updates and independent restoration/release modes. Lower allocation/lock/object-reference/port-creation/send-release/transport effects remain premises. Native registry, rights, ownership balance and complete daemon continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', OC1-OC8, original source/fixups, source registry construction/snapshot/collision, descriptor and counter fields, restoration/release modes and original conversion/cleanup oracles, independent A64 read/write/branch replay and preserved globals, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':35,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
