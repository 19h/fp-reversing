#!/usr/bin/env python3
"""Seal original remote IORPC route, destination/header and shared-transport ABI evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='iorpc_remote'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='a1d0b5de4d4a4b8f1974befcea5f2cfcc9fd00cc1b64500f6e9853bc081ef266';m=json.loads(prior.read_text());assert len(m['files'])==5979;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5973 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'same_FairPlay_common_transport_source_join_checked': 1, 'same_prior_port_reference_copy_source_join_checked': 1, 'exact_actor_and_global_transfers_checked': 16, 'prior_object_images_with_declared_device_link_checked': 2528, 'remote_without_local_dispatch_or_thread_clear_checked': 16, 'original_builder_to_server_routes_checked': 14, 'transport_argument_frames_checked': 13, 'source_outgoing_header_oracles_checked': 13, 'API_declared_queue_lookup_model': 15, 'API_declared_port_reference_copy_model': 14, 'API_declared_request_object_conversion_model': 13, 'native_transport_bodies_unexecuted_checked': 16, 'port_then_queue_release_order_checked': 9, 'reply_content_and_conversion_modes_checked': 5, 'returned_status_cases_checked': 12, 'declared_source_reply_transfers_checked': 5, 'API_declared_kernel_transport_model': 9, 'API_declared_port_send_release_model': 9, 'API_declared_queue_release_model': 10, 'API_declared_reply_or_cleanup_conversion_model': 8, 'unmoved_request_cleanup_cases_checked': 2, 'moved_request_cleanup_skip_checked': 1, 'fallback_queue_retain_frontier_checked': 1, 'API_declared_queue_retain_model': 1, 'conditional_reply_conversion_cleanup_checked': 1, 'API_declared_reply_cleanup_model': 1, 'source_request_component_transfers_checked': 2, 'cases': 16, 'functions': 100, 'captured_instructions': 9148, 'remote_slots': 7, 'recaptured_bindings': 31}
 assert len(prof['cases'])==16 and sum(len(r['source_visits'])for r in prof['cases'])==4012 and sum(len(r['API_models'])for r in prof['cases'])==80
 assert totals=={'source_visits_checked': 4012, 'logical_authentication_steps_checked': 128, 'writes_checked': 937, 'write_bytes_checked': 7176, 'reads_checked': 971, 'read_bytes_checked': 7343, 'logical_indirect_edges_checked': 98, 'rpc_frames_checked': 16, 'remote_frames_checked': 16, 'queue_lookup_frames_checked': 15, 'declared_API_models_checked': 80, 'port_copy_frames_checked': 14, 'conversion_frames_checked': 21, 'transport_frames_checked': 13, 'final_boundaries_checked': 16, 'final_objects_checked': 2656, 'final_source_globals_checked': 32, 'final_environment_globals_checked': 112, 'final_RPC_buffers_checked': 16, 'declared_model_memory_effects_checked': 14, 'declared_model_write_bytes_checked': 680, 'release_frames_checked': 20, 'logical_return_steps_checked': 32, 'reply_cleanup_frames_checked': 1}
 for obj in [src,prof,checks]:
  for key in ['native_registry_or_platform_effects_executed','native_port_objects_observed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','native_remote_transport_executed','hardware_PAC_executed','native_IPC_executed']:assert obj[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']+src['iorpc_slots']+src['remote_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RM'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5979,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':31,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Conditional original service-to-server remote IORPC route, queue/port/header/transport ABI, reference-request ordering, moved-dependent cleanup and reply/caller contracts. Hierarchy/link/queue/port/conversion/reference/transport outcomes remain premises. Native right effects, delivery, platform success and complete daemon continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RM1-RM8, original source/fixups, service association and common-transport byte joins, queue/header/transport frames, release ordering, moved cleanup and normal/error reply oracles, independent A64 read/write/branch replay and preserved globals, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':31,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
