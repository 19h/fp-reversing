#!/usr/bin/env python3
"""Seal original platform IORPC local dispatch, kernel packet and output ABI evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='platform_iorpc'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='fbf7011fb240a8f02174e374da25c8a2bbac0bc651fdb4ff95552326e5d18c97';m=json.loads(prior.read_text());assert len(m['files'])==5966;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5960 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'fresh_SDK_layout_compiles_checked': 2, 'exact_object_and_global_transfers_checked': 18, 'prior_objects_preserved': 2844, 'source_request_packet_oracles_checked': 18, 'local_Dispatch_Invoke_thunk_backend_chains_checked': 7, 'thread_context_clear_restore_pairs_checked': 7, 'original_unsupported_without_reply_cases_checked': 3, 'private_only_write_cases_checked': 18, 'original_reply_and_reader_cases_checked': 4, 'API_declared_platform_backend_model': 4, 'custom_dispatch_without_reply_cases_checked': 6, 'API_declared_custom_dispatch_model': 11, 'source_reply_transfer_and_guard_cases_checked': 5, 'cases': 18, 'functions': 88, 'captured_instructions': 7533, 'iorpc_slots': 2, 'recaptured_bindings': 24}
 assert len(prof['cases'])==18 and sum(len(r['source_visits'])for r in prof['cases'])==2967 and sum(len(r['API_models'])for r in prof['cases'])==15
 assert totals=={'source_visits_checked': 2967, 'logical_authentication_steps_checked': 119, 'writes_checked': 852, 'write_bytes_checked': 6528, 'reads_checked': 714, 'read_bytes_checked': 5336, 'logical_indirect_edges_checked': 81, 'rpc_frames_checked': 18, 'thread_frames_checked': 7, 'dispatch_frames_checked': 14, 'invoke_frames_checked': 7, 'thunk_frames_checked': 7, 'device_method_frames_checked': 7, 'controller_method_frames_checked': 7, 'logical_return_steps_checked': 46, 'final_boundaries_checked': 18, 'final_objects_checked': 2880, 'final_source_globals_checked': 36, 'final_environment_globals_checked': 108, 'final_RPC_buffers_checked': 18, 'declared_API_models_checked': 15, 'declared_model_memory_effects_checked': 7, 'declared_model_write_bytes_checked': 648}
 for obj in [src,prof,checks]:
  for key in ['native_registry_or_platform_effects_executed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','native_remote_transport_executed','hardware_PAC_executed','native_IPC_executed']:assert obj[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']+src['iorpc_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| IR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5966,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':24,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original three-method kernel-form IORPC builders, local Invoke/Dispatch/adapters/thunks/direct-backend chain, thread clear/restore, replies and power-output lifetime. Hierarchy, nominal objects/tables, PAC and backend/custom-dispatch outcomes are explicit premises. Native remote IPC, rights, actual platform success and complete daemon continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', IR1-IR8, original source/fixups, kernel/user SDK layouts, request/reply buffers, local dispatch/callback identities, thread restoration, error/no-reply and guarded power-output oracles, independent A64 read/write/branch replay and preserved globals, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':24,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
