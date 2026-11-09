#!/usr/bin/env python3
"""Seal candidate interrupt/job and conditional common completion ABI evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='aes_completion_contract'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='3305274929b055c1c6b847b28d0f5b8e9d4b521579a86bec191705243214106f';m=json.loads(prior.read_text());assert len(m['files'])==5888;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5882 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay'];assert expected=={'static_origin_sites_checked': 6, 'source_object_transfers_checked': 5, 'API_descriptor_prepare_model': 2, 'API_descriptor_physical_address_model': 2, 'API_close_gate_no_effect_model': 4, 'API_on_thread_model': 4, 'API_open_gate_no_effect_model': 4, 'API_opaque_submission_return_no_effect_model': 1, 'separate_admission_return_checked': 1, 'declared_status_consumer_cases_checked': 4, 'partial_same_carrier_requeue_checked': 1, 'API_descriptor_complete_no_effect_model': 6, 'API_completion_callback_no_effect_model': 2, 'descriptor_completion_roles_checked': 6, 'pool_return_before_saved_callback_checked': 2, 'null_callback_deferred_pool_return_checked': 1, 'cases': 5, 'functions': 43, 'captured_instructions': 4256, 'additional_slots': 4}
 assert len(prof['cases'])==5 and sum(len(r['source_visits'])for r in prof['cases'])==1220 and sum(len(r['API_models'])for r in prof['cases'])==25
 assert totals=={'source_visits_checked': 1220, 'logical_authentication_steps_checked': 78, 'writes_checked': 181, 'write_bytes_checked': 1398, 'reads_checked': 311, 'read_bytes_checked': 2398, 'logical_indirect_edges_checked': 46, 'declared_API_models_checked': 25, 'pool_action_frames_checked': 3, 'logical_return_steps_checked': 7, 'pool_action_statuses_checked': 3, 'action_frames_checked': 1, 'submission_return_frames_checked': 1, 'final_boundaries_checked': 5, 'final_objects_checked': 245, 'driver_quantum_frontiers_checked': 1, 'completion_callback_frames_checked': 2, 'completion_wakeup_frontiers_checked': 1}
 for obj in [src,prof,checks]:
  for key in ['hardware_origin_executed','authentic_completion_status_established']:assert obj[key]is False
 for key in ['native_IPC_executed','native_descriptor_or_DMA_executed','native_workloop_or_lock_effects_executed','native_hardware_AES_executed','hardware_PAC_executed','runtime_candidate_identity_established','actual_kext_key_data_established']:assert checks[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CC'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5888,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':4,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original candidate IRQ/job adapter source and conditional common completion consumers. Submission return, event status, class/descriptor/thread/lock premises remain explicit; authentic hardware status, crypto output and native constructor/daemon continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CC1-CC8, original source/fixups, declared status consumers, source-produced object transfers, independent A64 read/write/branch replay and pool/callback/wakeup oracles, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':4,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
