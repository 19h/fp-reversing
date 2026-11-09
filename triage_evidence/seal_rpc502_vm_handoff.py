#!/usr/bin/env python3
"""Seal produced-copy state handoffs and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='rpc502_vm_handoff'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='5a49c55878b2e1d131bf0aa3830f1c49ec03546dec7cf0853edeaf1e0d8f96f2';m=json.loads(prior.read_text());assert len(m['files'])==6031;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6025 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'original_file_policy2_and_restored_map_state_checked': 18, 'source_error_counter_epoch_transfers_checked': 18, 'exact_normalized_reply_seed_frames_checked': 4, 'source_factory_components_checked': 4, 'source_constructed_type3_objects_checked': 6, 'source_removal_publication_descriptor_order_checked': 6, 'source_map_remove_before_publication_requests_checked': 6, 'exact_whole_RAM_snapshot_transfers_checked': 14, 'exact_whole_RAM_bytes_transferred_checked': 14680064, 'exact_image_global_snapshot_transfers_checked': 14, 'source_consume_or_preserve_outcomes_checked': 6, 'source_discarded_produced_objects_checked': 7, 'source_NULL_discard_checked': 1, 'exact_produced_payload_copyouts_checked': 3, 'exact_produced_payload_bytes_checked': 36865, 'original_X8_map_context_save_restore_pairs_checked': 4, 'source_payload_clear_release_header_release_sequences_checked': 10, 'failed_destination_mapping_cleanup_requests_checked': 1, 'cases': 18, 'functions': 23, 'captured_instructions': 4492, 'original_instruction_roles': 32}
 assert totals=={'source_visits_checked': 3321, 'logical_PAC_steps_checked': 72, 'writes_checked': 630, 'write_bytes_checked': 4706, 'reads_checked': 787, 'read_bytes_checked': 5502, 'final_boundaries_checked': 18, 'whole_final_RAM_images_checked': 18, 'whole_final_RAM_bytes_checked': 18874368, 'final_image_globals_checked': 126, 'VM_handoff_frames_checked': 45, 'original_copyin_argument_frames_checked': 6, 'declared_effect_calls_checked': 45, 'declared_API_models_checked': 89, 'declared_effect_patches_checked': 31, 'declared_effect_bytes_checked': 82536, 'logical_data_sign_steps_checked': 12, 'logical_data_auth_steps_checked': 22, 'map_context_frames_checked': 8}
 assert len(prof['cases'])==18 and sum(len(r['source_visits'])for r in prof['cases'])==3321 and sum(len(r['API_models'])for r in prof['cases'])==89
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| VH'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6031,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'original_instruction_roles_recaptured':32,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original type3 factories with file policy2 under explicit map/thread prerequisites, exact whole-RAM/global transfer to consuming copyout and discard, NULL/error ownership channels, removal/publication order and map context. Native VM, transport, retirement, type2 and complete daemon/kext continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', VH1-VH8, exact source/roles, produced type3 headers/backings, ordered source removal/publication, whole RAM/globals, cloned branch epochs, NULL/error source outcomes and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
