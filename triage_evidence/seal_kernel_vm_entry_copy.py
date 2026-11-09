#!/usr/bin/env python3
"""Seal original VM entry eligibility, structural type2 publication and discard and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_vm_entry_copy'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='c080e9ea7ef71d235def9d5ecc19dbc78f79bd3c24e4e7f773b197f6f853b473';m=json.loads(prior.read_text());assert len(m['files'])==6057;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6051 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'fresh_held_prefix_reconstructions_checked': 1, 'completed_original_cursor_reader_unwinds_checked': 7, 'exact_held_RAM_aux_globals_GP_SP_NZCV_SIMD_transfers_checked': 1, 'original_entry_bit8_bit4_gate_and_status_checked': 5, 'original_rejected_entry_working_header_cleanup_checked': 4, 'original_64byte_entry_copy_adjustments_checked': 1, 'original_type2_single_entry_header_and_two_descriptor_publication_checked': 1, 'distinct_entry_allocator_and_source_removal_ABIs_checked': 1, 'type2_source_removal_before_copy_publication_checked': 1, 'original_copy_list_head_tail_and_count_stores_checked': 1, 'exact_produced_RAM_aux_global_handoffs_checked': 2, 'original_type2_unlink_64byte_entry_and_48byte_header_release_checked': 1, 'stale_descriptor_bits_after_release_protocol_checked': 2, 'separate_produced_type3_discard_checked': 1, 'cases': 7, 'functions': 50, 'captured_instructions': 8224}
 assert totals=={'entry_copy_frames_checked': 11, 'cursor_frames_checked': 22, 'source_visits_checked': 3998, 'logical_PAC_steps_checked': 138, 'writes_checked': 1031, 'write_bytes_checked': 7644, 'reads_checked': 1057, 'read_bytes_checked': 7342, 'entry_copy_return_frames_checked': 5, 'VM_handoff_frames_checked': 19, 'declared_effect_patches_checked': 8, 'declared_effect_bytes_checked': 353, 'declared_effect_calls_checked': 14, 'declared_API_models_checked': 45, 'final_boundaries_checked': 7, 'whole_final_RAM_images_checked': 7, 'whole_final_RAM_bytes_checked': 7340032, 'final_image_globals_checked': 55, 'final_auxiliary_regions_checked': 14, 'original_copyin_argument_frames_checked': 5, 'position_frames_checked': 4, 'logical_callback_edges_checked': 4, 'callback_frames_checked': 4, 'range_lock_frames_checked': 5, 'cursor_return_frames_checked': 9, 'logical_data_sign_steps_checked': 3, 'logical_data_auth_steps_checked': 1}
 assert len(prof['cases'])==7 and sum(len(r['source_visits'])for r in prof['cases'])==3998 and sum(len(r['API_models'])for r in prof['cases'])==45
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 assert im.pointer(0xfffffe0007e6a150)==src['range_callback']['pointer']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| EC'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6057,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'original_callback_bindings_recaptured':1,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original entry bit gates, exact held-state unwind, structural NULL-object type2 clone/list/publication and produced-copy discard continuity. Native search/mapping/rights, real backing bytes, allocator retirement and full FairPlay continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', EC1-EC8, exact source/fixup/constants, flag gates, exact held-state resume, original clone/list/publication/unwind, produced-copy transfers and original discard, whole RAM/auxiliary/globals and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
