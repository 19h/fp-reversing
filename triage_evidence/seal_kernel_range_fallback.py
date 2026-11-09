#!/usr/bin/env python3
"""Seal original marked fallback and exact reservation-to-abort/store-retirement joins and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_range_fallback'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='48b48c6664b33ec43af039a7d2fe2cdd4000974e048e0fbf06a6ce6abb5f7f57';m=json.loads(prior.read_text());assert len(m['files'])==6109;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6103 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'fresh_copy_and_map_producer_reconstructions_checked': 2, 'zero_cursor_nesting_at_components_checked': 19, 'exact_primary_auxiliary_component_transfers_checked': 19, 'exact_inherited_global_transfers_checked': 19, 'no_whole_range_or_position_model_checked': 19, 'declared_map_flag_epoch_and_other_descriptor_preservation_checked': 3, 'original_complete_fallback_direct_store_oracles_checked': 2, 'original_2e_fallback_marked_address_null_token_join_checked': 2, 'original_generic_search_ABI_and_no_record_or_rng_consumption_checked': 2, 'exact_source_produced_pre_insertion_reservation_frontier_checked': 1, 'standalone_abort_call_without_insertion_or_return_status_claim_checked': 3, 'rollback_argument_ABI_checked': 3, 'original_zero_token_or_bit63_data_state_noop_checked': 2, 'original_bucket_unlink_pool_coalescing_and_record_retirement_checked': 1, 'last_slot_return_to_entire_pool_removal_join_checked': 1, 'inactive_root_bits_and_hint_distinguished_from_live_record_checked': 1, 'real_lookup_after_original_fallback_checked': 8, 'real_lookup_with_retained_or_removed_pool_without_entry_checked': 5, 'cases': 19, 'functions': 76, 'captured_instructions': 13296}
 assert totals=={'type2_consumer_frames_checked': 23, 'source_visits_checked': 4124, 'reads_checked': 1078, 'read_bytes_checked': 7435, 'logical_PAC_steps_checked': 101, 'writes_checked': 677, 'write_bytes_checked': 5107, 'declared_API_models_checked': 18, 'range_allocator_frames_checked': 9, 'lower_allocator_return_frames_checked': 3, 'fallback_frames_checked': 8, 'range_result_frames_checked': 3, 'entry_copy_frames_checked': 2, 'map_constructor_frames_checked': 29, 'declared_effect_patches_checked': 10, 'declared_effect_bytes_checked': 260, 'declared_effect_calls_checked': 10, 'final_boundaries_checked': 19, 'whole_final_RAM_images_checked': 19, 'whole_final_RAM_bytes_checked': 19922944, 'final_image_globals_checked': 304, 'final_auxiliary_regions_checked': 57}
 assert len(prof['cases'])==19 and sum(len(r['source_visits'])for r in prof['cases'])==4124 and sum(len(r['API_models'])for r in prof['cases'])==18
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 assert im.pointer(0xfffffe0007e6a150)==src['range_callback']['pointer']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| FR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6109,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'original_callback_bindings_recaptured':1,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original fallback/marked raw interval and signed extraction, exact pre-validation reservation, standalone rollback guards, last-bit/bucket/pool removal and record-retirement requests with real lookup. Live validation-error/outer-caller causality, native VM/ownership/boot state and full FairPlay continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', FR1-FR8, exact source, fresh producers and snapshots, explicit flag/bounds/cache epochs, raw marker and signed extraction, saved pre-validation state, original bit/list/store rollback, inactive bytes versus active records and real lookups, whole RAM/auxiliary/globals and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
