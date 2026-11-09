#!/usr/bin/env python3
"""Seal original map/root construction, completed type2 insertion and real resolver joins and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_map_store_init'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='30833291b1baa655e293ef543ace60b7ce3b3199f7ea5a80fa4fd36a4c7b815c';m=json.loads(prior.read_text());assert len(m['files'])==6083;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6077 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'original_constructor_alias_and_move_symbols_checked': 1, 'exact_counter_address_ADRP_ADD_join_checked': 1, 'syntactic_class_bounds_page_references_checked': 116, 'instruction_words_scanned': 2558560, 'fresh_source_copy_producer_reconstruction_checked': 1, 'final_zero_cursor_nesting_checked': 17, 'exact_factory_to_constructor_RAM_aux_transfer_checked': 4, 'exact_256byte_original_map_and_root_oracles_checked': 4, 'rounding_flags_reference_identifier_oracles_checked': 4, 'distinct_map_root_allocator_ABIs_checked': 4, 'exported_map_constructor_defaults_checked': 1, 'original_optional_aux_store_path_checked': 1, 'exact_constructed_component_RAM_aux_global_handoffs_checked': 13, 'constructed_map_unmodeled_resolver_frontier_checked': 1, 'constructed_map_resolver_failure_preservation_checked': 1, 'completed_original_root_keys_records_map_links_and_entry_oracles_checked': 2, 'completed_original_exclusive_release_and_zero_return_checked': 2, 'wrapper_only_retirement_protocol_and_persistent_mapped_entry_checked': 2, 'completed_consuming_copyout_checked': 1, 'original_store_insert_to_entry_release_argument_join_checked': 2, 'completed_nonconsuming_clone_preserves_source_copy_checked': 1, 'post_copyout_discard_preserves_constructed_map_store_checked': 2, 'source_copy_retirement_keeps_distinct_mapped_clone_checked': 1, 'other_descriptor_retirement_keeps_mapped_entry_checked': 1, 'original_real_resolver_and_candidate_membership_cases_checked': 7, 'false_lookup_with_nonnull_candidate_checked': 1, 'end_exclusive_null_lookup_checked': 2, 'real_lookup_after_source_retirement_checked': 2, 'cases': 17, 'functions': 69, 'captured_instructions': 11322}
 assert totals=={'map_constructor_frames_checked': 23, 'source_visits_checked': 3043, 'logical_PAC_steps_checked': 84, 'writes_checked': 683, 'write_bytes_checked': 5134, 'reads_checked': 839, 'read_bytes_checked': 6015, 'declared_effect_patches_checked': 20, 'declared_effect_bytes_checked': 2408, 'declared_effect_calls_checked': 21, 'declared_API_models_checked': 43, 'final_boundaries_checked': 17, 'whole_final_RAM_images_checked': 17, 'whole_final_RAM_bytes_checked': 17825792, 'final_image_globals_checked': 204, 'final_auxiliary_regions_checked': 51, 'type2_consumer_frames_checked': 29, 'VM_handoff_frames_checked': 15, 'entry_copy_frames_checked': 6, 'logical_data_auth_steps_checked': 1}
 assert len(prof['cases'])==17 and sum(len(r['source_visits'])for r in prof['cases'])==3043 and sum(len(r['API_models'])for r in prof['cases'])==43
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 assert im.pointer(0xfffffe0007e6a150)==src['range_callback']['pointer']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| MS'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6083,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'original_callback_bindings_recaptured':1,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original map/root construction, encoded store publication, completed singleton type2 copyout/release, source-copy retirement with mapped clone preserved and real resolver/candidate joins. Native boot kernel-map and class bounds, range resolution, actual backing bytes/mappings/rights/retirement and full FairPlay continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', MS1-MS8, exact source/aliases/counter address/constants/globals, repeated bounded page-reference scan, fresh producer and exact transfers, map/root oracles, original store insertion/release/cleanup and real resolver lookups, whole RAM/auxiliary/globals and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
