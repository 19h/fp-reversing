#!/usr/bin/env python3
"""Seal original range reservation, bitmap records, nonzero output token and tagged lookups and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_range_resolver'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='ad4758aa219c4937250fd4ddae5e10109fcd2e52c751dba7d369eae3fcad72bc';m=json.loads(prior.read_text());assert len(m['files'])==6096;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6090 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected=={'fresh_copy_and_map_producer_reconstructions_checked': 2, 'completed_zero_cursor_nesting_components_checked': 25, 'exact_primary_and_auxiliary_component_transfers_checked': 25, 'exact_inherited_global_transfers_checked': 25, 'absence_of_whole_resolver_and_position_models_checked': 25, 'other_descriptor_and_message_preservation_checked': 5, 'original_size_class_pool_alignment_and_forward_search_ABIs_checked': 5, 'original_file_bounds_failure_without_range_model_checked': 1, 'declared_bound_bucket_rng_zone_epochs_checked': 4, 'original_16byte_address_record_result_checked': 4, 'original_record_header_bitmap_budget_and_self_links_checked': 4, 'original_cached_rng_slot_and_next_word_checked': 4, 'original_tagged_pool_root_and_secondary_index_oracles_checked': 4, 'original_completed_copyout_with_record_tagged_entry_checked': 4, 'record_zone_ABI_and_explicit_primitive_models_checked': 4, 'nonzero_record_output_to_map_insertion_join_checked': 4, 'secondary_index_store_and_wrapper_only_retirement_checked': 4, 'real_tagged_record_lookup_components_checked': 20, 'false_before_start_with_nonnull_candidate_checked': 4, 'end_exclusive_null_lookup_checked': 4, 'cases': 25, 'functions': 72, 'captured_instructions': 12376}
 assert totals=={'type2_consumer_frames_checked': 43, 'VM_handoff_frames_checked': 14, 'source_visits_checked': 7786, 'reads_checked': 1915, 'read_bytes_checked': 13021, 'logical_PAC_steps_checked': 162, 'writes_checked': 1200, 'write_bytes_checked': 8904, 'declared_API_models_checked': 31, 'range_allocator_frames_checked': 19, 'range_result_frames_checked': 5, 'final_boundaries_checked': 25, 'whole_final_RAM_images_checked': 25, 'whole_final_RAM_bytes_checked': 26214400, 'final_image_globals_checked': 396, 'final_auxiliary_regions_checked': 75, 'declared_effect_patches_checked': 16, 'declared_effect_bytes_checked': 496, 'declared_effect_calls_checked': 16, 'map_constructor_frames_checked': 44, 'entry_copy_frames_checked': 4}
 assert len(prof['cases'])==25 and sum(len(r['source_visits'])for r in prof['cases'])==7786 and sum(len(r['API_models'])for r in prof['cases'])==31
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 assert im.pointer(0xfffffe0007e6a150)==src['range_callback']['pointer']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RA'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6096,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'original_callback_bindings_recaptured':1,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original interval search, size-class pool/record producer, cached-random bitmap selection, address/record result ABI, nonzero-token copyout and tagged forward-candidate lookup. Native boot bounds/entropy, zone size, backing bytes/mappings/rights/retirement and full FairPlay continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RA1-RA8, exact source/cells, fresh copy/map producers, explicit bounds/cache/zone overlays, original pool/header/bitmap/prefix-index/tag oracles, nonzero output-token join, completed copyouts and real tagged lookups, whole RAM/auxiliary/globals and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
