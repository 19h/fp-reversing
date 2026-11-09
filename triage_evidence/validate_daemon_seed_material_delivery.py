#!/usr/bin/env python3
"""Seal the seed-material interface increment and its evidence boundaries.
O(artifact bytes+report links) time,O(largest JSON) space; no target runs.
"""
import json,re
from pathlib import Path
from validate_daemon_seed_material_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha

def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,k,q,p=map(read,['daemon_seed_material_contracts.json','daemon_seed_material_checks.json','daemon_seed_material_proofs.json','daemon_seed_material_preservation.json'])
 for obj,name in [(c,'recover_daemon_seed_material.py'),(k,'validate_daemon_seed_material.py'),(q,'prove_daemon_seed_material.py'),(p,'validate_daemon_seed_material_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 expected={'original_source_spans':16,'original_fixups_verified':39,'exhaustive_bank_inputs':1024,'live_IDB_source_rows_matched':551,'original_path_pool_instructions':1235,'path_pool_instructions_live_IDB_covered':419,'SDK_return_clauses_checked':2,'source_proof_pairs_unsat':27,'nonempty_premise_witnesses':4,'outside_domain_alignment_counterexamples':1,'symbolic_contexts':4,'symbolic_source_visits':1038336,'SSA_definitions_checked':40740,'old_unknown_bytes_preserved':448,'recovered_context_summaries_matched':4,'cached_source_state_tail_reads':2096,'state_word_writes_checked':5000,'less_record_calls_decoded':7484,'original_new_visit_bytes_checked':4153344,'independent_A64_replays':24,'fresh_full_A64_replays':4,'status_high_seconds_sensitivity_groups':2,'isolated_failure_reader_A64_replays':16,'conditional_no_output_failure_contexts':4,'distinct_representation_state_hashes':4};assert k['verified_counts']==expected and k['all_checks_pass']and p['all_checks_pass']
 totals={'source_visits':7260744,'read_bytes_checked':6128376,'register_effects_checked':6474552,'write_bytes_checked':2234496,'source_write_effects_checked':461112,'unknown_copied_bytes_checked':5184,'NZCV_effects_checked':245280};new={'source_visits':6230016,'read_bytes_checked':5686464,'register_effects_checked':5562480,'write_bytes_checked':1995360,'source_write_effects_checked':408384,'unknown_copied_bytes_checked':0,'NZCV_effects_checked':211896};assert k['independent_A64_totals']==totals and k['new_increment_A64_totals']==new and k['source_lift_counts']==q['source_lift_counts']and sum(k['source_lift_counts'].values())==209
 for row in q['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 replays=read('daemon_seed_material_replays.json');offsets={int(r['frontier']['selected_read_address'],16)-(int(r['material_record']['address'],16)-0x670+0x6d8)for r in replays['cases']};assert offsets=={0,4}
 assert sha(ROOT/'daemon_seed_material_prior_manifest.json')==BASELINE_SHA;old=read('daemon_seed_material_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED and len(old['files'])==2939 and p['unchanged_prior_artifacts']==2933
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in ['daemon_seed_material_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_seed_material_quality_gates.json',(name,target);links+=1
 report=(BASE/'daemon_seed_material_report.md').read_text()
 for term in ['SM14','QG7','unknown','624','623','2,496','36 bytes','0x100427514','0x10109FF38','0x10035C6F8','0x0179FA0FE732D262','0x101B14BF85AD82C7','0x5CF7672B','7,260,744','6,230,016','551','419','156','0x9908B0DF','32-byte','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','SM1-SM14 retain assumptions,dependencies and falsification probes.','Material/time/allocator interfaces,complete mixed state,complete less-than leaf and first-twist frontier covered; full objective active.','u32/u64 arithmetic,32-byte reservation,36-byte accessed footprint,2496-byte state,time units and bounded software counts explicit.','Accessed footprint/object size,API outputs/backing bits,conditional failure/native observation,cache probes/zero definitions,and static postlookup/replayed prefix distinguished.','16 source spans,39 fixups,1024 bank inputs,551 IDB rows,SDK documentation,27 proof pairs,24 A64 replays and16 isolated readers.','Impact-labeled bounded continuation table.'];outputs=['daemon_seed_material_contracts.json','daemon_seed_material_checks.json','daemon_seed_material_profiles.json','daemon_seed_material_replays.json','daemon_seed_material_proofs.json','daemon_seed_material_failure.json','daemon_seed_material_live_ida.json','daemon_seed_mixing_live_ida.json','daemon_seed_table_setup_live_ida.json','daemon_seed_material_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':e}for j,e in enumerate(evidence,1)},'verified_counts':expected,'independent_A64_totals':totals,'new_increment_A64_totals':new,'source_lift_counts':k['source_lift_counts'],'checked_report_links':links,'prior_artifacts_checked':2939,'unchanged_prior_artifacts':2933,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{name:sha(ROOT/name)for name in outputs},'native_failure_observed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'checked_report_links':links,'source_proof_pairs':27,'A64_replays':24,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
