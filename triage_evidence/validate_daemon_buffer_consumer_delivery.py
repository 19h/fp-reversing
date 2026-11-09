#!/usr/bin/env python3
"""Seal the scoped buffer-consumer evidence and preserve prior investigations.
O(artifact bytes+report links) time, O(largest JSON+manifest) space; no target runs.
"""
import json,re
from pathlib import Path
from validate_daemon_buffer_consumer_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'original_source_spans':13,'original_fixups_verified':7,'bank_inputs_checked':512,'SMT_queries_unsat':30,'source_proof_pairs_unsat':15,'complete_twists_checked':1024,'mask_words_checked':1024,'normalization_word_updates_checked':128,'post_exit_twists_checked':16,'decoded_comparison_calls':32,'original_dynamic_opcode_bytes_checked':54939072,'unknown_read_frontiers_retained':8,'full_prefix_A64_runs':8,'new_symbolic_API_models':0,'source_pool_unique_instructions':1905,'live_IDB_rows_matched':216,'unique_live_IDB_rows_matched':210,'isolated_A64_cases':1096,'isolated_A64_passes':2192,'forced_destination_selector_pairs':1024,'fresh_full_A64_runs':1}
TOTALS={'source_visits':13734768,'read_events':2627424,'read_bytes':13214744,'write_events':666864,'write_bytes':2704672}
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and not q['full_goal_complete']
 for dep,h in q.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return q
def main():
 files=[('daemon_buffer_consumer_contracts.json','recover_daemon_buffer_consumer.py'),('daemon_buffer_consumer_profiles.json','probe_daemon_buffer_consumer.py'),('daemon_buffer_consumer_proofs.json','prove_daemon_buffer_consumer.py'),('daemon_buffer_normalization_replays.json','replay_daemon_buffer_normalization.py'),('daemon_buffer_consumer_checks.json','validate_daemon_buffer_consumer.py'),('daemon_buffer_consumer_preservation.json','validate_daemon_buffer_consumer_preservation.py')]
 c,profiles,proofs,isolated,k,p=[checked(n,g)for n,g in files];assert k['verified_counts']==EXPECTED and k['dynamic_A64_totals']==TOTALS and k['all_checks_pass']and p['all_checks_pass']and isolated['all_checks_pass']
 assert len(proofs['proofs'])==15 and len(proofs['premise_witnesses'])==3
 for row in proofs['proofs']:assert row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256']
 for row in proofs['solver_diagnostics']:assert row['result']=='unknown'and sha(ROOT/row['retained_query_file'])==row['retained_query_sha256']
 assert sum(case['prefix_verified_counts']['source_visits']for case in profiles['cases'])==2633576
 assert sha(ROOT/'daemon_buffer_consumer_prior_manifest.json')==BASELINE_SHA;old=read('daemon_buffer_consumer_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED and len(old['files'])==3085 and p['unchanged_prior_artifacts']==3079
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:path=BASE/row['path'];assert path.stat().st_size==row['size_bytes']and sha(path)==row['sha256']
 links=0
 for name in ['daemon_buffer_consumer_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_buffer_consumer_quality_gates.json',(name,target);links+=1
 report=(BASE/'daemon_buffer_consumer_report.md').read_text()
 for term in ['BC15','QG7','unknown','512','252 bytes','0x1010C8268','0x1010C67D4','0x100315478','0x100315484','0x100315734','0x1003ECB98','0x10008D004','0x13203F54E','-0x30F772E6','0x100315764','0x74C29DEE','16,368,344','13,734,768','2,633,576','1,096','2,192','130','unknown` after 30 s','216','210','24','Mach','full investigation remains active']:assert term in report,term
 evidence=['Factual technical analysis.','BC1-BC15 retain assumptions, dependencies and falsification probes.','Complete mask loop, publication, normalization, record caller, post-exit journals and materializer covered; full objective active.','u32/u64, little-endian bytes, 512-byte mask,252-byte normalization extent,624-word states and software counts explicit.','Selected/static/native coverage, unknown inputs/backing bits, xref metadata/accesses, publication/synchronization and timeout/composition distinguished.','13 source spans,7 fixups,512 bank inputs,216 IDB rows,15 proof pairs,8 full runs,1096 isolated arrays and fresh full replay.','Impact-labeled bounded continuation table.']
 outputs=[n for n,g in files]+['daemon_buffer_consumer_live_ida.json','daemon_buffer_globals_live_ida.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':e}for j,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'dynamic_A64_totals':TOTALS,'prefix_A64_totals':k['prefix_A64_totals'],'checked_report_links':links,'prior_artifacts_checked':3085,'unchanged_prior_artifacts':3079,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'inputs_preserved':old['inputs_preserved'],'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_buffer_consumer_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':15,'full_A64_runs':8,'isolated_A64_cases':1096,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
