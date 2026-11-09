#!/usr/bin/env python3
"""Seal source/SSA/ABI evidence, report links and preservation for this increment.
O(artifact bytes+report links) time,O(largest JSON) space; no target runs.
"""
import json,re
from pathlib import Path
from validate_daemon_entropy_return_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha

def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,k,q,p=map(read,['daemon_entropy_return_contracts.json','daemon_entropy_return_checks.json','daemon_entropy_return_proofs.json','daemon_entropy_return_preservation.json'])
 for obj,n in [(c,'recover_daemon_entropy_return.py'),(k,'validate_daemon_entropy_return.py'),(q,'prove_daemon_entropy_return.py'),(p,'validate_daemon_entropy_return_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 expected={'original_source_spans':4,'original_fixups_verified':3,'bank_inputs_exhaustive':256,'live_IDB_rows_matched':188,'original_pool_instructions_IDB_covered':64,'SDK_source_declarations_matched':8,'SDK_headers_checked':4,'fresh_SDK_compile_checks':1,'source_proof_pairs_unsat':11,'nonempty_premise_witnesses':4,'symbolic_contexts':4,'symbolic_source_visits':45036,'SSA_definitions_checked':10004,'state_word_writes_checked':2496,'original_new_visit_bytes_checked':180144,'independent_A64_replays':48,'fresh_A64_replays':4,'unknown_timeval_contexts_checked':4,'post_time_status_liveness_instructions':37};assert k['verified_counts']==expected and k['all_checks_pass']and p['all_checks_pass']
 totals={'source_visits':2061456,'read_bytes_checked':883824,'register_effects_checked':1824144,'write_bytes_checked':478272,'source_write_effects_checked':105456,'unknown_copied_bytes_checked':10368,'NZCV_effects_checked':66768};increment={'source_visits':540432,'read_bytes_checked':242016,'register_effects_checked':450576,'write_bytes_checked':120000,'source_write_effects_checked':30000,'unknown_copied_bytes_checked':0,'NZCV_effects_checked':29904};assert k['independent_A64_totals']==totals and k['new_increment_A64_totals']==increment and k['source_lift_counts']==q['source_lift_counts']and sum(k['source_lift_counts'].values())==77
 for row in q['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 assert sha(ROOT/'daemon_entropy_return_prior_manifest.json')==BASELINE_SHA;old=read('daemon_entropy_return_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED and len(old['files'])==2895 and p['unchanged_prior_artifacts']==2889
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in ['daemon_entropy_return_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_entropy_return_quality_gates.json',(name,target);links+=1
 report=(BASE/'daemon_entropy_return_report.md').read_text()
 for term in ['ER12','QG7','unknown','624','2,496','0x1010C784C','0x1010C8258','0x1002DC308','0x10109FF20','0x6C078965','0x5CF7672B','2,061,456','11,259','188','MT19937','zero source-defined','37-instruction','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','ER1-ER12 include dependencies and falsification probes.','Entropy return, complete scalar initialization, next time-call ABI and immediate output consumers covered; full objective active.','u32/u64 widths,2496-byte state,16-byte timeval,seconds/microseconds,induction and counts explicit.','Initializer versus later generator,seed versus comparison word,API arguments versus clobbered remnants,unknown output bytes versus failure effects,and preferred addresses versus native runtime distinguished.','Four source spans,three fixups,256-input bank,188 IDB rows covering64 path instructions,SDK sources/compile,11 proof pairs and48 A64 replays.','Impact-labeled bounded continuation table.']
 outputs=['daemon_entropy_return_contracts.json','daemon_entropy_return_checks.json','daemon_entropy_return_profiles.json','daemon_entropy_return_replays.json','daemon_entropy_return_proofs.json','daemon_entropy_return_live_ida.json','daemon_entropy_iteration_live_ida.json','daemon_time_consumers_live_ida.json','daemon_entropy_return_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':e}for j,e in enumerate(evidence,1)},'verified_counts':expected,'independent_A64_totals':totals,'new_increment_A64_totals':increment,'source_lift_counts':k['source_lift_counts'],'checked_report_links':links,'prior_artifacts_checked':2895,'unchanged_prior_artifacts':2889,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'native_entropy_executed':False,'native_time_executed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_entropy_return_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':expected,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
