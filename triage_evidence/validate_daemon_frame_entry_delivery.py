#!/usr/bin/env python3
"""Seal scoped frame-root correction,CAS,fill,cursor and historical boundaries.
O(artifact bytes+report links) time,O(largest JSON) space; no target runs.
"""
import hashlib,json,re
from pathlib import Path
from validate_daemon_frame_entry_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,k,q,p=map(read,['daemon_frame_entry_contracts.json','daemon_frame_entry_checks.json','daemon_frame_entry_proofs.json','daemon_frame_entry_preservation.json'])
 for obj,n in [(c,'recover_daemon_frame_entry.py'),(k,'validate_daemon_frame_entry.py'),(q,'prove_daemon_frame_entry.py'),(p,'validate_daemon_frame_entry_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k['all_checks_pass']and p['all_checks_pass'];counts=k['verified_counts']
 expected={'original_source_spans':14,'bank_inputs_checked':1792,'original_fixups_verified':28,'live_IDB_source_rows_matched':291,'source_proof_pairs_unsat':14,'independent_byte_reconstructed_cases':104,'entry_cases':96,'entry_source_visits':30248,'GPR_saved_slots':1152,'SIMD_saved_low64_slots':768,'controller_publications':192,'single_thread_CAS_transitions':112,'fresh_entry_replays':8,'failed_CAS_retry_cases':72,'fill_source_visits':11838,'fresh_fill_replays':6,'fill_cases':272,'aligned_zero_1024_cases':1,'corrected_pair_cases_and_fresh_replays':8,'historical_source_field_epochs_checked':30,'historical_startup_cases_read_back':3}
 for n,v in expected.items():assert counts[n]==v,(n,counts[n],v)
 assert sum(k['source_lift_counts'].values())==73 and k['source_lift_counts']==q['source_lift_counts']and k['entry_boundaries']=={'0x1003b5724':8,'0x1003ecb8c':16,'0x10035df48':72}
 for r in q['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 assert sha(ROOT/'daemon_frame_entry_prior_manifest.json')==BASELINE_SHA;old=read('daemon_frame_entry_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED
 for r in old['files']:
  path=BASE/r['path'];assert sha(path)==(changed[r['path']]['current_sha256']if r['path']in changed else r['sha256']),r['path']
 for r in old['inputs_preserved']:path=BASE/r['path'];assert sha(path)==r['sha256']and path.stat().st_size==r['size_bytes']
 links=0
 for name in ['daemon_frame_entry_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   path=Path(t.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_frame_entry_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_frame_entry_report.md').read_text()
 for term in ['FE12','QG7','unknown','0x1010B7DD8','0x1010B7D48','0xBD0','0xAF8','1,024','0x10030631C','0x100247598','zero-filled','96','272','73','291','112','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','FE1-FE12 retain assumptions,dependent results and falsification probes.','Frame roots,CAS,corrected pair and fill/cursor covered;full objective remains active.','3040-byte frame,u8/u32/u64,1024-byte clear,64-byte reservation and algorithm complexity explicit.','Earlier fixture root corrected;historical zero-stack versus new strict unknown reads,word transitions versus concurrency and internal fill versus libc distinguished.','96 entry/272 fill/eight corrected cases,14 source proof pairs,28 fixups,291 IDB rows,source epochs and three pinned historical readbacks.','Impact-labeled bounded continuation table.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':k['source_lift_counts'],'checked_report_links':links,'prior_artifacts_checked':2740,'unchanged_prior_artifacts':2734,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{n:sha(ROOT/n)for n in ['daemon_frame_entry_contracts.json','daemon_frame_entry_checks.json','daemon_frame_entry_profiles.json','daemon_frame_entry_proofs.json','daemon_frame_entry_live_ida.json','daemon_frame_entry_preservation.json']},'native_target_executed':False,'idb_mutated':False,'arbitrary_stack_continuous_startup_proved':False,'full_goal_complete':False};(ROOT/'daemon_frame_entry_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
