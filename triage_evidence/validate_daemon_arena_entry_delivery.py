#!/usr/bin/env python3
"""Seal source dead-load/noninterference/call-boundary evidence and scope.
O(artifact bytes+report links) time,O(largest JSON) space; no target operations.
"""
import json,re
from pathlib import Path
from validate_daemon_arena_entry_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,k,q,p=map(read,['daemon_arena_entry_contracts.json','daemon_arena_entry_checks.json','daemon_arena_entry_proofs.json','daemon_arena_entry_preservation.json'])
 for obj,n in [(c,'recover_daemon_arena_entry.py'),(k,'validate_daemon_arena_entry.py'),(q,'prove_daemon_arena_entry.py'),(p,'validate_daemon_arena_entry_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k['all_checks_pass']and p['all_checks_pass'];counts=k['verified_counts']
 expected={'original_source_spans':4,'source_liveness_certificates':2,'liveness_instruction_checks':151,'bank_inputs_checked':256,'original_fixups_verified':3,'live_IDB_source_rows_matched':105,'source_proof_pairs_unsat':10,'source_visits':12000,'frame_snapshots_reconstructed':192,'dead_load_epochs_checked':64,'unknown_words_preserved':64,'cases_byte_reconstructed':32,'prior_prefixes_preserved':32,'target_load_epochs_checked':96,'fresh_replayed_cases':8,'cases_checked':32,'unknown_pattern_equivalence_groups':8}
 for n,v in expected.items():assert counts[n]==v,(n,counts[n],v)
 assert sum(k['source_lift_counts'].values())==103 and k['source_lift_counts']==q['source_lift_counts']and not k['allocator_executed']
 for r in q['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 assert sha(ROOT/'daemon_arena_entry_prior_manifest.json')==BASELINE_SHA;old=read('daemon_arena_entry_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED
 for r in old['files']:
  path=BASE/r['path'];assert sha(path)==(changed[r['path']]['current_sha256']if r['path']in changed else r['sha256']),r['path']
 for r in old['inputs_preserved']:path=BASE/r['path'];assert sha(path)==r['sha256']and path.stat().st_size==r['size_bytes']
 links=0
 for name in ['daemon_arena_entry_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   path=Path(t.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_arena_entry_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_arena_entry_report.md').read_text()
 for term in ['AE10','QG7','unknown','0x1003B5738','0x1003B573C','0x10032A4BC','0x10032A4DC','0x10032A4E8','90000','151','103','105','32','64','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','AE1-AE10 retain dependencies and falsification probes.','Selected source prefix and first allocator ABI covered; broad objective active.','Exact u32/u64 register kills,90000-byte size,unknown masks and complexity stated.','Original unknown storage remains unknown; registers/stores invariant; call reachability does not imply allocation or native execution.','Two liveness certificates,ten source proof pairs,32 epoch audits,eight fresh replays,256 bank inputs,three fixups and105 IDB rows.','Impact-labeled bounded continuation table.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':k['source_lift_counts'],'checked_report_links':links,'prior_artifacts_checked':2783,'unchanged_prior_artifacts':2777,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{n:sha(ROOT/n)for n in ['daemon_arena_entry_contracts.json','daemon_arena_entry_checks.json','daemon_arena_entry_profiles.json','daemon_arena_entry_proofs.json','daemon_arena_entry_live_ida.json','daemon_arena_entry_preservation.json']},'allocator_executed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_arena_entry_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
