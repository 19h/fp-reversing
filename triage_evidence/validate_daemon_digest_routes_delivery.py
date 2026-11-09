#!/usr/bin/env python3
"""Seal compact routing and saved-continuation contracts with native limits.
O(owned artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_digest_routes_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and not r['full_goal_complete']
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_digest_routes_contracts.json','recover_daemon_digest_routes.py'),('daemon_digest_routes_proofs.json','prove_daemon_digest_routes.py'),('daemon_digest_routes_profiles.json','probe_daemon_digest_routes.py'),('daemon_digest_routes_checks.json','validate_daemon_digest_routes.py'),('daemon_digest_routes_preservation.json','validate_daemon_digest_routes_preservation.py')];c,p,r,k,keep=[checked(n,g)for n,g in pairs];assert k['all_checks_pass']and keep['all_checks_pass'];v=k['verified_counts']
 expected={'original_source_spans':8,'literal_modifier_candidates':6,'entry_fixups_checked':1,'retained_alternate_target_edges_checked':48,'original_continuation_slots_checked':13,'continuation_phase_low6_inputs_checked':448,'raw_count_compatible_modes_checked':2,'continuation_and_branch_fixups_checked':15,'live_IDB_ranges':7,'live_IDB_bytes':548,'exhaustive_low16_inputs':131072,'rebuilt_source_obligations_unsat':15,'SMT_files_unsat_and_formula_matched':30,'source_lift_visits':144,'ordered_source_reads_checked':400,'ordered_source_writes_checked':544,'new_context_field_layouts_checked':48,'freshly_recomputed_A64_cases':128,'persisted_A64_cases':128,'source_visits_checked':2080,'existing_prefix_fragments_checked':16,'existing_route_fragments_checked':16,'existing_argument_fragments_checked':16,'callee_frame_captures_checked':16,'negative_signed_index_cases_checked':4,'saved_continuation_fragments_checked':16};assert v==expected,(v,expected)
 assert len(p['proofs'])==15 and len(list(ROOT.glob('daemon_digest_routes_*.smt2')))==30 and len(r['cases'])==128;assert not k['native_caller_established']and not k['new_port_emission_established'];assert len(c['original_IA7315_continuation_slots'])==13 and len(c['continuation_phase_biases'])==7
 assert sha(ROOT/'daemon_digest_routes_prior_manifest.json')==BASELINE_SHA;old=read('daemon_digest_routes_prior_manifest.json');changed={x['path']:x for x in keep['allowed_existing_changes']};assert len(old['files'])==3923 and keep['unchanged_prior_artifacts']==3917 and set(changed)==ALLOWED
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 reports=['daemon_digest_routes_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_digest_routes_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text();assert report.isascii()
 for term in ['DR12','QG7','2,080','0x6292','0x0240','signed32(P)','F+2F48','C+0x64 (100 bytes)','032B','0371','471C','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 assert '| C+100 |'not in report
 scripts=list(ROOT.glob('*daemon_digest_routes*.py'));assert len(scripts)==6
 for f in scripts:ast.parse(f.read_text(),filename=str(f))
 evidence=['Factual original-source and register/frame ABI analysis.','DR1-DR12 register source,roots,control,owners,cursor,signed indices,continuation preservation,raw-count and scope premises with probes.','Compact candidate routing,context setup,saved arguments,continuation constraints and buffered-count gate covered; full objective remains active.','u32/u64 modular identities,signed table indexing,100/128-byte extents and exact finite/algebraic counts explicit.','Entry index,continuation index,metadata compatibility,raw-count convention and native reachability separated; retained alternate target checked.','Original source/fixups,15 rebuilt proof pairs,128 fresh isolated A64 cases,byte ledgers,131072 low16 inputs,448 low6 inputs,548 IDB bytes and48 retained alternate edges verified.','Impact-bounded native caller,frame/owner,return invariant,other-mode and transport questions retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'source_sha256':sha(source),'source_lift_counts':p['source_lift_counts'],'prior_artifacts_checked':3923,'unchanged_prior_artifacts':3917,'checked_report_links':links,'new_python_files_syntax_checked':len(scripts),'inputs_preserved':old['inputs_preserved'],'native_caller_established':False,'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_digest_routes_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'proof_pairs':15,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
