#!/usr/bin/env python3
"""Seal this descriptor-reader increment; full interface objective remains active.
O(artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import json,re,ast
from pathlib import Path
from validate_daemon_descriptor_readers_preservation import ROOT,BASE,ALLOWED,BASELINE_SHA,sha
EXPECTED={'original_spans_checked':10,'bank_cases_checked':1024,'banks_checked':4,'original_fixups_checked':41,'SMT_queries_unsat':36,'source_proof_pairs_unsat':18,'nonempty_premise_witnesses':3,'source_lift_visits':127,'source_visits_checked':49528,'record_epochs_checked':120,'fixture_transitions_checked':192,'integer_only_X18_free_opcodes_checked':834,'conditional_reader_cases_checked':96,'isolated_guard_cases_checked':4608,'isolated_guard_source_visits':188928,'fresh_independent_guard_cases':16,'fresh_independent_guard_visits':656,'live_IDB_raw_bytes':512,'live_IDB_raw_ranges':4,'live_IDB_display_rows':113,'live_IDB_partial_macro_rows':0,'live_IDB_incoming_data_xrefs':2,'model_API_calls_checked':200,'source_pool_opcodes_checked':834,'independent_A64_reader_cases':96,'fresh_independent_reader_cases':2}
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and q['full_goal_complete']is False
 for dep,h in q.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return q
def main():
 pairs=[('daemon_descriptor_readers_profiles.json','probe_daemon_descriptor_readers.py'),('daemon_descriptor_guard_profiles.json','probe_daemon_descriptor_guard.py'),('daemon_descriptor_readers_contracts.json','recover_daemon_descriptor_readers.py'),('daemon_descriptor_readers_proofs.json','prove_daemon_descriptor_readers.py'),('daemon_descriptor_readers_replays.json','replay_daemon_descriptor_readers.py'),('daemon_descriptor_readers_checks.json','validate_daemon_descriptor_readers.py'),('daemon_descriptor_readers_preservation.json','validate_daemon_descriptor_readers_preservation.py')];p,g,c,proofs,replays,k,preservation=[checked(n,s)for n,s in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and replays['all_checks_pass']and preservation['all_checks_pass'];assert len(proofs['proofs'])==18 and len(proofs['composition_cuts'])==3 and len(proofs['nonempty_premise_witnesses'])==3
 for row in proofs['proofs']:assert row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert sha(ROOT/'daemon_descriptor_readers_prior_manifest.json')==BASELINE_SHA;old=read('daemon_descriptor_readers_prior_manifest.json');changes={r['path']:r for r in preservation['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3302 and preservation['unchanged_prior_artifacts']==3296
 for r in old['files']:assert sha(BASE/r['path'])==(changes[r['path']]['current_sha256']if r['path']in changes else r['sha256']),r['path']
 for r in old['inputs_preserved']:f=BASE/r['path'];assert f.stat().st_size==r['size_bytes']and sha(f)==r['sha256']
 for n in ['daemon_descriptor_readers_live_ida.json','daemon_descriptor_readers_ida_retry.json']:assert not read(n).get('isError')
 reports=['daemon_descriptor_readers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for n in reports:
  for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   link=link.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',link)or link.startswith('#'):continue
   f=Path(link.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_descriptor_readers_quality_gates.json',(n,link);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['DR17','QG7','0x1010C8218','0x10021ECF4','0x100A636EC','0x10021ED90','0x10025F0E8','0x1010B9638','49,528','4,608','57168','160','192','unknown','broader interface investigation remains active']:assert term in report,term
 syntax=0
 for f in sorted(ROOT.glob('*daemon_descriptor*.py')):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==8
 evidence=['Factual technical binary/interface analysis.','DR1-DR17 state source,roots,phases,fixture splices,ABI,alignment,PAC,lifetime,IDB and native limitations with falsification probes.','Local reader/record/guard/stack/cursor contracts and port implications covered; full interface objective active.','Explicit u32/u64 modular arithmetic,little-endian records,byte extents,stack calculation,case products and bounded algorithms.','Record epochs,source-versus-fixture transitions,captured-versus-reread token,count-versus-readiness and unresolved phase/native boundaries separated.','Ten original spans,41 fixups,four exhaustive banks,18 proof pairs,96 independent reader replays,4608 guards,16 fresh guards and512 live IDB bytes verified.','Impact-labeled producer,lifetime,traversal,fallback,frame and xref continuation boundaries retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(source),'new_validation_outputs':{n:sha(ROOT/n)for n,s in pairs},'live_IDB_outputs':{n:sha(ROOT/n)for n in ['daemon_descriptor_readers_live_ida.json','daemon_descriptor_readers_ida_retry.json']},'report_sha256':{n:sha(BASE/n)for n in reports},'prior_artifacts_checked':3302,'unchanged_prior_artifacts':3296,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'live_IDB_automatic_analysis_complete':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_readers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':18,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
