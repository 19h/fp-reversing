#!/usr/bin/env python3
"""Seal predecessor/classifier/marker provenance and the report correction.
O(owned artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_creation_predecessors_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_creation_predecessors_contracts.json','recover_daemon_creation_predecessors.py'),('daemon_creation_predecessors_proofs.json','prove_daemon_creation_predecessors.py'),('daemon_creation_predecessors_replays.json','replay_daemon_creation_predecessors.py'),('daemon_creation_predecessors_checks.json','validate_daemon_creation_predecessors.py'),('daemon_creation_predecessors_preservation.json','validate_daemon_creation_predecessors_preservation.py')];c,p,r,k,keep=[checked(n,g)for n,g in pairs];assert all(x['all_checks_pass']for x in [r,k,keep])and k['correction_verified']and not k['reader_B_reached'];v=k['verified_counts']
 expected={'original_source_spans_checked':11,'literal_0156_fragment_spans_checked':18,'original_fixups_checked':25,'exhaustive_bank_inputs_checked':512,'retained_contexts_checked':18,'bounded_excluded_fragment_starts':13,'unexcluded_other_fragment_starts':4,'selected_classifier_chain_starts':1,'SMT_file_queries_unsat':46,'rebuilt_source_obligations_unsat':23,'source_lift_visits':311,'persisted_A64_cases':819,'persisted_A64_source_visits':105796,'persisted_A64_cases_freshly_recomputed':819,'additional_A64_cases':4,'additional_A64_source_visits':719,'distinct_retired_opcodes_within_checked_spans':323,'live_IDB_ranges_checked':4,'live_IDB_raw_bytes_checked':704};assert v==expected
 assert len(p['proofs'])==23 and len(list(ROOT.glob('daemon_creation_predecessors_*.smt2')))==46
 for row in p['proofs']:assert row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256']
 census=c['literal_0156_census'];assert sum(x['branch_operands']=='x8, x17'for x in census)==2;assert sum(x['name'].startswith('incompatible_whole_fragment_')for x in p['proofs'])==8 and len(k['constant_fragment_exclusions'])==2
 assert sha(ROOT/'daemon_creation_predecessors_prior_manifest.json')==BASELINE_SHA;old=read('daemon_creation_predecessors_prior_manifest.json');changed={x['path']:x for x in keep['allowed_existing_changes']};assert len(old['files'])==3643 and keep['unchanged_prior_artifacts']==3636 and set(changed)==ALLOWED and len(ALLOWED)==7
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 prior_report='daemon_object_creation_report.md';historical=read('daemon_object_creation_quality_gates.json')['report_sha256'][prior_report];assert historical==changed[prior_report]['prior_sha256'];corrected=(BASE/prior_report).read_text();assert 'W22=0817' in corrected and 'callback `0x100B353A4`'in corrected and 'W22=40C7 belongs to a separate source-proof fixture'in corrected
 reports=['daemon_creation_predecessors_report.md',prior_report,'obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_creation_predecessors_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['CP12','QG7','2..200','0x1010C8254','0x1010C8238','W22=0817','0x100B353A4','SP+2FAC','819','105,796','704','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 syntax=0
 for f in ROOT.glob('*daemon_creation_predecessors*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==6
 assert not read('daemon_creation_predecessors_ida_bytes.json').get('isError')
 evidence=['Factual source,frame,registry and ABI analysis.','CP1-CP12 delimit source identity,cutpoint/frame,mode,presence/classifier,owners,epoch,bank roots,context preservation,census,PAC,journals and layout with falsification probes.','Selected predecessor/classifier,marker/reset globals,census and reporting correction covered; full interface goal remains active.','u32/u64 modular equations,199 admitted classifier values,4/4/8-byte writes,704 IDB bytes,complexity and30 s solver limits explicit.','Retained0817 callback state separated from40C7 proof fixture;49C journals separated from candidate49D continuation; native meaning and construction unknown.','11 source spans,18 census spans,25 fixups,2 exhaustive banks,23 proof pairs,819 recomputed A64 cases and704 fresh IDB bytes verified.','Impact-bounded continuation49D production,classifier consumers,reset/synchronization/marker composition,object publication and descriptor layout retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':p['source_lift_counts'],'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'source_sha256':sha(source),'prior_artifacts_checked':3643,'unchanged_prior_artifacts':3636,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'superseded_report_snapshot':{'path':prior_report,'historical_gate_report_sha256':historical,'corrected_report_sha256':sha(BASE/prior_report),'reason':'Proof-fixture phase40C7 was described as executed removal state; source journals show0817 and callbackB353A4.','old_gate_artifact_modified':False},'live_IDB_outputs':{'daemon_creation_predecessors_ida_bytes.json':sha(ROOT/'daemon_creation_predecessors_ida_bytes.json')},'inputs_preserved':old['inputs_preserved'],'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_creation_predecessors_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':23,'checked_links':links,'correction_verified':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
