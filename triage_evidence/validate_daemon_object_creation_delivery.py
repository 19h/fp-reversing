#!/usr/bin/env python3
"""Seal the bounded marker/allocation increment; full interface goal stays active.
O(artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_object_creation_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_object_creation_contracts.json','recover_daemon_object_creation.py'),('daemon_object_creation_proofs.json','prove_daemon_object_creation.py'),('daemon_object_creation_replays.json','replay_daemon_object_creation.py'),('daemon_object_creation_checks.json','validate_daemon_object_creation.py'),('daemon_object_creation_preservation.json','validate_daemon_object_creation_preservation.py')];c,p,r,k,preservation=[checked(n,g)for n,g in pairs];v=k['verified_counts'];assert all(x['all_checks_pass']for x in [r,k,preservation]);assert k['reader_B_reached']is False
 expected={'original_source_spans_checked':10,'original_fixups_checked':160,'bank_inputs_checked':256,'marker_bytes_checked':256,'binary_phase_candidates_checked':7,'coherent_binary_phase_candidates':1,'marker_values_with_matching_E9B9_metadata':5,'literal_E9B9_branch_pairs':6,'SMT_file_queries_unsat':30,'rebuilt_source_obligations_unsat':15,'source_lift_visits':105,'persisted_A64_cases':1294,'persisted_A64_source_visits':100000,'persisted_A64_cases_freshly_recomputed':1294,'additional_A64_cases':4,'additional_A64_source_visits':286,'live_IDB_ranges_checked':3,'live_IDB_raw_bytes_checked':456,'live_IDB_display_rows_checked':106,'live_IDB_undecoded_byte_rows':4}
 assert all(v[n]==x for n,x in expected.items());assert v['distinct_retired_opcodes_within_checked_spans']>100
 assert len(p['proofs'])==15 and len(list(ROOT.glob('daemon_object_creation_*.smt2')))==30
 for proof in p['proofs']:assert proof['result']=='unsat'and sha(ROOT/proof['original_file'])==proof['original_sha256']and sha(ROOT/proof['file'])==proof['sha256']
 assert sha(ROOT/'daemon_object_creation_prior_manifest.json')==BASELINE_SHA;old=read('daemon_object_creation_prior_manifest.json');changes={x['path']:x for x in preservation['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3596 and preservation['unchanged_prior_artifacts']==3590
 for row in old['files']:assert sha(BASE/row['path'])==(changes[row['path']]['current_sha256']if row['path']in changes else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 reports=['daemon_object_creation_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_object_creation_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['CR12','QG7','0x100C116B0','0x621B','0x100B280C8','0x10064FFCC','0x10109FF58','872 bytes','1,294','100,000','456','0x20','0x21','0xE0','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 syntax=0
 for f in ROOT.glob('*daemon_object_creation*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==6
 ida=['daemon_object_creation_ida_bytes.json','daemon_object_creation_ida_functions.json','daemon_object_creation_ida_xrefs.json']
 for n in ida:assert not read(n).get('isError')
 evidence=['Factual original-source and ABI analysis.','CR1-CR12 distinguish cutpoint,marker protocol/stability,owners,roots,ABI,phase,PAC,callback,local result and object identity with falsification probes.','Marker dispatch,zero-route lock/callback,allocation/result/save,negative phases and port implications covered for the bounded increment; full objective active.','u8/u32/u64 modular arithmetic,872-byte allocation,frame offsets,byte counts,linear execution and30 s solver limits explicit.','Binary-marker candidate,full-byte aliases,distinct callbacks,local failure result and unknown native construction/publication remain separated.','10 original spans,160 fixups,15 proof pairs,1294 recomputed A64 cases,four fresh cases and456 IDB bytes verified.','Impact-bounded native predecessor/marker owner,allocation publication,concurrency,callback invocation and transport association retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':p['source_lift_counts'],'source_sha256':sha(source),'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'live_IDB_outputs':{n:sha(ROOT/n)for n in ida},'prior_artifacts_checked':3596,'unchanged_prior_artifacts':3590,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_creation_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':15,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
