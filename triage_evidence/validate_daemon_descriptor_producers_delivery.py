#!/usr/bin/env python3
"""Seal the mode471C/cursor/stack-probe increment; full interface goal active.
O(artifact bytes+report links) time,O(largest artifact+manifest) space.
"""
import json,re,ast
from pathlib import Path
from validate_daemon_descriptor_producers_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'installed_cache_files_hashed':3,'installed_cache_helper_bytes_checked':108,'original_reexport_aliases_checked':1,'libSystem_reexport_edges_checked':1,'original_source_spans_checked':11,'exhaustive_bank_input_cases':3072,'selection_rules_checked':12,'distinct_bank_identities_checked':7,'original_fixups_checked':62,'nonzero_import_addends_checked':1,'SMT_queries_unsat':46,'source_proof_pairs_unsat':23,'source_lift_visits':192,'nonempty_premise_witnesses':2,'continuous_prefix_source_visits':21096,'continuous_prefix_cases':48,'returning_null_cases':24,'private_unknown_write_effects_retained':40,'retained_word_expression_checks':4,'arbitrary_byte_continuations':4,'arbitrary_byte_continuation_visits':2844,'unknown_byte_origins_retained':144,'distinct_retired_daemon_opcodes_checked':1169,'distinct_cache_helper_opcodes_in_compositions':26,'distinct_inspected_daemon_opcodes_checked':1170,'additional_unretired_boundary_opcodes_checked':1,'cache_helper_instruction_rows_checked':27,'fresh_original_helper_cases':32,'fresh_original_helper_visits':608,'exact_4096_duplicate_touch_cases':2,'independent_A64_replay_cases':64,'fresh_independent_composed_replays':2,'live_IDB_raw_ranges':6,'live_IDB_raw_bytes':1024,'live_IDB_display_rows':211,'live_IDB_partial_macro_rows':7}
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_descriptor_producers_source.json','capture_daemon_descriptor_producers.py'),('daemon_descriptor_producers_profiles.json','probe_daemon_descriptor_producers.py'),('daemon_descriptor_producers_copies.json','continue_daemon_descriptor_producers.py'),('daemon_descriptor_producers_contracts.json','recover_daemon_descriptor_producers.py'),('daemon_descriptor_producers_proofs.json','prove_daemon_descriptor_producers.py'),('daemon_descriptor_producers_replays.json','replay_daemon_descriptor_producers.py'),('daemon_descriptor_producers_checks.json','validate_daemon_descriptor_producers.py'),('daemon_descriptor_producers_preservation.json','validate_daemon_descriptor_producers_preservation.py')];source,p,co,c,proofs,replays,k,preservation=[checked(n,g)for n,g in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and replays['all_checks_pass']and preservation['all_checks_pass'];assert not c['reader_B_reached']and not k['reader_B_reached'];assert len(proofs['proofs'])==23 and len(proofs['composition_cuts'])==3
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['original_file'])==r['original_sha256']and sha(ROOT/r['file'])==r['sha256']
 binary=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(binary)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert sha(ROOT/'daemon_descriptor_producers_prior_manifest.json')==BASELINE_SHA;old=read('daemon_descriptor_producers_prior_manifest.json');changes={r['path']:r for r in preservation['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3359 and preservation['unchanged_prior_artifacts']==3353
 for r in old['files']:assert sha(BASE/r['path'])==(changes[r['path']]['current_sha256']if r['path']in changes else r['sha256']),r['path']
 for r in old['inputs_preserved']:p=BASE/r['path'];assert p.stat().st_size==r['size_bytes']and sha(p)==r['sha256']
 IDB=['daemon_descriptor_producers_live_ida.json','daemon_descriptor_producers_more_ida.json','daemon_descriptor_producers_xrefs_ida.json']
 for n in IDB:assert not read(n).get('isError')
 reports=['daemon_descriptor_producers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for n in reports:
  for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   link=link.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',link)or link.startswith('#'):continue
   f=Path(link.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_descriptor_producers_quality_gates.json',(n,link);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['DP18','QG7','0x10039C894','0x100ABCA64','0x100A59BB4','0x100A636EC','0x1010C67C0','0x1010C8218','0x6AE8388F','0x74C29D88','0xE3B88695C0D52DBC','39,576','1,024','36','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 syntax=0
 for f in ROOT.glob('*daemon_descriptor_producers*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==9
 evidence=['Factual binary/interface analysis.','DP1-DP18 retain source,entry,frame,cache,TLS,PAC,opaque bytes,record,relocation,IDB,census,retirement and lifetime assumptions with falsification probes.','Mode471C record,continuous cursor/callee,original helper ABI,word transform,distinct creator destination and port implications covered; full objective active.','Explicit u32/u64 arithmetic,24/8-byte extents,160-byte cursor,16..256-byte reserve,57168-byte frame,helper page touches and algorithm bounds.','Native versus private state,opaque input versus prior writes,distinct global cells,source versus inspected call,cache version and unreached reader phases remain separated.','Eleven source spans,62 fixups,12 exhaustive rules,23 proof pairs,64 A64 replays,32 helper cases,three consumed cache hashes and1024 live IDB raw bytes verified.','Impact-bounded phase,lock,allocation,thread,relocation,adapter and census continuations retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(binary),'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'live_IDB_outputs':{n:sha(ROOT/n)for n in IDB},'report_sha256':{n:sha(BASE/n)for n in reports},'prior_artifacts_checked':3359,'unchanged_prior_artifacts':3353,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':23,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
