#!/usr/bin/env python3
"""Seal the registry/head-unlink increment with explicit prior narrative fixes.
O(artifact bytes+links) time, O(largest artifact+manifest) space. Full goal active.
"""
import json,re,ast,zlib,base64
from pathlib import Path
from validate_daemon_registry_lookup_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'source_spans_checked':27,'bounded_frame_slot_census_matches':52,'bounded_ADRP_page_candidates_checked':227,'bias_construction_candidates_checked':3,'saved_annotation_entries_checked':4920,'exhaustive_bank_input_cases':512,'original_fixups_checked':116,'dispatch_slots_checked':18,'SMT_file_queries_unsat':42,'rebuilt_source_obligations_unsat':21,'source_lift_visits':236,'prior_symbolic_representation_relations_unsat':28,'continuous_cases_checked':64,'continuation_source_visits':94308,'private_byte_origins_retained':2320,'API_byte_origins_retained':177424,'new_word_representation_values_checked':128,'outer_scan_read_sequences_checked':64,'inner_scan_read_sequences_checked':64,'selected_index_sequences_checked':64,'source_opcodes_checked':94308,'key_owner_effects_checked':288,'returning_paths_checked':44,'payload_owner_effects_checked':108,'partial_object_paths_checked':20,'object_owner_effects_checked':26,'head_link_replacements_checked':4,'independent_A64_replays':256,'fresh_composed_replays':2,'live_IDB_ranges_checked':12,'live_IDB_raw_bytes_checked':1472,'live_IDB_display_rows_checked':324,'live_IDB_partial_macro_rows':3,'live_IDB_undecoded_byte_rows':4,'IDB_direct_xref_queries_checked':1,'distinct_continuation_retired_opcodes':1722,'distinct_continuation_inspected_opcodes':1724}
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r

def main():
 pairs=[('daemon_registry_lookup_source.json','capture_daemon_registry_lookup.py'),('daemon_registry_lookup_profiles.json','probe_daemon_registry_lookup.py'),('daemon_registry_lookup_payloads.json','probe_daemon_registry_lookup_payloads.py'),('daemon_registry_lookup_contracts.json','recover_daemon_registry_lookup.py'),('daemon_registry_lookup_proofs.json','prove_daemon_registry_lookup.py'),('daemon_registry_lookup_replays.json','replay_daemon_registry_lookup.py'),('daemon_registry_lookup_payload_replays.json','replay_daemon_registry_lookup_payloads.py'),('daemon_registry_lookup_checks.json','validate_daemon_registry_lookup.py'),('daemon_registry_lookup_preservation.json','validate_daemon_registry_lookup_preservation.py')];source,p,ph,c,proofs,r1,r2,k,preservation=[checked(n,g)for n,g in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and r1['all_checks_pass']and r2['all_checks_pass']and preservation['all_checks_pass'];assert len(proofs['proofs'])==21 and c['representation_contract']['prior_copy_narrative_corrected']and not c['representation_contract']['prior_source_proof_artifacts_changed'];assert not c['bounded_writer_graph_complete']
 for row in p['cases']+ph['cases']:
  trace=json.loads(zlib.decompress(base64.b64decode(row['payload_zlib_base64'])));assert all(st['pc']!='0x100a636ec'for st in trace['steps'])and all(st['pc']!='0x100a636ec'for st in row['prefix']['source_visits'])
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['original_file'])==r['original_sha256']and sha(ROOT/r['file'])==r['sha256']
 assert len(list(ROOT.glob('daemon_registry_lookup_*.smt2')))==42
 binary=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(binary)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert sha(ROOT/'daemon_registry_lookup_prior_manifest.json')==BASELINE_SHA;old=read('daemon_registry_lookup_prior_manifest.json');changes={r['path']:r for r in preservation['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3468 and preservation['unchanged_prior_artifacts']==3460
 for r in old['files']:assert sha(BASE/r['path'])==(changes[r['path']]['current_sha256']if r['path']in changes else r['sha256']),r['path']
 for r in old['inputs_preserved']:f=BASE/r['path'];assert f.stat().st_size==r['size_bytes']and sha(f)==r['sha256']
 ida=['daemon_registry_lookup_live_ida.json','daemon_registry_lookup_more_ida.json','daemon_registry_lookup_unlink_ida.json','daemon_registry_lookup_ida_refs.json']
 for n in ida:assert not read(n)['isError']
 reports=['daemon_registry_lookup_report.md','daemon_descriptor_producers_report.md','daemon_mode471c_lifecycle_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for n in reports:
  for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   link=link.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',link)or link.startswith('#'):continue
   f=Path(link.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_registry_lookup_quality_gates.json',(n,link);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['RK14','QG7','0x1009F016C','0x100A264E0','0x1010C67D0','0x1010CA2B0','0x1010C9288','872 bytes','490,896','1,472','header/token','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 for n in reports[1:3]:assert '0x1009F016C'in(BASE/n).read_text()and 'corrects the earlier copy description'in(BASE/n).read_text()
 syntax=0
 for f in ROOT.glob('*daemon_registry_lookup*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==10,syntax
 evidence=['Factual binary/interface analysis.','RK1-RK14 identify source,entry,state,owners,word,API,unknown bytes,object,field meaning,candidate phases,censuses,PAC,IDB and correction premises with probes.','Nested scans,head replacement,partial object fields,precise source boundaries and port implications covered; full goal remains active.','Explicit u32/u64,16/32-byte strides,872-byte minimum,owner bounds,linear scan state and solver limits.','Word copy narrative corrected; raw header semantics,two bounds,conditional mutation,partial paths and native ownership remain separate.','27 spans,116 fixups,2 exhaustive banks,21 proof pairs,256 A64 replays,28 prior symbolic relations and1472 fresh IDB raw bytes verified; undecoded rows explicit.','Impact-bounded object consumers,chain,constructors,record-to-IPC,type/lifetime and alias followups included.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(binary),'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'live_IDB_outputs':{n:sha(ROOT/n)for n in ida},'prior_artifacts_checked':3468,'unchanged_prior_artifacts':3460,'narrative_correction_reports':reports[1:3],'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_registry_lookup_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':21,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
