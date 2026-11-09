#!/usr/bin/env python3
"""Seal the object-removal/destruction increment; full interface goal stays active.
O(artifact bytes+report links) time,O(largest artifact+manifest) space.
"""
import json,re,ast,base64,zlib
from pathlib import Path
from validate_daemon_object_consumers_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'original_source_spans_checked':18,'original_fixups_checked':138,'exhaustive_bank_inputs_checked':1024,'dispatch_slots_checked':6,'SMT_file_queries_unsat':34,'rebuilt_source_obligations_unsat':17,'source_lift_visits':143,'raw_stage_prefixes_matched':18,'source_opcodes_checked':740553,'key_owner_effects_checked':273,'payload_owner_effects_checked':67,'object_owner_effects_checked':20208,'overwrite_bytes_verified':20056,'key_clear_and_counter_paths_checked':23,'completed_cleanup_cases_checked':27,'continuation_source_visits':740553,'private_byte_origins_retained':2076,'API_byte_origins_retained':117320,'independent_A64_replays':108,'fresh_composed_replays':2,'exhaustive_byte_A64_cases':512,'exhaustive_byte_A64_source_visits':13312,'live_IDB_ranges_checked':10,'live_IDB_raw_bytes_checked':1312,'live_IDB_display_rows_checked':304,'live_IDB_partial_macro_rows':5,'live_IDB_undecoded_byte_rows':8,'literal_allocation_candidates_checked':1}
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r

def main():
 pairs=[('daemon_object_consumers_profiles.json','probe_daemon_object_consumers.py'),('daemon_object_consumers_continuations.json','continue_daemon_object_consumers.py'),('daemon_object_consumers_counters.json','probe_daemon_object_consumers_counters.py'),('daemon_object_consumers_contracts.json','recover_daemon_object_consumers.py'),('daemon_object_consumers_proofs.json','prove_daemon_object_consumers.py'),('daemon_object_consumers_replays.json','replay_daemon_object_consumers.py'),('daemon_object_consumers_counter_replays.json','replay_daemon_object_consumers_counters.py'),('daemon_object_consumers_checks.json','validate_daemon_object_consumers.py'),('daemon_object_consumers_preservation.json','validate_daemon_object_consumers_preservation.py')];raw,p,sup,c,proofs,r1,r2,k,preservation=[checked(n,g)for n,g in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and r1['all_checks_pass']and r2['all_checks_pass']and preservation['all_checks_pass'];assert len(proofs['proofs'])==17 and len(k['isolated_original_body_cases'])==512;assert c['literal_allocation_census']['candidate_continuous_allocation_to_registry']=='unknown'
 for row in p['cases']+sup['cases']:
  t=json.loads(zlib.decompress(base64.b64decode(row['payload_zlib_base64'])));assert all(st['pc']!='0x100a636ec'for st in t['steps'])and all(st['pc']!='0x100a636ec'for st in row['prefix']['source_visits'])
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['original_file'])==r['original_sha256']and sha(ROOT/r['file'])==r['sha256']
 assert len(list(ROOT.glob('daemon_object_consumers_*.smt2')))==34
 binary=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(binary)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert sha(ROOT/'daemon_object_consumers_prior_manifest.json')==BASELINE_SHA;old=read('daemon_object_consumers_prior_manifest.json');changes={r['path']:r for r in preservation['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3536 and preservation['unchanged_prior_artifacts']==3530
 for r in old['files']:assert sha(BASE/r['path'])==(changes[r['path']]['current_sha256']if r['path']in changes else r['sha256']),r['path']
 for r in old['inputs_preserved']:f=BASE/r['path'];assert f.stat().st_size==r['size_bytes']and sha(f)==r['sha256']
 ida=['daemon_object_consumers_live_ida.json','daemon_object_consumers_more_ida.json','daemon_object_consumers_alloc_ida.json']
 for n in ida:assert not read(n)['isError']
 reports=['daemon_object_consumers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for n in reports:
  for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   link=link.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',link)or link.startswith('#'):continue
   f=Path(link.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_object_consumers_quality_gates.json',(n,link);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['OC14','QG7','0x100BDF330','0x100BE0E80','0x100BD9D88','0x100926C0C','0x2F40B33D2E85D192','872 bytes','3,010,164','1,312','counter','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 syntax=0
 for f in ROOT.glob('*daemon_object_consumers*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==11,syntax
 evidence=['Factual source/ABI analysis.','OC1-OC14 specify source,entry,registry,owner,chain,free,sync,phase,unknown-byte,counter,sharing,allocation,IDB and PAC/result premises with probes.','Matched/exhausted removal,head/interior unlink,buffer/object free,overwrite,key/count,result and port implications covered; full goal active.','u8/u32/u64 arithmetic,872-byte span,4096-byte fixture owner,modular counters,linear loop and solver bounds explicit.','Zero-counter fixture behavior separated from occupied-key cases;native type/allocation,field sharing,candidate publisher and caller boundary remain unknown.','18 spans,138 fixups,4 exhaustive banks,17 proof pairs,108 A64 compositions,512 byte-block cases and1312 fresh IDB bytes verified.','Impact-bounded allocator/publication,query-to-IPC,caller frame,buffer ownership and counter/synchronization followups retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(binary),'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'live_IDB_outputs':{n:sha(ROOT/n)for n in ida},'prior_artifacts_checked':3536,'unchanged_prior_artifacts':3530,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_consumers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':17,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
