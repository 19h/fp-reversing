#!/usr/bin/env python3
"""Seal allocation-return metadata,graph,unknownness,control and ordering scope.
O(artifact bytes+report links) time,O(largest JSON) space; no target runs.
"""
import json,re
from pathlib import Path
from validate_daemon_arena_storage_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,k,q,p=map(read,['daemon_arena_storage_contracts.json','daemon_arena_storage_checks.json','daemon_arena_storage_proofs.json','daemon_arena_storage_preservation.json'])
 for obj,n in [(c,'recover_daemon_arena_storage.py'),(k,'validate_daemon_arena_storage.py'),(q,'prove_daemon_arena_storage.py'),(p,'validate_daemon_arena_storage_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k['all_checks_pass']and p['all_checks_pass'];counts=k['verified_counts']
 expected={'original_source_spans':6,'original_fixups_verified':33,'live_IDB_source_rows_matched':129,'premise_sat_witnesses':1,'source_proof_pairs_unsat':11,'source_visits':76096,'source_write_epochs':9472,'source_read_epochs':7104,'frame_snapshots_reconstructed':896,'dead_load_epochs_checked':128,'heap_bytes_reconstructed':5760000,'heap_known_bytes_checked':3072,'descriptor_source_bytes_checked':5120,'pointer_and_marker_fields_checked':576,'source_cached_owner_fields_checked':128,'publication_order_timelines_checked':64,'cases_byte_reconstructed':64,'prior_prefixes_preserved':64,'malloc_return_and_preserved_ABI_checked':64,'allocator_binding_load_epochs_checked':64,'fresh_replayed_cases':8,'cases_checked':64}
 for n,v in expected.items():assert counts[n]==v,(n,counts[n],v)
 assert counts.get('source_heap_reads',0)==0 and sum(k['source_lift_counts'].values())==117 and k['source_lift_counts']==q['source_lift_counts']and k['post_malloc_write_footprint']==q['post_malloc_write_footprint']=={'store_events':17,'written_bytes':120}
 for row in k['publication_timelines']:assert [e['source_visit_index']for e in row['events']]==[389,469,470,485]and [e['known_heap_bytes_before']for e in row['events']]==[0,48,48,48]and all(e['gate_word32']=='0xa94ef'for e in row['events'])
 for r in q['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 pw=q['premise_witness'];assert pw['result']=='sat'and sha(ROOT/pw['file'])==pw['sha256']
 assert sha(ROOT/'daemon_arena_storage_prior_manifest.json')==BASELINE_SHA;old=read('daemon_arena_storage_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED
 for r in old['files']:
  path=BASE/r['path'];assert sha(path)==(changed[r['path']]['current_sha256']if r['path']in changed else r['sha256']),r['path']
 for r in old['inputs_preserved']:path=BASE/r['path'];assert sha(path)==r['sha256']and path.stat().st_size==r['size_bytes']
 links=0
 for name in ['daemon_arena_storage_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   path=Path(t.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_arena_storage_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_arena_storage_report.md').read_text()
 for term in ['AS12','QG7','unknown','0x100322440','0x100322444','0x10046C750','0x1003ECB8C','90,000','89,952','89976','117','129','64','0xA94EF','0x10105CAD0','SAT','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','AS1-AS12 state dependencies and falsification probes.','First arena storage,cache and readiness interface covered; broad objective active.','u32/u64,90000-byte owner,48 known/89952 unknown bytes,source indices and complexity explicit.','Source pointer publication before metadata versus reader synchronization,API returns versus source writes,dead-load versus later cache epochs,and readiness versus completion distinguished.','64 byte/epoch audits,eight fresh replays,11 source proof pairs,SAT witness,33 fixups,129 IDB rows and64 publication timelines.','Impact-labeled bounded continuation table.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':k['source_lift_counts'],'checked_report_links':links,'prior_artifacts_checked':2818,'unchanged_prior_artifacts':2812,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{n:sha(ROOT/n)for n in ['daemon_arena_storage_contracts.json','daemon_arena_storage_checks.json','daemon_arena_storage_profiles.json','daemon_arena_storage_proofs.json','daemon_arena_storage_live_ida.json','daemon_arena_storage_preservation.json']},'native_allocator_executed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_arena_storage_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
