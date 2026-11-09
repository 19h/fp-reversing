#!/usr/bin/env python3
"""Seal the scoped PRNG consumer increment; no native target execution.
O(artifact bytes+report links) time, O(largest JSON+manifest) space.
"""
import json,re
from pathlib import Path
from validate_daemon_prng_output_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha

EXPECTED={'original_source_spans':15,'original_fixups_verified':15,'exhaustive_bank_inputs':256,'live_IDB_rows_matched':285,'original_path_pool_rows':377,'path_pool_rows_live_IDB_covered':231,'source_proof_pairs_unsat':24,'nonempty_premise_witnesses':7,'outside_domain_alignment_probes':1,'constructor_key_liveness_instructions':221,'symbolic_contexts':4,'symbolic_source_visits':106664,'SSA_definitions_checked':85728,'original_visit_bytes_checked':426656,'finite_read_certificates_checked':4992,'nonzero_seed_guard_paths_checked':4,'independent_full_A64_replays':8,'fresh_full_A64_replays':2}
TOTALS={'source_visits':2633576,'read_bytes_checked':2247320,'register_effects_checked':2341128,'write_bytes_checked':786464,'source_write_effects_checked':164016,'unknown_copied_bytes_checked':1728,'NZCV_effects_checked':91824}
NEW={'source_visits':213328,'read_bytes_checked':204528,'register_effects_checked':182944,'write_bytes_checked':41632,'source_write_effects_checked':10312,'unknown_copied_bytes_checked':0,'NZCV_effects_checked':10064}
def read(n):return json.loads((ROOT/n).read_text())
def check(n,generator):
 q=read(n);assert q['generator_sha256']==sha(ROOT/generator)and not q['full_goal_complete'],n
 for dep,h in q.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return q

def main():
 c=check('daemon_prng_output_contracts.json','recover_daemon_prng_output.py')
 k=check('daemon_prng_output_checks.json','validate_daemon_prng_output.py')
 q=check('daemon_prng_output_proofs.json','prove_daemon_prng_output.py')
 profiles=check('daemon_prng_output_profiles.json','probe_daemon_prng_output.py')
 replays=check('daemon_prng_output_replays.json','replay_daemon_prng_output.py')
 provenance=check('daemon_prng_output_provenance.json','audit_daemon_prng_output_provenance.py')
 p=check('daemon_prng_output_preservation.json','validate_daemon_prng_output_preservation.py')
 assert k['verified_counts']==EXPECTED and k['all_checks_pass']and p['all_checks_pass']and provenance['all_checks_pass']
 assert k['independent_A64_totals']==TOTALS and k['new_increment_A64_totals']==NEW
 assert k['source_lift_counts']==q['source_lift_counts']and sum(q['source_lift_counts'].values())==247
 assert len(q['proofs'])==24 and q['constructor_key_liveness']['instructions_checked']==221
 assert not q['constructor_key_liveness']['overwrites']and not q['constructor_key_liveness']['branches_or_calls']
 for row in q['proofs']:
  assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 cases=replays['cases'];assert len(cases)==8
 for field,expected in [('verified_counts',TOTALS),('new_verified_counts',NEW)]:
  assert {key:sum(case[field][key]for case in cases)for key in expected}==expected
 older=read('daemon_seed_material_replays.json')['cases'];offsets=set()
 for case in cases:
  matches=[old for old in older if all(case[key]==old[key]for key in ('input','values','pattern'))];assert len(matches)==1
  old=matches[0];offsets.add(int(old['frontier']['selected_read_address'],16)-(int(old['material_record']['address'],16)-0x670+0x6d8))
  assert case['finite_reads_checked']==1248 and case['API_models_count']==4
  assert not case['native_target_executed']and not case['native_entropy_or_time_executed']
 assert offsets=={0,4}
 assert len(provenance['contexts'])==4
 for context in provenance['contexts']:
  h=context['writer_histories'];assert len(h)==5
  publication=h['global_buffer_pointer'];assert len(publication)==1 and publication[0]['pc']=='0x1002fb820'
  for name in ('first_buffer_word','second_buffer_word'):
   assert len(h[name])==4 and all(row['pc']=='0x1004c8398'and row['write_size_bytes']==1 and row['source_visit_index']<publication[0]['source_visit_index']for row in h[name])
  assert h['frame1E0'][-1]['pc']=='0x1002c5934'
 assert sha(ROOT/'daemon_prng_output_prior_manifest.json')==BASELINE_SHA
 old=read('daemon_prng_output_prior_manifest.json');changed={row['path']:row for row in p['allowed_existing_changes']}
 assert set(changed)==ALLOWED and len(old['files'])==3015 and p['unchanged_prior_artifacts']==3009
 for row in old['files']:
  assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 links=0
 for name in ['daemon_prng_output_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path
   assert path.exists()or path==ROOT/'daemon_prng_output_quality_gates.json',(name,target);links+=1
 report=(BASE/'daemon_prng_output_report.md').read_text()
 for term in ['PG14','QG7','unknown','0x1010C8278','0x1010C67DC','0x1010C8258','0x100444D6C','0x100350624','0x10029A130','0x1003505B8','0x1004C8398','0x1002C5934','0x823819558515CFBD','0xEBBDCC7D8FD10B17','5119','5121','128','126','4,992','2,633,576','213,328','285','231','0x9908B0DF','40 bytes','512 bytes','Mach','full interface investigation remains active']:
  assert term in report,term
 evidence=['Factual technical analysis.','PG1-PG14 retain assumptions, dependencies and falsification probes.','Twist/temper, two buffer updates, comparison record, counter and loop contracts covered; full objective active.','u32/u64 operations, little-endian byte widths, 512-byte loop, 5121-operation conditional cycle and bounded software counts explicit.','Executed/static/native coverage, temporal scratch reuse, selected twist schedule and unknown writers distinguished.','Pinned source/fixups, 285 IDB rows, 24 source proof pairs, 4992 finite-read certificates, byte provenance and eight full-prefix A64 replays.','Impact-labeled bounded continuation table.']
 outputs=['daemon_prng_output_'+name+'.json'for name in ['contracts','checks','profiles','replays','proofs','provenance','live_ida','preservation']]+['daemon_prng_twist_live_ida.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':e}for j,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':TOTALS,'new_increment_A64_totals':NEW,'source_lift_counts':q['source_lift_counts'],'initial_table_choice_offsets':sorted(offsets),'byte_writer_histories_checked':20,'checked_report_links':links,'prior_artifacts_checked':3015,'unchanged_prior_artifacts':3009,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{name:sha(ROOT/name)for name in outputs},'source_sha256':sha(source),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'daemon_prng_output_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({'scoped_gates_pass':True,'checked_report_links':links,'source_proof_pairs':24,'full_A64_replays':8,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
