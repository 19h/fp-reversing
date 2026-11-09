#!/usr/bin/env python3
"""Seal context-lock/sealing evidence; full daemon/kext interface goal active.
O(artifact bytes+report links) time, O(largest artifact+manifest) space.
No native target/API/authentication or IDB mutation executes.
"""
import json,re,ast
from pathlib import Path
from validate_daemon_context_lock_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'preserved_success_prefix_visits': 3959, 'snapshot_regions_checked': 231, 'snapshot_bytes_checked': 1093632, 'source_spans_checked': 14, 'original_fixups_checked': 51, 'SMT_queries_unsat': 36, 'source_proof_pairs_unsat': 18, 'nonempty_premise_witnesses': 4, 'live_IDB_raw_ranges': 4, 'live_IDB_raw_bytes': 640, 'live_IDB_display_rows': 139, 'live_IDB_macro_rows_partial_display_bytes': 3, 'conditional_reader_candidates': 2, 'source_visits_checked': 43843, 'outside_owner_failure_paths': 5, 'opaque_API_memory_bytes_checked': 10320, 'source_cleared_headers_before_initializer': 21, 'callback_epilogue_paths': 6, 'array_records_initialized': 20, 'array_stride_bytes': 48, 'array_source_bytes_defined': 960, 'array_source_stores': 160, 'rejoined_known_lock_creator_calls': 2, 'retained_context_codec_cases': 13, 'varied_context_codec_cases': 33, 'total_isolated_context_codec_cases': 46, 'context_extent_bytes': 552, 'context_words': 69, 'word_swaps_per_context': 68, 'raw_lock_token_field_offset_bytes': 8, 'encoded_lock_token_field_offset_bytes': 248, 'header_self_text_u32_reads_checked': 104, 'retained_header_codec_contracts_checked': 13, 'fresh_isolated_header_codec_cases': 2, 'conditional_paths_checked': 13, 'source_pool_opcodes_checked': 1182, 'source_unknown_byte_reads': 0, 'arbitrary_API_bytes_retained': 38040, 'modeled_API_calls_checked': 47, 'modeled_malloc_calls': 26, 'modeled_initializer_calls': 21, 'source_lift_visits': 110, 'X18_free_source_opcodes_checked': 1182, 'source_gate_targets_checked': 8, 'independent_A64_cases': 52, 'fresh_A64_source_visits': 7424, 'fresh_A64_cases': 2}

def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and q['full_goal_complete']is False
 for dep,h in q.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return q

def main():
 pairs=[('daemon_context_lock_snapshot.json','capture_daemon_context_lock.py'),('daemon_context_lock_profiles.json','probe_daemon_context_lock.py'),('daemon_context_lock_success.json','probe_daemon_context_lock_success.py'),('daemon_context_lock_contracts.json','recover_daemon_context_lock.py'),('daemon_context_lock_proofs.json','prove_daemon_context_lock.py'),('daemon_context_lock_replays.json','replay_daemon_context_lock.py'),('daemon_context_seal_contracts.json','recover_daemon_context_seal.py'),('daemon_context_seal_checks.json','validate_daemon_context_seal.py'),('daemon_context_lock_checks.json','validate_daemon_context_lock.py'),('daemon_context_lock_preservation.json','validate_daemon_context_lock_preservation.py')]
 snap,paths,extended,c,proofs,replays,seals,sealchecks,k,p=[checked(n,g)for n,g in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and p['all_checks_pass']and replays['all_checks_pass']and sealchecks['all_checks_pass']
 scratch=checked('daemon_context_stack_scratch_checks.json','validate_daemon_context_stack_scratch.py');assert scratch['all_checks_pass']and scratch['verified_counts']['conditional_paths']==13 and scratch['verified_counts']['modeled_API_calls']==47 and scratch['verified_counts']['other_post_API_reads_of_prior_lower_stack']==0
 assert extended['preceding_prefix_identical']and extended['preceding_prefix_source_visits']==3959 and len(proofs['proofs'])==18 and sum(proofs['source_lift_counts'].values())==110 and len(proofs['nonempty_premise_witnesses'])==4
 for row in proofs['proofs']:assert row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha(ROOT/'daemon_context_lock_prior_manifest.json')==BASELINE_SHA;old=read('daemon_context_lock_prior_manifest.json');changes={r['path']:r for r in p['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3237 and p['unchanged_prior_artifacts']==3231
 for row in old['files']:assert sha(BASE/row['path'])==(changes[row['path']]['current_sha256']if row['path']in changes else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 for n in ['daemon_context_lock_live_ida.json','daemon_context_lock_ida_bytes.json']:assert not read(n).get('isError')
 links=0;reports=['daemon_context_lock_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
 for name in reports:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   f=Path(target.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_context_lock_quality_gates.json',(name,target);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['KL16','QG7','0x1010C8218','0x1010C9298','0x100492644','0x1003AE608','0x10038EB5C','0x100407458','0x10030631C','552','69','248','960','48','20','0x78396E8D','0xE5F6A0000600F0B1','175,372','7424','38040','640','139','unknown','full investigation remains active']:assert term in report,term
 syntax=0
 for f in ROOT.glob('*context*lock*.py'):
  if f.name.startswith(('capture_daemon_context_lock','probe_daemon_context_lock','recover_daemon_context_lock','prove_daemon_context_lock','replay_daemon_context_lock','validate_daemon_context_lock','daemon_context_lock')):ast.parse(f.read_text(),filename=str(f));syntax+=1
 for n in ['recover_daemon_context_seal.py','validate_daemon_context_seal.py']:f=ROOT/n;ast.parse(f.read_text(),filename=str(f));syntax+=1
 evidence=['Factual technical binary/interface analysis.','KL1-KL16 retain source/state/ABI/heap/PAC/representation/candidate/IDB assumptions and falsification probes.','Creator gates, descriptor/array layout,552-byte codec, lock-token movement, status/owner boundaries and known synchronization rejoin covered; full objective active.','u8/u32/u64 wrapping,20*48=960,34*16+2*4=552,69*8=552,owner extents and linear codec complexity explicit.','Raw/encoded field lifetime, creator publication versus codec stores, opaque initializer outputs versus defined array, partial publication, callback return token and IDB macro display rows distinguished.','Original source1182 opcodes,14 spans,51 fixups,18 proof pairs,52 A64 replays,46 isolated codec cases,fresh replays and640 live IDB raw bytes verified; native behavior unknown.','Impact-labeled continuation table preserves full daemon/kext/deeper interface objective.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(source),'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'post_call_stack_scratch_checks':scratch['verified_counts'],'stack_scratch_output_sha256':sha(ROOT/'daemon_context_stack_scratch_checks.json'),'live_IDB_outputs':{n:sha(ROOT/n)for n in ['daemon_context_lock_live_ida.json','daemon_context_lock_ida_bytes.json']},'report_sha256':{n:sha(BASE/n)for n in reports},'prior_artifacts_checked':3237,'unchanged_prior_artifacts':3231,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'live_IDB_automatic_analysis_complete':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':18,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
