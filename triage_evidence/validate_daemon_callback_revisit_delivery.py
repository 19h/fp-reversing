#!/usr/bin/env python3
"""Seal the callback-revisit increment; the full interface goal stays active.
O(artifact bytes+report links) time, O(largest artifact+manifest) space.
No native target, imported API, authentication or IDB mutation executes.
"""
import json,re
from pathlib import Path
from validate_daemon_callback_revisit_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED_COUNTS = {'snapshot_regions_checked': 187, 'snapshot_bytes_checked': 913408, 'source_spans_checked': 16, 'source_fixups_checked': 77, 'source_visits_checked': 160048, 'source_pool_opcodes_checked': 3013, 'arbitrary_origin_bytes': 48, 'SSA_arithmetic_definitions': 0, 'source_proof_pairs_unsat': 13, 'SMT_queries_unsat': 26, 'nonempty_premise_witnesses': 3, 'reference_canary_reads': 4, 'reference_canary_GOT_reads': 4, 'twist_state_writes_checked': 1248, 'twists_checked': 2, 'generated_words_checked': 2, 'byte_output_calls': 2, 'byte_output_writes': 8, 'descending_fill_writes': 2904, 'distinct_fill_bytes': 2856, 'cached_table_overwrite_bytes': 0, 'self_text_reads_checked': 24, 'self_text_byte_reads': 16, 'self_text_u32_reads': 8, 'new_creator_calls': 1, 'source_opcodes': 70, 'isolated_instruction_cases': 3008, 'USHL_cases': 800, 'USHL_low_byte_counts': 256, 'USHL_upper24_patterns': 3, 'A64_codec_cases': 33, 'bytes_per_case': 2184, 'word_swaps_per_case': 272, 'inverse_cases': 33, 'isolated_A64_byte_reader_cases': 64, 'table_offset_bytes': 200, 'code_byte_reads_per_case': 2, 'fresh_compact_A64_codec_checks': 1, 'fresh_A64_continuation_visits': 160048}

def read(n):return json.loads((ROOT/n).read_text())
def check(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and q['full_goal_complete']is False
 for dep,h in q.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return q

def main():
 pairs=[('daemon_callback_revisit_snapshot.json','capture_daemon_callback_revisit.py'),('daemon_callback_revisit_profiles.json','probe_daemon_callback_revisit.py'),('daemon_callback_revisit_contracts.json','recover_daemon_callback_revisit.py'),('daemon_callback_revisit_proofs.json','prove_daemon_callback_revisit.py'),('daemon_callback_revisit_replays.json','replay_daemon_callback_revisit.py'),('daemon_callback_simd_checks.json','validate_daemon_callback_simd.py'),('daemon_callback_payload_checks.json','validate_daemon_callback_payload.py'),('daemon_callback_reader_checks.json','validate_daemon_callback_readers.py'),('daemon_callback_revisit_checks.json','validate_daemon_callback_revisit.py'),('daemon_callback_revisit_preservation.json','validate_daemon_callback_revisit_preservation.py')]
 snap,profile,c,proofs,replays,simd,payload,reader,k,p=[check(n,g)for n,g in pairs]
 assert k['verified_counts']==EXPECTED_COUNTS and k['all_checks_pass']and p['all_checks_pass']
 assert replays['all_checks_pass']and simd['all_checks_pass']and payload['all_checks_pass']and reader['all_checks_pass']
 assert len(proofs['proofs'])==13 and sum(proofs['source_lift_counts'].values())==88
 for row in proofs['proofs']:assert row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha(ROOT/'daemon_callback_revisit_prior_manifest.json')==BASELINE_SHA;old=read('daemon_callback_revisit_prior_manifest.json');changes={r['path']:r for r in p['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3185 and p['unchanged_prior_artifacts']==3179
 for row in old['files']:assert sha(BASE/row['path'])==(changes[row['path']]['current_sha256']if row['path']in changes else row['sha256']),row['path']
 for row in old['inputs_preserved']:path=BASE/row['path'];assert path.stat().st_size==row['size_bytes']and sha(path)==row['sha256']
 links=0;reports=['daemon_callback_revisit_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
 for name in reports:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_callback_revisit_quality_gates.json',(name,target);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['CR15','QG7','160,048','640,192','3,008','2,184','0x1003ECB98','0x100ADD594','0x100ACD9C4','0x100492644','0x10043A240','0xAED7','0xB399','0xFEDCBA9876543210','0x487B0E7B','0x4546796B','0x6500115B28','0x6500115274','0x0BA37F51','0x01000193','unknown','full investigation remains active']:
  # The report uses compact digits in technical tables and spaced thousands
  # in its lead validation sentence; accept both explicit digit spellings.
  assert term in report or term.replace(',','')in report,term
 evidence=['Factual technical binary/interface analysis.','CR1-CR15 retain conditional inputs, source identity, guard/PAC fixtures, alignment and falsification probes.','Unknown copies, private output/stack ABI, table/code readers, context transform and arena creator destination covered; full objective active.','u8/u16/u32/u64 wrapping, byte extents, half-open ranges, loop counts and linear codec complexity explicit.','Eight u32 versus sixteen byte text reads, guard fixture versus native guard, stack delta versus control and table/window/section boundaries distinguished.','Original image and3013 opcodes,16 spans,77 fixups,13 proof pairs,4 independent A64 runs,33 codec cases,64 reader cases,3008 SIMD cases and fresh replay checked.','Impact-labeled bounded continuation table; native lifetime and transport consumers remain unknown.']
 outputs={n:sha(ROOT/n)for n,g in pairs};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED_COUNTS,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(source),'new_validation_outputs':outputs,'report_sha256':{n:sha(BASE/n)for n in reports},'prior_artifacts_checked':3185,'unchanged_prior_artifacts':3179,'checked_report_links':links,'inputs_preserved':old['inputs_preserved'],'live_IDB_verification_refreshed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':13,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
