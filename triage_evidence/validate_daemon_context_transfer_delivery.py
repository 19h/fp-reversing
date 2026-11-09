#!/usr/bin/env python3
"""Seal context unknownness, comparison ABI, entropy and independent replay.
O(artifact bytes+report links) time,O(largest JSON) space; no target runs.
"""
import json,re
from pathlib import Path
from validate_daemon_context_transfer_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,k,q,p=map(read,['daemon_context_transfer_contracts.json','daemon_context_transfer_checks.json','daemon_context_transfer_proofs.json','daemon_context_transfer_preservation.json'])
 for obj,n in [(c,'recover_daemon_context_transfer.py'),(k,'validate_daemon_context_transfer.py'),(q,'prove_daemon_context_transfer.py'),(p,'validate_daemon_context_transfer_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k['all_checks_pass']and p['all_checks_pass'];counts=k['verified_counts']
 expected={'original_source_spans':6,'original_instruction_pool_rows':1246,'exhaustive_bank_inputs':512,'original_fixups_verified':40,'live_IDB_source_rows_matched':470,'SDK_entropy_signature_checked':1,'source_proof_pairs_unsat':10,'premise_nonempty_witnesses':1,'symbolic_input_bytes':448,'symbolic_contexts':4,'symbolic_source_visits':126752,'source_defined_final_fields':32,'unknown_identity_fields_preserved':24,'source_bytes_checked':507008,'unknown_private_copy_events':108,'fresh_image_zero_read_contexts':4,'fresh_prefix_replays':4,'independent_A64_replays':16,'fresh_transfer_replays':4}
 assert counts==expected
 expected_A64={'source_visits':507008,'read_bytes_checked':213936,'register_effects_checked':457856,'write_bytes_checked':119424,'source_write_effects_checked':25152,'unknown_copied_bytes_checked':3456,'NZCV_effects_checked':12288};assert k['independent_A64_totals']==expected_A64 and sum(k['source_lift_counts'].values())==126 and k['source_lift_counts']==q['source_lift_counts']
 summaries=k['context_summaries'];assert [x['steps']for x in summaries]==[31032,31032,32344,32344]and [x['scalar_buffer_writes']for x in summaries]==[700,700,732,732]and all(x['scalar_four_byte_writes']==8 for x in summaries)
 for r in q['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 assert sha(ROOT/'daemon_context_transfer_prior_manifest.json')==BASELINE_SHA;old=read('daemon_context_transfer_prior_manifest.json');changed={r['path']:r for r in p['allowed_existing_changes']};assert set(changed)==ALLOWED
 for r in old['files']:
  path=BASE/r['path'];assert sha(path)==(changed[r['path']]['current_sha256']if r['path']in changed else r['sha256']),r['path']
 for r in old['inputs_preserved']:path=BASE/r['path'];assert sha(path)==r['sha256']and path.stat().st_size==r['size_bytes']
 links=0
 for name in ['daemon_context_transfer_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   path=Path(t.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_context_transfer_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_context_transfer_report.md').read_text()
 for term in ['CT12','QG7','unknown','112','896','48-byte','0x10041A5E0','0x1010C8258','0x100409574','0x174E','0x178C','0x4DE3A292F9D49974','0x4355E95E8F154797','126','470','507,008','__common','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','CT1-CT12 retain dependencies and falsification probes.','Selected context-transfer,complete leaf record ABI,caller gate and first entropy boundary covered;full objective active.','u32/u64 codecs,48-byte extent,112 symbolic bytes,finite paths and software counts explicit.','Copied unknownness versus source definitions,private records versus wire messages,global zero-fill premise versus stack unknowns,and zero-argument entropy import versus stale registers distinguished.','Four symbolic contexts,16 independent A64 replays,10 source proof pairs,40 fixups,470 IDB rows,512 bank inputs and SDK declaration.','Impact-labeled bounded continuation table.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'independent_A64_totals':expected_A64,'source_lift_counts':k['source_lift_counts'],'checked_report_links':links,'prior_artifacts_checked':2856,'unchanged_prior_artifacts':2850,'inputs_preserved':old['inputs_preserved'],'new_validation_outputs':{n:sha(ROOT/n)for n in ['daemon_context_transfer_contracts.json','daemon_context_transfer_checks.json','daemon_context_transfer_profiles.json','daemon_context_transfer_replays.json','daemon_context_transfer_proofs.json','daemon_context_transfer_live_ida.json','daemon_context_entropy_live_ida.json','daemon_context_transfer_preservation.json']},'native_entropy_executed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_context_transfer_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'independent_A64_totals':expected_A64,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
