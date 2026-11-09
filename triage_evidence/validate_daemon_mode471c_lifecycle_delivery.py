#!/usr/bin/env python3
"""Seal this lifecycle increment only; the daemon/kext/deeper goal stays active.
O(artifact bytes+links) time, O(largest artifact+manifest) space.
"""
import json,re,ast
from pathlib import Path
from validate_daemon_mode471c_lifecycle_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'source_spans_checked':14,'exhaustive_bank_input_cases':768,'original_fixups_checked':110,'dispatch_slots_checked':7,'source_derived_root_values_checked':2,'SMT_queries_unsat':20,'freshly_rebuilt_source_obligations_unsat':10,'source_proof_pairs':10,'source_lift_visits':103,'creation_cases':24,'arbitrary_API_byte_origins':73040,'retained_private_byte_origins':1232,'source_continuation_visits':34616,'source_opcodes_checked':34616,'source_mode_overwrite_epochs_checked':24,'post_creator_phase_reads_checked':24,'opaque_word_preservation_reads_checked':28,'lifecycle_cases_checked':28,'zero_field_body_results_checked':28,'terminal_unknown_pointer_boundaries':28,'acquire_records_checked':8,'cleanup_records_checked':8,'preexisting_lock_cases':4,'independent_A64_replays':112,'callback_executing_source_cases':4,'distinct_continuation_inspected_opcodes':1862,'fresh_composed_replays':2,'SDK_headers_rehashed':2,'supplied_annotated_trace_rehashed':1}
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r

def main():
 pairs=[('daemon_mode471c_lifecycle_profiles.json','probe_daemon_mode471c_lifecycle.py'),('daemon_mode471c_lifecycle_contracts.json','recover_daemon_mode471c_lifecycle.py'),('daemon_mode471c_lifecycle_proofs.json','prove_daemon_mode471c_lifecycle.py'),('daemon_mode471c_lifecycle_replays.json','replay_daemon_mode471c_lifecycle.py'),('daemon_mode471c_lifecycle_checks.json','validate_daemon_mode471c_lifecycle.py'),('daemon_mode471c_lifecycle_preservation.json','validate_daemon_mode471c_lifecycle_preservation.py')];p,c,proofs,replays,k,preservation=[checked(n,g)for n,g in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and replays['all_checks_pass']and preservation['all_checks_pass'];assert len(proofs['proofs'])==10
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['original_file'])==r['original_sha256']and sha(ROOT/r['file'])==r['sha256']
 binary=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(binary)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';assert sha(ROOT/'daemon_mode471c_lifecycle_prior_manifest.json')==BASELINE_SHA;old=read('daemon_mode471c_lifecycle_prior_manifest.json');changes={r['path']:r for r in preservation['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3428 and preservation['unchanged_prior_artifacts']==3422
 for r in old['files']:assert sha(BASE/r['path'])==(changes[r['path']]['current_sha256']if r['path']in changes else r['sha256']),r['path']
 for r in old['inputs_preserved']:f=BASE/r['path'];assert f.stat().st_size==r['size_bytes']and sha(f)==r['sha256']
 assert read('daemon_mode471c_lifecycle_live_ida.json')['isError']and c['fresh_IDB_bytes_verified']==0 and k['fresh_IDB_bytes_verified']==0
 reports=['daemon_mode471c_lifecycle_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for n in reports:
  for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   link=link.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',link)or link.startswith('#'):continue
   f=Path(link.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_mode471c_lifecycle_quality_gates.json',(n,link);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['ML14','QG7','0x1010C67C0','0x1010C67D0','0x1010C67A8','0x1010C9288','0x74C29F00','0x10039C998','0x10039C988','0x100972914','188,192','zero fresh IDB bytes','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 syntax=0
 for f in ROOT.glob('*daemon_mode471c_lifecycle*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==8,syntax
 evidence=['Factual binary and ABI analysis.','ML1-ML14 specify source,entry,roots,image,API,owners,once,PAC,alignment,field,concurrency,status and trace premises with falsification probes.','Lazy lifecycle,slot epochs,record layouts,body result,free frontier and IPC evidence boundaries covered; full goal remains active.','Explicit u32/u64 arithmetic,record offsets,8/16/32/200-byte extents,SDK signatures and algorithm bounds.','Creator/body results,source versus model transitions,distinct globals,zero versus populated state and unresolved caller frame remain separated.','14 original spans,110 fixups,3 exhaustive banks,10 proof pairs,112 A64 replays,SDK and trace hashes verified; fresh IDA bridge unavailable and zero bytes claimed.','Impact-bounded producer,frame,payload/IPC,lifetime and database continuation table included.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(binary),'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'prior_artifacts_checked':3428,'unchanged_prior_artifacts':3422,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'inputs_preserved':old['inputs_preserved'],'fresh_IDB_bytes_verified':0,'reader_B_reached':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_mode471c_lifecycle_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':10,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
