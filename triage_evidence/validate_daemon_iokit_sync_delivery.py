#!/usr/bin/env python3
"""Seal source/ABI/profile/byte/proof/preservation evidence for this increment.
O(pinned artifact bytes+I+reports) time,O(largest JSON) space. No native target.
"""
import hashlib,json,re
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE
from validate_daemon_iokit_sync_preservation import BASELINE_SHA,ALLOWED
BASE=ROOT.parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 baseline=read('daemon_iokit_sync_prior_manifest.json');assert sha(ROOT/'daemon_iokit_sync_prior_manifest.json')==BASELINE_SHA and len(baseline['files'])==2496
 c,check,proof,pre=map(read,['daemon_iokit_sync_contracts.json','daemon_iokit_sync_checks.json','daemon_iokit_sync_proofs.json','daemon_iokit_sync_preservation.json'])
 for obj,name in [(c,'recover_daemon_iokit_sync.py'),(check,'validate_daemon_iokit_sync.py'),(proof,'prove_daemon_iokit_sync.py'),(pre,'validate_daemon_iokit_sync_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 counts=check['verified_counts'];assert check['all_checks_pass']and pre['all_checks_pass']
 for name,v in [('original_source_spans',14),('exhaustive_bank_rules',2),('bank_inputs_checked',512),('original_binding_decodes',3),('SDK_syntax_checks',1),('SDK_function_signature_checks',3),('SDK_width_assertions',2),('zerofill_cell_extent_checks',1),('live_IDB_source_rows_matched',161),('source_proof_pairs_unsat',15),('generated_cases',684),('independent_byte_reconstructed_cases',684),('fresh_replayed_cases',30),('embedded_original_class_source_sequences',664),('outer_result_publications_and_ABI_returns',616),('acquire_once_models',684),('write_lock_models',676),('cleanup_once_models',616),('unlock_models',608),('source_callback_invocations',674)]:assert counts[name]==v,(name,counts[name],v)
 assert sum(check['source_lift_counts'].values())==131 and check['source_lift_counts']==proof['source_lift_counts'];assert check['frontier_matrix']=={'before_external_caller_after_outer_return':616,'before_matching_error_continuation':32,'before_open_error_continuation':12,'before_main_port_error_continuation':24}
 assert counts['original_fixups_verified']==80 and counts['source_instruction_visits']==1175922
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 for row in proof['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert set(allowed)==ALLOWED and pre['prior_artifacts_checked']==2496 and pre['unchanged_prior_artifacts']==2490
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in ['daemon_iokit_sync_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   p=Path(t.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'daemon_iokit_sync_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_iokit_sync_report.md').read_text()
 for term in ['DS12','QG7','unknown','684','664','30','15','131','161','0x1010C8240','0x1010B9638','0x1010B8CD0','zerofill','Mach','0x100336FCC']:assert term in report,term
 evidence=['Factual source/interface analysis.','DS1-DS12 include dependencies and falsification probes.','Selected full entry,acquisition,common cleanup and return covered;full objective remains active.','Byte extents,u32/u64 arithmetic,alignment,SDK signatures and complexity explicit.','Captured/fresh pointers,file/runtime state,source/API effects,error frontiers and raw status distinguished.','684 independent epoch audits,30 fresh replays,15 original-source proof pairs,161 IDB rows,original fixups and SDK compile.','Impact-labeled bounded continuation table.'];outputs=['daemon_iokit_sync_contracts.json','daemon_iokit_sync_profiles.json','daemon_iokit_sync_checks.json','daemon_iokit_sync_proofs.json','daemon_iokit_sync_live_ida.json','daemon_iokit_sync_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':check['source_lift_counts'],'frontier_matrix':check['frontier_matrix'],'prior_artifacts_checked':2496,'unchanged_prior_artifacts':2490,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'native_target_executed':False,'native_synchronization_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_sync_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
