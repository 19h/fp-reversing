#!/usr/bin/env python3
"""Seal source creator/publication/marker/SDK/epoch/proof/preservation evidence.
O(pinned artifact bytes+reports) time,O(largest JSON) space;no native target.
"""
import hashlib,json,re
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,verify_original_fixups
from validate_daemon_rwlock_lifecycle_preservation import BASELINE_SHA,ALLOWED
BASE=ROOT.parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 old=read('daemon_rwlock_lifecycle_prior_manifest.json');assert sha(ROOT/'daemon_rwlock_lifecycle_prior_manifest.json')==BASELINE_SHA and len(old['files'])==2658
 c,check,proof,pre=map(read,['daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_checks.json','daemon_rwlock_lifecycle_proofs.json','daemon_rwlock_lifecycle_preservation.json'])
 for obj,name in [(c,'recover_daemon_rwlock_lifecycle.py'),(check,'validate_daemon_rwlock_lifecycle.py'),(proof,'prove_daemon_rwlock_lifecycle.py'),(pre,'validate_daemon_rwlock_lifecycle_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert check['all_checks_pass']and pre['all_checks_pass'];counts=check['verified_counts']
 expected={'original_source_spans':14,'primary_bias_literal_matches':2,'fallback_high16_literal_matches':7,'exhaustive_bank_rules':7,'bank_inputs_checked':1792,'original_fixups_verified':32,'original_import_bindings_checked':4,'zerofill_cell_sections_checked':2,'SDK_compile_exit_zero':1,'SDK_static_initializer_bytes_equal':200,'live_IDB_source_rows_matched':423,'source_proof_pairs_unsat':32,'independent_byte_reconstructed_cases':290,'cases_audited':290,'source_visits':177522,'paired_caller_cases':288,'creator_returns_checked':576,'creator_target_load_epochs_checked':576,'first_result_unread_windows_checked':288,'source_state09_publications':48,'source_lock_pointer_publications':96,'malloc_models_checked':576,'opaque_heap_unknown_extents_checked':576,'fresh_replayed_cases':12,'first_failure_second_success_state09_cases':40,'rwlock_init_models_checked':480,'first_success_second_failure_state_retained_cases':40,'null_cell_creator_returns':2,'API_binding_load_epochs_checked':1056}
 for name,v in expected.items():assert counts[name]==v,(name,counts[name],v)
 assert check['case_matrix']=={'first_error_second_error':200,'first_error_second_ok':40,'first_ok_second_error':40,'first_ok_second_ok':8}and sum(check['source_lift_counts'].values())==187 and check['source_lift_counts']==proof['source_lift_counts']and len(proof['proofs'])==32
 for row in proof['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 dec=verify_original_fixups([int(r['address'],16)for r in c['original_fixup_records']['records']]);assert dec==c['original_fixup_records'];by={r['address']:r for r in dec['records']};routes=[]
 for index,target,div in [(0xaed7,0x1001937e4,0xcd54),(0xaedc,0x1001c0128,0xcd54),(0x5625,0x100130f60,0xdd7f),(0x5640,0x1001c0128,0xdd7f),(0xa03c,0x1003131a4,0x4d7),(0x8dc6,0x10014d86c,0xc2c5),(0x8e30,0x100276ba0,0xc2c5),(0x6ac3,0x1002097dc,0x4d05),(0x3bbf,0x10014d328,0x4d05),(0x82d2,0x1002c67e0,0xf80f),(0x82ea,0x100269a88,0xf80f),(0x6f7f,0x1001c0128,0x4d05),(0x3b73,0x1001a84bc,0x4d05),(0x4433,0x1001c0128,0xb1e0),(0x6293,0x1003062a4,0xf1f2),(0x70bb,0x1001f1f98,0xf1f2)]:
  a=TABLE+index*8;r=by[hex(a)];assert r['decoded_target']==hex(target)and r['diversity']==hex(div)and r['key']=='IA'and r['address_diversity']==0 and FIXUPS[a]['target']==target;routes.append({'index':hex(index),**r})
 sdk=c['SDK'];assert sha(ROOT/'daemon_rwlock_lifecycle_sdk.c')==sdk['source_sha256']and sha(ROOT/'daemon_rwlock_lifecycle_sdk.o')==sdk['object_sha256']and sdk['initializer200_hex']==IMAGE.read(0x1010b7478,200).hex()and sdk['exit_code']==0
 for h in sdk['headers']:assert sha(Path(h['path']))==h['sha256']
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert set(allowed)==ALLOWED and pre['prior_artifacts_checked']==2658 and pre['unchanged_prior_artifacts']==2652
 for row in old['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in old['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in ['daemon_rwlock_lifecycle_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   p=Path(t.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'daemon_rwlock_lifecycle_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_rwlock_lifecycle_report.md').read_text()
 for term in ['RL12','QG7','unknown','290','288','32','187','423','200','192','0x1010C8240','0x1010C5748','0x1001F1FF8','0x1002097DC','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','RL1-RL12 include dependencies and falsification probes.','Selected paired creator,static fallback and state producer covered;full goal remains active.','u16/u32/u64,20-byte accessed extent,200/8/192-byte object extents,signed comparisons and compiled-only SDK data explicit.','Destination/value,first/second result,file/runtime state,publication/native initialization and producer/continuous path distinguished.','290 epoch audits,12 fresh replays,32 proof pairs,32 fixups,seven banks,423 IDB rows,API load epochs and200 SDK bytes.','Impact-labeled bounded continuation table.'];outputs=['daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_profiles.json','daemon_rwlock_lifecycle_checks.json','daemon_rwlock_lifecycle_proofs.json','daemon_rwlock_lifecycle_live_ida.json','daemon_rwlock_lifecycle_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':check['source_lift_counts'],'case_matrix':check['case_matrix'],'dispatch_routes_verified':routes,'SDK_object_sha256':sdk['object_sha256'],'upstream_caller_context_proved':False,'native_lock_initialization_proved':False,'prior_artifacts_checked':2658,'unchanged_prior_artifacts':2652,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_rwlock_lifecycle_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
