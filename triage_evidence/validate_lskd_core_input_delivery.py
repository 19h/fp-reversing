#!/usr/bin/env python3
"""Seal core rejection/allocation frontiers and conditional UserClient status.

O(pinned bytes+I+256R) time,O(largest JSON) space plus solver cost30 s/query.
No target executes. All broad native/transport conclusions remain unresolved.
"""
import hashlib,json,re,struct
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_core_input_symbolic import queries
from lskd_core_input_caller import queries as caller_queries
BASE=ROOT.parent;BASELINE_SHA='d8370d5ca597cc1d268aa3e83c27a7eaceaa9888f9991e7de7b848f0fde03688'
EXPECTED={'bounded_kext_source_spans':3,'original_native_function_readbacks':4,'exhaustive_bank_rules':4,'bank_byte_input_checks':1024,'cleanup_view_metadata_bytes_checked':64,'source_proof_pairs_unsat':7,'fresh_cases':98,'source_instruction_visits':1351240,'source_instruction_byte_checks':5404960,'source_write_epochs':126272,'source_read_epochs':116588,'discarded_stack_probe_reads':196,'byte_reconstructed_cases':98,'preceding_complete_prefixes_equal':43,'cases_without_work_region_value_reads':98,'cases_without_input_or_output_buffer_access':98,'source_saved_bank_cells_checked':588,'register_only_model_returns':344,'rejection_callee_saved_GP_registers_restored':814,'rejection_cleanup_models_checked':148,'original_rejection_returns':74,'equal_stack_guard_epilogues':74,'selected_paths_stopped_before_data_allocation':24}
CALLER_EXPECTED={'caller_source_spans':2,'caller_source_proof_pairs_unsat':3,'caller_fresh_cases':5,'caller_original_instruction_visits':14,'caller_instruction_byte_checks':56,'caller_source_status_stores':5,'caller_source_nonzero_count_clears':4,'caller_data_reads':0}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def solve(q,row):
 assert row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
 for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
  s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',row['name']
def main():
 assert sha(ROOT/'lskd_core_input_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_core_input_prior_manifest.json');assert len(baseline['files'])==2159
 c=read('lskd_core_input_contracts.json');checks=read('lskd_core_input_checks.json');proof=read('lskd_core_input_proofs.json');preserve=read('lskd_core_input_preservation.json');caller=read('lskd_core_input_caller.json');cc=read('lskd_core_input_caller_checks.json')
 for obj,name in[(c,'recover_lskd_core_input.py'),(checks,'validate_lskd_core_input.py'),(proof,'prove_lskd_core_input.py'),(preserve,'validate_lskd_core_input_preservation.py'),(caller,'lskd_core_input_caller.py'),(cc,'validate_lskd_core_input_caller.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'lskd_core_input_replays.json')==checks['fresh_replays_sha256']and cc['all_checks_pass']and cc['verified_counts']==CALLER_EXPECTED
 for flag in['input_content_validated','successful_core_operation_executed','native_target_executed','external_IPC_emission_proved']:assert not checks[flag]
 assert checks['model_memory_writes']==checks['private_uninitialized_values_consumed']==cc['model_memory_writes']==0 and not cc['descriptor_release_executed']and not cc['actual_Mach_reply_observed']
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']==caller['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']==caller['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']+caller['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for f in c['native_functions']:assert k.function(int(f['start'],16))==f
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for ptr in c['guard_dispatch_slots']+c['free_view']['original_pointer_fields']+[b['original_pointer']for b in c['bank_rules']]:assert pointer(k,int(ptr['slot'],16))==ptr
 assert c['free_view']['size32_bytes']==4096 and c['free_view']['flags32']=='0xe4'and not c['free_view']['runtime_link_state_known']and c['rejection_return_status32']=='0xffff5966'and c['rejection_return_signed32']==-42650
 allocated=read('lskd_core_workspace_contracts.json')['typed_view'];freed=c['free_view'];assert allocated['address']!=freed['address']and allocated['flags32']==freed['flags32']and allocated['size32_bytes']==freed['size32_bytes']and[ptr['target']for ptr in allocated['original_pointer_fields']]==[ptr['target']for ptr in freed['original_pointer_fields']]
 previous=read('lskd_writers_contracts.json');ps=next(s for s in previous['spans']if s['label']=='selector18_method');now=span(k,int(ps['start'],16),int(ps['end'],16));assert all(now[n]==ps[n]for n in now)
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==7 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==20
 for(name,q),row in zip(qs,proof['proofs']):assert name==row['name'];solve(q,row)
 cqs=caller_queries(caller);assert len(cqs)==3
 for(name,q,n),row in zip(cqs,caller['proofs']):assert name==row['name']and n==row['source_instructions_lifted']==1;solve(q,row)
 assert cc['fresh_cases']==caller['cases']and len(cc['fresh_cases'])==5
 fresh=read('lskd_core_input_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_lskd_core_input.py')and fresh['dependencies']==checks['dependencies']and len(fresh['cases'])==98 and not fresh['full_goal_complete'];rejections=[];frontiers=[]
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['native_heap_executed']and not r['complete_core_operation_executed']and r['model_memory_writes']==0 and r['uninitialized_read_boundary']is None and r['shape_edge_executed']
  if r['complete_original_rejection_return']:
   assert r['boundary']['registers31'][0]=='0xffff5966'and r['boundary']['SP']==r['entry_SP']and len(r['cleanup_models'])==2;rejections.append({'input':r['input'],'shape_boundary':r['shape_boundary'],'cleanup_models':r['cleanup_models'],'return_boundary':r['boundary']})
  else:assert r['boundary']['pc']=='0xfffffe000a56d228'and len(r['models'])==2;frontiers.append({'input':r['input'],'call':r['additional_calls'][-1],'boundary':r['boundary']})
 assert len(rejections)==74 and len(frontiers)==24;del fresh
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==2159 and preserve['unchanged_prior_artifacts']==2153
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_core_input_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'lskd_core_input_source_identity.json',ROOT/'lskd_core_input_quality_gates.json'],(name,target);links+=1
 report=(BASE/'lskd_core_input_report.md').read_text()
 for term in['CI11','QG7','unknown','98','1351240','2159','2153','42650','5216','Mach','IOMallocData','0xfffffe000a504780','register-only','descriptor release','preliminary verification']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'source_spans':c['spans'],'caller_spans':caller['spans'],'free_view':freed,'allocation_view_identity':{n:allocated[n]for n in['address','name','flags32','size32_bytes','original_pointer_fields']},'guard_dispatch_slots':c['guard_dispatch_slots'],'original_bank_slots':[b['original_pointer']for b in c['bank_rules']],'rejection_return_cases':rejections,'selected_allocation_frontiers':frontiers,'caller_composition_premise':caller['composition_premise'],'input_content_validated':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_core_input_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','CI1-CI11 list dependencies and falsification probes.','Guard successors, cleanup, status and conditional caller publication covered; full objective remains active.','Exact widths/extents, status arithmetic, counts and sequential reproduction.','Shape/content, private/native heap, source/unknown bytes, status layers and conditional caller composition separated.','98 fresh core audits,43 exact preceding prefixes,5 fresh local caller cases,10 source proof pairs,original metadata/fixup/native readbacks.','Impact-labeled continuation table.'];outputs=['lskd_core_input_contracts.json','lskd_core_input_profiles.json','lskd_core_input_replays.json','lskd_core_input_checks.json','lskd_core_input_proofs.json','lskd_core_input_caller.json','lskd_core_input_caller_checks.json','lskd_core_input_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'caller_verified_counts':CALLER_EXPECTED,'source_lift_counts':lifts,'total_source_proof_pairs':10,'total_source_instruction_instances_lifted':23,'prior_artifacts_checked':2159,'unchanged_prior_artifacts':2153,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_core_input_source_identity.json'),'preliminary_validation_rejected_stale_generator_hash':True,'accepted_validation_after_producer_termination':True,'model_memory_writes':0,'input_content_validated':False,'successful_core_operation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_core_input_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_core_cases':98,'fresh_caller_cases':5,'source_proof_pairs':10,'prior_artifacts_checked':2159,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
