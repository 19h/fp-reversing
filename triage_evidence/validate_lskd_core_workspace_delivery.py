#!/usr/bin/env python3
"""Seal core workspace/clear/shape evidence with source/proof/hash readback.

O(pinned bytes+I+256R) time, O(largest JSON) space plus solver cost30 s/query.
No target executes. Model/native and numeric/content boundaries remain explicit.
"""
import hashlib,json,re,struct
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_core_workspace_symbolic import queries
BASE=ROOT.parent;BASELINE_SHA='28135d229461215e161dac7846c1c06697691e6f675499d6fa25bd829331910d'
EXPECTED={'bounded_kext_source_spans':4,'original_native_allocator_functions_readback':2,'exhaustive_bank_rules':4,'bank_byte_input_checks':1024,'typed_view_metadata_bytes_checked':64,'source_proof_pairs_unsat':8,'fresh_cases':43,'source_instruction_visits':590018,'source_instruction_byte_checks':2360072,'source_write_epochs':55384,'source_read_epochs':49751,'discarded_stack_probe_reads':86,'byte_reconstructed_cases':43,'register_only_allocator_models':86,'source_unsigned_ordering_calls':86,'preceding_complete_prefixes_equal':36,'source_frame_pointer_store_pairs':5848,'original_scratch_zero_byte_stores':47128,'stack_guard_cells_preserved_through_clear':43,'source_clear_loop_authenticated_edges':47128,'workspace_source_initialized_bytes':688,'cases_without_work_region_value_reads':43,'shape_guard_rejected_cases':41,'shape_guard_selected_cases':2}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_core_workspace_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_core_workspace_prior_manifest.json');assert len(baseline['files'])==2125
 c=read('lskd_core_workspace_contracts.json');checks=read('lskd_core_workspace_checks.json');proof=read('lskd_core_workspace_proofs.json');preserve=read('lskd_core_workspace_preservation.json')
 for obj,name in[(c,'recover_lskd_core_workspace.py'),(checks,'validate_lskd_core_workspace.py'),(proof,'prove_lskd_core_workspace.py'),(preserve,'validate_lskd_core_workspace_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'lskd_core_workspace_replays.json')==checks['fresh_replays_sha256']
 for flag in['input_content_validated','complete_core_operation_executed','native_target_executed','external_IPC_emission_proved']:assert not checks[flag]
 assert checks['model_memory_writes']==checks['private_uninitialized_values_consumed']==0
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 assert k.function(0xfffffe000c4ba154)==c['native_typed_allocator']and k.function(0xfffffe000bcfeb8c)==c['native_type_delegate']and k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for ptr in c['dispatch_slots']+c['typed_view']['original_pointer_fields']:assert pointer(k,int(ptr['slot'],16))==ptr
 assert c['typed_view']['size32_bytes']==4096 and c['typed_view']['flags32']=='0xe4'and not c['typed_view']['native_runtime_links_known']and c['scratch']['size_bytes']==1096 and c['numeric_guard']['u32_length_max_bytes_inclusive']==65536 and not c['numeric_guard']['input_content_validated']
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==8 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==328
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=read('lskd_core_workspace_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_lskd_core_workspace.py')and fresh['dependencies']==checks['dependencies']and len(fresh['cases'])==43 and not fresh['full_goal_complete'];timelines=[]
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['native_heap_executed']and not r['complete_core_operation_executed']and r['model_memory_writes']==0 and r['uninitialized_read_boundary']is None
  assert r['boundary']['kind']=='before_core_input_guard_selected_fragment'and r['unexecuted_dispatch']['target_executed']==False
  F=int(r['frame_base_SP'],16);writes=[w for w in r['source_writes']if int(w['address'],16)==F+0xd90 and w['size_bytes']==8];assert[(w['pc'],w['after_hex'])for w in writes]==[('0xfffffe000a5304b0',struct.pack('<Q',0xfffffe000846c428).hex()),('0xfffffe000a530914',struct.pack('<Q',0x63000084e0).hex())];timelines.append({'frame_SP':hex(F),'epochs':writes})
 del fresh
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==2125 and preserve['unchanged_prior_artifacts']==2119
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_core_workspace_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'lskd_core_workspace_source_identity.json',ROOT/'lskd_core_workspace_quality_gates.json'],(name,target);links+=1
 report=(BASE/'lskd_core_workspace_report.md').read_text()
 for term in['CW11','QG7','unknown','43','590018','2125','2119','1096','136','16','65536','Mach','CCMP','0xfffffe000a530564','register-only']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'typed_view':c['typed_view'],'dispatch_slots':c['dispatch_slots'],'scratch':c['scratch'],'numeric_guard':c['numeric_guard'],'source_frame_pointer_pairs':c['frame_pointer_pairs'],'D90_source_epoch_timelines':timelines,'input_content_validated':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_core_workspace_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','CW1-CW11 list dependencies and falsification probes.','Core work/frame/clear/shape interfaces covered; full objective remains active.','Exact widths/extents, calculations, counts and reproduction.','Models/native effects, ordering/allocation bounds, unknown/initialized storage and shape/content predicates separated.','43 fresh byte audits,36 exact preceding prefixes,8 source proof pairs,136 source pointer pairs and original native allocator/metadata readbacks.','Impact-labeled continuation table.'];outputs=['lskd_core_workspace_contracts.json','lskd_core_workspace_profiles.json','lskd_core_workspace_replays.json','lskd_core_workspace_checks.json','lskd_core_workspace_proofs.json','lskd_core_workspace_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'source_D90_epoch_cases_checked':43,'prior_artifacts_checked':2125,'unchanged_prior_artifacts':2119,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_core_workspace_source_identity.json'),'model_memory_writes':0,'input_content_validated':False,'complete_core_operation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_core_workspace_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':43,'source_proof_pairs':8,'source_pointer_pairs':136,'prior_artifacts_checked':2125,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
