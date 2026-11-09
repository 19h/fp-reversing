#!/usr/bin/env python3
"""Seal allocator/entropy/callback-source evidence and preserve all prior artifacts.

O(pinned bytes+I+256R) time,O(largest JSON) space plus solver cost30 s/query.
Native entropy, registration, authentication and actual Mach replies are unproved.
"""
import hashlib,json,re,struct
from pathlib import Path
import z3,capstone
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from recover_lskd_input_buffers import generic
from lskd_input_buffers_symbolic import queries
from lskd_entropy_registration_walk import walk
BASE=ROOT.parent;BASELINE_SHA='8985a072a3f57e3dd2ec081eb3dce65ce100882cb2b45a394f0292a4f5f20fc6'
EXPECTED={'bounded_kext_source_spans': 5, 'external_source_spans_readback': 4, 'original_native_function_readbacks': 2, 'corecrypto_start_function_readbacks': 1, 'exhaustive_bank_rules': 2, 'bank_byte_input_checks': 512, 'original_dispatch_or_import_slots_checked': 6, 'runtime_zero_file_cells_retained': 3, 'registration_source_instruction_visits': 120, 'source_callback_table_stores': 6, 'source_registry_publications': 7, 'abstract_PAC_token_events': 18, 'source_proof_pairs_unsat': 15, 'output_pointer_no_redefinition_instructions': 42, 'original_CMP_alias_destination_certificates': 1, 'fresh_cases': 48, 'source_instruction_visits': 663504, 'source_instruction_byte_checks': 2654016, 'source_write_epochs': 62112, 'source_read_epochs': 56616, 'discarded_stack_probe_reads': 96, 'byte_reconstructed_cases': 48, 'preceding_selected_prefixes_equal': 24, 'register_only_allocator_models': 168, 'fully_unknown_buffer_snapshots_preserved': 120, 'cases_without_extended_private_buffer_access': 48, 'cases_without_work_region_value_reads': 48, 'source_auxiliary_pointer_publications': 72, 'source_saved_allocator_bank_cells_checked': 96, 'source_nonnull_dispatch_edges': 72, 'zero_capacity_allocation_frontiers': 24, 'entropy_frontiers': 24, 'disjoint_request_region_layouts': 24}

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_input_buffers_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_input_buffers_prior_manifest.json');assert len(baseline['files'])==2202
 c=read('lskd_input_buffers_contracts.json');checks=read('lskd_input_buffers_checks.json');proof=read('lskd_input_buffers_proofs.json');preserve=read('lskd_input_buffers_preservation.json')
 for obj,name in[(c,'recover_lskd_input_buffers.py'),(checks,'validate_lskd_input_buffers.py'),(proof,'prove_lskd_input_buffers.py'),(preserve,'validate_lskd_input_buffers_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'lskd_input_buffers_replays.json')==checks['fresh_replays_sha256']and sha(ROOT/'lskd_entropy_registration_walk.json')==checks['registration_walk_sha256']
 for flag in['input_content_read','native_registration_executed','entropy_operation_executed','postentropy_continuation_executed','native_target_executed','external_IPC_emission_proved']:assert not checks[flag]
 assert checks['model_memory_writes']==checks['private_uninitialized_values_consumed']==0
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for s in c['external_source_spans']:assert generic(k,s['label'],int(s['start'],16),int(s['end'],16))==s
 for f in c['native_functions']:assert k.function(int(f['start'],16))==f
 cc=next(e for e in k.entries if e['name']=='com.apple.kec.corecrypto');assert cc['uuid']==c['corecrypto_entry_uuid']=='6bdded85-b6a0-31ec-8c64-b4fd1ee511e8'and function(k,cc,0xfffffe000baf476c)==c['corecrypto_start']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),base=int(b['base'],16));assert all(now[n]==b[n]for n in now)
 for ptr in c['dispatch_slots']+c['import_bindings']+[b['original_pointer']for b in c['bank_rules']]:assert pointer(k,int(ptr['slot'],16))==ptr
 for cell in c['runtime_cells']:assert k.read(int(cell['address'],16),8).hex()==cell['original8_hex']=='00'*8 and not cell['native_value_known']
 sw=walk(c);assert sw==read('lskd_entropy_registration_walk.json')and not sw['native_registration_executed']and not sw['native_PAC_executed']and not sw['runtime_backend_observed']and len(sw['source_visits'])==120
 for v in sw['source_visits']:assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex']
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==15 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==68
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 raw=k.read(0xfffffe000a544130,4);assert raw.hex()=='1f0000f1'and int.from_bytes(raw,'little')&31==31
 fresh=read('lskd_input_buffers_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_lskd_input_buffers.py')and fresh['dependencies']==checks['dependencies']and len(fresh['cases'])==48 and not fresh['full_goal_complete'];frontiers=[];saved8e8=[]
 old=read('lskd_core_workspace_contracts.json');pair=next(p for p in old['frame_pointer_pairs']if p['frame_SP_offset_bytes']==0x8e8);assert pair['store_PC']=='0xfffffe000a530708'and pair['region']=='workspace'and pair['region_offset_bytes']==12
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['native_heap_executed']and not r['complete_core_operation_executed']and not r['entropy_operation_executed']and not r['input_content_read']and r['model_memory_writes']==0 and r['uninitialized_read_boundary']is None
  good=r['input'].get('buffer_fixture')is not None;assert r['boundary']['pc']==('0xfffffe000a58c428'if good else'0xfffffe000a544120')and len(r['models'])==(4 if good else 3)
  frontiers.append({'input':r['input'],'call':r['additional_calls'][-1],'boundary':r['boundary'],'models':r['models'],'buffer_edges':r['buffer_edges']})
  frame=bytes.fromhex(r['frame']['bytes_hex']);known=bytes.fromhex(r['frame']['known_mask_hex']);F=int(r['frame_base_SP'],16);assert frame[0x8e8:0x8f0]==struct.pack('<Q',0x630000800c)and known[0x8e8:0x8f0]==bytes([1])*8
  writes=[e for e in r['source_writes']if int(e['address'],16)==F+0x8e8];assert len(writes)==1 and writes[0]['pc']=='0xfffffe000a530708';saved8e8.append(writes[0])
 del fresh
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==2202 and preserve['unchanged_prior_artifacts']==2196
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_input_buffers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'lskd_input_buffers_source_identity.json',ROOT/'lskd_input_buffers_quality_gates.json'],(name,target);links+=1
 assert links>850
 report=(BASE/'lskd_input_buffers_report.md').read_text()
 for term in['IB13','QG7','unknown','48','663504','2202','2196','120','28','256','4096','0x61','0x9EA','Mach','_cckprng_generate','1f0000f1','register-only']:assert term in report,term
 for row in c['source_callback_catalog']:
  for key in['raw_function','global_callback_cell','startup_store_PC','registration_store_PC']:assert row[key]in report,(key,row[key])
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'corecrypto_entry_uuid':cc['uuid'],'source_spans':c['spans'],'external_source_spans':c['external_source_spans'],'import_bindings':c['import_bindings'],'source_callback_catalog':c['source_callback_catalog'],'registration_source_walk':sw,'runtime_file_cells':c['runtime_cells'],'read_random_abi':c['read_random_abi'],'conditional_postentropy_frame_pointer_epochs':saved8e8,'CMP_alias_certificate':{'PC':'0xfffffe000a544130','bytes_hex':raw.hex(),'encoded_destination':'XZR','X0_modified':False,'installed_capstone_version':capstone.__version__},'frontiers':frontiers,'native_registration_executed':False,'entropy_operation_executed':False,'postentropy_continuation_executed':False,'input_content_read':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_input_buffers_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','IB1-IB13 list dependencies and falsification probes.','Allocations, entropy import, native callback ABI and source registration covered; full objective remains active.','Exact widths/extents, chunk/alignment calculations, counts and sequential reproduction.','Source/runtime registration,PAC tokens/native authentication,unknown contents,source proofs/private execution separated.','48 fresh byte audits,24 exact selected prefixes,15 source proof pairs,source callback walk,original metadata/import/native/corecrypto readbacks.','Impact-labeled continuation table.'];outputs=['lskd_input_buffers_contracts.json','lskd_input_buffers_profiles.json','lskd_input_buffers_replays.json','lskd_input_buffers_checks.json','lskd_input_buffers_proofs.json','lskd_entropy_registration_walk.json','lskd_input_buffers_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'source_postentropy_pointer_epochs_checked':48,'source_only_registration_walk':True,'native_PAC_proved':False,'prior_artifacts_checked':2202,'unchanged_prior_artifacts':2196,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_input_buffers_source_identity.json'),'model_memory_writes':0,'input_content_read':False,'native_registration_executed':False,'entropy_operation_executed':False,'postentropy_continuation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_input_buffers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':48,'source_proof_pairs':15,'source_callback_entries':6,'prior_artifacts_checked':2202,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
