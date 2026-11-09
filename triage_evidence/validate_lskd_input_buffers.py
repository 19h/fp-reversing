#!/usr/bin/env python3
"""Fresh allocation/entropy frontiers, byte provenance and callback source lineage.

O(B+C*(V+E)+I+256R) time/space plus solver cost30 s/query. No entropy,
input-content processing, registration, native heap or IPC executes.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3,capstone
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from recover_lskd_input_buffers import generic
from probe_lskd_input_buffers import Buffers,cases,WORK,AUX,P,DATA,RESULT,INPUT,END
from lskd_input_buffers_symbolic import queries
from lskd_input_buffers_audit import audit
from lskd_entropy_registration_walk import walk
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_input_buffers_contracts.json');p=read('lskd_input_buffers_profiles.json');proof=read('lskd_input_buffers_proofs.json');old=read('lskd_core_input_profiles.json');previous=[r for r in old['cases']if r['boundary']['pc']=='0xfffffe000a56d228'];assert len(previous)==24;del old;k=Kernel();counts=Counter();outcomes=Counter()
 for obj,name in[(c,'recover_lskd_input_buffers.py'),(p,'probe_lskd_input_buffers.py'),(proof,'prove_lskd_input_buffers.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_kext_source_spans']+=1
 for s in c['external_source_spans']:assert generic(k,s['label'],int(s['start'],16),int(s['end'],16))==s;counts['external_source_spans_readback']+=1
 for f in c['native_functions']:assert k.function(int(f['start'],16))==f;counts['original_native_function_readbacks']+=1
 cc=next(e for e in k.entries if e['name']=='com.apple.kec.corecrypto');assert cc['uuid']==c['corecrypto_entry_uuid']and function(k,cc,0xfffffe000baf476c)==c['corecrypto_start'];counts['corecrypto_start_function_readbacks']=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_input_checks']+=256
 for ptr in c['dispatch_slots']+c['import_bindings']:assert pointer(k,int(ptr['slot'],16))==ptr;counts['original_dispatch_or_import_slots_checked']+=1
 for cell in c['runtime_cells']:assert k.read(int(cell['address'],16),8).hex()==cell['original8_hex']=='00'*8 and not cell['native_value_known'];counts['runtime_zero_file_cells_retained']+=1
 sourcewalk=walk(c);assert len(sourcewalk['source_visits'])==120 and len(sourcewalk['constructor_stores'])==6 and len(sourcewalk['registry_publications'])==7 and len(sourcewalk['PAC_token_events'])==18
 for v in sourcewalk['source_visits']:assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex']
 counts.update({'registration_source_instruction_visits':120,'source_callback_table_stores':6,'source_registry_publications':7,'abstract_PAC_token_events':18})
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==15 and lifts==proof['source_lift_counts']and sum(lifts.values())==68
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for start,end in[(0xfffffe000a544124,0xfffffe000a544160),(0xfffffe000a58c3bc,0xfffffe000a58c428)]:
  for ins in cs.disasm(k.read(start,end-start),start):
   _,writes=ins.regs_access()
   if any(ins.reg_name(x)in['x0','w0']for x in writes):
    # Capstone reports CMP's first operand as written; SUBS encodes Rd=XZR.
    assert ins.address==0xfffffe000a544130 and bytes(ins.bytes).hex()=='1f0000f1'and int.from_bytes(ins.bytes,'little')&31==31 and ins.mnemonic=='cmp';counts['original_CMP_alias_destination_certificates']+=1
   counts['output_pointer_no_redefinition_instructions']+=1
 rows=[];inputs=list(cases());assert len(inputs)==48 and[r['input']for r in p['cases']]==inputs
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Buffers(case);r=f.run();del f;assert r==retained,(j,case);rows.append(r);counts['fresh_cases']+=1;counts['source_instruction_visits']+=len(r['source_visits']);audit(r,k,counts)
  assert r['uninitialized_read_boundary']is None and r['shape_edge_executed']and not r['complete_original_rejection_return']
  for flag in['native_target_executed','native_heap_executed','complete_core_operation_executed','external_IPC_emission_proved','full_goal_complete','entropy_operation_executed','input_content_read']:assert not r[flag],flag
  assert r['model_memory_writes']==0 and len(r['cleanup_models'])==0;F=int(r['frame_base_SP'],16);cut=r['preceding_data_call']['source_visit_index'];goodcase=j>=24
  if j<24:
   prev=previous[j];assert case==prev['input']and r['source_visits'][:cut]==prev['source_visits']and r['preceding_data_boundary']==prev['boundary']and r['preceding_data_call']==prev['additional_calls'][-1]
   for name in['source_reads','source_writes']:assert[e for e in r[name]if e['source_visit_index']<cut]==prev[name]
   for name in['prior_boundary','source_calls','bounds_calls','source_dispatches','shape_boundary','preceding_shape_dispatch']:assert r[name]==prev[name]
   assert r['models'][:2]==prev['models'];counts['preceding_selected_prefixes_equal']+=1
  assert len(r['models'])==(4 if goodcase else 3)
  for m in r['models']:
   assert not m['target_executed']and not m['memory_effects_modeled']and not any(e['source_visit_index']==m['source_visit_index']for e in r['source_reads']+r['source_writes']);counts['register_only_allocator_models']+=1
  assert r['models'][2]['kind']=='input_data_nonnull_register_return'and int(r['models'][2]['result_X0_fixture'],16)==DATA and int(r['models'][2]['registers8'][0],16)==case['inputs8'][1]&0xffffffff
  for name in['input_data_buffer','output_data_buffer']+(['source_input_buffer']if goodcase else[]):
   snap=r[name];n=snap['size_bytes'];assert bytes.fromhex(snap['known_mask_hex'])==bytes(n)and bytes.fromhex(snap['provenance_hex'])==bytes(n)and bytes.fromhex(snap['bytes_hex'])==b'\xa5'*n;counts['fully_unknown_buffer_snapshots_preserved']+=1
  assert not any(P+0x20000<=int(e['address'],16)<END for e in r['source_reads']+r['source_writes']);counts['cases_without_extended_private_buffer_access']+=1
  assert not any(WORK<=int(e['address'],16)<AUX+4096 for e in r['source_reads']);counts['cases_without_work_region_value_reads']+=1
  assert sum(bytes.fromhex(r['workspace']['known_mask_hex']))==16 and sum(bytes.fromhex(r['typed_auxiliary']['known_mask_hex']))==(16 if goodcase else 8)
  for pc,at,value in[(0xfffffe000a56d238,AUX+0x60,DATA)]+([(0xfffffe000a54412c,AUX+0x1a0,RESULT)]if goodcase else[]):
   w=[e for e in r['source_writes']if int(e['pc'],16)==pc];assert len(w)==1 and int(w[0]['address'],16)==at and w[0]['after_hex']==struct.pack('<Q',value).hex();counts['source_auxiliary_pointer_publications']+=1
  frame=bytes.fromhex(r['frame']['bytes_hex'])
  for off,val in{0xd80:0xfffffe00079172c0,0xd88:0xfffffe0007919cb0}.items():assert struct.unpack('<Q',frame[off:off+8])[0]==val;counts['source_saved_allocator_bank_cells_checked']+=1
  assert len(r['buffer_edges'])==(2 if goodcase else 1)
  for edge,pc,target,modifier in zip(r['buffer_edges'],[0xfffffe000a56d264,0xfffffe000a544160],[0xfffffe000a54409c,0xfffffe000a58c3bc],[0xf457,0x7f88]):assert int(edge['pc'],16)==pc and int(edge['target'],16)==target and int(edge['modifier16'],16)==modifier and edge['target_executed'];counts['source_nonnull_dispatch_edges']+=1
  assert r['boundary']['kind']=='before_unmodeled_core_call';call=r['additional_calls'][-1]
  if goodcase:
   assert r['boundary']['pc']=='0xfffffe000a58c428'and call['target']=='0xfffffe000a508d6c'and[int(x,16)for x in call['registers8'][:2]]==[RESULT,28]and int(r['boundary']['registers31'][19],16)==case['inputs8'][1]&0xffffffff and not call['target_executed'];counts['entropy_frontiers']+=1
   assert int(r['models'][3]['registers8'][0],16)==3072 and int(r['models'][3]['result_X0_fixture'],16)==RESULT and INPUT+(case['inputs8'][1]&0xffffffff)<=DATA and DATA+(case['inputs8'][1]&0xffffffff)<=RESULT;counts['disjoint_request_region_layouts']+=1
  else:assert r['boundary']['pc']=='0xfffffe000a544120'and call['target']=='0xfffffe000c4ba60c'and int(call['registers8'][0],16)==0 and not call['target_executed'];counts['zero_capacity_allocation_frontiers']+=1
  assert not any(int(v['pc'],16)in[0xfffffe000a508d6c,0xfffffe000a69f394,0xfffffe000be57d68,0xfffffe000c4ba60c,0xfffffe000c6393c4]for v in r['source_visits'])
  outcomes[r['boundary']['pc']]+=1
  if j%8==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==48 and counts['entropy_frontiers']==24 and counts['zero_capacity_allocation_frontiers']==24 and counts['preceding_selected_prefixes_equal']==24 and counts['register_only_allocator_models']==168 and counts['source_auxiliary_pointer_publications']==72
 deps={n:sha(ROOT/n)for n in['lskd_input_buffers_contracts.json','lskd_input_buffers_profiles.json','lskd_input_buffers_proofs.json','lskd_input_buffers_symbolic.py','lskd_input_buffers_audit.py','lskd_entropy_registration_walk.py','probe_lskd_input_buffers.py','recover_lskd_input_buffers.py','lskd_core_input_profiles.json','probe_lskd_core_input.py','probe_lskd_core_workspace.py','probe_lskd_writers.py','probe_legacy_stack.py','legacy_stack_contracts.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_input_buffers_replays.json').write_text(json.dumps(out,indent=2)+'\n');(ROOT/'lskd_entropy_registration_walk.json').write_text(json.dumps(sourcewalk,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'outcome_counts':dict(outcomes),'fresh_replays_sha256':sha(ROOT/'lskd_input_buffers_replays.json'),'registration_walk_sha256':sha(ROOT/'lskd_entropy_registration_walk.json'),'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'all_checks_pass':True,'model_memory_writes':0,'private_uninitialized_values_consumed':0,'input_content_read':False,'native_registration_executed':False,'entropy_operation_executed':False,'postentropy_continuation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_input_buffers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
