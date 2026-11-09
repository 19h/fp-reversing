#!/usr/bin/env python3
"""Fresh source execution, independent byte epochs and source proof readback.

O(B+C*(V+E)+I+256R) time/space plus solver cost30 s/query. No native
heap, input-content processing, credential, synchronization or IPC executes.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from probe_lskd_core_input import Input,cases,WORK,AUX,P,HALT
from lskd_core_input_symbolic import queries
from lskd_core_workspace_audit import audit
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_core_input_contracts.json');p=read('lskd_core_input_profiles.json');proof=read('lskd_core_input_proofs.json');old=read('lskd_core_workspace_profiles.json');k=Kernel();counts=Counter();outcomes=Counter()
 for obj,name in[(c,'recover_lskd_core_input.py'),(p,'probe_lskd_core_input.py'),(proof,'prove_lskd_core_input.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_kext_source_spans']+=1
 for f in c['native_functions']:assert k.function(int(f['start'],16))==f;counts['original_native_function_readbacks']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_input_checks']+=256
 view=c['free_view'];a=int(view['address'],16);assert k.read(a,64).hex()==view['original64_hex']and IMAGE.read(a,64).hex()==view['normalized64_hex']and struct.unpack('<II',k.read(a+40,8))==(0xe4,4096)
 for ptr in view['original_pointer_fields']+c['guard_dispatch_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 assert k.read(int(view['original_pointer_fields'][0]['target'],16),64).split(b'\0',1)[0].decode()==view['name']=='site.AllocType';counts['cleanup_view_metadata_bytes_checked']=64
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==7 and lifts==proof['source_lift_counts']
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 rows=[];inputs=list(cases());assert len(inputs)==98 and[r['input']for r in p['cases']]==inputs
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Input(case);r=f.run();del f;assert r==retained,(j,case);rows.append(r);counts['fresh_cases']+=1;counts['source_instruction_visits']+=len(r['source_visits']);audit(r,k,counts)
  assert r['uninitialized_read_boundary']is None and r['shape_edge_executed']
  for flag in['native_target_executed','native_heap_executed','complete_core_operation_executed','external_IPC_emission_proved','full_goal_complete']:assert not r[flag],flag
  assert r['model_memory_writes']==0;F=int(r['frame_base_SP'],16);cut=next(v['source_visit_index']for v in r['source_visits']if v['pc']=='0xfffffe000a594d14');good=case['inputs8'][0]!=0 and 16<=case['inputs8'][1]&0xffffffff<=65536
  assert r['preceding_shape_dispatch']['pc']=='0xfffffe000a594d14'and r['preceding_shape_dispatch']['target']==('0xfffffe000a56d1b4'if good else'0xfffffe000a58c0bc')and int(r['shape_boundary']['registers31'][16],16)==0xad677e52 and int(r['shape_boundary']['registers31'][21],16)==0x8de
  if j<43:
   prev=old['cases'][j];assert case==prev['input']and r['source_visits'][:cut]==prev['source_visits']and r['shape_boundary']==prev['boundary']and r['preceding_shape_dispatch']==prev['unexecuted_dispatch']
   for name in['source_reads','source_writes']:assert[e for e in r[name]if e['source_visit_index']<cut]==prev[name]
   for name in['prior_boundary','source_calls','bounds_calls','source_dispatches']:assert r[name]==prev[name]
   assert r['models'][:2]==prev['models'];counts['preceding_complete_prefixes_equal']+=1
  assert not any(WORK<=int(e['address'],16)<AUX+4096 for e in r['source_reads']);counts['cases_without_work_region_value_reads']+=1
  assert not any(P+0x2000<=int(e['address'],16)<P+0x6000 for e in r['source_reads']+r['source_writes']);counts['cases_without_input_or_output_buffer_access']+=1
  assert sum(bytes.fromhex(r['workspace']['known_mask_hex']))==16 and sum(bytes.fromhex(r['typed_auxiliary']['known_mask_hex']))==0
  assert len(r['bounds_calls'])==2
  bankvalues={0xbf8:0xfffffe00079171c0,0xbf0:0xfffffe0007919bb0,0xc08:0xfffffe000791d3b0,0xc10:0xfffffe0007920e10,0xc28:0xfffffe0007920c10,0xc30:0xfffffe00079170c0};frame=bytes.fromhex(r['frame']['bytes_hex'])
  for off,val in bankvalues.items():assert struct.unpack('<Q',frame[off:off+8])[0]==val;counts['source_saved_bank_cells_checked']+=1
  for m in r['models']:
   assert not m['target_executed']and not m['memory_effects_modeled']and not any(e['source_visit_index']==m['source_visit_index']for e in r['source_reads']+r['source_writes']);counts['register_only_model_returns']+=1
  assert not any(v['pc']in[f['start']for f in c['native_functions']]for v in r['source_visits'])
  afterwrites=[e for e in r['source_writes']if e['source_visit_index']>cut]
  if good:
   assert not r['complete_original_rejection_return']and r['boundary']['kind']=='before_unmodeled_core_call'and r['boundary']['pc']=='0xfffffe000a56d228'and not r['cleanup_models']and len(r['models'])==2
   call=r['additional_calls'][-1];assert call['pc']=='0xfffffe000a56d228'and call['target']=='0xfffffe000c4ba60c'and int(call['registers8'][0],16)==case['inputs8'][1]&0xffffffff and not call['target_executed']
   assert[(e['pc'],int(e['address'],16),e['after_hex'])for e in afterwrites]==[('0xfffffe000a56d21c',F+0x4f8,struct.pack('<Q',case['inputs8'][1]&0xffffffff).hex()),('0xfffffe000a56d220',F+0xd40,struct.pack('<Q',AUX).hex())];counts['selected_paths_stopped_before_data_allocation']+=1
  else:
   assert r['complete_original_rejection_return']and r['boundary']['kind']=='returned_original_core'and int(r['boundary']['pc'],16)==HALT and int(r['boundary']['registers31'][0],16)==0xffff5966 and r['boundary']['SP']==r['entry_SP']and len(r['models'])==4 and not afterwrites
   for rn in range(19,30):assert int(r['boundary']['registers31'][rn],16)==0x111100000000+rn*0x1111;counts['rejection_callee_saved_GP_registers_restored']+=1
   assert int(r['boundary']['registers31'][30],16)==HALT
   for m,pc,target,x0,x1,modifier in zip(r['cleanup_models'],[0xfffffe000a58c14c,0xfffffe000a58c194],[0xfffffe000c4ba368,0xfffffe000c4b9a24],[0xfffffe000847aee0,WORK],[AUX,16384],[0x560f,0xb389]):assert int(m['pc'],16)==pc and int(m['target'],16)==target and[int(x,16)for x in m['registers8'][:2]]==[x0,x1]and int(m['modifier16'],16)==modifier;counts['rejection_cleanup_models_checked']+=1
   guardreads=[e for e in r['source_reads']if e['pc']in['0xfffffe000a58c198','0xfffffe000a58c1a4']];assert len(guardreads)==2 and guardreads[0]['bytes_hex']==guardreads[1]['bytes_hex'];counts['original_rejection_returns']+=1;counts['equal_stack_guard_epilogues']+=1
  outcomes[r['boundary']['kind']]+=1
  if j%12==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==98 and counts['original_rejection_returns']==74 and counts['selected_paths_stopped_before_data_allocation']==24 and counts['preceding_complete_prefixes_equal']==43
 deps={n:sha(ROOT/n)for n in['lskd_core_input_contracts.json','lskd_core_input_profiles.json','lskd_core_input_proofs.json','lskd_core_input_symbolic.py','probe_lskd_core_input.py','lskd_core_workspace_audit.py','probe_lskd_core_workspace.py','lskd_core_workspace_profiles.json','probe_lskd_writers.py','probe_legacy_stack.py','legacy_stack_contracts.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_core_input_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'outcome_counts':dict(outcomes),'fresh_replays_sha256':sha(ROOT/'lskd_core_input_replays.json'),'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'all_checks_pass':True,'model_memory_writes':0,'private_uninitialized_values_consumed':0,'input_content_validated':False,'successful_core_operation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_core_input_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
