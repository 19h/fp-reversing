#!/usr/bin/env python3
"""Fresh modeled-allocator continuation with independent byte/epoch reconstruction.

O(B+C*(V+E)+I+256R) time/space plus solver cost30 s/query. No native allocator,
input-content parsing, cryptographic operation or IPC executes.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3,capstone
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_lskd_core_workspace import pointer_pairs
from probe_lskd_core_workspace import Workspace,cases,WORK,AUX
from lskd_core_workspace_symbolic import queries
from lskd_core_workspace_audit import audit
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_core_workspace_contracts.json');p=read('lskd_core_workspace_profiles.json');proof=read('lskd_core_workspace_proofs.json');old=read('lskd_writers_profiles.json');k=Kernel();counts=Counter();targets=Counter()
 for obj,name in[(c,'recover_lskd_core_workspace.py'),(p,'probe_lskd_core_workspace.py'),(proof,'prove_lskd_core_workspace.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_kext_source_spans']+=1
 assert k.function(0xfffffe000c4ba154)==c['native_typed_allocator']and k.function(0xfffffe000bcfeb8c)==c['native_type_delegate'];counts['original_native_allocator_functions_readback']=2
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_input_checks']+=256
 assert pointer_pairs(k)==c['frame_pointer_pairs']and len(c['frame_pointer_pairs'])==136
 view=c['typed_view'];a=int(view['address'],16);assert k.read(a,64).hex()==view['original64_hex']and IMAGE.read(a,64).hex()==view['normalized64_hex']and struct.unpack('<II',k.read(a+40,8))==(0xe4,4096)
 for ptr in view['original_pointer_fields']+c['dispatch_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 assert k.read(int(view['original_pointer_fields'][0]['target'],16),64).split(b'\0',1)[0].decode()==view['name']=='site.AllocType';assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];counts['typed_view_metadata_bytes_checked']=64
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==8 and lifts==proof['source_lift_counts']and sum(lifts.values())==328
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for ins in cs.disasm(k.read(0xfffffe000a53063c,0x484),0xfffffe000a53063c):
  rd,wr=ins.regs_access();assert not any(ins.reg_name(x)in['x8','w8']for x in wr)
 rows=[];inputs=list(cases());assert len(inputs)==43 and[r['input']for r in p['cases']]==inputs
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Workspace(case);r=f.run();del f;assert r==retained,(j,case);rows.append(r);counts['fresh_cases']+=1;counts['source_instruction_visits']+=len(r['source_visits']);audit(r,k,counts)
  assert r['boundary']['kind']=='before_core_input_guard_selected_fragment'and r['boundary']['pc']=='0xfffffe000a594d14'and r['uninitialized_read_boundary']is None
  for flag in['native_target_executed','native_heap_executed','complete_core_operation_executed','external_IPC_emission_proved','full_goal_complete']:assert not r[flag],flag
  assert r['model_memory_writes']==0 and len(r['models'])==2;F=int(r['frame_base_SP'],16)
  for m,pc,target,result in zip(r['models'],['0xfffffe000a5304c8','0xfffffe000a530564'],['0xfffffe000c4b9a08','0xfffffe000c4ba154'],[WORK,AUX]):
   assert m['pc']==pc and m['target']==target and int(m['result_X0_fixture'],16)==result and not m['target_executed']and not m['memory_effects_modeled'];assert not any(x['source_visit_index']==m['source_visit_index']for x in r['source_reads']+r['source_writes']);counts['register_only_allocator_models']+=1
  assert not any(v['pc']in['0xfffffe000c4b9a08','0xfffffe000c4ba154','0xfffffe000bcfeb8c']for v in r['source_visits'])
  assert len(r['bounds_calls'])==2
  for b,pc,lo,hi in zip(r['bounds_calls'],['0xfffffe000a5305d0','0xfffffe000a530630'],[WORK+0xd00,AUX+0x400],[WORK+0x4000,AUX+0x1000]):assert b['pc']==pc and b['target']=='0xfffffe000a561058'and b['target_executed']and list(map(lambda x:int(x,16),b['registers8'][:2]))==[lo,hi];counts['source_unsigned_ordering_calls']+=1
  if j<36:
   previous=old['cases'][j];cut=len(previous['source_visits']);assert case==previous['input']and r['source_visits'][:cut]==previous['source_visits']and r['prior_boundary']==previous['boundary']
   for n in['source_reads','source_writes']:assert[x for x in r[n]if x['source_visit_index']<cut]==previous[n]
   assert r['source_calls']==previous['source_calls'];counts['preceding_complete_prefixes_equal']+=1
  frame=bytes.fromhex(r['frame']['bytes_hex']);known=bytes.fromhex(r['frame']['known_mask_hex']);provenance=bytes.fromhex(r['frame']['provenance_hex'])
  for row in c['frame_pointer_pairs']:
   expected=(WORK if row['region']=='workspace'else AUX)+row['region_offset_bytes'];off=row['frame_SP_offset_bytes'];assert frame[off:off+8]==struct.pack('<Q',expected)and known[off:off+8]==b'\1'*8 and provenance[off:off+8]==b'\1'*8
   matches=[x for x in r['source_writes']if x['pc']==row['store_PC']];assert len(matches)==1 and int(matches[0]['address'],16)==F+off and matches[0]['after_hex']==struct.pack('<Q',expected).hex();counts['source_frame_pointer_store_pairs']+=1
  clears=[x for x in r['source_writes']if x['pc']=='0xfffffe000a56d124'];assert len(clears)==1096 and[int(x['address'],16)for x in clears]==list(range(F+0xf68,F+0x13b0))and all(x['size_bytes']==1 and x['after_hex']=='00'for x in clears);counts['original_scratch_zero_byte_stores']+=1096
  assert frame[0xf68:0x13b0]==bytes(1096)and known[0xf68:0x13b0]==b'\1'*1096 and provenance[0xf68:0x13b0]==b'\1'*1096
  guard_writes=[x for x in r['source_writes']if int(x['address'],16)<F+0x13b8 and int(x['address'],16)+x['size_bytes']>F+0x13b0];assert len(guard_writes)==1 and guard_writes[0]['pc']=='0xfffffe000a530354';counts['stack_guard_cells_preserved_through_clear']+=1
  assert len(r['source_dispatches'])==1097 and r['source_dispatches'][0]['pc']=='0xfffffe000a530ac0'and r['source_dispatches'][0]['target']=='0xfffffe000a56d11c'
  for ix,d in enumerate(r['source_dispatches'][1:],1):assert d['pc']=='0xfffffe000a56d148'and int(d['X8_after_iteration'],16)==ix and d['target']==('0xfffffe000a594c70'if ix==1096 else'0xfffffe000a56d11c')and d['modifier16']=='0x97f6';counts['source_clear_loop_authenticated_edges']+=1
  assert sum(bytes.fromhex(r['workspace']['known_mask_hex']))==16 and sum(bytes.fromhex(r['typed_auxiliary']['known_mask_hex']))==0;counts['workspace_source_initialized_bytes']+=16
  assert not any(WORK<=int(x['address'],16)<AUX+4096 for x in r['source_reads']);counts['cases_without_work_region_value_reads']+=1
  pointer_arg,length=case['inputs8'][0],case['inputs8'][1]&0xffffffff;good=pointer_arg!=0 and 16<=length<=65536;target='0xfffffe000a56d1b4'if good else'0xfffffe000a58c0bc';assert r['unexecuted_dispatch']['target']==target and not r['unexecuted_dispatch']['target_executed'];targets[target]+=1;counts['shape_guard_selected_cases'if good else'shape_guard_rejected_cases']+=1
  if j%6==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==43 and counts['source_instruction_visits']==590018 and counts['register_only_allocator_models']==86 and counts['source_unsigned_ordering_calls']==86 and counts['source_frame_pointer_store_pairs']==5848 and counts['original_scratch_zero_byte_stores']==47128 and counts['shape_guard_selected_cases']==2 and counts['shape_guard_rejected_cases']==41
 deps={n:sha(ROOT/n)for n in['lskd_core_workspace_contracts.json','lskd_core_workspace_profiles.json','lskd_core_workspace_proofs.json','lskd_core_workspace_symbolic.py','lskd_core_workspace_audit.py','probe_lskd_core_workspace.py','lskd_writers_profiles.json','probe_lskd_writers.py','probe_legacy_stack.py','legacy_stack_contracts.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_core_workspace_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'shape_guard_target_counts':dict(targets),'fresh_replays_sha256':sha(ROOT/'lskd_core_workspace_replays.json'),'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'all_checks_pass':True,'model_memory_writes':0,'private_uninitialized_values_consumed':0,'input_content_validated':False,'complete_core_operation_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_core_workspace_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
