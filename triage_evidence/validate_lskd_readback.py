#!/usr/bin/env python3
"""Fresh guarded replay, independent byte epochs and exact readback contracts.

O(B+C*(V+E)+I) time/space plus solver-dependent cost (30 s/query). Only
register allocator/free effects; no native target, heap, crypto or IPC.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from recover_carrier_control import span
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from probe_lskd_readback import Readback,cases
from validate_lskd_values import audit
from lskd_readback_symbolic import queries
from probe_lskd_response import P,OBJECT,RESPONSE,PARAM

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_readback_contracts.json');p=read('lskd_readback_profiles.json');proof=read('lskd_readback_proofs.json');old=read('lskd_values_profiles.json');prior=read('legacy_stack_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');response=read('lskd_response_contracts.json');handlers=read('lskd_handlers_contracts.json');handlers={**handlers,'additional_mutable_globals':handlers['additional_mutable_globals']+c['additional_mutable_globals']};k=Kernel();counts=Counter();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_lskd_readback.py'),(p,'probe_lskd_readback.py'),(proof,'prove_lskd_readback.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_source_spans']+=1
 assert function(k,e,int(c['query_caller_static']['start'],16))==c['query_caller_static']and k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 assert k.read(0xfffffe000847af60,64).hex()==c['typed_free_view']['original64_hex'];assert struct.unpack_from('<I',k.read(0xfffffe000847af60,64),44)[0]==160
 for d in c['additional_mutable_globals']:assert k.read(int(d['address'],16),8).hex()==d['original8_hex'];counts['additional_controller_cells']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and[n for n,q in qs]==[q['name']for q in proof['proofs']]
 for(name,q),row in zip(qs,proof['proofs']):
  op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   solver=z3.Solver();solver.set(timeout=30000);solver.add(f);assert str(solver.check())=='unsat',name
  counts['relifted_local_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected==[r['input']for r in old['cases']];fresh=[];boundaries=Counter();handoffs=Counter();slots={};TABLE=0xfffffe000846c420
 def edge(r,ix,target,modifier):
  candidates=[z for z in r['source_reads']if z['source_visit_index']<ix and z['size_bytes']==8 and TABLE<=int(z['address'],16)<0xfffffe0008471c00 and z['bytes_hex']==struct.pack('<Q',int(target,16)).hex()];assert candidates,(ix,target);ptr=pointer(k,int(candidates[-1]['address'],16));assert ptr['target']==target and ptr['authenticated']and int(ptr['diversity'],16)==modifier;slots[ptr['slot']]=ptr;counts['original_authenticated_edges']+=1
 for j,(case,retained,previous)in enumerate(zip(expected,p['cases'],old['cases'])):
  g=Readback(case);r=g.run();del g;assert r==retained,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);boundaries[r['boundary']['kind']]+=1
  assert not any(r[f]for f in['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','stop_helper_executed','external_IPC_emission_proved','full_goal_complete','native_object_free_executed'])
  assert not any(v['pc']in['0xfffffe000c4ba368','0xfffffe000a54e220','0xfffffe000a52f9f4','0xfffffe000a55ce30','0xfffffe000a55b390','0xfffffe000a508d6c','0xfffffe000be57d68']for v in r['source_visits'])
  assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])))
  extra_snaps=[{'source_visit_index':x['source_visit_index'],'out_reference':s}for x in r['readback_returns']for s in x['snapshots'].values()]+[{'source_visit_index':x['source_visit_index'],'out_reference':x['record']}for x in r['readback_calls']if x['record']is not None]
  audit({**r,'observations':r['observations']+extra_snaps},response,prior,ctor,fields,execute,k,counts,handlers)
  cut=len(previous['source_visits']);assert r['source_visits'][:cut]==previous['source_visits'];assert(r['preceding_values_boundary']if r['preceding_values_boundary']is not None else r['boundary'])==previous['boundary']
  for name in['source_reads','source_writes','source_calls','source_dispatches','models']:assert[x for x in r[name]if x['source_visit_index']<cut]==previous[name],(j,name)
  assert not any(any(int(d['address'],16)<=int(x['address'],16)<int(d['address'],16)+8 for d in c['additional_mutable_globals'])for x in previous['source_reads']);counts['preceding_complete_prefixes_equal']+=1
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64'];counts['FP64_contexts_preserved']+=1
  for m in r['models']:
   assert not m['target_executed']and not m['memory_effects_modeled'];counts['register_only_models']+=1
   if m['pc']=='0xfffffe000a517dd0':
    assert m['target']=='0xfffffe000c4ba368'and m['registers8'][0]=='0xfffffe000847af60'and int(m['registers8'][1],16)in[OBJECT,RESPONSE];edge(r,m['source_visit_index'],m['target'],0x560f);counts['source_stream_free_preparations']+=1
  for x in r['readback_branches']:edge(r,x['source_visit_index'],x['target'],int(x['registers31'][17],16))
  for x in r['readback_calls']:
   ins=next(CS.disasm(k.read(int(x['pc'],16),4),int(x['pc'],16)))
   if ins.mnemonic=='blraa':edge(r,x['source_visit_index'],x['target'],int(x['registers31'][17],16))
   else:assert ins.mnemonic=='bl'and int(ins.op_str[1:],16)==int(x['target'],16)
   if x['source_visit_index']==len(r['source_visits']):
    assert r['boundary']['kind']=='new_readback_call_boundary';handoffs[x['pc']+' -> '+x['target']]+=1;assert k.symbols([int(x['target'],16)])[x['target']]==x['target_symbols'];counts['unexecuted_next_calls']+=1
  for x in r['readback_returns']:
   if x['target']!='0xfffffe000a52eed4':continue
   call=max((z for z in r['readback_calls']if z['pc']==x['call_pc']and z['source_visit_index']<x['source_visit_index']and int(z['registers31'][0],16)==int(x['snapshots']['record']['address'],16)),key=lambda z:z['source_visit_index']);gaddr=int(x['snapshots']['record']['address'],16);b=bytes.fromhex(call['record']['bytes_hex']);key=((gaddr^0xae0701e7)*0x952f3cb7)&0xffffffff;tag=(struct.unpack_from('<H',b,4)[0]-key-0x12bd)&65535;assert struct.unpack_from('<I',b,24)[0]^key==0x526
   b=bytes.fromhex(x['snapshots']['record']['bytes_hex']);assert struct.unpack_from('<I',b)[0]==0x5e561849
   length=int.from_bytes(bytes.fromhex(x['snapshots']['length']['bytes_hex']),'little');ptr=int.from_bytes(bytes.fromhex(x['snapshots']['data_pointer']['bytes_hex']),'little');assert length==(4 if tag in[0x65,0x7e]else 8)
   getter=next(z for z in r['readback_returns']if z['source_visit_index']>x['source_visit_index']and z['target']in['0xfffffe000a55132c','0xfffffe000a50eccc']);out=getter['snapshots']['value'];outaddr=int(out['address'],16);writepc='0xfffffe000a525dd8'if length==4 else'0xfffffe000a544018';readpcs=['0xfffffe000a525d90','0xfffffe000a525d98','0xfffffe000a525da0','0xfffffe000a525da8']if length==4 else['0xfffffe000a544014'];reads=[z for z in r['source_reads']if x['source_visit_index']<z['source_visit_index']<getter['source_visit_index']and z['pc']in readpcs];assert len(reads)==(4 if length==4 else 1)and[int(z['address'],16)for z in reads]==([ptr+i for i in range(4)]if length==4 else[ptr]);payload=b''.join(bytes.fromhex(z['bytes_hex'])for z in reads);expectedword=int.from_bytes(payload,'big'if length==4 else'little');assert out['bytes_hex']==expectedword.to_bytes(length,'little').hex()
   writes=[z for z in r['source_writes']if x['source_visit_index']<z['source_visit_index']<getter['source_visit_index']and int(z['address'],16)==outaddr];assert len(writes)==1 and writes[0]['pc']==writepc and writes[0]['size_bytes']==length
   assert tag in([0x65]if case.get('caller')=='query'else[0x7e]if case.get('provider')=='allowed'else[0x8b]if case.get('provider')=='vault'else[0x6b,0x6c,0x89,0x8a]);counts['original_additional_field_returns']+=1;counts['source_BE32_outputs'if length==4 else'source_raw8_outputs']+=1
  if case.get('caller')=='query':
   assert r['source_execution_wrapper_returned']and r['source_query_success_executed']and r['query_method_return_executed']and r['boundary']['registers31'][0]=='0x13180000'and r['boundary']['SP']==r['entry_SP'];assert [int(x,16)for x in r['boundary']['registers31'][19:30]]==[0x111100000000+n*0x1111 for n in range(19,30)];assert len([m for m in r['models']if m['pc']=='0xfffffe000a517dd0'])==2;assert r['query_wrapper_return']['registers31'][0]=='0x0';counts['original_query_method_returns']+=1
  if case.get('provider')=='avd':
   if case['context64']==0:assert r['boundary']['kind']=='wrapper_returned_to_provider'and r['boundary']['registers31'][0]=='0xffff5953';counts['AVD_zero_context_error_returns']+=1
   else:assert r['boundary']['pc']=='0xfffffe000a531d60'and r['boundary']['registers31'][8]=='0xfffffe000a54e220';counts['AVD_nonzero_context_helper_boundaries']+=1
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==343 and counts['original_query_method_returns']==12 and counts['source_stream_free_preparations']==24 and counts['AVD_zero_context_error_returns']==counts['AVD_nonzero_context_helper_boundaries']==12
 deps={n:sha(ROOT/n)for n in['probe_lskd_readback.py','lskd_readback_spec.py','lskd_readback_contracts.json','lskd_readback_symbolic.py','lskd_values_symbolic.py','validate_lskd_values.py','lskd_values_profiles.json','lskd_readback_profiles.json']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_readback_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundary_coverage':dict(boundaries),'next_call_coverage':dict(handoffs),'original_authenticated_slots':list(slots.values()),'fresh_replays_sha256':sha(ROOT/'lskd_readback_replays.json'),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'all_checks_pass':True,'model_memory_writes':0,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_readback_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'boundaries':dict(boundaries),'next_calls':dict(handoffs)}),flush=True)
if __name__=='__main__':main()
