#!/usr/bin/env python3
"""Original-source obligations and independent continuous-platform witnesses.
O(source+formula DAG+visits+journals+RAM) construction/space; SMT search separate,
30 s/query. No native hardware, IDB mutation or target IPC.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_kernel_boot_environment_publication import Model
from lskd_values_symbolic import resize
import recover_kernel_platform_environment_execution as R
import probe_kernel_platform_environment_execution as CPU
from replay_kernel_platform_environment_execution import oracle,Replay
E=R.E

def source_proofs(e):
 proofs=[];coverage=[]
 def local():v=Model(e);v.regions=[];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16)
  v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad,premises=()):
  common=[*v.owned(),*premises];counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label)
  s.add(*v.bindings_for([*common,counter]),counter);result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'logic':'QF_AUFBV'});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instruction_instances':v.count,'linked_edge_obligations':len(v.edge_checks)});print(label,flush=True)
 v=local();v.regions=[(0xfffffe000cba40f8,8)];cache=v.load(0xfffffe000cba40f8,8);cut(v,0xfffffe000c5e5cd0,0xfffffe000c5e5cdc)
 prove('anchor_cache_pointer_zero_selects_original_property_reads',v,v.next!=z3.If(cache==0,resize(0xfffffe000c5e5cf8,64),resize(0xfffffe000c5e5cdc,64)))
 v=local();v.regions=[(0xfffffe000cba4120,8)];anchor=v.load(0xfffffe000cba4120,8);cut(v,0xfffffe000c5e5cdc,0xfffffe000c5e5ce8);prove('cached_anchor_returns_saved_u64',v,z3.Or(v.read('x0')!=anchor,v.next!=0xfffffe000c5e5d7c))
 pointer=CPU.TREE+0x100;v=local();v.regions=[(pointer,16),(0xfffffe000cba4120,8)];anchor=v.load(pointer+8,8);v.setmem(v.sp0+0x10,8,pointer);cut(v,0xfffffe000c5e5d6c,0xfffffe000c5e5d7c)
 prove('anchor_miss_returns_and_caches_second_ranges_u64',v,z3.Or(v.read('x0')!=anchor,v.load(0xfffffe000cba4120,8)!=anchor))
 value=z3.BitVec('PE_frequency64',64);input_address=CPU.TREE+0x200
 for index,(wide,narrow) in enumerate([(0xfffffe000c5e5a28,0xfffffe000c5e5a3c),(0xfffffe000c5e5a8c,0xfffffe000c5e5aa0),(0xfffffe000c5e5af8,0xfffffe000c5e5b0c),(0xfffffe000c5e5b58,0xfffffe000c5e5b6c),(0xfffffe000c5e5bb8,0xfffffe000c5e5bc0),(0xfffffe000c5e5c08,0xfffffe000c5e5c10)]):
  for n,pc in [(8,wide),(4,narrow)]:
   v=local();v.regions=[(input_address,8)];v.setmem(input_address,8,value);v.seed('x8',input_address);cut(v,pc,pc+4)
   prove('clock_property_'+str(index)+'_load_'+str(n)+'_bytes',v,v.read('x8')!=(value if n==8 else z3.ZeroExt(32,z3.Extract(31,0,value))))
 C=0xfffffe000cb5c5b0
 for label,a,b,base,offset in [('bus',0xfffffe000c5e5ab0,0xfffffe000c5e5abc,'x28',0),('CPU',0xfffffe000c5e5990,0xfffffe000c5e599c,'x26',8)]:
  v=local();v.regions=[(C,200)];v.seed(base,C+offset);v.seed('x8',value);v.seed('x23',0xffffffff);cut(v,a,b);prove(label+'_frequency_u64_is_capped_to_u32_max',v,v.load(C+offset,8)!=z3.If(z3.ULT(value,0xffffffff),value,resize(0xffffffff,64)))
 length=z3.BitVec('PE_property_length32',32)
 for label,a,b,cap,dest in [('debug',0xfffffe000c5e6960,0xfffffe000c5e6974,4,'w2'),('system_firmware',0xfffffe000c5e69b0,0xfffffe000c5e69c4,128,'w20'),('firmware',0xfffffe000c5e6a10,0xfffffe000c5e6a24,128,'w20'),('chip',0xfffffe000c5e6a70,0xfffffe000c5e6a84,8,'w2'),('DRAM',0xfffffe000c5e6ac0,0xfffffe000c5e6ad0,4,'w2')]:
  v=local();v.setmem(v.sp0+0x34,4,length);cut(v,a,b);prove(label+'_copy_width_is_unsigned_min_'+str(cap),v,v.read(dest)!=z3.If(z3.ULT(length,cap),length,resize(cap,32)))
 for label,a,base,size_reg,dest_reg,cap in [('target',0xfffffe000c5e67f0,0xfffffe000cb5c404,'w19','x20',16),('model',0xfffffe000c5e6898,0xfffffe000cb5c414,'w20','x21',16),('subproduct',0xfffffe000c5e690c,0xfffffe000cb5c424,'w19','x20',32)]:
  v=local();v.regions=[(base,cap)];v.seed(size_reg,length);v.seed(dest_reg,base);cut(v,a,a+8);prove(label+'_nonempty_copied_string_terminates_last_byte',v,v.load(base+z3.ZeroExt(32,length-1),1)!=0,[z3.UGE(length,1),z3.ULE(length,cap)])
 requested=z3.BitVec('PE_requested_events64',64);v=local();v.setmem(v.sp0+8,8,requested);cut(v,0xfffffe000be8551c,0xfffffe000be8553c)
 prove('present_event_divisor_clamps_to_1_through_1000000',v,v.read('x8')!=z3.If(requested==0,resize(1,64),z3.If(z3.ULT(requested,1000000),requested,resize(1000000,64))))
 v=local();cut(v,0xfffffe000be8553c,0xfffffe000be85544);prove('absent_event_divisor_defaults_to_1000000',v,v.read('x8')!=1000000)
 quotient,frequency,divisor=z3.BitVecs('PE_timer_quotient64 PE_timer_frequency64 PE_timer_divisor64',64);v=local();v.seed('x8',divisor);v.seed('x9',frequency);v.seed('x10',quotient);cut(v,0xfffffe000be85550,0xfffffe000be85584)
 expected=resize(31,32)
 for n in reversed(range(1,33)):expected=z3.If(z3.ULE(quotient,1<<n),resize(n-1,32),expected)
 prove('timer_parameter_is_clamped_ceil_log2_quotient_minus1_for_1_to_2pow32',v,v.read('w8')!=expected,[z3.UGE(quotient,1),z3.ULE(quotient,1<<32),z3.UGE(frequency,divisor),z3.UGE(divisor,1)])
 mask=z3.BitVec('PE_ACTLR64',64);v=local();v.system['actlr_el1']=mask;cut(v,0xfffffe000be864e4,0xfffffe000be864fc);prove('ACTLR_mask_clears_bits9_10_11_and_preserves_bit0',v,v.read('x0')!=(mask&0xfffffffffffff1ff))
 v=local();v.seed('x0',mask);cut(v,R.ACTLR_WRITE+4,R.ACTLR_WRITE+8);prove('ACTLR_leaf_logically_stores_exact_X0',v,v.system['actlr_el1']!=mask)
 return proofs,coverage

def semantic_count(o):return len(o['checks'])+len(o['prefix_contracts']['checks'])+sum(len(o[k]['checks']) for k in ['tree_API_contracts','option_API_contracts','copy_contracts'])

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,coverage=source_proofs(e);prior=[]
 for p in json.loads(read(ROOT/(E.P+'_audit.json')))['source_proofs']:
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;prior.append({**p,'source_artifact_sha256':sha(ROOT/(E.P+'_audit.json'))})
 image=Image();components=[];totals=Counter()
 for c in CPU.cases():
  row=CPU.Probe(image,c).run();row['independent_oracle']=oracle(row,e);q=Replay(image,row).run();totals.update(q);row['independent_replay']=q;components.append(row);print(c['label'],len(row['source_visits']),flush=True)
 controls=[]
 for index,pc in [(2,0xfffffe000c5e5ab8),(0,0xfffffe000c5e5d78),(1,0xfffffe000c5e67f4),(0,0xfffffe000be85588),(3,0xfffffe000c5e50e8),(3,0xfffffe000c5e51c0)]:
  row=CPU.Probe(image,CPU.cases()[index],mutate=pc).run()
  try:oracle(row,e)
  except AssertionError as error:controls.append({'component':row,'oracle_rejection':list(error.args[0])})
  else:raise AssertionError(('changed_source_accepted',hex(pc)))
 visited={v['pc'] for c in components for v in c['source_visits']};source={i['ea'] for f in e['functions'] for i in f['instructions']};forbidden={i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']};assert visited<=source and not visited&forbidden
 stats={'source_queries_unsat':len(proofs),'prior_source_queries_rechecked':len(prior),'proved_source_PCs':len({pc for q in coverage for pc in q['PCs']}),'proof_instruction_instances':sum(q['instruction_instances'] for q in coverage),'linked_edge_obligations':sum(q['linked_edge_obligations'] for q in coverage),'components':len(components),'source_visits':sum(len(c['source_visits']) for c in components),'executed_source_PCs':len(visited),'changed_source_controls':len(controls),'independent_semantic_checks':sum(semantic_count(c['independent_oracle']) for c in components),'original_API_calls_and_returns':sum(len(c['original_API_entries']) for c in components),'original_platform_returns':len(components),'continuous_main_enumeration_call_boundaries':sum(not c['configuration'].get('platform_only') for c in components),'generic_initializer_calls':0,'whole_mutable_checkpoint_bytes_checked':sum(3*c['independent_oracle']['whole_mutable_bytes_per_checkpoint'] for c in components),'private_nonstack_bytes_checked':sum(c['independent_oracle']['private_nonstack_bytes_checked'] for c in components),'tree_API_calls_and_returns':sum(c['independent_oracle']['tree_API_contracts']['API_calls'] for c in components),'option_API_calls_and_returns':sum(c['independent_oracle']['option_API_contracts']['API_calls'] for c in components),'copy_and_strlcpy_calls_and_returns':sum(c['independent_oracle']['copy_contracts']['calls'] for c in components),'copy_contract_destination_bytes_checked':sum(c['independent_oracle']['copy_contracts']['destination_bytes_checked'] for c in components)}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_platform_environment_execution.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'proof_coverage':coverage,'components':components,'negative_controls':controls,'independent_totals':stats,'independent_replay_totals':dict(totals),'executed_function_coverage':[{'start':f['start'],'captured_words':len(f['instructions']),'executed_unique_PCs':len({i['ea'] for i in f['instructions']}&visited)} for f in e['functions']],'conditional_kernel_platform_environment_execution_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
