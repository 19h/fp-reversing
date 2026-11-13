#!/usr/bin/env python3
"""Source-only completion of the provider-absent core wrapper and result ABI.

Exact parent prefixes; original dispatcher call/frame anchors its epilogue.
Separate void frees retire auxiliary/workspace spans only in analysis. A
separate original UserClient suffix consumes the actual source-produced return.
O(receipt+C*V+I+Q) time/space plus 30 s/query; 10000 steps per interval.
"""
import json
from collections import Counter
import z3
from verify_daemon_reader_record_payloads_publication import read,sha
from verify_versioned_stream_initialization_publication import no_queries
from recover_kext_aes_handoff import function
from recover_carrier_control import span
from lskd_values_symbolic import resize,part,mem,cell
from recover_versioned_inner_entry import Flags,DC
import recover_versioned_error_release as Parent
P='versioned_wrapper_error_return';ROOT=Parent.ROOT
PIN='f1776efe92cb22fe7f829ea4764407864bfc0fb779e4a7b2b1e1b6e64f3bcedd'
EPILOGUE=0xfffffe000a5a729c;ENTRY=0xfffffe000a5a2bac;DISPATCH_CALL=0xfffffe000a5a2f50
AUX_FREE=0xfffffe000a5a2fe4;WORK_FREE=0xfffffe000a5a3030
GUEST=Parent.Parent.Parent.Parent.Parent.GUEST;HALT=GUEST+0x1f000
Frontier=Parent.Frontier;VALUE=Parent.VALUE
class Completion(Parent.Release):
 def __init__(self,*a):self.outer=False;super().__init__(*a)
 def step(self,pc):
  if self.outer and pc==HALT:
   self.boundary={'kind':'returned_to_declared_core_caller','pc':hex(pc),'X0':VALUE(self.read('x0')),'SP':hex(self.concrete(self.read('sp'))),'instruction_executed':False};raise Frontier()
  if self.outer and pc==EPILOGUE:return Parent.Parent.Admission.step(self,pc)
  return super().step(pc)
 def finish_interval(self,pc):
  row=self.cleanup_interval(pc);row.update(mutable_count_at_boundary=self.snapshot(GUEST+0x2000,4),wrapper_count_local=self.snapshot(self.outer_F+0x88,4),outer_registers={str(j):VALUE(self.read('x'+str(j)))for j in range(31)},outer_SP=hex(self.concrete(self.read('sp'))))
  return row
 def finish_dispatcher(self,prep):
  assert self.boundary['pc']==hex(EPILOGUE)and not self.call_stack;self.outer=True;self.outer_F=int(prep['frame_SP'],16);self.outer_entry_SP=int(prep['entry_SP'],16)
  call=next(c for c in prep['source_calls']if c['pc']==hex(DISPATCH_CALL));assert call['target']=='0xfffffe000a5a5470'and call['modifier']=='0x1e46'
  reads=[r for r in prep['source_reads']if r['visit']<call['visit']and r['size_bytes']==8 and int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')==int(call['target'],16)];assert reads;origin=reads[-1];p=Parent.Parent.Parent.Parent.Parent.Parent.pointer(self.k,int(origin['address'],16));assert p['target']==call['target']and p['diversity']==call['modifier']and p['authenticated']
  root={'pc':'declared_core_wrapper_entry','target':hex(ENTRY),'SP':hex(self.outer_entry_SP),'return_pc':hex(HALT),'entry_premise':True}
  joined={'pc':hex(DISPATCH_CALL),'target':call['target'],'SP':hex(self.outer_F),'return_pc':hex(DISPATCH_CALL+4),'original_pointer':p}
  self.call_stack=[root,joined];row=self.finish_interval(EPILOGUE);row['original_dispatcher_call_join']={'source_call':call,'source_pointer_read':origin,'original_pointer':p,'entry_SP':hex(self.outer_F),'root_entry_premise':root};return row
 def finish_free(self,kind):
  event=dict(self.boundary);pc=int(event['pc'],16);assert pc==(AUX_FREE if kind=='auxiliary'else WORK_FREE)
  ptr=GUEST+(0xc000 if kind=='auxiliary'else 0x4000);extent=4096 if kind=='auxiliary'else 16384
  if kind=='auxiliary':assert event['X0']=={'bytes_hex':'60ba470800feffff'}and event['X1']=={'bytes_hex':ptr.to_bytes(8,'little').hex()}
  else:assert event['X0']=={'bytes_hex':ptr.to_bytes(8,'little').hex()}and event['X1']=={'bytes_hex':'0040000000000000'}
  self.retired.append((ptr,ptr+extent))
  for j in range(19):self.seed('x'+str(j),z3.BitVec('wrapper_'+kind+'_void_clobber_x'+str(j),64))
  self.seed('x30',pc+4);row=self.finish_interval(pc+4);row['ordinary_void_return_premise']={'pending_call':event,'registers_clobbered':list(range(19)),'model_memory_effects':0,'logical_retirement_only':kind,'native_API_executed':False};return row

def result_component(k,status):
 assert status!=0
 ins=[]
 for pc in [0xfffffe000a5050a0,0xfffffe000a5050a4,0xfffffe000a5050b0]:
  raw=k.read(pc,4);assert raw==Parent.Parent.Parent.Parent.Parent.Parent.IMAGE.read(pc,4);i=next(DC.disasm(raw,pc));ins.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 branch=next(DC.disasm(k.read(0xfffffe000a5050a4,4),0xfffffe000a5050a4));assert branch.mnemonic=='cbnz'and branch.reg_name(branch.operands[0].reg)=='w0'and branch.operands[1].imm&((1<<64)-1)==0xfffffe000a5050b0
 return {'scope':'separate original UserClient suffix with valid post-provider output/ABI; no native caller identity or transport join','source_status32':hex(status),'source_trace':ins,'relative_output_writes':[{'pc':'0xfffffe000a5050a0','offset_bytes':0x224,'size_bytes':4,'bytes_hex':status.to_bytes(4,'little').hex()}],'count_field_at_0x220_written':False,'method_outer_status32':0,'native_API_executed':False}

def proofs(wrapper,uc):
 qs=[];counts={};c={'spans':[wrapper,uc]}
 def run(label,a,z,seeds=(),memory=()):
  v=Flags(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(label,q,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat;s.add(q);status=s.check();assert status==z3.unsat,(label,str(status));qs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True})
 F,W,Q,O=z3.BitVecs('wrapper_frame64 wrapper_workspace64 wrapper_count_pointer64 userclient_output64',64);STATUS,COUNT,OLD=z3.BitVecs('wrapper_status32 mutable_count32 post_provider_count32',32)
 v=run('wrapper_status_latch_and_count_copy',0xfffffe000a5a2f54,0xfffffe000a5a2f60,[('x27',W),('sp',F),('x24',Q)],[(W,4,STATUS),(F+0x88,4,COUNT)])
 claim('wrapper_status_latch_and_count_copy',z3.Or(v.read('w19')!=STATUS,cell(v,Q,4)!=COUNT))
 v=run('wrapper_result_translation',0xfffffe000a5a3034,0xfffffe000a5a3040,[('w19',STATUS)])
 claim('wrapper_result_translation',v.read('w0')!=(STATUS^0x31ae0066))
 v=run('userclient_error_status_store',0xfffffe000a5050a0,0xfffffe000a5050a4,[('x19',O),('w0',STATUS)],[(O+0x220,4,OLD)])
 original=v.c;v.c=part(c,'error_return',0xfffffe000a5050b0,0xfffffe000a5050b4);v.run('error_return');v.c=original;counts['userclient_error_status_store']=v.count
 # CBNZ's original target/width is checked by result_component. The separate
 # 3-instruction error arm is conditional on nonzero provider status.
 claim('userclient_nonzero_result_fields',z3.Or(cell(v,O+0x224,4)!=STATUS,cell(v,O+0x220,4)!=OLD,v.read('w0')!=0),[STATUS!=0])
 return qs,counts

def build(limit=None):
 assert sha(ROOT/'versioned_error_release_checks.json')==PIN
 old=json.loads(read(ROOT/'versioned_error_release_checks.json'));assert old['generator_sha256']==sha(Parent.__file__)
 ha=json.loads(read(ROOT/'versioned_hardware_admission_checks.json'));hand=json.loads(read(ROOT/'versioned_lock_handoff_checks.json'));ap=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'));inn=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'))
 k=Parent.Parent.Parent.Parent.Parent.Parent.Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');wrapper=function(k,entry,ENTRY);ranges=[(int(s['start'],16),int(s['end'],16))for s in [dispatcher['source_function'],out['adapter_source'],inn['inner_source'],inn['probe_source'],inn['bounds_source'],ap['fill_source'],hand['acquire_source'],hand['job_adapter_source'],hand['job_inner_source'],ha['initializer_source'],old['release_source'],wrapper]];rows=[];totals=Counter()
 for expected in old['cases'][:limit]:
  ix=expected['parent_case_index'];b=expected['branches'];a=next(c for c in ha['cases']if c['parent_case_index']==ix)['branches'];h=next(c for c in hand['cases']if c['parent_case_index']==ix)['branches'];p=next(c for c in ap['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');i=next(c for c in inn['cases']if c['parent_case_index']==ix);w=next(c for c in words['cases']if c['parent_case_index']==ix);st=next(c for c in strict['cases']if c['parent_case_index']==ix and c['boundary']['pc']=='0xfffffe000a5a731c');o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object')
  v=Completion(k,prep['cases'][ix]);assert v.prefix(w,st,o,ranges)==i['strict_prefix'];assert v.continuation(0)==i['continuations'][0];assert v.parameters('fresh_distinct_object')=={n:x for n,x in p.items()if n not in ['lock_origin_continuation','parent_case_index','configuration','operand_profile']};assert v.lock_continuation()==p['lock_origin_continuation']
  for name,fn in [('strict_wrapper_prefix',v.lock_prefix),('explicit_null',lambda:v.explicit(False)),('strict_cached_origin_prefix',v.cached_prefix),('cached_null',lambda:v.cached(False)),('no_primitive_job_prefix',v.job_prefix)]:assert no_queries(fn())==no_queries(h[name])
  for name,fn in [('strict_initializer_prefix',v.init_prefix),('arbitrary_readiness_origin',v.flag_origin),('cold_matching_request',lambda:v.readiness(False)),('matching_return',lambda:v.api_return(Parent.Parent.M)),('wait_return',lambda:v.api_return(Parent.Parent.S)),('provider_absent',lambda:v.service(False))]:assert no_queries(fn())==no_queries(a[name])
  for name,fn in [('fresh_release_origin',v.release_origin),('release_wrapper_prefix',v.release_prefix),('explicit_null',lambda:v.explicit(False)),('fresh_cached_origin',v.cached_origin),('cached_null',lambda:v.cached_release(False)),('parameter_retirement_return',lambda:v.ordinary_void('parameters')),('output_retirement_return',lambda:v.ordinary_void('output')),('input_retirement_return',lambda:v.ordinary_void('input'))]:assert no_queries(fn())==no_queries(b[name])
  d=v.finish_dispatcher(prep['cases'][ix]);aux=v.finish_free('auxiliary');workspace=v.finish_free('workspace');branches={'dispatcher_epilogue_and_count':d,'auxiliary_retirement_return':aux,'workspace_retirement_return':workspace};rows.append({'parent_case_index':ix,'configuration':expected['configuration'],'operand_profile':expected['operand_profile'],'branches':branches,'UserClient_result_component':result_component(k,int.from_bytes(bytes.fromhex(workspace['boundary']['X0']['bytes_hex']),'little'))})
  assert workspace['outer_SP']==prep['cases'][ix]['entry_SP']and workspace['boundary']['X0']=={'bytes_hex':'5e5affff00000000'}
  for r in branches.values():
   for key,events in [('source_visits','source_trace'),('authenticated_transfers','source_transfers'),('source_returns','source_returns'),('unique_observables_proved','unique_observable_proofs')]:totals[key]+=len(r[events])
   totals['source_read_bytes']+=sum(x['size_bytes']for x in r['source_reads']);totals['source_write_bytes']+=sum(x['size_bytes']for x in r['source_writes'])
  print(json.dumps({'parent':ix,'intervals':{n:{'visits':len(r['source_trace']),'boundary':r['boundary']}for n,r in branches.items()}}),flush=True)
 uc=function(k,entry,0xfffffe000a50500c);adapter=function(k,entry,0xfffffe000a504ea0);qs,lifts=proofs(wrapper,uc);deps=['recover_versioned_error_release.py',*old['dependencies']]
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'wrapper_source':wrapper,'UserClient_source':uc,'provider_adapter_source':adapter,'workspace_free_source':k.function(0xfffffe000c4b9a24),'workspace_free_symbols':k.symbols([0xfffffe000c4b9a24]),'source_proofs':qs,'source_lift_counts':lifts,'cases':rows,'verified_counts':{'parent_cases':len(rows),'retained_intervals':3*len(rows),'separate_UserClient_components':len(rows),'component_source_visits':3*len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(lifts.values()),'source_branch_instructions_checked':1,**totals},'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
