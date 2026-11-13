#!/usr/bin/env python3
"""Source-only lock routing and parameter handoff from pinned reaching state.

Unknown words remain arbitrary; explicit predicates qualify resolved controls.
Native lock calls stay pending. Separate void-return continuations declare no
memory effect or native ownership. O(receipt+C*V+I+Q) time/space; 10000 new
steps/case, 30 s per uniqueness/source query. No native API or guest executes.
"""
import json
from collections import Counter
import z3
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_carrier_control import span
from recover_kext_aes_handoff import function
from lskd_values_symbolic import resize,part,mem,cell
from verify_versioned_stream_initialization_publication import no_queries
import recover_versioned_aes_parameters as Parent

P='versioned_lock_handoff';ROOT=Parent.ROOT
PIN='4f38b356c30c213c0040f9c536c4bfa19115090c932726f351e015fe38d99968'
CALL=0xfffffe000a69db54;ACQUIRE=0xfffffe000a5b403c
GATE=0xfffffe000a5b41bc;CACHED_READ=0xfffffe000a5b4274;CACHED_GATE=0xfffffe000a5b4294
CACHED=0xfffffe000ccceab8;MUTEX_CALL=0xfffffe000a5b4218;RW_CALL=0xfffffe000a5b42f0
JOB_CALL=0xfffffe000a69dc14;JOB_ADAPTER=0xfffffe000a688ebc;JOB_INNER=0xfffffe000a687ee0
CONTROLLERS=[0xfffffe000ccc3698,0xfffffe000ccc3348,0xfffffe000ccc7740,0xfffffe000ccc30c8]
SOURCE_CALLS={CALL:ACQUIRE,JOB_CALL:JOB_ADAPTER,0xfffffe000a68901c:0xfffffe000a5a1cc4,0xfffffe000a6890b4:JOB_INNER}
L=z3.BitVec('startup_lock_cell64',64);G=z3.BitVec('cached_rw_lock_cell64',64)

class Handoff(Parent.Parameters):
 def __init__(self,*a):self.handoff=False;self.in_job=False;self.predicates=[];self.allow_cached=False;self.unique=[];super().__init__(*a)
 def concrete(self,v):
  if not self.handoff or not self.predicates or z3.is_bv_value(z3.simplify(v)):return super().concrete(v)
  s=z3.Solver();s.set(timeout=30000);s.add(*self.predicates);assert s.check()==z3.sat;candidate=s.model().eval(v,model_completion=True);assert z3.is_bv_value(candidate);s.add(v!=candidate)
  if s.check()!=z3.unsat:return super().concrete(v)
  self.unique.append({'pc':hex(self.pc),'visit':len(self.trace),'expression':v.sexpr(),'width_bits':v.size(),'value':hex(candidate.as_long()),'predicate_expressions':[p.sexpr()for p in self.predicates],'query':s.to_smt2(),'result':'unsat'});self.observables.append(candidate);return candidate.as_long()
 def load(self,a,n):
  if self.handoff and self.allow_cached and self.pc==CACHED_READ:
   assert self.concrete(a)==CACHED and n==8;self.loads.append({'visit':len(self.trace),'pc':hex(self.pc),'address':hex(CACHED),'size_bytes':8,**Parent.Parent.value(G),'origin_contract':'arbitrary cached lock-cell word; no object-type or native lifetime premise'});return G
  return super().load(a,n)
 def transfer_pointer(self,target,modifier,pc):
  if self.handoff and pc==CALL:
   p=self.reaching_boundary['original_pointer'];assert p['target']==hex(target)and p['diversity']==hex(modifier)and p['authenticated'];return p
  if self.handoff and self.in_job and pc==JOB_CALL:
   p=self.job_reaching['original_pointer'];assert p['target']==hex(target)and p['diversity']==hex(modifier)and p['authenticated'];return p
  if self.handoff and pc==0xfffffe000a68901c:
   p=Parent.Parent.Parent.pointer(self.k,0xfffffe000847c618);assert p['target']==hex(target)and p['diversity']=='0x0'and modifier==int(p['slot'],16)and p['authenticated'];return p
  return super().transfer_pointer(target,modifier,pc)
 def store(self,a,n,v,pc):
  if self.handoff:
   at=self.concrete(a)
   if any(g<=at<at+n<=g+8 for g in CONTROLLERS):
    v=z3.simplify(resize(v,n*8));assert z3.is_bv_value(v);self.writes.append({'visit':len(self.trace),'pc':hex(pc),'address':hex(at),'size_bytes':n,**Parent.Parent.value(v)})
    for j in range(n):self.state[at+j]=z3.Extract(8*j+7,8*j,v);self.known.add(at+j)
    return
  return super().store(a,n,v,pc)
 def step(self,pc):
  try:return super().step(pc)
  except Parent.Frontier:
   if not self.handoff or pc not in SOURCE_CALLS or pc!=CALL and not self.in_job:raise
   e=self.boundary;assert e['target']==hex(SOURCE_CALLS[pc]);e={k:v for k,v in e.items()if k not in ['kind','instruction_executed']};self.edges.append(e);self.call_stack.append(e);self.write('x30',pc+4);self.boundary=None;raw=self.k.read(pc,4);i=next(Parent.Parent.DC.disasm(raw,pc));self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});return SOURCE_CALLS[pc]
 def reset_new(self):self.reset_journal();self.unique=[]
 def run_to_frontier(self,pc):
  self.boundary=None
  for _ in range(10000):
   try:pc=self.step(pc)
   except Parent.Frontier:break
  assert self.boundary is not None
  if self.boundary['pc']==hex(MUTEX_CALL):self.boundary['kind']='before_pending_IOLockLock_wrapper'
  elif self.boundary['pc']==hex(RW_CALL):self.boundary['kind']='before_pending_IORWLockWrite_wrapper'
  elif self.boundary['pc']==hex(JOB_CALL):self.boundary['kind']='before_parameter_stack_adapter'
  elif self.boundary['pc']=='0xfffffe000a6881dc':self.boundary['kind']='before_initKernelAESHW'
  row=self.receipt();row.update(parameters_at_boundary=self.snapshot(self.parameters_object,104),lock_record_at_boundary=self.snapshot(self.lock_record,0x28),retained_parameter_register=Parent.Parent.value(self.read('x28')),unique_observable_proofs=self.unique,predicate_expressions=[p.sexpr()for p in self.predicates],allocator_model_memory_writes=0,native_lock_executed=False)
  return row

 def lock_prefix(self):
  assert self.boundary['pc']==hex(CALL);self.reaching_boundary=dict(self.boundary);self.handoff=True;self.predicates=[];self.reset_new();row=self.run_to_frontier(CALL);assert row['boundary']['pc']==hex(GATE);return row
 def explicit(self,nonnull):
  assert self.boundary['pc']==hex(GATE);self.predicates=[L!=0 if nonnull else L==0];self.reset_new();row=self.run_to_frontier(GATE);assert row['boundary']['pc']==hex(MUTEX_CALL if nonnull else CACHED_READ);return row
 def cached_prefix(self):
  assert self.boundary['pc']==hex(CACHED_READ);self.allow_cached=True;self.reset_new();row=self.run_to_frontier(CACHED_READ);assert row['boundary']['pc']==hex(CACHED_GATE);return row
 def cached(self,nonnull):
  assert self.boundary['pc']==hex(CACHED_GATE);self.predicates.append(G!=0 if nonnull else G==0);self.reset_new();return self.run_to_frontier(CACHED_GATE)
 def after_primitive(self):
  assert self.boundary['pc']in [hex(MUTEX_CALL),hex(RW_CALL)];event=dict(self.boundary);self.reset_new()
  for j in range(19):self.seed('x'+str(j),z3.BitVec('void_lock_return_clobber_x'+str(j),64))
  pc=int(event['pc'],16)+4;self.seed('x30',pc);row=self.run_to_frontier(pc);row['void_primitive_return_premise']={'pending_call':event,'return_pc':hex(pc),'registers_clobbered':list(range(19)),'model_memory_effects':0,'native_acquisition_established':False};return row
 def job_prefix(self):
  assert self.boundary['pc']==hex(JOB_CALL);self.job_reaching=dict(self.boundary);self.job_delta=self.concrete(self.read('x1'));self.in_job=True;self.reset_new();row=self.run_to_frontier(JOB_CALL)
  row['job_delta_cell']=self.snapshot(self.job_delta,8)
  edges=[e for e in self.edges if e['pc']=='0xfffffe000a6890b4']
  if edges:row['job_private_header']=self.snapshot(int.from_bytes(bytes.fromhex(edges[0]['X1']['bytes_hex']),'little'),8)
  return row

def proofs(acquire,caller,inner):
 c={'spans':[acquire,caller,inner]};qs=[];counts={};F=0x51010000
 def run(label,a,z,seeds=(),memory=()):
  v=Parent.Parent.Flags(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(label,q):
  s=z3.Solver();s.set(timeout=30000);s.add(q);status=s.check();assert status==z3.unsat,(label,str(status),s.reason_unknown()if status==z3.unknown else str(s.model()));qs.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 v=run('explicit_pointer_route',0xfffffe000a5b414c,0xfffffe000a5b4170,[('x0',L),('w17',0x729)])
 claim('explicit_pointer_route',z3.Or(v.read('w17')!=z3.If(L!=0,z3.BitVecVal(0x736,32),z3.BitVecVal(0x729,32)),v.read('w20')!=0x555))
 v=run('cached_pointer_route',0xfffffe000a5b4278,0xfffffe000a5b4294,[('x0',G),('w2',0x729),('w16',0x26c),('w1',0x618),('w17',0xc3),('w15',0x545)])
 claim('cached_pointer_route',z3.Or(v.read('w11')!=z3.If(G==0,z3.BitVecVal(0x555,32),z3.BitVecVal(0x545,32)),v.read('w20')!=0x555))
 C,H,D,S=z3.BitVecs('handoff_record64 handoff_parameters64 handoff_buffer64 handoff_seed64',64);PH=z3.BitVec('handoff_phase32',32)
 v=run('parameter_record_pack',0xfffffe000a69db58,0xfffffe000a69dbb4,[('x24',C),('x25',D),('x28',H),('w22',PH)])
 K=(resize(C,32)^0xdb228b70)*0x82f37eeb
 claim('parameter_record_pack',z3.Or(cell(v,C,8)!=H,cell(v,C+0x10,8)!=D,cell(v,C+0x20,8)!=D,cell(v,C+0x18,4)+K!=PH-0x43a,cell(v,C+0x1c,4)-K!=0x46d8b889))
 packed=v
 v=run('matching_inner_key',0xfffffe000a687ffc,0xfffffe000a688048,[('x0',C)])
 claim('matching_inner_key',resize(v.read('x10'),32)!=K)
 # Compose the two preceding proved key/field lemmas in canonical form.
 v=run('parameter_record_admission',0xfffffe000a688048,0xfffffe000a688078,[('x0',C),('x10',resize(K,64))],[(C+0x18,4,PH-0x43a-K),(C,8,H),(C+0x10,8,D),(C+0x20,8,D)])
 claim('parameter_record_admission',z3.Or(v.read('x25')!=H,v.read('x15')!=D,v.read('x16')!=D,v.read('w19')!=PH-0x43a,v.read('w11')!=((PH-0x43a)^z3.If(z3.And(H!=0,D!=0),z3.BitVecVal(0x8fb,32),z3.BitVecVal(0,32)))))
 SIZE=z3.BitVec('parameter_span32',32)
 v=run('parameter_span_route',0xfffffe000a6880d4,0xfffffe000a6880ec,[('x25',H),('w19',0x352)],[(H+0x28,4,SIZE)])
 claim('parameter_span_route',v.read('w8')!=(z3.BitVecVal(0x352,32)^z3.If(z3.ULE(SIZE,8192),z3.BitVecVal(0xfa,32),z3.BitVecVal(0,32))))
 v=run('retained_count_admission',0xfffffe000a6880fc,0xfffffe000a68815c,[('x0',C),('x25',H),('x10',resize(K,64)),('w19',0x352),('sp',F)],[(C+0x1c,4,K+0x46d8b889),(H+0x24,4,0)])
 claim('retained_count_admission',z3.Or(cell(v,F+0x80,4)!=0x46d8b889,v.read('w8')!=0xbea,(cell(v,F+0x80,4)+0x31c19255-0x789a4abe)!=32))
 HEADER=z3.BitVec('handoff_header64',64)
 v=run('nested_header_restoration',0xfffffe000a687ff0,0xfffffe000a687ffc,[('x1',HEADER)],[(HEADER,8,S-0x100)])
 claim('nested_header_restoration',cell(v,HEADER,8)!=S)
 return qs,counts
def build():
 assert sha(ROOT/'versioned_aes_parameters_checks.json')==PIN
 previous=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'));assert previous['generator_sha256']==sha(Parent.__file__)
 old=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'));k=Parent.Parent.Parent.Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');acquire=function(k,entry,ACQUIRE)
 adapter=function(k,entry,JOB_ADAPTER);inner=function(k,entry,JOB_INNER);ranges=[(int(s['start'],16),int(s['end'],16))for s in [dispatcher['source_function'],out['adapter_source'],old['inner_source'],old['probe_source'],old['bounds_source'],previous['fill_source'],acquire,adapter,inner]];rows=[];counts=Counter()
 for expected in previous['cases']:
  if expected['allocation_return_fixture']!='fresh_distinct_object':continue
  ix=expected['parent_case_index'];case=next(c for c in old['cases']if c['parent_case_index']==ix);word=next(c for c in words['cases']if c['parent_case_index']==ix);st=next(c for c in strict['cases']if c['parent_case_index']==ix and c['boundary']['pc']=='0xfffffe000a5a731c');o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object')
  def fresh():
   v=Handoff(k,prep['cases'][ix]);assert v.prefix(word,st,o,ranges)==case['strict_prefix'];assert v.continuation(0)==case['continuations'][0];a=v.parameters('fresh_distinct_object');assert a=={n:x for n,x in expected.items()if n not in ['lock_origin_continuation','parent_case_index','configuration','operand_profile']};assert v.lock_continuation()==expected['lock_origin_continuation'];return v
  def same(a,b):assert no_queries(a)==no_queries(b)
  v=fresh();prefix=v.lock_prefix();v=fresh();same(v.lock_prefix(),prefix);positive=v.explicit(True);mutex_return=v.after_primitive();mutex_job=v.job_prefix();v=fresh();same(v.lock_prefix(),prefix);negative=v.explicit(False);cached=v.cached_prefix();v=fresh();same(v.lock_prefix(),prefix);same(v.explicit(False),negative);same(v.cached_prefix(),cached);rw=v.cached(True);rw_return=v.after_primitive();rw_job=v.job_prefix();v=fresh();same(v.lock_prefix(),prefix);same(v.explicit(False),negative);same(v.cached_prefix(),cached);empty=v.cached(False);empty_job=v.job_prefix()
  branches={'strict_wrapper_prefix':prefix,'explicit_nonnull':positive,'mutex_void_return':mutex_return,'mutex_job_prefix':mutex_job,'explicit_null':negative,'strict_cached_origin_prefix':cached,'cached_nonnull':rw,'rw_void_return':rw_return,'rw_job_prefix':rw_job,'cached_null':empty,'no_primitive_job_prefix':empty_job};row={'parent_case_index':ix,'configuration':expected['configuration'],'operand_profile':expected['operand_profile'],'branches':branches};rows.append(row)
  for b in branches.values():
   counts['source_visits']+=len(b['source_trace']);counts['source_read_bytes']+=sum(x['size_bytes']for x in b['source_reads']);counts['source_write_bytes']+=sum(x['size_bytes']for x in b['source_writes']);counts['authenticated_transfers']+=len(b['source_transfers']);counts['source_returns']+=len(b['source_returns']);counts['unique_observables_proved']+=len(b['unique_observable_proofs'])
  print(json.dumps({'case':ix,'branches':{n:{'visits':len(b['source_trace']),'boundary':b['boundary']}for n,b in branches.items()}}),flush=True)
 qs,lifts=proofs(acquire,old['inner_source'],inner);bindings=[]
 for wrapper,stub,slot,name in [(0xfffffe000a508dd4,0xfffffe000a69f094,0xfffffe000847c378,'_IOLockLock'),(0xfffffe000a508d94,0xfffffe000a69f144,0xfffffe000847c3d0,'_IORWLockWrite')]:
  p=Parent.Parent.Parent.pointer(k,slot);symbols=k.symbols([int(p['target'],16)])[p['target']];assert name in [x['name']for x in symbols];bindings.append({'wrapper_source':span(k,wrapper,wrapper+8),'stub_source':span(k,stub,stub+16),'import_pointer':p,'exact_symbols':symbols,'native_primitive_executed':False})
 routes=[{'index':hex(ix),'pointer':Parent.Parent.Parent.pointer(k,Parent.Parent.Parent.TABLE+8*ix)}for ix in [0x729,0x736,0x545,0x555,0xba9,0x3a8,0xbea,0x352]]
 deps=['recover_versioned_aes_parameters.py','recover_versioned_inner_entry.py','recover_versioned_output_stream.py','recover_versioned_stream_words.py','recover_versioned_stream_initialization.py','recover_versioned_dispatcher_frame.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py','recover_carrier_control.py','verify_versioned_stream_initialization_publication.py']
 references={n:sha(ROOT/n)for n in ['sample_lock_checks.json','sample_lock_contracts.json','cached_lock_origin_checks.json','core_stack_delta_abi_checks.json','inner_write_frontier_checks.json']}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'prior_context_sha256':references,'acquire_source':acquire,'job_adapter_source':adapter,'job_inner_source':inner,'source_proofs':qs,'source_lift_counts':lifts,'composition_lemmas':{'parameter_record_admission':['parameter_record_pack','matching_inner_key'],'retained_count_admission':['parameter_record_pack','matching_inner_key']},'primitive_bindings':bindings,'selected_routes':routes,'cases':rows,'verified_counts':{'parent_cases':len(rows),'retained_branches':11*len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(lifts.values()),'primitive_bindings':len(bindings),'selected_original_routes':len(routes),**counts},'new_guest_executed':False,'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
