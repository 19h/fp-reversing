#!/usr/bin/env python3
"""Source-only provider-absent release, record reuse and cleanup continuation.

Fresh arbitrary release-lock words; native unlock/free calls remain pending.
Separate ordinary void returns have no modeled memory effects; retirement is
analysis bookkeeping. O(receipt+C*V+I+Q) time/space plus 30 s/query, 10000 steps.
"""
import json
from collections import Counter
import z3
from verify_daemon_reader_record_payloads_publication import read,sha
from verify_versioned_stream_initialization_publication import no_queries
from recover_kext_aes_handoff import function
from recover_carrier_control import span
from lskd_values_symbolic import resize,part,mem,cell
import recover_versioned_hardware_admission as Parent
P='versioned_error_release';ROOT=Parent.ROOT
PIN='bc9265d25e394e365d782d7cbbab9520eb8852b3298bf26dc0486659f347e81e'
READ=0xfffffe000a69dcd0;CALL=0xfffffe000a69dd84;RELEASE=0xfffffe000a5bfc6c
GATE=0xfffffe000a5bfe24;CACHE_READ=0xfffffe000a5bfef8;CACHE_GATE=0xfffffe000a5bff18
MUTEX=0xfffffe000a5bfe84;RW=0xfffffe000a5bff64;PARAM_FREE=0xfffffe000a69de14
LOCK=0xfffffe000cccda78;CACHED=0xfffffe000ccceab8
E=z3.BitVec('post_operation_lock64',64);G=z3.BitVec('post_operation_cached_lock64',64)
Frontier=Parent.Frontier;VALUE=Parent.VALUE
class Release(Parent.Admission):
 def __init__(self,*a):self.cleanup=False;self.allow_post_cache=False;self.retired=[];self.pointer_history={};self.historical_edges=[];super().__init__(*a)
 def load(self,a,n):
  if self.cleanup:
   if self.pc in [READ,CACHE_READ]:
    at=self.concrete(a);assert(at,n)==(LOCK if self.pc==READ else CACHED,8)
    if self.pc==CACHE_READ and not self.allow_post_cache:
     self.boundary={'kind':'before_fresh_release_cached_lock_read','pc':hex(self.pc),'address':hex(at),'size_bytes':8,'instruction_executed':False};raise Frontier()
    v=E if self.pc==READ else G;self.loads.append({'pc':hex(self.pc),'visit':len(self.trace),'address':hex(at),'size_bytes':8,**VALUE(v),'origin_contract':'fresh arbitrary post-operation lock word; no acquisition identity/type/lifetime premise'});return v
   at=self.concrete(a)
   if any(at<z and at+n>b for b,z in self.retired):
    self.boundary={'kind':'before_logically_retired_object_read','pc':hex(self.pc),'address':hex(at),'size_bytes':n,'instruction_executed':False};raise Frontier()
  v=super().load(a,n)
  if self.loads:
   r=self.loads[-1];p=r.get('original_pointer_fixup')
   if p is not None and p['authenticated']:self.pointer_history.setdefault(p['target'],[]).append({'read_pc':r['pc'],'read_address':r['address'],'original_pointer':p})
  return v
 def store(self,a,n,v,pc):
  if self.cleanup:
   at=self.concrete(a)
   assert not any(at<z and at+n>b for b,z in self.retired),('retired write',hex(pc),hex(at))
   if pc==0xfffffe000a69dd14 or 0xfffffe000ccc7748<=at<at+n<=0xfffffe000ccc7750:
    v=z3.simplify(resize(v,n*8));assert pc!=0xfffffe000a69dd14 or at==self.lock_record and n==8 and z3.eq(v,E)
    self.writes.append({'pc':hex(pc),'visit':len(self.trace),'address':hex(at),'size_bytes':n,**VALUE(v)})
    for j in range(n):self.state[at+j]=z3.simplify(z3.Extract(8*j+7,8*j,v));self.known.add(at+j)
    return
  return super().store(a,n,v,pc)
 def transfer_pointer(self,target,modifier,pc):
  if self.cleanup and pc==0xfffffe000a5a9320:
   history=[p for p in self.pointer_history.get(hex(target),[])if p['original_pointer']['diversity']==hex(modifier)];assert history
   origin=history[-1];self.historical_edges.append({'pc':hex(pc),'target':hex(target),'origin':origin});return origin['original_pointer']
  if self.cleanup and self.enter_release and pc==CALL:
   p=self.release_reaching['original_pointer'];assert p['target']==hex(target)and p['diversity']==hex(modifier)and p['authenticated'];return p
  return super().transfer_pointer(target,modifier,pc)
 def step(self,pc):
  if self.cleanup and pc==0xfffffe000a5a729c:
   self.boundary={'kind':'before_dispatcher_epilogue','pc':hex(pc),'instruction_executed':False};raise Frontier()
  try:return super().step(pc)
  except Frontier:
   if not self.cleanup or not self.enter_release or pc!=CALL:raise
   e=self.boundary;assert e['target']==hex(RELEASE);e={k:v for k,v in e.items()if k not in ['kind','instruction_executed']};self.edges.append(e);self.call_stack.append(e);self.write('x30',pc+4);self.boundary=None;raw=self.k.read(pc,4);i=next(Parent.Parent.Parent.Parent.DC.disasm(raw,pc));self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});return RELEASE
 def cleanup_interval(self,pc):
  self.reset_new();self.historical_edges=[];row=self.run_to_frontier(pc);row['historical_pointer_origins']=self.historical_edges
  if row['boundary'].get('call'):row['boundary']['X2']=VALUE(self.read('x2'))
  row.update(job_delta_cell=self.snapshot(self.job_delta,8),job_private_header=self.snapshot(self.job_header,8),provider_cell=self.snapshot(Parent.PROVIDER,8),initializer_timeout=self.snapshot(self.init_entry_SP-0x28,8),local_constant_at_boundary=self.snapshot(Parent.Parent.Parent.Parent.GUEST+0x4118,32),auxiliary_parameter_cell=self.snapshot(Parent.Parent.Parent.Parent.GUEST+0xc270,8),dispatcher_result_at_boundary=self.snapshot(Parent.Parent.Parent.Parent.GUEST+0x4000,4),retained_registers={r:VALUE(self.read(r))for r in ['w19','w22','w23','w25','w26','x0','x1','x2','x28']},logical_retired_spans=[{'start':hex(a),'end':hex(z)}for a,z in self.retired])
  return row
 def release_origin(self):
  assert self.boundary['pc']==hex(READ);self.cleanup=True;self.enter_release=False;return self.cleanup_interval(READ)
 def release_prefix(self):
  assert self.boundary['pc']==hex(CALL);self.release_reaching=dict(self.boundary);self.enter_release=True;return self.cleanup_interval(CALL)
 def explicit(self,nonnull):
  if not self.cleanup:return super().explicit(nonnull)
  assert self.boundary['pc']==hex(GATE);self.predicates.append(E!=0 if nonnull else E==0);return self.cleanup_interval(GATE)
 def cached_origin(self):
  assert self.boundary['pc']==hex(CACHE_READ);self.allow_post_cache=True;return self.cleanup_interval(CACHE_READ)
 def cached_release(self,nonnull):
  assert self.boundary['pc']==hex(CACHE_GATE);self.predicates.append(G!=0 if nonnull else G==0);return self.cleanup_interval(CACHE_GATE)
 def ordinary_void(self,retire=None):
  event=dict(self.boundary);pc=int(event['pc'],16);assert pc in [MUTEX,RW,PARAM_FREE,0xfffffe000a5a92e4]
  if retire is not None:
   ptr=int.from_bytes(bytes.fromhex(event['X1']['bytes_hex']),'little');extent=104 if retire=='parameters'else 32;assert ptr==(self.parameters_object if retire=='parameters'else self.heap+0x200 if retire=='output'else self.heap);self.retired.append((ptr,ptr+extent))
  for j in range(19):self.seed('x'+str(j),z3.BitVec(('retire_'+str(retire)if retire else 'unlock')+'_void_clobber_x'+str(j),64))
  self.seed('x30',pc+4);row=self.cleanup_interval(pc+4);row['ordinary_void_return_premise']={'pending_call':event,'registers_clobbered':list(range(19)),'model_memory_effects':0,'logical_retirement_only':retire,'native_API_executed':False};return row

def proofs(caller,release):
 c={'spans':[caller,release]};qs=[];counts={}
 def run(label,a,z,seeds=(),memory=()):
  v=Parent.Parent.Parent.Parent.Flags(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(label,q):
  s=z3.Solver();s.set(timeout=30000);s.add(q);status=s.check();assert status==z3.unsat,(label,str(status));qs.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 C=z3.BitVec('release_record64',64);PH=z3.BitVec('release_phase32',32)
 LOW=resize(C,32)^0x734a22b2;K=LOW*0x8c229611
 v=run('release_pack_key',0xfffffe000a69dcd4,0xfffffe000a69dd08,[('x0',C),('w19',PH)])
 claim('release_pack_key',z3.Or(v.read('w10')!=LOW,v.read('w9')!=PH+0x8da))
 v=run('release_record_pack',0xfffffe000a69dd08,0xfffffe000a69dd20,[('x0',C),('x8',E),('w9',PH+0x8da),('w10',LOW)])
 encoded=cell(v,C+8,4)
 claim('release_record_pack',z3.Or(cell(v,C,8)!=E,encoded^K!=PH+0x8da))
 v=run('release_decoder_key',0xfffffe000a5bfd54,0xfffffe000a5bfd90,[('x0',C)])
 claim('release_decoder_key',z3.Or(v.read('w15')!=LOW,v.read('w16')!=0x8c229611))
 v=run('matching_release_decoder',0xfffffe000a5bfd90,0xfffffe000a5bfda0,[('x0',C),('w15',LOW),('w16',0x8c229611)],[(C,8,E),(C+8,4,(PH+0x8da)^K)])
 claim('matching_release_decoder',z3.Or(v.read('x0')!=E,v.read('w16')!=PH+0x8da))
 v=run('explicit_release_route',0xfffffe000a5bfda0,0xfffffe000a5bfdd8,[('x0',E),('w16',0xc33)])
 A=((0xc33+0x066eb39c)&0xffffffff)&0xf99147fb
 claim('explicit_release_route',z3.Or(v.read('w16')!=z3.If(E!=0,z3.BitVecVal(0xc36,32),z3.BitVecVal(0xc33,32)),v.read('w20')!=0x53c,v.read('w15')!=A))
 setup=run('cached_release_setup',0xfffffe000a5bfe98,0xfffffe000a5bfeb0,[('w15',A)])
 v=run('cached_release_route',0xfffffe000a5bfefc,0xfffffe000a5bff18,[('x0',G),('w15',A),('w16',setup.read('w16')),('w20',setup.read('w20'))])
 claim('cached_release_route',v.read('w12')!=z3.If(G==0,z3.BitVecVal(0x7fd,32),z3.BitVecVal(0x7cb,32)))
 return qs,counts

def build(limit=None):
 assert sha(ROOT/'versioned_hardware_admission_checks.json')==PIN
 old=json.loads(read(ROOT/'versioned_hardware_admission_checks.json'));assert old['generator_sha256']==sha(Parent.__file__)
 hand=json.loads(read(ROOT/'versioned_lock_handoff_checks.json'));ap=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'));inn=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'))
 k=Parent.Parent.Parent.Parent.Parent.Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');release=function(k,entry,RELEASE);ranges=[(int(s['start'],16),int(s['end'],16))for s in [dispatcher['source_function'],out['adapter_source'],inn['inner_source'],inn['probe_source'],inn['bounds_source'],ap['fill_source'],hand['acquire_source'],hand['job_adapter_source'],hand['job_inner_source'],old['initializer_source'],release]];rows=[];totals=Counter()
 for expected in old['cases'][:limit]:
  ix=expected['parent_case_index'];b=expected['branches'];h=next(c for c in hand['cases']if c['parent_case_index']==ix)['branches'];p=next(c for c in ap['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');i=next(c for c in inn['cases']if c['parent_case_index']==ix);w=next(c for c in words['cases']if c['parent_case_index']==ix);st=next(c for c in strict['cases']if c['parent_case_index']==ix and c['boundary']['pc']=='0xfffffe000a5a731c');o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object')
  def fresh():
   v=Release(k,prep['cases'][ix]);assert v.prefix(w,st,o,ranges)==i['strict_prefix'];assert v.continuation(0)==i['continuations'][0];assert v.parameters('fresh_distinct_object')=={n:x for n,x in p.items()if n not in ['lock_origin_continuation','parent_case_index','configuration','operand_profile']};assert v.lock_continuation()==p['lock_origin_continuation']
   for name,fn in [('strict_wrapper_prefix',v.lock_prefix),('explicit_null',lambda:v.explicit(False)),('strict_cached_origin_prefix',v.cached_prefix),('cached_null',lambda:v.cached(False)),('no_primitive_job_prefix',v.job_prefix)]:assert no_queries(fn())==no_queries(h[name])
   for name,fn in [('strict_initializer_prefix',v.init_prefix),('arbitrary_readiness_origin',v.flag_origin),('cold_matching_request',lambda:v.readiness(False)),('matching_return',lambda:v.api_return(Parent.M)),('wait_return',lambda:v.api_return(Parent.S)),('provider_absent',lambda:v.service(False))]:assert no_queries(fn())==no_queries(b[name])
   return v
  v=fresh();origin=v.release_origin();prefix=v.release_prefix();mutex=v.explicit(True);mutex_return=v.ordinary_void()
  v=fresh();v.release_origin();v.release_prefix();null=v.explicit(False);cache=v.cached_origin();rw=v.cached_release(True);rw_return=v.ordinary_void()
  v=fresh();v.release_origin();v.release_prefix();v.explicit(False);v.cached_origin();empty=v.cached_release(False);parameter_retire=v.ordinary_void('parameters');output_retire=v.ordinary_void('output');input_retire=v.ordinary_void('input')
  branches={'fresh_release_origin':origin,'release_wrapper_prefix':prefix,'explicit_nonnull':mutex,'mutex_void_return':mutex_return,'explicit_null':null,'fresh_cached_origin':cache,'cached_nonnull':rw,'rw_void_return':rw_return,'cached_null':empty,'parameter_retirement_return':parameter_retire,'output_retirement_return':output_retire,'input_retirement_return':input_retire};rows.append({'parent_case_index':ix,'configuration':expected['configuration'],'operand_profile':expected['operand_profile'],'branches':branches})
  for r in branches.values():
   for key,events in [('source_visits','source_trace'),('authenticated_transfers','source_transfers'),('source_returns','source_returns'),('unique_observables_proved','unique_observable_proofs')]:totals[key]+=len(r[events])
   totals['source_read_bytes']+=sum(x['size_bytes']for x in r['source_reads']);totals['source_write_bytes']+=sum(x['size_bytes']for x in r['source_writes'])
  print(json.dumps({'parent':ix,'intervals':{n:{'visits':len(r['source_trace']),'boundary':r['boundary']}for n,r in branches.items()}}),flush=True)
 qs,lifts=proofs(inn['inner_source'],release);bindings=[]
 for wrapper,stub,slot,name in [(0xfffffe000a508de4,0xfffffe000a69f0b4,0xfffffe000847c388,'_IOLockUnlock'),(0xfffffe000a508d9c,0xfffffe000a69f134,0xfffffe000847c3c8,'_IORWLockUnlock')]:
  p=Parent.Parent.Parent.Parent.Parent.pointer(k,slot);symbols=k.symbols([int(p['target'],16)])[p['target']];assert name in[x['name']for x in symbols];bindings.append({'wrapper_source':span(k,wrapper,wrapper+8),'stub_source':span(k,stub,stub+16),'import_pointer':p,'exact_symbols':symbols})
 routes=[{'index':hex(ix),'pointer':Parent.Parent.Parent.Parent.Parent.pointer(k,Parent.Parent.Parent.Parent.Parent.TABLE+8*ix)}for ix in [0xc33,0xc36,0x7cb,0x7fd,0x53c]]
 deps=['recover_versioned_hardware_admission.py',*old['dependencies']]
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'release_source':release,'source_proofs':qs,'source_lift_counts':lifts,'composition_lemmas':{'release_record_pack':['release_pack_key'],'matching_release_decoder':['release_decoder_key','release_pack_key','release_record_pack'],'cached_release_route':['explicit_release_route','cached_release_setup']},'primitive_bindings':bindings,'selected_routes':routes,'typed_free_source':k.function(0xfffffe000c4ba368),'free_symbols':k.symbols([0xfffffe000c4ba368]),'cases':rows,'verified_counts':{'parent_cases':len(rows),'retained_intervals':12*len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(lifts.values()),**totals},'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
