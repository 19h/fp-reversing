#!/usr/bin/env python3
"""Source-only selector-21 hardware readiness and first parameter demand.

Strict runtime flag, arbitrary matching/service returns, qualified branches.
No native service, dictionary, lock, allocator, hardware, IPC or guest executes.
O(receipt+C*V+I+Q) time/space plus 30 s/query; 10000 new steps/interval.
"""
import json
from collections import Counter
import z3
from verify_daemon_reader_record_payloads_publication import read,sha
from verify_versioned_stream_initialization_publication import no_queries
from recover_kext_aes_handoff import function
from recover_carrier_control import span
from lskd_values_symbolic import resize,part,mem,cell
import recover_versioned_lock_handoff as Parent

P='versioned_hardware_admission';ROOT=Parent.ROOT
PIN='98802a68b25b7e78a3f39bd34328f22a1b9c569a09812d04ee2462e181c0eeeb'
CALL=0xfffffe000a6881dc;INIT=0xfffffe000a508030
FLAG=0xfffffe000ccceb00;FLAG_READ=0xfffffe000a50804c;FLAG_BRANCH=0xfffffe000a508050
MATCH=0xfffffe000a508070;WAIT=0xfffffe000a508078;SERVICE_BRANCH=0xfffffe000a50807c
PROVIDER=0xfffffe000ccceb08;FILL_CALL=0xfffffe000a68826c
F=z3.BitVec('aes_readiness_byte8',8);M=z3.BitVec('matching_result64',64);S=z3.BitVec('wait_service_result64',64)
Frontier=Parent.Parent.Frontier;VALUE=Parent.Parent.Parent.value
EXTERNALS={MATCH:(0xfffffe000a69f254,0xfffffe000847c458),WAIT:(0xfffffe000a69f244,0xfffffe000847c450)}

class Admission(Parent.Handoff):
 def __init__(self,*a):self.admission=False;self.allow_flag=False;super().__init__(*a)
 def load(self,a,n):
  if self.admission and self.pc==FLAG_READ:
   assert self.concrete(a)==FLAG and n==1
   if not self.allow_flag:
    self.boundary={'kind':'before_runtime_AES_readiness_read','pc':hex(self.pc),'address':hex(FLAG),'size_bytes':1,'instruction_executed':False};raise Frontier()
   self.loads.append({'pc':hex(self.pc),'visit':len(self.trace),'address':hex(FLAG),'size_bytes':1,**VALUE(F),'origin_contract':'arbitrary coherent runtime readiness byte; no file-zero or provider premise'});return F
  return super().load(a,n)
 def store(self,a,n,v,pc):
  if self.admission and pc==0xfffffe000a508084:
   at=self.concrete(a);assert at==PROVIDER and n==8 and z3.eq(z3.simplify(v),S)
   self.writes.append({'pc':hex(pc),'visit':len(self.trace),'address':hex(at),'size_bytes':n,**VALUE(v)})
   for j in range(n):self.state[at+j]=z3.Extract(8*j+7,8*j,v);self.known.add(at+j)
   return
  return super().store(a,n,v,pc)
 def transfer_pointer(self,target,modifier,pc):
  if self.admission and pc==CALL:
   p=self.init_reaching['original_pointer'];assert p['target']==hex(target)and p['diversity']==hex(modifier)and p['authenticated'];return p
  if self.admission and self.enter_fill and pc==FILL_CALL:
   p=self.fill_reaching['original_pointer'];assert p['target']==hex(target)and p['diversity']==hex(modifier)and p['authenticated'];return p
  return super().transfer_pointer(target,modifier,pc)
 def step(self,pc):
  if not self.admission:return super().step(pc)
  raw=self.k.read(pc,4);assert raw==Parent.Parent.Parent.Parent.IMAGE.read(pc,4);i=next(Parent.Parent.Parent.DC.disasm(raw,pc));self.pc=pc
  if pc in EXTERNALS:
   stub,slot=EXTERNALS[pc];assert i.mnemonic=='bl'and i.operands[0].imm&((1<<64)-1)==stub
   self.boundary={'kind':'before_external_service_API','pc':hex(pc),'target':hex(stub),'original_import_pointer':Parent.Parent.Parent.Parent.pointer(self.k,slot),'X0':VALUE(self.read('x0')),'X1':VALUE(self.read('x1')),'SP':hex(self.concrete(self.read('sp'))),'return_pc':hex(pc+4),'instruction_executed':False};raise Frontier()
  if i.mnemonic in ['tbz','tbnz']:
   assert pc==FLAG_BRANCH;test=self.read(i.reg_name(i.operands[0].reg))&(1<<i.operands[1].imm)==0
   if i.mnemonic=='tbnz':test=z3.Not(test)
   take=self.concrete(z3.If(test,z3.BitVecVal(1,8),z3.BitVecVal(0,8)));nxt=i.operands[2].imm&((1<<64)-1)if take else pc+4
   self.decisions.append({'pc':hex(pc),'target':hex(nxt),'taken':bool(take),'visit':len(self.trace)});self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});return nxt
  try:return super().step(pc)
  except Frontier:
   if pc not in [CALL,FILL_CALL]or pc==FILL_CALL and not self.enter_fill:raise
   e=self.boundary;target=INIT if pc==CALL else Parent.Parent.FILL;assert e['target']==hex(target)
   e={k:v for k,v in e.items()if k not in ['kind','instruction_executed']};self.edges.append(e);self.call_stack.append(e);self.write('x30',pc+4);self.boundary=None;self.trace.append({'pc':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str});return target
 def interval(self,pc):
  self.reset_new();row=self.run_to_frontier(pc)
  if row['boundary'].get('call'):row['boundary']['X2']=VALUE(self.read('x2'))
  row.update(job_delta_cell=self.snapshot(self.job_delta,8),job_private_header=self.snapshot(self.job_header,8),provider_cell=self.snapshot(PROVIDER,8),initializer_timeout=self.snapshot(self.init_entry_SP-0x28,8),retained_registers={r:VALUE(self.read(r))for r in ['w19','w23','x0','x1','x2','x25']})
  return row
 def init_prefix(self):
  assert self.boundary['pc']==hex(CALL);self.init_reaching=dict(self.boundary);self.init_entry_SP=self.concrete(self.read('sp'));self.job_header=int.from_bytes(bytes.fromhex(next(e for e in self.edges if e['pc']=='0xfffffe000a6890b4')['X1']['bytes_hex']),'little');self.admission=True;self.enter_fill=False;return self.interval(CALL)
 def flag_origin(self):
  assert self.boundary['pc']==hex(FLAG_READ);self.allow_flag=True;return self.interval(FLAG_READ)
 def readiness(self,ready):
  assert self.boundary['pc']==hex(FLAG_BRANCH);self.predicates.append(F&1!=0 if ready else F&1==0);return self.interval(FLAG_BRANCH)
 def api_return(self,origin):
  pc=int(self.boundary['pc'],16);assert pc in EXTERNALS;event=dict(self.boundary)
  for j in range(1,19):self.seed('x'+str(j),z3.BitVec(('matching'if pc==MATCH else 'wait')+'_return_clobber_x'+str(j),64))
  self.seed('x0',origin);self.seed('x30',pc+4);row=self.interval(pc+4);row['external_return_premise']={'pending_call':event,'return_value':VALUE(origin),'registers_clobbered':list(range(1,19)),'model_memory_effects':0,'native_API_executed':False};return row
 def service(self,present):
  assert self.boundary['pc']==hex(SERVICE_BRANCH);self.predicates.append(S!=0 if present else S==0);return self.interval(SERVICE_BRANCH)
 def warm_fill(self):
  assert self.boundary['pc']==hex(FILL_CALL);self.fill_reaching=dict(self.boundary);self.enter_fill=True;return self.interval(FILL_CALL)

def proofs(init,inner):
 qs=[];counts={};c={'spans':[init,inner]}
 class Flags(Parent.Parent.Parent.Flags):
  def run(self,label):
   original=self.c;row=next(s for s in self.c['spans']if s['label']==label)
   for i in Parent.Parent.Parent.DC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if i.mnemonic=='subs':
     self.pc=i.address;n=self.width(i.reg_name(i.operands[0].reg));a=self.operand(i,i.operands[1],n);b=self.operand(i,i.operands[2],n);self.write(i.reg_name(i.operands[0].reg),a-b);self.equal=a-b==0;self.cmp_left=a;self.cmp_right=b;self.count+=1
    else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
   self.c=original;return self
 def run(label,a,z,seeds=(),memory=()):
  v=Flags(part(c,label,a,z))
  for r,x in seeds:v.seed(r,x)
  for a,n,x in memory:mem(v,a,n,x)
  v.run(label);counts[label]=v.count;return v
 def claim(label,q):
  s=z3.Solver();s.set(timeout=30000);s.add(q);status=s.check();assert status==z3.unsat,(label,str(status));qs.append({'label':label,'query':s.to_smt2(),'result':'unsat'})
 FRAME=z3.BitVec('initializer_frame64',64)
 v=run('cold_timeout_and_match_arguments',0xfffffe000a50805c,MATCH,[('sp',FRAME)])
 claim('cold_timeout_and_match_arguments',z3.Or(cell(v,FRAME+8,8)!=0x100000000,v.read('x0')!=0xfffffe000790ba3c,v.read('x1')!=0))
 R=z3.BitVec('initializer_result32',32);ACC=z3.BitVec('status_accumulator32',32);PH=z3.BitVec('operation_phase32',32)
 # The first instruction in the gate slice restores record X0; its address is
 # explicitly seeded, while the original return value is copied before that load.
 v=run('consumer_return_gate',0xfffffe000a6881e4,0xfffffe000a688210,[('x0',resize(R,64)),('w23',ACC),('w19',PH),('sp',FRAME)],[(FRAME+0x28,8,0)])
 T=R-(z3.BitVecVal(0x635c00cc,32)&(R<<1))
 claim('consumer_return_gate',z3.Or(v.read('w23')!=ACC+T,v.read('w8')!=(PH^z3.If(T==0,z3.BitVecVal(0x540,32),z3.BitVecVal(0,32))),z3.Xor(T==0,R==0)))
 v=run('absence_status',0xfffffe000a508134,0xfffffe000a50813c)
 claim('absence_status',v.read('x0')!=0xffffffd8)
 return qs,counts

def build():
 assert sha(ROOT/'versioned_lock_handoff_checks.json')==PIN
 old=json.loads(read(ROOT/'versioned_lock_handoff_checks.json'));assert old['generator_sha256']==sha(Parent.__file__)
 ap=json.loads(read(ROOT/'versioned_aes_parameters_checks.json'));inner=json.loads(read(ROOT/'versioned_inner_entry_checks.json'));out=json.loads(read(ROOT/'versioned_output_stream_checks.json'));words=json.loads(read(ROOT/'versioned_stream_words_checks.json'));strict=json.loads(read(ROOT/'versioned_stream_initialization_checks.json'));prep=json.loads(read(ROOT/'versioned_core_preparation_checks.json'));dispatcher=json.loads(read(ROOT/'versioned_dispatcher_frame_checks.json'))
 k=Parent.Parent.Parent.Parent.Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');init=function(k,entry,INIT);ranges=[(int(s['start'],16),int(s['end'],16))for s in [dispatcher['source_function'],out['adapter_source'],inner['inner_source'],inner['probe_source'],inner['bounds_source'],ap['fill_source'],old['acquire_source'],old['job_adapter_source'],old['job_inner_source'],init]];rows=[];totals=Counter()
 for expected in old['cases']:
  ix=expected['parent_case_index'];b=expected['branches'];p=next(c for c in ap['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object');inn=next(c for c in inner['cases']if c['parent_case_index']==ix);w=next(c for c in words['cases']if c['parent_case_index']==ix);st=next(c for c in strict['cases']if c['parent_case_index']==ix and c['boundary']['pc']=='0xfffffe000a5a731c');o=next(c for c in out['cases']if c['parent_case_index']==ix and c['allocation_return_fixture']=='fresh_distinct_object')
  def fresh():
   v=Admission(k,prep['cases'][ix]);assert v.prefix(w,st,o,ranges)==inn['strict_prefix'];assert v.continuation(0)==inn['continuations'][0];assert v.parameters('fresh_distinct_object')=={n:x for n,x in p.items()if n not in ['lock_origin_continuation','parent_case_index','configuration','operand_profile']};assert v.lock_continuation()==p['lock_origin_continuation']
   for name,fn in [('strict_wrapper_prefix',v.lock_prefix),('explicit_null',lambda:v.explicit(False)),('strict_cached_origin_prefix',v.cached_prefix),('cached_null',lambda:v.cached(False)),('no_primitive_job_prefix',v.job_prefix)]:assert no_queries(fn())==no_queries(b[name])
   return v
  v=fresh();a=v.init_prefix();origin=v.flag_origin();warm=v.readiness(True);fill=v.warm_fill()
  v=fresh();assert no_queries(v.init_prefix())==no_queries(a);assert no_queries(v.flag_origin())==no_queries(origin);cold=v.readiness(False);matching=v.api_return(M);wait=v.api_return(S);absent=v.service(False)
  v=fresh();v.init_prefix();v.flag_origin();assert no_queries(v.readiness(False))==no_queries(cold);assert no_queries(v.api_return(M))==no_queries(matching);assert no_queries(v.api_return(S))==no_queries(wait);present=v.service(True)
  branches={'strict_initializer_prefix':a,'arbitrary_readiness_origin':origin,'warm_return':warm,'warm_scratch_fill':fill,'cold_matching_request':cold,'matching_return':matching,'wait_return':wait,'provider_absent':absent,'provider_present':present};rows.append({'parent_case_index':ix,'configuration':expected['configuration'],'operand_profile':expected['operand_profile'],'branches':branches})
  for r in branches.values():
   for key,events in [('source_visits','source_trace'),('authenticated_transfers','source_transfers'),('source_returns','source_returns'),('unique_observables_proved','unique_observable_proofs')]:totals[key]+=len(r[events])
   totals['source_read_bytes']+=sum(x['size_bytes']for x in r['source_reads']);totals['source_write_bytes']+=sum(x['size_bytes']for x in r['source_writes'])
  print(json.dumps({'parent':ix,'intervals':{n:{'visits':len(r['source_trace']),'boundary':r['boundary']}for n,r in branches.items()}}),flush=True)
 qs,lifts=proofs(init,old['job_inner_source']);bindings=[]
 for pc,(stub,slot)in EXTERNALS.items():
  ptr=Parent.Parent.Parent.Parent.pointer(k,slot);bindings.append({'call_site':hex(pc),'stub_source':span(k,stub,stub+16),'import_pointer':ptr,'exact_symbols':k.symbols([int(ptr['target'],16)])[ptr['target']]})
 deps=['recover_versioned_lock_handoff.py',*old['dependencies']]
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'parent_checks_sha256':PIN,'kernel_collection_sha256':k.sha256,'initializer_source':init,'service_bindings':bindings,'matching_literal':{'address':'0xfffffe000790ba3c','bytes_hex':k.read(0xfffffe000790ba3c,17).hex()},'prior_context_sha256':{n:sha(ROOT/n)for n in ['kext_cold_init_checks.json','inner_write_frontier_checks.json']},'source_proofs':qs,'source_lift_counts':lifts,'cases':rows,'verified_counts':{'parent_cases':len(rows),'retained_intervals':9*len(rows),'source_queries_unsat':len(qs),'source_lift_instructions':sum(lifts.values()),**totals},'native_target_executed':False,'full_goal_complete':False}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
