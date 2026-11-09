#!/usr/bin/env python3
"""Guarded cold-state liveness and complete original stop-method continuation.

O(C*(B+V+E)) time/retained space. Unknown origin words remain uninitialized;
only source loads certified dead before their first use may execute when the
context-cache predicate is zero. Every intervening use/definition is checked.
Only inherited allocator/free register effects; no model memory writes,
native synchronization/API/IPC or cryptographic operation.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_lskd_continuations import Continuations,cases as continuation_cases
from probe_lskd_response import RESPONSE
from probe_lskd_request import OBJECT
from probe_lskd_request import kernel
from probe_legacy_stack import P
from kext_port_tools import CS
from kext_port_tools import ROOT,SOURCE
from lskd_state_spec import ORIGINS
C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_state_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class State(Continuations):
 def __init__(self,c):
  super().__init__(c);self.state_prior=None;self.dead_windows=[];self.dead_active=None;self.kill_pending=None;self.extra=[];self.new_state_calls=[];self.stop_phase=False;self.stop_wrapper_return=None;self.new_state_returns=[];self.new_state_return_sites={};self.state_predicates=[]
  for item in contracts()['spans']:self.ranges.append((int(item['start'],16),int(item['end'],16)))
  if c.get('context_cache_fixture')=='opaque_nonnull':self.u.mem_write(0xfffffe000ccc78d0,struct.pack('<Q',P+0xe800));self.fixture_additions.append({'address':'0xfffffe000ccc78d0','bytes_hex':struct.pack('<Q',P+0xe800).hex()})
 def expand(self,a):
  assert any(x<=a<z for x,z in self.ranges),('undeclared state continuation',hex(a))
 def read(self,u,access,a,n,v,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC)
  if self.dead_active is not None and pc==int(self.dead_active['origin']['pc'],16)and a==int(self.dead_active['unknown_address'],16):
   assert n==8 and not any(self.known[a-P:a-P+8]);self.reads.append({'pc':hex(pc),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':8,'bytes_hex':bytes(u.mem_read(a,8)).hex(),'probe_only':False,'discarded_dead_load':True});self.dead_active['read_epoch_index']=len(self.reads)-1;return
  return super().read(u,access,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000a5054dc and self.original_case.get('caller')=='stop':
   self.state_prior=self.boundary_snapshot(a,'continued_wrapper_returned_to_provider');self.stop_wrapper_return=self.state_prior;self.stop_phase=True;self.execute_return_pc=None
  if self.kill_pending is not None:
   self.kill_pending['register13_after']=hex(self.reg(13));assert self.reg(13)==0xfffffe000ccc2000;self.kill_pending=None
  if a in ORIGINS:self.state_predicates.append({'pc':hex(a),'source_visit_index':self.seq,'address':'0xfffffe000ccc78d0','value64':hex(int.from_bytes(u.mem_read(0xfffffe000ccc78d0,8),'little'))})
  if a in ORIGINS and int.from_bytes(u.mem_read(0xfffffe000ccc78d0,8),'little')==0:
   off,width=ORIGINS[a];sp=u.reg_read(ar.UC_ARM64_REG_SP);snap=self.snapshot(sp+off,width);assert snap['known_mask_hex'][:16]=='00'*8;assert self.dead_active is None
   if self.state_prior is None:self.state_prior=self.boundary_snapshot(a,'before_uninitialized_private_read')
   row={'origin':{'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'snapshot':snap},'unknown_address':hex(sp+off),'register':'x13','cache_predicate':{'address':'0xfffffe000ccc78d0','value64':'0x0'},'intervening':[],'kill':None};self.dead_windows.append(row);self.dead_active=row;self.unknown_read=None;self.visit(a);return
  if self.dead_active is not None:
   i=next(self.cs.disasm(kernel().read(a,4),a));r,w=i.regs_access();reads=[i.reg_name(x)for x in r];writes=[i.reg_name(x)for x in w]
   row={'pc':hex(a),'bytes_hex':kernel().read(a,4).hex(),'source_visit_index':self.seq,'reads':reads,'writes':writes};self.dead_active['intervening'].append(row)
   if any(x in['x13','w13']for x in reads):return self.stop(a,'before_unknown_register_consumption')
   if any(x in['x13','w13']for x in writes):
    assert a==0xfffffe000a551f64 and i.mnemonic=='adrp';self.dead_active['kill']=row;self.kill_pending=self.dead_active;self.dead_active=None
  if self.stop_phase:
   if a in self.new_state_return_sites:
    call=self.new_state_return_sites.pop(a);self.new_state_returns.append({'pc':hex(a),'source_visit_index':self.seq,'target':call['target'],'call_pc':call['pc'],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(int(call['record']['address'],16),128)if call['record']is not None else None})
   if a==P+0x1f000:return self.stop(a,'original_stop_method_return')
   self.expand(a)
   if a==0xfffffe000a517dd0:
    assert self.reg(0)==0xfffffe000847af60 and self.reg(1)in[OBJECT,RESPONSE];return self.register_model(a,0xfffffe000c4ba368,'stop_stream_free_register_clobbers',0xd00d0000feed0000)
   i=next(CS.disasm(kernel().read(a,4),a));m=i.mnemonic
   if m in['bl','blraa']:
    target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]));row={'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(self.reg(0),128)if P<=self.reg(0)<P+0x20000-128 else None};self.new_state_calls.append(row)
    if target not in[0xfffffe000a50d088,0xfffffe000a560468]:return self.stop(a,'stop_method_unexecuted_call')
    self.new_state_return_sites[a+4]=row;self.expand(a+4);self.visit(a);self.calls.append({'kind':'original_stop_continuation_call','pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':row['registers31'][:8],'target_executed_in_private_guest':True,**({'record':row['record']}if row['record']is not None else{})});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
   if m=='braa':
    target=self.reg(int(i.op_str.split(',',1)[0][1:]));self.expand(target);self.visit(a);self.dispatches.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)]});return u.reg_write(ar.UC_ARM64_REG_PC,target)
   from probe_lskd_response import Response
   return Response.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.pop('undefined_private_value_reads');r.update(state_prior_boundary=self.state_prior,state_dead_load_windows=self.dead_windows,state_load_predicates=self.state_predicates,state_stop_wrapper_return=self.stop_wrapper_return,state_stop_calls=self.new_state_calls,state_stop_returns=self.new_state_returns,original_stop_method_return_executed=self.reason=='original_stop_method_return',uninitialized_private_loads=[x for x in self.reads if x.get('discarded_dead_load')],uninitialized_values_consumed=[],dead_register_value_live_at_boundary=self.dead_active is not None)
  assert self.dead_active is None and self.kill_pending is None and all(x['kill']is not None and x['register13_after']=='0xfffffe000ccc2000'for x in self.dead_windows)
  if self.stop_wrapper_return is not None:r.update(source_execution_wrapper_returned=True,source_stop_local_success_executed=self.stop_wrapper_return['registers31'][0]=='0x0')
  return r

def cases():
 old=list(continuation_cases())
 for c in old:yield json.loads(json.dumps(c))
 for c in old:
  if c.get('provider')in['vault','allowed']and c['context64']:yield {**c,'context_cache_fixture':'opaque_nonnull'}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=State(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 deps=['lskd_state_contracts.json','lskd_state_spec.py','probe_lskd_continuations.py','lskd_continuations_contracts.json','lskd_continuations_spec.py','probe_lskd_readback.py','lskd_readback_contracts.json','lskd_readback_spec.py','probe_lskd_values.py','lskd_values_contracts.json','probe_lskd_handlers.py','lskd_handlers_contracts.json','probe_lskd_consumer.py','lskd_consumer_contracts.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_synchronization_executed':False,'model_memory_writes':0,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_state_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
