#!/usr/bin/env python3
"""Guarded LSKD helper/lock continuations and source-value preflight.

O(C*(B+V+E)) time and retained space. Only inherited allocator/free register
effects; no model memory writes, native heap/synchronization/API/IPC or
cryptographic operation. Uninitialized private reads stop before execution.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
from probe_lskd_readback import Readback,cases as readback_cases
from probe_lskd_response import Response,RESPONSE
from probe_lskd_request import kernel
from probe_legacy_stack import P
from kext_port_tools import CS
from kext_port_tools import ROOT,SOURCE
from lskd_continuations_spec import GLOBALS,PURE_TARGETS,ENTRY_CALLS
TARGETS=set(PURE_TARGETS);CALLS=ENTRY_CALLS
C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_continuations_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Continuations(Readback):
 def __init__(self,c):
  super().__init__(c);self.deeper=False;self.deeper_start=None;self.deeper_entry=None;self.prior_readback_boundary=None;self.continuation_returns=[];self.continuation_return_sites={};self.extra=[];self.more_calls=[];self.more_branches=[];self.cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.cs.detail=True;self.unknown_read=None
  for s in contracts()['spans']:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  if c.get('entity_fixture')=='opaque_nonnull':self.u.mem_write(0xfffffe000ccc78a8,struct.pack('<Q',P+0xe000));self.fixture_additions.append({'address':'0xfffffe000ccc78a8','bytes_hex':struct.pack('<Q',P+0xe000).hex()})
  for j,a in enumerate(GLOBALS,28):
   v=int.from_bytes(kernel().read(a,8),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&((1<<64)-1);self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
 def expand(self,a):
  assert any(x<=a<z for x,z in self.ranges),('undeclared continuation source',hex(a))
 def code(self,u,a,n,d):
  if a in CALLS:
   self.flush();assert self.reg(8)==CALLS[a];self.deeper=True;self.deeper_start=self.seq;self.prior_readback_boundary=self.boundary_snapshot(a,'before_stop_helper'if self.original_case['operation32']==0x1b5a else'new_readback_call_boundary');self.deeper_entry={'pc':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(self.reg(0),128)}
  if not self.deeper:return super().code(u,a,n,d)
  self.flush()
  if a in self.continuation_return_sites:
   call=self.continuation_return_sites.pop(a);self.continuation_returns.append({'pc':hex(a),'source_visit_index':self.seq,'call_pc':call['pc'],'target':call['target'],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(int(call['record']['address'],16),128)if call['record']is not None else None})
  if a==0xfffffe000a522e44:
   sp=u.reg_read(ar.UC_ARM64_REG_SP);self.publication={'pc':hex(a),'source_visit_index':self.seq,'SP':hex(sp),'registers31':[hex(self.reg(j))for j in range(31)],'out_reference_before':self.snapshot(self.reg(8),8),'candidate':self.snapshot(RESPONSE,160),'frame_out_reference':self.snapshot(sp+8,8),'frame_candidate':self.snapshot(sp+0x28,8)}
  if a==self.execute_return_pc:return self.stop(a,'continued_wrapper_returned_to_provider')
  if a==P+0x1f000:return self.stop(a,'continued_execution_wrapper_return'if self.original_case['kind']=='execute'else'continued_original_method_return')
  self.expand(a)
  i=next(self.cs.disasm(kernel().read(a,4),a))
  if i.mnemonic in['ldp','ldr','ldur','ldrh','ldrb','ldurb','ldurh']:
   mem=next((o for o in i.operands if o.type==ARM64_OP_MEM),None)
   if mem is not None and not mem.mem.index and(i.reg_name(mem.mem.base)in['sp','fp']or i.reg_name(mem.mem.base).startswith('x')):
    dest=i.reg_name(i.operands[0].reg);width=(1 if i.mnemonic in['ldrb','ldurb']else 2 if i.mnemonic in['ldrh','ldurh']else 4 if dest.startswith(('w','s'))else 16 if dest.startswith(('q','v'))else 8)*(2 if i.mnemonic=='ldp'else 1);base=u.reg_read(ar.UC_ARM64_REG_SP)if i.reg_name(mem.mem.base)=='sp'else self.reg(29 if i.reg_name(mem.mem.base)=='fp'else int(i.reg_name(mem.mem.base)[1:]));at=base+mem.mem.disp
    if P<=at<at+width<=P+0x20000 and not all(self.known[at-P:at-P+width]):
     self.unknown_read={'instruction':{'pc':hex(a),'mnemonic':i.mnemonic,'operands':i.op_str},'snapshot':self.snapshot(at,width)};return self.stop(a,'before_uninitialized_private_read')
  if a in[0xfffffe000a5356d8,0xfffffe000a50c8f8,0xfffffe000a50c950]:return Response.code(self,u,a,n,d)
  i=next(CS.disasm(kernel().read(a,4),a));m=i.mnemonic
  if m in['bl','blraa']:
   target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]));row={'pc':hex(a),'target':hex(target),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(self.reg(0),128)if target!=0xfffffe000a561058 and P<=self.reg(0)<P+0x20000-128 else None};self.more_calls.append(row)
   if target not in TARGETS:row['target_symbols']=kernel().symbols([target])[hex(target)];return self.stop(a,'continuation_unexecuted_call')
   self.continuation_return_sites[a+4]=row;self.expand(a+4);self.visit(a);self.calls.append({'kind':'original_continuation_call','pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':row['registers31'][:8],'target_executed_in_private_guest':True,**({'record':row['record']}if row['record']is not None else{})});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m=='braa':
   target=self.reg(int(i.op_str.split(',',1)[0][1:]));row={'pc':hex(a),'target':hex(target),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)]};self.more_branches.append(row);self.expand(target);self.visit(a);self.dispatches.append(row);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  return Response.code(self,u,a,n,d)
 def run(self):
  r=super().run();r.pop('stop_helper_executed');r.pop('complete_business_handler_executed',None);returned=r['source_execution_wrapper_returned']or self.reason in['continued_wrapper_returned_to_provider','continued_execution_wrapper_return'];r.update(continuation_entry=self.deeper_entry,preceding_readback_boundary=self.prior_readback_boundary,continuation_stage_start=self.deeper_start,continuation_calls=self.more_calls,continuation_branches=self.more_branches,continuation_returns=self.continuation_returns,unexecuted_unknown_private_read=self.unknown_read,source_execution_wrapper_returned=returned,lock_acquisition_adapter_executed_in_private_guest=any(x['target']=='0xfffffe000a54e220'and x['source_visit_index']<len(r['source_visits'])for x in self.more_calls),source_continued_inner_dispatcher_returned=self.deeper and any(v['pc']=='0xfffffe000a58a3bc'and v['source_visit_index']>=self.deeper_start for v in r['source_visits']),source_stop_local_success_executed=self.original_case['operation32']==0x1b5a and returned and r['boundary']['registers31'][0]=='0x0',native_complete_business_handler_executed=False,native_synchronization_executed=False);return r

def cases():
 for c in readback_cases():yield json.loads(json.dumps(c))
 for c in readback_cases():
  if c.get('caller')=='stop':yield {**c,'entity_fixture':'opaque_nonnull'}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Continuations(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 deps=['lskd_continuations_contracts.json','lskd_continuations_spec.py','probe_lskd_readback.py','lskd_readback_contracts.json','lskd_readback_spec.py','probe_lskd_values.py','lskd_values_contracts.json','probe_lskd_handlers.py','lskd_handlers_contracts.json','probe_lskd_consumer.py','lskd_consumer_contracts.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_synchronization_executed':False,'model_memory_writes':0,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_continuations_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
