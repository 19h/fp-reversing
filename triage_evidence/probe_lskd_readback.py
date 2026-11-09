#!/usr/bin/env python3
"""Guarded original query method, metadata/u32/raw8 getters and cleanup preparation.

O(C*(B+V+E)) time and retained space. Abstract PAC; inherited allocator/free
register effects plus the exact typed stream free site. No model memory
writes, native target/heap/IPC, randomness or cryptographic operations.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_lskd_values import Values,cases
from probe_lskd_response import Response,RESPONSE
from probe_lskd_request import kernel,OBJECT
from probe_legacy_stack import P
from kext_port_tools import CS
from kext_port_tools import ROOT,SOURCE
from lskd_readback_spec import GLOBALS,PURE_TARGETS
NEW=set(PURE_TARGETS)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def contracts():return json.loads((ROOT/'lskd_readback_contracts.json').read_text())
class Readback(Values):
 def __init__(self,c):
  super().__init__(c);self.new_stage=False;self.extra=[];self.new_calls=[];self.new_branches=[];self.return_marks=[];self.wrapper_return=None;self.preceding_boundary=None;self.readback_returns=[];self.return_sites={};self.stage_start=None
  for s in contracts()['spans']:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  for j,a in enumerate(GLOBALS,22):
   v=int.from_bytes(kernel().read(a,8),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&((1<<64)-1);self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
 def add(self,a):
  assert any(x<=a<z for x,z in self.ranges),('undeclared source continuation',hex(a))
 def begin(self,a,kind):
  if not self.new_stage:self.preceding_boundary=self.boundary_snapshot(a,kind);self.stage_start=self.seq;self.new_stage=True
 def collect_return(self,a):
  if a not in self.return_sites:return
  call=self.return_sites.pop(a);row={'pc':hex(a),'source_visit_index':self.seq,'call_pc':call['pc'],'target':call['target'],'registers31':[hex(self.reg(j))for j in range(31)],'snapshots':{}}
  if call['target']=='0xfffffe000a52eed4':
   g=int(call['registers31'][0],16);raw=bytes(self.u.mem_read(g,40));lp,dp=struct.unpack_from('<QQ',raw,8);row['snapshots']={'record':self.snapshot(g,40),'length':self.snapshot(lp,2),'data_pointer':self.snapshot(dp,8)}
  elif call['target']in['0xfffffe000a50eccc','0xfffffe000a55132c','0xfffffe000a54f50c']:
   g=int(call['registers31'][0],16);raw=bytes(self.u.mem_read(g,32));off=16 if call['target']=='0xfffffe000a54f50c'else 8;out=struct.unpack_from('<Q',raw,off)[0];row['snapshots']={'record':self.snapshot(g,32),'value':self.snapshot(out,8 if call['target']=='0xfffffe000a50eccc'else 4)}
  self.readback_returns.append(row)
 def code(self,u,a,n,d):
  if a==self.execute_return_pc and self.original_case.get('caller')=='query':
   self.flush();self.begin(a,'wrapper_returned_to_provider');self.wrapper_return=self.boundary_snapshot(a,'wrapper_returned_to_provider');self.execute_return_pc=None
  if a in self.handoffs and int(self.handoffs[a]['target'],16)in [0xfffffe000a50eccc,0xfffffe000a55132c]:self.begin(a,'before_next_record_helper')
  if self.new_stage:
   self.flush();self.collect_return(a)
   if a==P+0x1f000:return self.stop(a,'original_caller_return')
   self.add(a)
   if a in [0xfffffe000a5356d8,0xfffffe000a50c8f8,0xfffffe000a50c950]:return Response.code(self,u,a,n,d)
   if a==0xfffffe000a517dd0:
    assert self.reg(0)==0xfffffe000847af60 and self.reg(1)in[OBJECT,RESPONSE];return self.register_model(a,0xfffffe000c4ba368,'readback_stream_free_register_clobbers',0xd00d0000feed0000)
   i=next(CS.disasm(kernel().read(a,4),a));m=i.mnemonic
   if m in ['bl','blraa']:
    target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]));row={'pc':hex(a),'target':hex(target),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)],'record':self.snapshot(self.reg(0),48)if P<=self.reg(0)<P+0x20000-48 else None};self.new_calls.append(row)
    if target not in NEW:
     row['target_symbols']=kernel().symbols([target])[hex(target)];return self.stop(a,'new_readback_call_boundary')
    self.return_sites[a+4]=row;self.add(a+4);self.visit(a);self.calls.append({'kind':'readback_original_call','pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':row['registers31'][:8],'target_executed_in_private_guest':True,'record':row['record']}if row['record']is not None else {'kind':'readback_original_call','pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':row['registers31'][:8],'target_executed_in_private_guest':True});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
   if m=='braa':
    target=self.reg(int(i.op_str.split(',',1)[0][1:]));self.new_branches.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)]});self.add(target);self.visit(a);self.dispatches.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)]});return u.reg_write(ar.UC_ARM64_REG_PC,target)
   return Response.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(readback_calls=self.new_calls,readback_returns=self.readback_returns,readback_branches=self.new_branches,preceding_values_boundary=self.preceding_boundary,readback_stage_start=self.stage_start,query_wrapper_return=self.wrapper_return,query_method_return_executed=self.reason=='original_caller_return',native_object_free_executed=False)
  if self.wrapper_return is not None:r.update(source_execution_wrapper_returned=True,source_query_success_executed=self.publication is not None and self.wrapper_return['registers31'][0]=='0x0')
  return r

def main():
 rows=[]
 for j,c in enumerate(cases()):
  x=Readback(c);r=x.run();del x;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 deps=['lskd_readback_contracts.json','lskd_readback_spec.py','probe_lskd_values.py','lskd_values_contracts.json','probe_lskd_handlers.py','lskd_handlers_contracts.json','probe_lskd_consumer.py','lskd_consumer_contracts.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_object_free_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_readback_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
