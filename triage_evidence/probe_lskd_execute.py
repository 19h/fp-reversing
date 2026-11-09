#!/usr/bin/env python3
"""Source workspace/dispatcher prefixes and null-output cleanup in private guest.

Only allocator/free register effects are modeled; no model writes memory.
Nonnull-output paths stop before the first protected state. Null workspace
stops before the first dependent store; inverted bounds stop before BRK.
No native heap/free, provider/crypto operation, Mach, target-file or IDB action.
O(C*(B+V+E)) time/space, 30000 visits per case, abstract PAC.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_legacy_stack import P,HALT,M64
from probe_lskd_request import kernel,OBJECT,PARAM,OUT,OTHER_OUT
from probe_lskd_fields import Fields,cases as field_cases,contracts as field_contracts
WORK=P+0x8000;AUX=P+0xc000
C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_execute_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Execute(Fields):
 def __init__(self,c):
  base=c if c['kind']=='provider'else dict(c,kind='field',family='span',route='unused',carrier_fields={'header32':1,'entry_limit32':8,'byte_limit32':128,'entry_count32':0,'cursor32':0})
  super().__init__(base);self.original_case=c;self.provider=next(p for p in field_contracts()['providers']if p['label']==c['provider'])if c['kind']=='provider'else None;self.execute_return_pc=None;self.execution_input=None;self.workspace_pointer=None;self.auxiliary_pointer=None
  if c['kind']!='provider':self.start=0xfffffe000a561058 if c['kind']=='bounds'else 0xfffffe000a50c508
  for s in contracts()['spans'][:4]:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  for j,d in enumerate(contracts()['additional_mutable_globals'],13):
   a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
 def visit(self,a):
  self.flush();assert any(x<=a<a+4<=z for x,z in self.ranges);raw=kernel().read(a,4);assert bytes(self.u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq,'source':'kext'});self.seq+=1
 def stop(self,a,kind):
  self.flush();self.reason=kind;self.boundary={'kind':kind,'pc':hex(a),'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return self.u.emu_stop()
 def register_model(self,a,target,kind,result):
  self.visit(a);i=next(CS.disasm(kernel().read(a,4),a));assert i.mnemonic=='blraa'and self.reg(int(i.op_str.split(',',1)[0][1:]))==target;row={'kind':kind,'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'result_X0_fixture':hex(result),'target_executed':False,'memory_effects_modeled':False};self.models.append(row);self.setreg(0,result)
  for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def code(self,u,a,n,d):
  c=self.original_case
  if a==self.execute_return_pc:return self.stop(a,'wrapper_returned_to_provider')
  if a==0xfffffe000a561068:return self.stop(a,'before_bounds_trap')
  if a==0xfffffe000a50c7e4 and not c['workspace_nonnull']:return self.stop(a,'before_null_workspace_store')
  if a==0xfffffe000a55f814 and c['mode']=='prefix':return self.stop(a,'before_first_protected_state')
  if c['kind']=='provider':
   provider=self.provider
   if a==int(provider['execution_call'],16):
    self.visit(a);assert next(CS.disasm(kernel().read(a,4),a)).op_str=='#0xfffffe000a50c508';self.execution_input={'pc':hex(a),'source_visit_index':self.seq-1,'request_pointer':hex(self.reg(0)),'response_reference':self.snapshot(self.reg(1),8),'request':self.snapshot(OBJECT,160)};self.execute_return_pc=a+4;self.calls.append({'kind':'provider_execute_wrapper','pc':hex(a),'target':'0xfffffe000a50c508','source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'target_executed_in_private_guest':True});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,0xfffffe000a50c508)
  if a==0xfffffe000a50c6ac:
   assert self.reg(0)==0x4000 and self.reg(1)==0x40;self.workspace_pointer=WORK if c['workspace_nonnull']else 0;return self.register_model(a,0xfffffe000c4b9a08,'aligned_workspace_register_return',self.workspace_pointer)
  if a==0xfffffe000a50c74c:
   assert self.reg(0)==0xfffffe000847ae20;self.auxiliary_pointer=AUX if c['auxiliary_nonnull']else 0;return self.register_model(a,0xfffffe000c4ba154,'auxiliary_typed_register_return',self.auxiliary_pointer)
  if a in[0xfffffe000a50c8f8,0xfffffe000a50c950]:
   assert c['mode']=='null_output_return';return self.register_model(a,0xfffffe000c4ba368 if a==0xfffffe000a50c8f8 else 0xfffffe000c4b9a24,'typed_free_register_clobbers'if a==0xfffffe000a50c8f8 else'aligned_free_register_clobbers',0xd00d0000feed0000)
  if a==0xfffffe000a50c858:
   self.visit(a);assert self.reg(8)==0xfffffe000a55f5e4;self.calls.append({'kind':'dispatcher_prefix','pc':hex(a),'target':'0xfffffe000a55f5e4','source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'target_executed_in_private_guest':True,'workspace_header':self.snapshot(WORK,64)});self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,0xfffffe000a55f5e4)
  before=len(self.calls);result=super().code(u,a,n,d)
  if len(self.calls)>before and self.calls[-1]['target']=='0xfffffe000a561058':self.calls[-1]['kind']='unsigned_bounds_checker'
  return result
 def run(self):
  self.u.emu_start(self.start,0,count=30000);self.flush();assert self.reason is not None,('visit bound',self.original_case)
  return {'input':self.original_case,'entry_SP':hex(self.sp0),'fixture_additions':self.fixture_additions,'initial_params256_hex':self.initial_params_hex,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.calls,'source_dispatches':self.dispatches,'observations':self.observations,'models':self.models,'execution_input':self.execution_input,'workspace_pointer':None if self.workspace_pointer is None else hex(self.workspace_pointer),'auxiliary_pointer':None if self.auxiliary_pointer is None else hex(self.auxiliary_pointer),'workspace':self.snapshot(WORK,0x4000),'auxiliary':self.snapshot(AUX,0x1000),'object':self.snapshot(OBJECT,160),'params':self.snapshot(PARAM,256),'out_reference':self.snapshot(OUT,8),'boundary':self.boundary,'undefined_private_value_reads':[],'request_wrapper_executed_in_private_guest':self.original_case['kind']!='bounds','protected_dispatcher_prefix_executed_in_private_guest':any(v['kind']=='dispatcher_prefix'for v in self.calls),'first_nonnull_output_state_executed':False,'native_API_executed':False,'native_heap_executed':False,'native_request_execution_executed':False,'protected_operation_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False}
def cases():
 for g in['original','zero','declared_noise']:
  for placement in[0,0x100]:
   for request in[0,OBJECT]:
    for output in[0,OUT]:
     for w in[False,True]:
      for aux in[False,True]:yield {'kind':'execute','mode':'prefix','inputs8':[request,output,0,0,0,0,0,0],'workspace_nonnull':w,'auxiliary_nonnull':aux,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0xabcdef0112345678}
    for aux in[False,True]:yield {'kind':'execute','mode':'null_output_return','inputs8':[request,0,0,0,0,0,0,0],'workspace_nonnull':True,'auxiliary_nonnull':aux,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0xabcdef0112345678}
 for c in field_cases():
  if c['kind']=='provider':yield {**c,'mode':'prefix','workspace_nonnull':True,'auxiliary_nonnull':True}
 for placement in[0,0x100]:
  for start,end in[(0,0),(0,1),(1,0),(0,M64),(M64,0),(M64,M64),(M64-1,M64),(M64,M64-1),(0x8000000000000000,0x7fffffffffffffff),(0x7fffffffffffffff,0x8000000000000000),(WORK+0x40,WORK+0x4000),(WORK+0x80,WORK+0x4000)]:yield {'kind':'bounds','mode':'bounds_only','inputs8':[start,end,0,0,0,0,0,0],'workspace_nonnull':True,'auxiliary_nonnull':True,'global_fixture':'original','placement':placement,'heap_nonnull':True,'out_initial64':0xabcdef0112345678}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Execute(c);r=f.run();del f;rows.append(r)
  if j%16==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_heap_executed':False,'protected_operation_executed':False,'full_goal_complete':False};(ROOT/'lskd_execute_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
