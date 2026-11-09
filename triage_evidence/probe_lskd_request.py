#!/usr/bin/env python3
"""Original LSKD construction and real provider prefixes in a private guest.

Only IOMallocTypeImpl's register return/clobbers are modeled; its native heap
backend never executes. Original memset/copy, constructor/initializer/append
instructions execute with PAC abstracted. Stop before IOMallocData, request
execution, or the next typed-field call. No native API/provider/crypto/IPC.
O(C*(B+V+E)) time/space with 30000 visits per case.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_legacy_stack import Bridge,P,HALT,M64
OBJECT=P+0x2000;PARAM=P+0x4000;OUT=P+0x5000;OTHER_OUT=P+0x5100
C=None;T=None;K=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_request_contracts.json').read_text())
 return C
def tlv():
 global T
 if T is None:T=json.loads((ROOT/'legacy_tlv_contracts.json').read_text())
 return T
def kernel():
 global K
 if K is None:K=Kernel()
 return K
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Request(Bridge):
 def __init__(self,c):
  super().__init__(c);self.ranges=[];self.kernels=[];self.dispatches=[];self.observations=[];self.out_address=c['inputs8'][3]if c['kind']=='constructor'else None;self.create_return_pc=None;self.request_record=None;self.init_record=None;self.start=0xfffffe000a50c048 if c['kind']=='constructor'else int(next(p for p in contracts()['providers']if p['label']==c['provider'])['start'],16)
  for s in contracts()['spans']+tlv()['spans']:
   if s['label']not in['ctor_encode','ctor_key','init_encode','init_fields_symbolic','payload_symbolic','tag_symbolic','header_symbolic','counter_symbolic']:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  for f in contracts()['functions']:
   if int(f['start'],16)in[0xfffffe000a505848,0xfffffe000a505958,0xfffffe000a505ac8,0xfffffe000a505de0,0xfffffe000a508c78]:self.ranges.append((int(f['start'],16),int(f['end'],16)))
  for f in contracts()['kernel_functions']+tlv()['kernel_functions']:
   a=int(f['start'],16);z=int(f['end'],16);self.ranges.append((a,z));self.kernels.append((a,z))
   for page in range(a&~4095,(z+4095)&~4095,4096):
    if page not in self.pages:self.u.mem_map(page,4096);self.u.mem_write(page,kernel().read(page,4096));self.pages.add(page)
  for j,d in enumerate(contracts()['additional_mutable_globals'],6):
   a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
  self.seed(OUT,struct.pack('<Q',c['out_initial64']));self.seed(OTHER_OUT,b'\0'*8);params=bytearray(b'\xa5'*256);struct.pack_into('<I',params,0,c.get('version32',1));struct.pack_into('<Q',params,8,c.get('context64',0));struct.pack_into('<I',params,16,0x13579bdf);self.seed(PARAM,params);self.initial_params_hex=bytes(params).hex();self.initial_object_hex=bytes(self.u.mem_read(OBJECT,160)).hex()
 def seed(self,a,b):
  assert P<=a<a+len(b)<=P+0x20000;self.u.mem_write(a,bytes(b));self.known[a-P:a-P+len(b)]=b'\1'*len(b);self.provenance[a-P:a-P+len(b)]=b'\3'*len(b)
 def code(self,u,a,n,d):
  self.flush();provider=None if self.case['kind']=='constructor'else next(p for p in contracts()['providers']if p['label']==self.case['provider'])
  if a==HALT or a==0xfffffe000a560cb8 or provider and a==int(provider['boundary_call'],16):
   kind='returned'if a==HALT else'before_dynamic_allocation'if a==0xfffffe000a560cb8 else'before_next_provider_call';self.reason=kind;self.boundary={'kind':kind,'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq,'source':'kernel'if any(x<=a<z for x,z in self.kernels)else'kext'});self.seq+=1;i=next(CS.disasm(raw,a));m=i.mnemonic
  if a==self.create_return_pc:self.observations.append({'kind':'constructor_return_to_provider','pc':hex(a),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)],'out_reference':self.snapshot(self.out_address,8),'object':self.snapshot(OBJECT,160)})
  if a==0xfffffe000a529be0:
   assert self.reg(13)==0xfffffe000c4ba154 and self.reg(0)==0xfffffe000847b160;result=OBJECT if self.case['heap_nonnull']else 0;self.models.append({'kind':'typed_heap_register_return','pc':hex(a),'target':hex(self.reg(13)),'source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'result_X0_fixture':hex(result),'target_executed':False,'memory_effects_modeled':False});self.setreg(0,result)
   for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['bl','blraa']:
   target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in self.ranges),('unmodeled call',hex(a),hex(target));row={'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'target_executed_in_private_guest':True}
   if target==0xfffffe000a50c048:self.out_address=self.reg(3);self.create_return_pc=a+4;row.update(kind='provider_create',out_reference=self.snapshot(self.out_address,8))
   elif a==0xfffffe000a50c274:self.request_record=self.reg(0);row.update(kind='constructor_record',record=self.snapshot(self.reg(0),32))
   elif a==0xfffffe000a5218bc:self.init_record=self.reg(0);row.update(kind='initializer_record',record=self.snapshot(self.reg(0),28),object_before=self.snapshot(OBJECT,160))
   elif target==0xfffffe000a50c2b0:row.update(kind='provider_append64',object_before=self.snapshot(OBJECT,160))
   elif a==0xfffffe000a50c4cc:self.outer_record=self.reg(0);row.update(kind='append_record',record=self.snapshot(self.reg(0),32))
   elif a==0xfffffe000a5302ac:self.inner_record=self.reg(0);row.update(kind='append_operation',record=self.snapshot(self.reg(0),32),payload=self.snapshot(self.reg(0)-8,8))
   elif a==0xfffffe000a521748:row.update(kind='original_memset')
   elif a==0xfffffe000a51a600:row.update(kind='original_payload_copy',payload=self.snapshot(self.reg(1),8))
   else:row.update(kind='status_helper'if target==0xfffffe000a508c78 else'other_original_call')
   self.calls.append(row);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m=='braa':
   target=self.reg(int(i.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in self.ranges),('branch escape',hex(a),hex(target));self.dispatches.append({'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)]});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert m not in['blr','blrab','brab','svc','hvc','smc','mrs','casa','casl','brk'],('unmodeled boundary',hex(a),m)
  if m in['bti','pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert not m.startswith(('pac','aut','xpac'))
 def run(self):
  self.u.emu_start(self.start,0,count=30000);self.flush();assert self.reason is not None,('visit bound',self.case)
  aux=None
  if self.reason=='before_next_provider_call':
   if self.case['provider']=='scalar64':aux=self.snapshot(self.reg(1),8)
   elif self.case['provider']in['vault','avd']:aux=self.snapshot(self.reg(2),8)
  return {'input':self.case,'entry_SP':hex(self.sp0),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.calls,'source_dispatches':self.dispatches,'observations':self.observations,'models':self.models,'initial_object160_hex':self.initial_object_hex,'object':self.snapshot(OBJECT,160),'out_address':None if not self.out_address else hex(self.out_address),'out_reference':None if not self.out_address else self.snapshot(self.out_address,8),'initial_params256_hex':self.initial_params_hex,'params':self.snapshot(PARAM,256),'boundary':self.boundary,'boundary_memory':aux,'undefined_private_value_reads':[],'native_API_executed':False,'typed_heap_executed':False,'request_execution_executed':False,'external_IPC_emission_proved':False,'native_carrier_validity_proved':False}
def cases():
 specs=[(0x1b69,1,8),(0x1b6b,2,16),(0x1b6a,5,44),(0x1b6c,2,12),(0,0,0),(1,1,124),(1,1,125),(1,0,128),(1,0,129),(1,32,0),(1,33,0)]
 for g in['original','zero','declared_noise']:
  for placement in[0,0x100]:
   for j,(op,n,b)in enumerate(specs):yield {'kind':'constructor','inputs8':[op,n,b,OUT,0,0,0,0],'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0 if j%2==0 else 0xabcdef0112345678}
   for op,n,b in specs[:4]:
    yield {'kind':'constructor','inputs8':[op,n,b,OUT,0,0,0,0],'global_fixture':g,'placement':placement,'heap_nonnull':False,'out_initial64':0xabcdef0112345678}
    yield {'kind':'constructor','inputs8':[op,n,b,0,0,0,0,0],'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0}
   for provider in['scalar64','vault','avd','allowed']:
    for context in[0,0x1234567887654321]:
     args=[0x1111222233334444,context,OTHER_OUT,OUT,0,0,0,0]
     if provider=='avd':args[2]=PARAM
     if provider=='allowed':args[1]=PARAM
     yield {'kind':'provider','provider':provider,'guard':'valid','inputs8':args,'context64':context,'version32':1,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0}
   for provider,versions in[('avd',[None]),('allowed',[None,0,2,0xffffffff])]:
    for version in versions:
     for context in[0,0x1234567887654321]:
      args=[0x1111222233334444,context,OTHER_OUT,OUT,0,0,0,0]
      if provider=='avd':args[2]=0
      else:args[1]=0 if version is None else PARAM
      yield {'kind':'provider','provider':provider,'guard':'null'if version is None else'version','inputs8':args,'context64':context,'version32':1 if version is None else version,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  r=Request(c);rows.append(r.run());del r
  if j%12==0:gc.collect()
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'typed_heap_executed':False,'request_execution_executed':False,'full_goal_complete':False};(ROOT/'lskd_request_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
