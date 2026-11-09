#!/usr/bin/env python3
"""Original span/u32 builders and complete pre-execution provider requests.

Private guarded storage, abstract PAC; only typed-heap register returns/clobbers
are modeled in provider compositions. Original copy/clear source executes.
No native API, crypto/provider, Mach, heap, synchronization or target-file call.
O(C*(B+V+E)) time/space with 30000 source visits per case.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_legacy_stack import P,HALT,M64
from probe_lskd_request import Request,kernel,OBJECT,PARAM,OUT,OTHER_OUT
BUFFER=P+0x7000;DATA=P+0x7400
C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'lskd_fields_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Fields(Request):
 def __init__(self,c):
  super().__init__(dict(c,kind='constructor')if c['kind']=='field'else c);self.case=c;self.fixture_additions=[];self.field_returns={}
  for s in contracts()['spans'][:3]:self.ranges.append((int(s['start'],16),int(s['end'],16)))
  for j,d in enumerate(contracts()['additional_mutable_globals'],10):
   a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
  if c['kind']=='field':
   self.out_address=None;self.start=0xfffffe000a50bdfc if c['family']=='span'else 0xfffffe000a50df34;raw=bytearray(b'\xa5'*160);f=c['carrier_fields']
   for off,name in[(0,'header32'),(8,'entry_limit32'),(12,'byte_limit32'),(152,'entry_count32'),(156,'cursor32')]:struct.pack_into('<I',raw,off,f[name])
   struct.pack_into('<Q',raw,144,0 if c['route']=='null_buffer'else BUFFER)
   for a,b in[(OBJECT,raw),(BUFFER,b'\xa5'*512),(DATA,bytes((n*37+11)&255 for n in range(64)))]:self.seed(a,b);self.fixture_additions.append({'address':hex(a),'bytes_hex':bytes(b).hex()})
  self.initial_object_hex=bytes(self.u.mem_read(OBJECT,160)).hex()
 def code(self,u,a,n,d):
  self.flush();provider=None if self.case['kind']=='field'else next(p for p in contracts()['providers']if p['label']==self.case['provider'])
  if a==HALT or a==0xfffffe000a560cb8 or provider and a==int(provider['execution_call'],16):
   kind='returned'if a==HALT else'before_dynamic_allocation'if a==0xfffffe000a560cb8 else'before_request_execution';self.reason=kind;self.boundary={'kind':kind,'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq,'source':'kernel'if any(x<=a<z for x,z in self.kernels)else'kext'});self.seq+=1;i=next(CS.disasm(raw,a));m=i.mnemonic
  if a==self.create_return_pc:self.observations.append({'kind':'constructor_return_to_provider','pc':hex(a),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)],'out_reference':self.snapshot(self.out_address,8),'object':self.snapshot(OBJECT,160)})
  if a in self.field_returns:self.observations.append({'kind':'field_return_to_provider','call_pc':self.field_returns[a],'pc':hex(a),'source_visit_index':self.seq-1,'registers31':[hex(self.reg(j))for j in range(31)],'object':self.snapshot(OBJECT,160)})
  if a==0xfffffe000a529be0:
   assert self.reg(13)==0xfffffe000c4ba154 and self.reg(0)==0xfffffe000847b160;result=OBJECT if self.case['heap_nonnull']else 0;self.models.append({'kind':'typed_heap_register_return','pc':hex(a),'target':hex(self.reg(13)),'source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'result_X0_fixture':hex(result),'target_executed':False,'memory_effects_modeled':False});self.setreg(0,result)
   for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['bl','blraa']:
   target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in self.ranges),('unmodeled call',hex(a),hex(target));row={'pc':hex(a),'target':hex(target),'source_visit_index':self.seq-1,'registers8':[hex(self.reg(j))for j in range(8)],'target_executed_in_private_guest':True}
   if target==0xfffffe000a50c048:self.out_address=self.reg(3);self.create_return_pc=a+4;row.update(kind='provider_create',out_reference=self.snapshot(self.out_address,8))
   elif a==0xfffffe000a50c274:row.update(kind='constructor_record',record=self.snapshot(self.reg(0),32))
   elif a==0xfffffe000a5218bc:row.update(kind='initializer_record',record=self.snapshot(self.reg(0),28),object_before=self.snapshot(OBJECT,160))
   elif target==0xfffffe000a50c2b0:row.update(kind='provider_append64',object_before=self.snapshot(OBJECT,160));self.field_returns[a+4]=hex(a)
   elif target in[0xfffffe000a50bdfc,0xfffffe000a50df34]:
    row.update(kind='provider_span'if target==0xfffffe000a50bdfc else'provider_u32',object_before=self.snapshot(OBJECT,160));self.field_returns[a+4]=hex(a)
    if target==0xfffffe000a50bdfc:row['argument_bytes']=self.snapshot(self.reg(2),self.reg(3)&0xffff)
   elif a==0xfffffe000a50c4cc:row.update(kind='append64_record',record=self.snapshot(self.reg(0),32))
   elif a==0xfffffe000a50e134:row.update(kind='u32_record',record=self.snapshot(self.reg(0),24))
   elif a in[0xfffffe000a5302ac,0xfffffe000a50c00c,0xfffffe000a54df54]:row.update(kind='generic_append_record',record=self.snapshot(self.reg(0),32))
   elif a==0xfffffe000a521748:row.update(kind='original_memset')
   elif a==0xfffffe000a51a600:
    assert self.reg(2)<=64;row.update(kind='original_payload_copy',payload=self.snapshot(self.reg(1),self.reg(2)),destination_before=self.snapshot(self.reg(0),self.reg(2)))
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
  return {'input':self.case,'entry_SP':hex(self.sp0),'fixture_additions':self.fixture_additions,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.calls,'source_dispatches':self.dispatches,'observations':self.observations,'models':self.models,'initial_object160_hex':self.initial_object_hex,'object':self.snapshot(OBJECT,160),'buffer':self.snapshot(BUFFER,512)if self.case['kind']=='field'else None,'out_address':None if not self.out_address else hex(self.out_address),'out_reference':None if not self.out_address else self.snapshot(self.out_address,8),'initial_params256_hex':self.initial_params_hex,'params':self.snapshot(PARAM,256),'boundary':self.boundary,'response_reference':self.snapshot(self.reg(1),8)if self.reason=='before_request_execution'else None,'undefined_private_value_reads':[],'native_API_executed':False,'typed_heap_executed':False,'request_execution_executed':False,'external_IPC_emission_proved':False,'native_carrier_validity_proved':False}
def base(family,route,g,placement,tag,value,length=0):
 f={'header32':1,'entry_limit32':8,'byte_limit32':128,'entry_count32':2,'cursor32':4}
 if route=='bad_header':f['header32']=2
 if route=='entry_full':f['entry_count32']=8
 if route=='byte_full':f['byte_limit32']=7
 return {'kind':'field','family':family,'route':route,'inputs8':[0 if route=='null_carrier'else OBJECT,tag,0 if route=='null_source'else DATA if family=='span'else value,length,0,0,0,0],'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0,'carrier_fields':f}
def cases():
 for g in['original','zero','declared_noise']:
  for placement in[0,0x100]:
   for family in['span','u32']:
    for route in['null_carrier','null_buffer','bad_header','entry_full','byte_full']:yield base(family,route,g,placement,0x12345678,0x87654321,8)
   for length in[0,8]:yield base('span','null_source',g,placement,0xffff,0,length)
   for tag in[0,0xffff,0x12345678]:
    for length in[0,1,4,8,17,0x10000,0x10001]:yield base('span','append',g,placement,tag,0,length)
    for value in[0,1,0x80000000,0xffffffff,0x1234567887654321]:yield base('u32','append',g,placement,tag,value)
   for provider in['scalar64','vault','avd','allowed']:
    for context in[0,0x1234567887654321]:
     args=[0x1111222233334444,context,OTHER_OUT,OUT,0,0,0,0]
     if provider=='avd':args[2]=PARAM
     if provider=='allowed':args[1]=PARAM
     yield {'kind':'provider','provider':provider,'guard':'valid','inputs8':args,'context64':context,'version32':1,'global_fixture':g,'placement':placement,'heap_nonnull':True,'out_initial64':0}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Fields(c);r=f.run();del f;rows.append(r)
  if j%24==0:gc.collect();print(json.dumps({'cases_completed':j+1}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'typed_heap_executed':False,'request_execution_executed':False,'full_goal_complete':False};(ROOT/'lskd_fields_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
