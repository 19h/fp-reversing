#!/usr/bin/env python3
"""Complete original selector-0x224 append/failure compositions, private only.

No inner-operation/API effect model. Original wrapper, bridge, shared code,
copy veneers and kernel copy instructions execute with PAC abstracted.
Synthetic carriers/buffers do not prove native type/lifetime/admissibility.
O(C*(B+V+E)) time/space with 30000 visits per case. No native IPC/heap/lock,
provider, crypto, credential, target-file or IDB operation.
"""
import gc,hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_legacy_stack import Bridge,P,HALT,M64
CARRIER=P+0x2000;BUFFER=P+0x3000;BUFFER_N=512
C=None;K=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'legacy_tlv_contracts.json').read_text())
 return C
def kernel():
 global K
 if K is None:K=Kernel()
 return K
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Append(Bridge):
 def __init__(self,c):
  super().__init__(c);self.ranges=[(int(s['start'],16),int(s['end'],16))for s in contracts()['spans']if s['label']not in['payload_symbolic','tag_symbolic','header_symbolic','counter_symbolic']];f=contracts()['kernel_functions'][0];self.kernel_range=(int(f['start'],16),int(f['end'],16));self.ranges.append(self.kernel_range)
  for page in range(self.kernel_range[0]&~4095,(self.kernel_range[1]+4095)&~4095,4096):
   assert page not in self.pages;self.u.mem_map(page,4096);self.u.mem_write(page,kernel().read(page,4096));self.pages.add(page)
  d=contracts()['additional_mutable_global'];a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+6*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8));self.dispatches=[]
  fields=c['carrier_fields'];raw=bytearray(b'\xa5'*160)
  for off,name in[(0,'header32'),(8,'entry_limit32'),(12,'byte_limit32'),(152,'entry_count32'),(156,'cursor32')]:struct.pack_into('<I',raw,off,fields[name])
  struct.pack_into('<Q',raw,144,0 if c['route']=='null_buffer'else BUFFER);self.seed_fixture(CARRIER,raw);self.seed_fixture(BUFFER,b'\xa5'*BUFFER_N);self.initial_carrier_hex=raw.hex();self.initial_buffer_hex=bytes(self.u.mem_read(BUFFER,BUFFER_N)).hex()
 def seed_fixture(self,a,b):
  assert P<=a<a+len(b)<=P+0x20000;self.u.mem_write(a,bytes(b));self.known[a-P:a-P+len(b)]=b'\1'*len(b);self.provenance[a-P:a-P+len(b)]=b'\3'*len(b)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:
   self.reason='returned';self.boundary={'kind':'returned','pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=kernel().read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq,'source':'kernel'if self.kernel_range[0]<=a<self.kernel_range[1]else'kext'});self.seq+=1;i=next(CS.disasm(raw,a));m=i.mnemonic
  if a in[0xfffffe000a55e9f8,0xfffffe000a58ffd8,0xfffffe000a51a460,0xfffffe000a51a604]:self.visits[-1]['observed_registers31']=[hex(self.reg(j))for j in range(31)]
  if m=='blraa':
   target=self.reg(8);assert a in[0xfffffe000a50c4cc,0xfffffe000a5302ac,0xfffffe000a51a600];want={0xfffffe000a50c4cc:0xfffffe000a52fd18,0xfffffe000a5302ac:0xfffffe000a55e8b0,0xfffffe000a51a600:0xfffffe000a508cf4}[a];assert target==want
   row={'pc':hex(a),'target':hex(target),'modifier16':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'source_visit_index':self.seq-1,'target_executed_in_private_guest':True}
   if a==0xfffffe000a50c4cc:self.outer_record=self.reg(0);row.update(kind='outer_bridge',record=self.snapshot(self.reg(0),32))
   elif a==0xfffffe000a5302ac:self.inner_record=self.reg(0);row.update(kind='inner_operation',record=self.snapshot(self.reg(0),32),payload=self.snapshot(self.reg(0)-8,8))
   else:row.update(kind='payload_copy',source_bytes=self.snapshot(self.reg(1),8),destination_before=self.snapshot(self.reg(0),8))
   self.calls.append(row);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m=='braa':
   name=i.op_str.split(',',1)[0];target=self.reg(int(name[1:]));assert any(x<=target<z for x,z in self.ranges),('branch escape',hex(a),hex(target));self.dispatches.append({'pc':hex(a),'target':hex(target),'registers31':[hex(self.reg(j))for j in range(31)],'source_visit_index':self.seq-1});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert m not in['bl','blr','blrab','brab','svc','hvc','smc','mrs','casa','casl','brk'],('unmodeled boundary',hex(a),m)
  if m in['bti','pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert not m.startswith(('pac','aut','xpac'))
 def run(self):
  r=super().run();assert not r['models'];r.update(initial_carrier160_hex=self.initial_carrier_hex,final_carrier=self.snapshot(CARRIER,160),initial_buffer512_hex=self.initial_buffer_hex,final_buffer=self.snapshot(BUFFER,BUFFER_N),inner_record_after=self.snapshot(self.inner_record,32),source_payload=self.snapshot(self.inner_record-8,8),source_dispatches=self.dispatches,inner_record_operations_executed=True,inner_record_operation_executed_in_private_guest=True,API_effect_models_used=False,external_TLV_emission_proved=False,cached_FairPlay_lock_publication_proved=False);return r
def fields(**updates):
 d={'header32':1,'entry_limit32':8,'byte_limit32':64,'entry_count32':2,'cursor32':4};d.update(updates);return d
def base(route,g,placement,tag,value,f):return {'family':'record32','inputs8':[0 if route=='null_carrier'else CARRIER,tag,value,0,0,0,0,0],'global_fixture':g,'placement':placement,'route':route,'carrier_fields':f}
def cases():
 for g in['original','zero','declared_noise']:
  for placement in[0,0x100]:
   for tag,value in[(0,0),(0xffff,M64)]:
    yield base('null_carrier',g,placement,tag,value,fields());yield base('null_buffer',g,placement,tag,value,fields())
    for header in[0,2,0xffffffff]:yield base('bad_header',g,placement,tag,value,fields(header32=header))
    for count in[8,0xffffffff]:yield base('entry_full',g,placement,tag,value,fields(entry_count32=count))
    for cursor,limit in[(0,11),(4,15),(16,27)]:yield base('byte_full',g,placement,tag,value,fields(cursor32=cursor,byte_limit32=limit))
   for j,tag in enumerate([0,1,0x7fff,0x8000,0xffff,0x9777,0x12348485,0x50db]):
    for vi,value in enumerate([0,M64,0xfedcba9876543210,0x0123456789abcdef]):yield base('append',g,placement,tag,value,fields(entry_count32=(j+vi)%3,cursor32=(j%2)*16+placement//0x40))
def main():
 rows=[]
 for j,c in enumerate(cases()):
  a=Append(c);rows.append(a.run());del a
  if j%12==0:gc.collect()
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_legacy_stack.py','legacy_stack_contracts.json','legacy_tlv_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'API_effect_models_used':False,'external_TLV_emission_proved':False,'full_goal_complete':False};(ROOT/'legacy_tlv_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'source_copies':sum(c['kind']=='payload_copy'for r in rows for c in r['source_calls'])}),flush=True)
if __name__=='__main__':main()
