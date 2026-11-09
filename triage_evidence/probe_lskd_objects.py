#!/usr/bin/env python3
"""Exhaustive local slot-layout fixtures, never complete positive-handler fixtures.

Both source prefixes execute for every ten-bit index with null/nonzero raw
slot words. No tag table, accepted context, object body or API call is supplied.
Synthetic initial memory is fixture setup; source makes the only guest writes.
O(C*I+8192) time, O(C+8192) retained space. No native target or model executes.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE
from kernel_native_reader import Kernel
P=0x6300000000;SP=P+0x1000;VECTOR=P+0x4000;CELL=0xfffffe000ccc78d0
PREFIXES={'vault':(0xfffffe000a58b7cc,0xfffffe000a58b7fc),'allowed':(0xfffffe000a57e26c,0xfffffe000a57e2bc)}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def word(i):return 0x8800000000000001+i*0x100000101
class Fixture:
 def __init__(self,provider):
  self.provider=provider;self.start,self.end=PREFIXES[provider];self.k=Kernel();self.raw=self.k.read(self.start,self.end-self.start);self.u=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.u.mem_map(self.start&~4095,4096);self.u.mem_write(self.start,self.raw);self.u.mem_map(P,0x10000);self.u.mem_map(CELL&~4095,4096);self.u.mem_write(CELL,struct.pack('<Q',VECTOR));self.initial_vector=b''.join(struct.pack('<Q',word(i))for i in range(1024));self.u.mem_write(VECTOR,self.initial_vector);self.visits=[];self.reads=[];self.writes=[]
  self.u.hook_add(unicorn.UC_HOOK_CODE,self.code);self.u.hook_add(unicorn.UC_HOOK_MEM_READ,self.read);self.u.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.write)
 def code(self,u,a,n,d):
  off=a-self.start;assert 0<=off<len(self.raw)and n==4 and bytes(u.mem_read(a,4))==self.raw[off:off+4];self.visits.append(a)
 def read(self,u,access,a,n,v,d):self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,v,d):self.writes.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'value64':hex(v)})
 def run(self,index,null):
  value=0 if null else word(index);at=VECTOR+index*8;self.u.mem_write(at,struct.pack('<Q',value));self.u.mem_write(SP,b'\xa5'*256)
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0x111100000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(ar.UC_ARM64_REG_X10,CELL);self.u.reg_write(ar.UC_ARM64_REG_X13,index)
  if self.provider=='vault':self.u.reg_write(ar.UC_ARM64_REG_X11,0x42b)
  else:self.u.reg_write(ar.UC_ARM64_REG_X8,0x500)
  self.visits=[];self.reads=[];self.writes=[];self.u.emu_start(self.start,self.end,count=100)
  assert self.u.reg_read(ar.UC_ARM64_REG_PC)==self.end and self.visits==list(range(self.start,self.end,4))
  slot_pc=0xfffffe000a58b7e4 if self.provider=='vault'else 0xfffffe000a57e2a0;root_pc=slot_pc-4;clear_pc=self.start+4;clear_offset=0x40 if self.provider=='vault'else 0x90
  assert self.reads==[{'pc':hex(root_pc),'address':hex(CELL),'size_bytes':8,'bytes_hex':struct.pack('<Q',VECTOR).hex()},{'pc':hex(slot_pc),'address':hex(at),'size_bytes':8,'bytes_hex':struct.pack('<Q',value).hex()}]
  assert self.writes==[{'pc':hex(clear_pc),'address':hex(SP+clear_offset),'size_bytes':8,'value64':'0x0'}]and bytes(self.u.mem_read(SP+clear_offset,8))==bytes(8)
  branch=self.u.reg_read(ar.UC_ARM64_REG_X10);expected=(0x455 if null else 0x42b)if self.provider=='vault'else(0x515 if null else 0x502);assert branch==expected and self.u.reg_read(ar.UC_ARM64_REG_X12)==value
  after=bytes(self.u.mem_read(VECTOR,8192));expected_vector=self.initial_vector[:index*8]+struct.pack('<Q',value)+self.initial_vector[index*8+8:];assert after==expected_vector
  r={'provider':self.provider,'index10':index,'null_slot':null,'fixture_slot_word64':hex(value),'source_visits':len(self.visits),'source_bytes_sha256':hashlib.sha256(self.raw).hexdigest(),'source_reads':self.reads,'source_writes':self.writes,'loaded_slot_word64':hex(self.u.reg_read(ar.UC_ARM64_REG_X12)),'selected_dispatch_index32':hex(branch),'boundary_PC':hex(self.end),'fixture_vector_unchanged_by_source':True,'complete_handler_executed':False,'native_reachability_proved':False,'model_memory_writes':0};self.u.mem_write(at,struct.pack('<Q',word(index)));return r
def main():
 rows=[]
 for provider in PREFIXES:
  f=Fixture(provider)
  for index in range(1024):
   for null in[False,True]:rows.append(f.run(index,null))
  print(json.dumps({'completed_provider':provider,'local_cases':len(rows)}),flush=True)
 deps={n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','lskd_objects_contracts.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'source_sha256':sha(SOURCE),'kernel_collection_sha256':Kernel().sha256,'fixture_scope':'Isolated instruction-layout fixtures. No tag-table bytes, accepted contexts, native objects or positive parent entry paths are supplied.','model_memory_writes':0,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_objects_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
