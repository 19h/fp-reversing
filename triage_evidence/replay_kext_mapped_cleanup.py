#!/usr/bin/env python3
"""Separate CPU replay of recorded original words, accesses and call contracts.
No probe executor reuse; O(image bytes+visits), O(mapped bytes+journals).
"""
import struct
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import IMAGE,CS
class Replay:
 def __init__(self,k,p):
  self.k=k;self.p=p;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.at=0;self.ri=0;self.wi=0;self.ei=0;self.mi=0;self.pending=[];self.stopped=False
  for va,off,n in IMAGE.segments:self.put(va,IMAGE.data[off:off+n])
  for e in p['initial_memory']:self.put(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  for j,v in enumerate(p['initial_registers31']):self.set(j,int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(p['initial_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(p['initial_NZCV'],16));self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def put(self,a,b):
  for pg in range(a&~4095,(a+len(b)+4095)&~4095,4096):
   if pg not in self.pages:self.u.mem_map(pg,4096);self.pages.add(pg)
  self.u.mem_write(a,b)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def set(self,n,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),v)
 def finish(self):
  for e in self.pending:assert bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()==e['after_hex']
  self.pending=[]
 def code(self,u,a,n,d):
  self.finish()
  if a==int(self.p['stop'],16):assert self.at==len(self.p['source_visits']);self.stopped=True;return u.emu_stop()
  assert self.p['source_visits'][self.at]==hex(a),(self.at,hex(a));self.at+=1;raw=bytes(u.mem_read(a,4));assert raw==self.k.read(a,4);i=next(CS.disasm(raw,a))
  if i.mnemonic not in ['braa','blraa']:return
  e=self.p['logical_edges'][self.ei];self.ei+=1;assert e['pc']==hex(a)and e['kind']==i.mnemonic and e['visit']==self.at-1
  target=self.reg(int(i.op_str.split(',')[0][1:]));assert target==int(e['target'],16)and self.reg(17)==int(e['modifier'],16)
  if i.mnemonic=='braa':return u.reg_write(ar.UC_ARM64_REG_PC,target)
  model=self.p['models'][self.mi];self.mi+=1;assert model['pc']==hex(a)and model['visit']==self.at-1 and model['arguments8']==[hex(self.reg(j))for j in range(8)]
  for j,v in model['clobbers'].items():self.set(int(j),int(v,16))
  self.set(0,int(model['return_status'],16));self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_NZCV,int(model['NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def read(self,u,access,a,n,value,d):
  e=self.p['reads'][self.ri];self.ri+=1;assert(e['pc'],e['visit'],e['address'],e['size_bytes'],e['bytes_hex'])==(hex(u.reg_read(ar.UC_ARM64_REG_PC)),self.at-1,hex(a),n,bytes(u.mem_read(a,n)).hex())
 def write(self,u,access,a,n,value,d):
  e=self.p['writes'][self.wi];self.wi+=1;assert(e['pc'],e['source_visit_index'],e['address'],e['size_bytes'])==(hex(u.reg_read(ar.UC_ARM64_REG_PC)),self.at-1,hex(a),n);self.pending.append(e)
 def run(self):
  self.u.emu_start(int(self.p['start'],16),0,count=10000);self.finish();assert self.stopped and self.ri==len(self.p['reads'])and self.wi==len(self.p['writes'])and self.ei==len(self.p['logical_edges'])and self.mi==len(self.p['models'])
  assert self.p['final_registers31']==[hex(self.reg(j))for j in range(31)]and self.p['final_SP']==hex(self.u.reg_read(ar.UC_ARM64_REG_SP))and self.p['final_NZCV']==hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
  for a,n,key in [(0x6100002000,0x80,'final_record_bytes_hex'),(0x6100001000,0x300,'final_parent_bytes_hex')]:assert bytes(self.u.mem_read(a,n)).hex()==self.p[key]
  return {'source_visits_checked':self.at,'reads_checked':self.ri,'writes_checked':self.wi,'logical_PAC_edges_checked':self.ei,'declared_API_models_checked':self.mi,'final_boundaries_checked':1}
def seed_components(k):
 u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);u.mem_map(0xfffffe000a5c0000,4096);u.mem_write(0xfffffe000a5c0000,k.read(0xfffffe000a5c0000,4096));u.emu_start(0xfffffe000a5c0b08,0xfffffe000a5c0b24)
 a=u.reg_read(ar.UC_ARM64_REG_X21);b=u.reg_read(ar.UC_ARM64_REG_X22);assert(a,b)==(0x1eb,0x7a3)
 u.emu_start(0xfffffe000a5c0b68,0xfffffe000a5c0b80);assert u.reg_read(ar.UC_ARM64_REG_X21)==a
 return {'no_aux_control_seed':hex(a),'aux_control_seed':hex(a),'companion_seed':hex(b),'source_instructions_checked':13}
