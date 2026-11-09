#!/usr/bin/env python3
"""Independent fresh CPU replay of KC MIG source, effects and API models.
No probe executor reuse, native kernel operation, IPC or PAC. O(visits+effects)
time, O(one private CPU map+journals) space beyond shared original KC metadata.
"""
from collections import Counter,defaultdict
import unicorn as uc
from unicorn import arm64_const as ar
class Replay:
 def __init__(self,image,p):
  self.image=image;self.p=p;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.seq=0;self.current=None;self.rc=self.wc=0;self.pending=[];self.models=p['API_models'];self.mi=0;self.counts=Counter();self.reads=defaultdict(list);self.writes=defaultdict(list)
  for e in p['source_reads']:self.reads[e['source_visit_index']].append(e)
  for e in p['source_writes']:self.writes[e['source_visit_index']].append(e)
  ram=p['private_RAM'];self.lo=int(ram['address'],16);self.hi=self.lo+ram['size_bytes'];self.u.mem_map(self.lo,ram['size_bytes']);self.u.mem_write(self.lo,bytes([ram['initial_byte']])*ram['size_bytes'])
  for e in p['initial_private_fixtures']+p['initial_image_fixtures']:a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
  for j,value in enumerate(p['entry_registers31']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(value,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(p['entry_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(p['entry_NZCV'],16));self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if self.lo<=pg<self.hi or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.image.logical_page(pg));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def finish(self):
  for e in self.pending:assert bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()==e['after_hex'];self.counts['writes_checked']+=1;self.counts['write_bytes_checked']+=e['size_bytes']
  self.pending=[]
  if self.current is not None:assert self.rc==len(self.reads[self.current])and self.wc==len(self.writes[self.current])
  self.current=None
 def read(self,u,t,a,n,v,d):
  e=self.reads[self.current][self.rc];self.rc+=1;assert e['address']==hex(a)and e['size_bytes']==n and e['bytes_hex']==bytes(u.mem_read(a,n)).hex();self.counts['reads_checked']+=1;self.counts['read_bytes_checked']+=n
 def write(self,u,t,a,n,v,d):e=self.writes[self.current][self.wc];self.wc+=1;assert e['address']==hex(a)and e['size_bytes']==n;self.pending.append(e)
 def code(self,u,a,n,d):
  self.finish()
  if self.mi<len(self.models)and a==int(self.models[self.mi]['pc'],16):
   e=self.models[self.mi];self.mi+=1;assert self.seq==e['before_source_visit_index']and self.reg(30)==int(e['return_pc'],16)
   for j,value in enumerate(e['arguments8']):assert self.reg(j)==int(value,16)
   for j,value in enumerate(e['after_registers31']):
    if j<18:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(value,16))
    else:assert self.reg(j)==int(value,16)
   u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['return_pc'],16));self.counts['declared_API_models_checked']+=1;return
  if self.seq==len(self.p['source_visits']):
   b=self.p['boundary'];assert a==int(b['pc'],16)and u.reg_read(ar.UC_ARM64_REG_SP)==int(b['SP'],16)and u.reg_read(ar.UC_ARM64_REG_NZCV)==int(b['NZCV'],16)
   for j,value in enumerate(b['registers31']):assert self.reg(j)==int(value,16)
   self.counts['final_boundaries_checked']+=1;return u.emu_stop()
  e=self.p['source_visits'][self.seq];assert e['pc']==hex(a)and bytes(u.mem_read(a,4)).hex()==e['bytes_hex']and bytes(u.mem_read(a,4))==self.image.k.read(a,4);ins=next(self.image.k.cs.disasm(bytes(u.mem_read(a,4)),a));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1
  if ins.mnemonic in ['pacibsp','autibsp']:self.counts['logical_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif ins.mnemonic=='retab':self.counts['logical_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert ins.mnemonic not in ['svc','hvc','smc','autda','blraa','brk']
 def run(self):
  entry=int(self.p['entry_PC'],16);self.ensure(entry);self.u.emu_start(entry,0,count=len(self.p['source_visits'])+len(self.models)+10);self.finish();assert self.seq==len(self.p['source_visits'])and self.mi==len(self.models)and self.counts['final_boundaries_checked']==1;return dict(self.counts)
