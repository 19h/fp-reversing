#!/usr/bin/env python3
"""Raw-image boot prefix and finite original fixup-loop cuts.
Linear source/journal/RAM work. PAC is an explicit logical identity.
"""
import struct
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_boot_fixup_projection as R
P=0x6800000000;SIZE=0x100000;SP=P+0xf0000;SLOT=P+0x20000;META=P+0x10000;BASES=P+0x30000
PAC=['pacibsp','pacia1716','pacib1716','pacda','pacdb']
def cases(e):
 out=[{'label':'raw_boot_prefix','mode':'prefix'}]
 for j,r in enumerate(e['source_CPU_samples']+e['cross_page_fixups']):out.append({'label':'original_word'+str(j),'mode':'word','word':int(r['raw'],16) if isinstance(r['raw'],str) else r['raw'],'format':8,'bases':[R.BANK]*4,'original_slot':r['slot']})
 for fmt in [8,11]:
  for key in range(4):
   for adiv in [0,1]:
    for div in [0,0x1234]:
     for step in [0,0xfff]:
      cache=key;word=0x2345678|(cache<<30)|(div<<32)|(adiv<<48)|(key<<49)|(step<<51)|(1<<63);out.append({'label':'auth_'+str((fmt,key,adiv,div,step)),'mode':'word','word':word,'format':fmt,'bases':[R.BANK+j*0x1000000 for j in range(4)]})
 for cache in range(4):out.append({'label':'missing_cache'+str(cache),'mode':'word','word':0x1234|(cache<<30),'format':8,'bases':[0]*4})
 for fmt in [0,7,9,12]:out.append({'label':'unsupported_format'+str(fmt),'mode':'word','word':0x1234,'format':fmt,'bases':[R.BANK]*4})
 return out
class Probe:
 def __init__(self,k,e,c,mutate=None):
  self.k=k;self.e=e;self.c=c;self.mutate=mutate;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.envelopes=[];self.boundary=None;self.u.mem_map(P,SIZE)
  self.initial=[((j+1)*0x1234567890123457)&((1<<64)-1) for j in range(31)]
  if c['mode']=='word':
   self.u.mem_write(SLOT,struct.pack('<Q',c['word']));self.u.mem_write(META+6,struct.pack('<H',c['format']));self.u.mem_write(BASES,struct.pack('<4Q',*c['bases']));self.initial[0]=SLOT;self.initial[12]=BASES;self.initial[13]=META;self.initial[16]=c['format'];self.entry=R.HEAD
  else:self.entry=R.BOOT
  for j,v in enumerate(self.initial):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.before=bytes(self.u.mem_read(P,SIZE))
  if mutate:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.k.read(pg,4096));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def flush(self):
  for w in self.pending:w['after_hex']=bytes(self.u.mem_read(int(w['address'],16),w['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,t,a,n,v,d):self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE
  w={'visit':len(self.visits)-1,'PC':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.writes.append(w);self.pending.append(w)
 def code(self,u,a,n,d):
  self.flush()
  if a in [R.END,R.FAIL] or a==R.HEAD and (self.c['mode']=='prefix' or self.visits):self.boundary=hex(a);return u.emu_stop()
  assert any(int(f['start'],16)<=a<int(f['end'],16) for f in self.e['functions']),hex(a);raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.k.read(a,4));i=next(self.k.cs.disasm(raw,a));index=len(self.visits);self.visits.append({'PC':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in PAC:
   self.envelopes.append({'visit':index,'PC':hex(a),'kind':i.mnemonic,'X16':hex(self.reg(16)),'X17':hex(self.reg(17)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'logical_identity':True});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100000);self.flush();assert self.boundary
  return {'configuration':self.c,'entry_PC':hex(self.entry),'initial_registers31':list(map(hex,self.initial)),'initial_private_sha256':sha256(self.before).hexdigest(),'source_word_mutated_to_NOP':None if self.mutate is None else hex(self.mutate),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'logical_PAC_envelopes':self.envelopes,'final_registers31':[hex(self.reg(j)) for j in range(31)],'final_SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'final_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'final_slot_hex':bytes(self.u.mem_read(SLOT,8)).hex(),'final_private_sha256':sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest(),'final_raw_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'boundary_PC':self.boundary,'native_target_executed':False,'hardware_PAC_executed':False}
