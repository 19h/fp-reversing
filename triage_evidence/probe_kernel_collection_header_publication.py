#!/usr/bin/env python3
"""Private original setter/getter CPU cases; no native boot or IPC.
Linear source visits, records and RAM; caller epochs are separate cases.
"""
import json,struct
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_collection_header_publication as R
P=0x6500000000;SIZE=0x100000;SP=P+0xf0000;HALT=P+0xff000
def headers(e):
 out=[]
 for name,commands in [('zero',[]),('no_segment',[(2,0)]),('one_segment',[(0x19,0x7000)]),('mixed7',[(0x19 if j%2 else 2,0xf000-j*0x1000) for j in range(7)]),('mixed8',[(0x19,0x10000-j*0x1000) for j in range(8)]),('mixed9',[(0x19 if j%3 else 2,0x10000-j*0x1000) for j in range(9)]),('segments16',[(0x19,((1<<64)-1) if j%2 else 0x20000-j*0x1000) for j in range(16)])]:
  data=bytearray(32);struct.pack_into('<8I',data,0,0xfeedfacf,0x100000c,2,12,len(commands),sum(72 if c==0x19 else 8 for c,v in commands),0,0)
  for command,value in commands:
   row=bytearray(72 if command==0x19 else 8);struct.pack_into('<II',row,0,command,len(row))
   if command==0x19:struct.pack_into('<Q',row,24,value)
   data+=row
  out.append({'label':name,'address':hex(P+0x10000),'bytes_hex':data.hex()})
 out.append({'label':'original_collection',**e['original_collection_header']});return out
def cases(e):
 return [{'label':h['label']+'_kind'+str(kind),'kind':kind,'slide':slide,'header':h} for h in headers(e) for kind,slide in [(1,0),(2,0x12345000),(3,(1<<64)-1),(0x100000001,0x1000)]]+ [{'label':'invalid_kind'+str(kind),'kind':kind,'slide':0,'header':headers(e)[0]} for kind in [0,4,0xffffffff]]
class Probe:
 def __init__(self,im,e,c,mode='set',banks=None,mutate=None):
  self.im=im;self.e=e;self.c=c;self.mode=mode;self.mutate=mutate;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.boundary=None
  self.u.mem_map(P,SIZE);self.ensure(R.SLOT,96);self.banks=bytes([0xa5])*96 if banks is None else banks;self.u.mem_write(R.SLOT,self.banks);self.ensure(R.MAP,24)
  self.header=bytes.fromhex(c['header']['bytes_hex']);self.at=int(c['header']['address'],16);self.ensure(self.at,len(self.header));self.u.mem_write(self.at,self.header)
  self.entry=R.SET if mode=='set' else R.GET;self.ensure(self.entry,0x300)
  self.initial=[((j+1)*0x1122334455667789)&((1<<64)-1) for j in range(31)];self.initial[:3]=[c['kind'],self.at,c['slide']];self.initial[30]=HALT
  for j,v in enumerate(self.initial):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.im.logical_page(pg));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def flush(self):
  for w in self.pending:w['after_hex']=bytes(self.u.mem_read(int(w['address'],16),w['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,t,a,n,v,d):self.reads.append({'visit':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,t,a,n,v,d):
  assert SP-0x100<=a<a+n<=SP or R.SLOT<=a<a+n<=R.SLOT+96
  w={'visit':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(w);self.pending.append(w)
 def code(self,u,a,n,d):
  self.flush()
  if a in [HALT,0xfffffe000c66291c,0xfffffe000c5e5684]:self.boundary={'PC':hex(a),'returned':a==HALT};return u.emu_stop()
  raw=bytes(u.mem_read(a,4));assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.im.k.read(a,4));i=next(self.im.k.cs.disasm(raw,a));self.visits.append({'PC':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','retab']:u.reg_write(ar.UC_ARM64_REG_PC,a+4 if i.mnemonic=='pacibsp' else u.reg_read(ar.UC_ARM64_REG_X30))
 def run(self):
  self.u.emu_start(self.entry,0,count=100000);self.flush();assert self.boundary is not None
  return {'configuration':self.c,'mode':self.mode,'source_word_mutated_to_NOP':None if self.mutate is None else hex(self.mutate),'initial_registers31':list(map(hex,self.initial)),'initial_SP':hex(SP),'initial_banks_hex':self.banks.hex(),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'final_banks_hex':bytes(self.u.mem_read(R.SLOT,96)).hex(),'final_private_sha256':sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest(),'final_registers31':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))) for j in range(31)],'final_SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'final_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'boundary':self.boundary,'native_target_executed':False}
