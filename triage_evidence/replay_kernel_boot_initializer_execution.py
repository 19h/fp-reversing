#!/usr/bin/env python3
"""Independent full raw-image replay and streamed receipt comparison.
O(source/memory events + final pages), bounded receipt storage; no probe import.
"""
import struct,json
from collections import Counter
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_boot_initializer_execution as R
P=0x6a00000000;SIZE=0x100000;SP=P+0xf0000;HALT=P+0xff000
class Replay:
 def __init__(self,k,e,row):
  self.k=k;self.e=e;self.row=row;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.u.mem_map(P,SIZE);self.pages=set();self.source={int(i['ea'],16):(bytes.fromhex(i['bytes_hex']),i['mnemonic']) for f in e['functions'] for i in f['instructions']};self.counts=Counter();self.read_counts=Counter();self.write_counts=Counter();self.PAC_counts=Counter();self.hashes={n:sha256() for n in ['source','reads','writes','fixups','PAC']};self.pending=[];self.current=0;self.visits=self.reads=self.writes=self.fixed=0;self.active=None;self.calls=[];self.stopped=False
  for j,v in enumerate(row['initial_registers31']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(row['initial_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(row['initial_NZCV'],16));assert sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==row['initial_private_sha256'];self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def map(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.k.read(pg,4096));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.map(a,n);return True
 def read(self,u,t,a,n,v,d):
  self.map(a,n);raw=bytes(u.mem_read(a,n));self.reads+=1;self.read_counts[self.current]+=1;self.hashes['reads'].update(struct.pack('<QQI',self.current,a,n)+raw)
  if self.current==0xfffffe000c660958:self.active=(a,int.from_bytes(raw,'little'))
 def write(self,u,t,a,n,value,d):
  value&=(1<<(n*8))-1;raw=value.to_bytes(n,'little');self.writes+=1;self.write_counts[self.current]+=1;self.hashes['writes'].update(struct.pack('<QQI',self.current,a,n)+raw);self.pending.append((a,raw))
  if self.current==0xfffffe000c660974:
   slot,word=self.active;assert a==slot and n==8;auth=word>>63;div=(word>>32)&65535;adiv=(word>>48)&1;key=(word>>49)&3;modifier=div if not adiv else (a if not div else (a&0xffffffffffff)|(div<<48));self.hashes['fixups'].update(struct.pack('<QQQQIBBB',a,word,value,modifier if auth else 0,((word>>51)&4095)*4,auth,key,adiv));self.fixed+=1
   if self.fixed%100000==0:print(json.dumps({'replay_fixups':self.fixed,'replay_source_visits':self.visits}),flush=True)
 def code(self,u,a,n,d):
  if self.pending:
   for at,raw in self.pending:assert bytes(u.mem_read(at,len(raw)))==raw
   self.pending=[]
  if self.visits==self.row['source_visits']:assert a==HALT;self.stopped=True;return u.emu_stop()
  assert a in self.source;raw,mnemonic=self.source[a]
  if a not in self.counts:assert bytes(u.mem_read(a,4))==raw
  self.current=a;self.visits+=1;self.counts[a]+=1;self.hashes['source'].update(struct.pack('<Q',a)+raw)
  if a in [R.BOOT,R.SET,R.RANGES,R.CHILD]:self.calls.append({'PC':hex(a),'source_visit':self.visits-1,'arguments8':[hex(self.reg(j)) for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30))})
  if mnemonic in ['pacia1716','pacib1716','pacda','pacdb']:
   self.PAC_counts[mnemonic]+=1;self.hashes['PAC'].update(struct.pack('<QQQQ',a,self.reg(16),self.reg(17),self.active[0]));u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif mnemonic=='pacibsp':self.PAC_counts[mnemonic]+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif mnemonic=='retab':self.PAC_counts[mnemonic]+=1;u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def run(self):
  self.map(R.BOOT);self.u.emu_start(R.BOOT,0,count=self.row['source_visits']+1);assert self.stopped and self.reads==self.row['source_reads'] and self.writes==self.row['source_writes'] and self.fixed==self.row['fixups_stored'];assert {n:h.hexdigest() for n,h in self.hashes.items()}==self.row['stream_sha256'];assert {hex(k):v for k,v in sorted(self.counts.items())}==self.row['source_visit_counts'];assert {hex(k):v for k,v in sorted(self.read_counts.items())}==self.row['read_PC_counts'] and {hex(k):v for k,v in sorted(self.write_counts.items())}==self.row['write_PC_counts'];assert dict(self.PAC_counts)==self.row['logical_PAC_counts'] and self.calls==self.row['original_call_entries'];assert [hex(self.reg(j)) for j in range(31)]==self.row['final_registers31'];assert hex(self.u.reg_read(ar.UC_ARM64_REG_SP))==self.row['final_SP'] and hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))==self.row['final_NZCV'];assert sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest()==self.row['final_private_sha256'];assert {hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in self.pages}==self.row['final_page_sha256'];return {'source_visits_checked':self.visits,'reads_checked':self.reads,'writes_checked':self.writes,'fixup_stores_checked':self.fixed,'stream_digests_checked':len(self.hashes),'private_bytes_checked':SIZE,'mapped_image_bytes_checked':4096*len(self.pages),'all_GPR_SP_NZCV_and_call_entries_checked':True}
