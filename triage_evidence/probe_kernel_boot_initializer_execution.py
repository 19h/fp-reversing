#!/usr/bin/env python3
"""Full raw-image boot initializer with bounded streamed receipts.
O(source/memory events + image/fixups) time; no per-instruction journal storage.
Logical PAC only; every instruction is visited, with no loop contraction.
"""
import struct,json
from collections import Counter
from hashlib import sha256
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_boot_initializer_execution as R
P=0x6a00000000;SIZE=0x100000;SP=P+0xf0000;HALT=P+0xff000
SLIDE_STORES={0xfffffe000c660eec,0xfffffe000c660f4c,0xfffffe000c660f68,0xfffffe000c660db8,0xfffffe000c660dd4,0xfffffe000c660e58}
class Probe:
 def __init__(self,im,e,mutate=None):
  self.im=im;self.e=e;self.mutate=mutate;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.u.mem_map(P,SIZE);self.pages=set();self.offsets={};self.source={int(i['ea'],16):(bytes.fromhex(i['bytes_hex']),i['mnemonic']) for f in e['functions'] for i in f['instructions']};self.source_counts=Counter();self.read_counts=Counter();self.write_counts=Counter();self.PAC_counts=Counter();self.streams={k:sha256() for k in ['source','reads','writes','fixups','PAC']};self.pending=[];self.fixups=0;self.expected=iter(im.meta.items());self.active=None;self.calls=[];self.current=None;self.returned=False;self.visits=0;self.reads=0;self.writes=0
  self.initial=[((j+1)*0x1234567890123457)&((1<<64)-1) for j in range(31)];self.initial[30]=HALT
  for j,v in enumerate(self.initial):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
  if mutate:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(UC_HOOK_MEM_READ,self.read);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.im.k.read(pg,4096));self.pages.add(pg);self.offsets[pg]=self.im.offset(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def flush(self):
  for a,n,value in self.pending:assert bytes(self.u.mem_read(a,n))==value.to_bytes(n,'little'),('post_store',hex(a),n)
  self.pending=[]
 def read(self,u,t,a,n,v,d):
  self.ensure(a,n);raw=bytes(u.mem_read(a,n));self.reads+=1;self.read_counts[self.current]+=1;self.streams['reads'].update(struct.pack('<QQI',self.current,a,n)+raw)
  if self.current==0xfffffe000c660958:
   assert n==8 and self.active is None;off=self.offsets[a&~4095]+(a&4095);wanted,row=next(self.expected);assert off==wanted and int.from_bytes(raw,'little')==int(row['raw'],16),('wrong_chain_slot',hex(a),hex(off),hex(wanted));word=int.from_bytes(raw,'little');div=(word>>32)&65535;modifier=div if not row['address_diversity'] else (a if div==0 else (a&0xffffffffffff)|(div<<48));self.active={'slot':a,'word':word,'row':row,'modifier':modifier if row['auth'] else 0,'signed':False,'stored':False}
 def write(self,u,t,a,n,value,d):
  value&=(1<<(8*n))-1;assert n<=8 and not any(start<=a<start+4 for start in self.source),('code_write',hex(a));self.writes+=1;self.write_counts[self.current]+=1;self.streams['writes'].update(struct.pack('<QQI',self.current,a,n)+value.to_bytes(n,'little'));self.pending.append((a,n,value))
  if P<=a<a+n<=P+SIZE:return
  if self.current==0xfffffe000c660974:
   row=self.active;assert row and not row['stored'] and a==row['slot'] and n==8 and value==int(row['row']['target'],16) and row['signed']==bool(row['row']['auth']),('fixup_store',hex(a));row['stored']=True;self.fixups+=1;r=row['row'];self.streams['fixups'].update(struct.pack('<QQQQIBBB',a,row['word'],value,row['modifier'],((row['word']>>51)&4095)*4,r['auth'],r['key'],r['address_diversity']))
   if self.fixups%100000==0:print(json.dumps({'fixups_stored':self.fixups,'source_visits':self.visits}),flush=True)
  elif self.current in SLIDE_STORES:assert n==8 and value==int.from_bytes(self.im.k.read(a,8),'little'),('zero_slide_changed_bytes',hex(a))
  else:
   wanted={int(r['address'],16):int(r['value'],16) for r in self.e['expected_global_words']};assert n==8 and a in wanted and value==wanted[a],('unexpected_image_store',hex(self.current),hex(a),hex(value))
 def code(self,u,a,n,d):
  if self.pending:self.flush()
  if a==HALT:self.returned=True;return u.emu_stop()
  assert a in self.source,('unexpected_PC',hex(a));raw,mnemonic=self.source[a]
  if a not in self.source_counts:assert bytes(u.mem_read(a,4))==(bytes.fromhex('1f2003d5') if a==self.mutate else raw)
  self.current=a;self.visits+=1;self.source_counts[a]+=1;self.streams['source'].update(struct.pack('<Q',a)+(bytes.fromhex('1f2003d5') if a==self.mutate else raw))
  if a==0xfffffe000c660978:
   assert self.active and self.active['stored'],('fixup_store_not_executed',self.fixups);self.active=None
  if a in [R.BOOT,R.SET,R.RANGES,R.CHILD]:self.calls.append({'PC':hex(a),'source_visit':self.visits-1,'arguments8':[hex(self.reg(j)) for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30))})
  if a==self.mutate:return
  if mnemonic in ['pacia1716','pacib1716','pacda','pacdb']:
   row=self.active;key={'pacia1716':0,'pacib1716':1,'pacda':2,'pacdb':3}[mnemonic];assert row and row['row']['auth'] and row['row']['key']==key and not row['signed'] and self.reg(16)==row['modifier'] and self.reg(17)==int(row['row']['target'],16),('PAC_custody',hex(a));row['signed']=True;self.PAC_counts[mnemonic]+=1;self.streams['PAC'].update(struct.pack('<QQQQ',a,self.reg(16),self.reg(17),row['slot']));u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif mnemonic=='pacibsp':self.PAC_counts[mnemonic]+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif mnemonic=='retab':self.PAC_counts[mnemonic]+=1;u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def run(self):
  self.ensure(R.BOOT);self.u.emu_start(R.BOOT,0,count=100000000);self.flush();assert self.returned and self.fixups==len(self.im.meta) and self.active is None
  assert next(self.expected,None) is None
  return {'entry_PC':hex(R.BOOT),'initial_registers31':list(map(hex,self.initial)),'initial_SP':hex(SP),'initial_NZCV':'0x0','initial_private_sha256':sha256(bytes(SIZE)).hexdigest(),'source_word_mutated_to_NOP':None if self.mutate is None else hex(self.mutate),'stream_record_formats':{'source':'Q PC + 4 instruction bytes','reads_writes':'Q PC,Q address,I byte_count + exact bytes','fixups':'Q slot,Q raw,Q target,Q modifier,I next_step,B auth,B key,B address_diversity','PAC':'Q PC,Q modifier,Q logical_target,Q slot'},'stream_sha256':{k:v.hexdigest() for k,v in self.streams.items()},'source_visit_counts':{hex(k):v for k,v in sorted(self.source_counts.items())},'read_PC_counts':{hex(k):v for k,v in sorted(self.read_counts.items())},'write_PC_counts':{hex(k):v for k,v in sorted(self.write_counts.items())},'logical_PAC_counts':dict(self.PAC_counts),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'fixups_stored':self.fixups,'original_call_entries':self.calls,'final_registers31':[hex(self.reg(j)) for j in range(31)],'final_SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'final_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'final_private_sha256':sha256(bytes(self.u.mem_read(P,SIZE))).hexdigest(),'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'published_global_words':[{'address':hex(a),'value':hex(int.from_bytes(self.u.mem_read(a,8),'little'))} for a in R.GLOBALS],'boundary':{'PC':hex(HALT),'returned':True},'native_target_executed':False,'hardware_PAC_executed':False,'loop_contractions':0}
