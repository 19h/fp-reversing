#!/usr/bin/env python3
"""Independent fresh CPU replay and streaming effect fingerprints.
No probe executor reuse. O(visits+effects), O(unique PCs+critical effects+RAM).
"""
import hashlib,struct
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as ar
class Stream:
 def __init__(self,kind):self.kind=kind;self.count=0;self.size=0;self.hash=hashlib.sha256();self.pcs=Counter()
 def append(self,e):
  self.count+=1;a=int(e['pc'],16);self.pcs[a]+=1
  if self.kind=='visits':data=struct.pack('<Q',a)+bytes.fromhex(e['bytes_hex'])
  elif self.kind in ['reads','writes']:
   v=bytes.fromhex(e['bytes_hex']if self.kind=='reads'else e['after_hex']);data=struct.pack('<QQIQ',a,int(e['address'],16),e['size_bytes'],e['source_visit_index'])+v;self.size+=e['size_bytes']
  elif self.kind=='edges':data=struct.pack('<QQQQB',a,e['visit'],int(e['target'],16),int(e['modifier'],16),1 if e['kind']=='blraa'else 2)
  else:data=struct.pack('<QQ8Q',a,int(e['target'],16),*[int(v,16)for v in e['args8']])
  self.hash.update(data)
 def result(self):return {'count':self.count,'data_bytes':self.size,'sha256':self.hash.hexdigest()}
class Replay:
 def __init__(self,im,p):
  self.im=im;self.p=p;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.lo=int(p['private_RAM']['address'],16);self.hi=self.lo+p['private_RAM']['size_bytes'];self.u.mem_map(self.lo,self.hi-self.lo);self.u.mem_write(self.lo,bytes(self.hi-self.lo));self.pages=set();self.pending=[];self.dec={};self.phase=0;self.mi=self.ti=self.ri=0;self.stopped=False;self.critical=[];self.lock_cookies=set();self.cells={0xfffffe000cccda68,0xfffffe000ccceaf8,0xfffffe000cccea88,0xfffffe000ccceab8,0xfffffe000ccca078};self.streams={name:Stream(name)for name in p['fingerprints']};self.words={int(r['pc'],16):r for r in p['original_PC_coverage']};self.counts=Counter();self.read_bounds=None
  for e in p['initial_private_fixtures']+p['initial_image_fixtures']:a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
  for j,v in enumerate(p['entry_registers31']):self.set(j,int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_SP,int(p['entry_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(p['entry_NZCV'],16));self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def set(self,j,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if self.lo<=pg<self.hi or pg in self.pages:continue
   self.u.mem_map(pg,4096);self.u.mem_write(pg,self.im.logical_page(pg));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def finish(self):
  for e in self.pending:
   a=int(e['address'],16);e['after_hex']=bytes(self.u.mem_read(a,e['size_bytes'])).hex();self.streams['writes'].append(e)
   if a in self.cells or self.lo+0x21000<=a<self.lo+0x21200 or(e['size_bytes']==8 and int.from_bytes(bytes.fromhex(e['after_hex']),'little')in self.lock_cookies):self.critical.append({**e,'phase':self.phase})
  self.pending=[]
 def read(self,u,t,a,n,v,d):
  self.streams['reads'].append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.streams['visits'].count-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
  if self.lo+0x21000<=a<self.lo+0x21200:self.read_bounds=[a,a+n]if self.read_bounds is None else[min(a,self.read_bounds[0]),max(a+n,self.read_bounds[1])]
 def write(self,u,t,a,n,v,d):
  assert self.lo<=a<a+n<=self.hi or 0xfffffe000ccc0000<=a<a+n<=0xfffffe000ccd0000
  self.pending.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.streams['visits'].count-1,'address':hex(a),'size_bytes':n})
 def regs_match(self,e):
  assert e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(self.u.reg_read(ar.UC_ARM64_REG_SP))and e['NZCV']==hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.finish();seq=self.streams['visits'].count
  if self.ri<len(self.p['returns']):
   e=self.p['returns'][self.ri]
   if a==int(self.p['boundary']['pc'],16)and seq==e['before_source_visit_index']:self.regs_match(e);self.ri+=1;self.counts['wrapper_returns_checked']+=1
  if self.ti<len(self.p['declared_call_transitions']):
   e=self.p['declared_call_transitions'][self.ti]
   if a==int(e['pc'],16)and seq==e['before_source_visit_index']:
    self.ti+=1;self.regs_match(e);assert hashlib.sha256(bytes(u.mem_read(self.lo,self.hi-self.lo))).hexdigest()==e['RAM_sha256'];self.ensure(0xfffffe000ccc0000,0x10000);assert hashlib.sha256(bytes(u.mem_read(0xfffffe000ccc0000,0x10000))).hexdigest()==e['BSS_sha256'];self.phase+=1
    for j,v in enumerate(e['after_registers31']):
     if j<18 or j==30:self.set(j,int(v,16))
     else:assert self.reg(j)==int(v,16)
    u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['entry_PC'],16));self.counts['memory_preserving_call_transitions_checked']+=1;return
  if self.mi<len(self.p['API_models']):
   e=self.p['API_models'][self.mi]
   if a==int(e['pc'],16)and seq==e['before_source_visit_index']:
    if e['symbol']=='lock_allocation_model'and int(e['return_value'],16):self.lock_cookies.add(int(e['return_value'],16))
    self.mi+=1;assert e['phase']==self.phase and e['arguments8']==[hex(self.reg(j))for j in range(8)]and self.reg(30)==int(e['return_pc'],16)
    for effect in e['memory_effects']:
     address=int(effect['address'],16);b=bytes.fromhex(effect['after_hex']);assert bytes(u.mem_read(address,len(b))).hex()==effect['before_hex'];u.mem_write(address,b);self.counts['declared_model_memory_effects_checked']+=1;self.counts['declared_model_write_bytes_checked']+=len(b)
    for j,v in enumerate(e['after_registers31']):
     if j<18:self.set(j,int(v,16))
     else:assert self.reg(j)==int(v,16)
    u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['return_pc'],16));self.counts['API_models_checked']+=1;return
  if seq==self.p['fingerprints']['visits']['count']:
   self.regs_match(self.p['boundary']);assert a==int(self.p['boundary']['pc'],16);self.stopped=True;self.counts['final_boundaries_checked']+=1;return u.emu_stop()
  expected=self.words[a];raw=bytes(u.mem_read(a,4));i=self.dec.get(a)
  if i is None:assert self.im.k.read(a,4).hex()==expected['bytes_hex'];i=next(self.im.k.cs.disasm(raw,a));self.dec[a]=i
  assert raw.hex()==expected['bytes_hex'];self.streams['visits'].append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp','retab']:
   self.counts['logical_PAC_steps_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else a+4)
  if i.mnemonic in ['braa','blraa']:
   operands=i.op_str.replace(',',' ').split();target=self.reg(int(operands[0][1:]));modifier=self.reg(int(operands[1][1:]));self.streams['edges'].append({'pc':hex(a),'visit':seq,'kind':i.mnemonic,'target':hex(target),'modifier':hex(modifier)})
   if i.mnemonic=='blraa':self.set(30,a+4);self.streams['calls'].append({'pc':hex(a),'target':hex(target),'args8':[hex(self.reg(j))for j in range(8)]})
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in ['svc','hvc','smc','brk','autda']
 def run(self):
  self.ensure(int(self.p['entry_PC'],16));self.u.emu_start(int(self.p['entry_PC'],16),0,count=self.p['fingerprints']['visits']['count']+len(self.p['API_models'])+20);self.finish();assert self.stopped and self.mi==len(self.p['API_models'])and self.ti==len(self.p['declared_call_transitions'])and self.ri==len(self.p['returns'])
  for name,s in self.streams.items():assert s.result()==self.p['fingerprints'][name],name;self.counts[name+'_fingerprint_events_checked']+=s.count
  assert{a:s['count']for a,s in self.words.items()}==dict(self.streams['visits'].pcs)and self.critical==self.p['critical_effects'];self.counts['critical_effects_checked']+=len(self.critical)
  assert([hex(v)for v in self.read_bounds]if self.read_bounds else None)==self.p['table_read_bounds']
  for a,h in self.p['final_cells_hex'].items():self.ensure(int(a,16),len(h)//2);assert bytes(self.u.mem_read(int(a,16),len(h)//2)).hex()==h
  self.ensure(0xfffffe000ccc0000,0x10000);assert bytes(self.u.mem_read(self.lo+0x21000,512)).hex()==self.p['final_table512_hex']and hashlib.sha256(bytes(self.u.mem_read(self.lo,self.hi-self.lo))).hexdigest()==self.p['final_RAM_sha256']and hashlib.sha256(bytes(self.u.mem_read(0xfffffe000ccc0000,0x10000))).hexdigest()==self.p['final_BSS_sha256'];return dict(self.counts)
