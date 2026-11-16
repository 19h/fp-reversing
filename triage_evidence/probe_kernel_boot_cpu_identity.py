#!/usr/bin/env python3
"""Execute selected original boot/thread/CPU/property paths in private RAM.
O(visits + journals + mapped bytes) time/space. Explicit logical system/PAC
effects and no-RAM helper contracts do not establish native execution.
"""
import json,bisect
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_UNMAPPED
from unicorn import arm64_const as ar
import recover_kernel_boot_cpu_identity as R
P=0x6500000000;SP=P+0xf000;HALT=P+0xe000;NODE=P+0x1000;VALUE=P+0x2000;OTHER=P+0x4000
MASK=(1<<64)-1
def rid(j):return getattr(ar,'UC_ARM64_REG_X'+str(j))

class Probe:
 def __init__(self,image,c,mutate=None):
  self.im=image;self.c=c;self.mutate=mutate;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.pages={};self.events=[];self.epochs=[];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.models=[];self.copies=[];self.current=-1;self.stop=None
  self.system={'tpidr_el1':R.THREAD,'tpidr_el0':c.get('tpidr0',(c.get('ordinal',0)&0xfff)|((c.get('cluster',1)&255)<<12)),
   'tpidrro_el0':0,'contextidr_el1':0,'midr_el1':c.get('midr',0x410fd0c1),'id_aa64dfr0_el1':c.get('dfr',0)}
  self.u.mem_map(P,0x10000)
  for pg in range(P,P+0x10000,4096):self.pages[pg]=bytes(4096)
  for a in R.FUNCTIONS:
   end=image.k.starts[bisect.bisect_left(image.k.starts,a)+1]
   for pg in range(a&~4095,(end+4095)&~4095,4096):self.map(pg)
  for a,n in [*R.BLOCKS,(0xfffffe000cb8ab68,20)]:
   for pg in range(a&~4095,(a+n+4095)&~4095,4096):self.map(pg)
  self.put(P+0x3000,bytes((i*17+3)&255 for i in range(4096)))
  self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(rid(30),HALT)
  for j in range(29):self.u.reg_write(rid(j),(0x123456789ab+j*0x10001)&MASK)
  if c['phase']=='bootstrap':
   ordinal=c['ordinal'];record=R.ARRAY+ordinal*136
   self.put(record,ordinal.to_bytes(4,'little')+c['physical'].to_bytes(4,'little')+c['cluster'].to_bytes(4,'little'))
   self.put(R.RECORD_PTR,record.to_bytes(8,'little'));self.put(R.ARGS+8,c['virt_base'].to_bytes(8,'little')+c['phys_base'].to_bytes(8,'little'))
   self.put(R.THREAD,bytes([0xa5])*0x5c0)
   self.put(R.CPU+0xa38,c.get('cpu_low48',0).to_bytes(8,'little'))
   self.put(R.CPU+4,c.get('magic',0).to_bytes(4,'little'));self.put(R.CPU+0x1dc,(0x87654321).to_bytes(4,'little'))
   self.start=0xfffffe000c639cc0
  elif c['phase']=='caller':
   cpu=R.CPU if c['boot'] else OTHER
   self.put(R.THREAD+0x1c0,cpu.to_bytes(8,'little'));self.put(R.THREAD+0x1b8,c['ordinal'].to_bytes(8,'little'))
   self.put(cpu,c['ordinal'].to_bytes(2,'little'));self.put(cpu+4,c.get('magic',0).to_bytes(4,'little'))
   self.put(cpu+0x1dc,(0xffffffff).to_bytes(4,'little'));self.put(cpu+0x890,bytes([0xa5])*0x28)
   self.put(0xfffffe0007ef81c8,(c.get('cap_nibble',13)<<16).to_bytes(4,'little'))
   self.start=R.CALLER
  elif c['phase']=='scalar':
   self.u.reg_write(rid(0),NODE);self.u.reg_write(rid(1),R.STRINGS[0]);self.u.reg_write(rid(2),c['fallback'])
   self.put(VALUE,bytes.fromhex(c['value_hex']));self.start=R.SCALAR
  elif c['phase']=='setter':
   self.put(R.THREAD+0x1c0,OTHER.to_bytes(8,'little'));self.put(OTHER+0xa38,c['cpu_low48'].to_bytes(8,'little'))
   self.put(R.THREAD+0x148,c['ro'].to_bytes(8,'little'));self.put(R.THREAD+0x510,c['context'].to_bytes(8,'little'))
   self.u.reg_write(rid(0),R.THREAD);self.start=R.SETTER
  else:raise AssertionError(c)
  if mutate is not None:self.put(mutate,bytes.fromhex('1f2003d5'))
  self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.memread);self.u.hook_add(UC_HOOK_MEM_WRITE,self.memwrite)
  self.initial_system=dict(self.system);self.initial_registers=self.regs();self.initial_SP=self.u.reg_read(ar.UC_ARM64_REG_SP)
  self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
 def regs(self):return [self.u.reg_read(rid(j)) for j in range(31)]
 def map(self,pg):
  if pg in self.pages:return
  raw=self.im.logical_page(pg);self.u.mem_map(pg,4096);self.u.mem_write(pg,raw);self.pages[pg]=raw
  if hasattr(self,'initial_pages'):self.initial_pages[pg]=raw
 def put(self,a,b):
  for pg in range(a&~4095,(a+len(b)+4095)&~4095,4096):self.map(pg)
  self.u.mem_write(a,b)
 def unmapped(self,u,access,a,n,value,d):
  self.map(a&~4095)
  if (a&4095)+n>4096:self.map((a&~4095)+4096)
  return True
 def finish(self):
  for index in self.pending:
   w=self.writes[index];w['after_hex']=bytes(self.u.mem_read(int(w['address'],16),w['size_bytes'])).hex()
  self.pending=[]
 def memread(self,u,access,a,n,value,d):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):self.map(pg)
  self.reads.append({'visit':self.current,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def memwrite(self,u,access,a,n,value,d):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):self.map(pg)
  self.writes.append({'visit':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()});self.pending.append(len(self.writes)-1)
 def model(self,a,name,result=0,api_writes=()):
  before=self.regs();sp=self.u.reg_read(ar.UC_ARM64_REG_SP);writes=[]
  for at,data in api_writes:
   self.map(at&~4095);old=bytes(self.u.mem_read(at,len(data)));self.u.mem_write(at,data);writes.append({'address':hex(at),'before_hex':old.hex(),'after_hex':data.hex()})
  index=len(self.models)
  for j in range(18):self.u.reg_write(rid(j),result if j==0 else ((j+1)*0x123456789abcdef^(index+1)*0x8b3dc651)&MASK)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if index%2==0 else 0)
  self.models.append({'PC':hex(a),'name':name,'before_visit':len(self.visits),'registers_before':list(map(hex,before)),'registers_after':list(map(hex,self.regs())),
   'SP':hex(sp),'NZCV_after':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'api_writes':writes,'return_value':hex(result)})
  self.u.reg_write(ar.UC_ARM64_REG_PC,before[30])
 def code(self,u,a,n,d):
  self.finish()
  if a in [HALT,R.TAIL,R.PANIC]:self.stop={'PC':hex(a),'registers':list(map(hex,self.regs()))};u.emu_stop();return
  if a==0xfffffe000c639dd8:
   assert self.c['phase']=='bootstrap';self.epochs.append({'PC':hex(a),'registers':list(map(hex,self.regs())),'system':dict(self.system),'writes_completed':len(self.writes),'before_visit':len(self.visits),
    'contract':'Same complete RAM; explicit new caller epoch bypasses intervening original registration/helpers; no native startup continuity claim'})
   self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.u.reg_write(rid(30),HALT);self.u.reg_write(ar.UC_ARM64_REG_PC,R.CALLER);return
  if a==R.PROPERTY:
   assert self.c['phase']=='scalar';regs=self.regs();writes=[]
   if self.c['present']:writes=[(regs[2],VALUE.to_bytes(8,'little')),(regs[3],self.c['length'].to_bytes(4,'little'))]
   self.model(a,'declared_SecureDT_property_output',int(self.c['present']),writes);return
  if a in [R.SPTM,R.CACHE,R.CONFIG]:
   self.model(a,{R.SPTM:'declared_SPTM_CPU_initializer_no_RAM',R.CACHE:'declared_cache_initializer_no_RAM',R.CONFIG:'declared_CPU_context_initializer_no_RAM'}[a]);return
  original=self.im.k.read(a,4);raw=original if a!=self.mutate else bytes.fromhex('1f2003d5')
  if a==self.mutate:self.u.mem_write(a,raw)
  i=next(self.im.k.cs.disasm(raw,a));self.current=len(self.visits);self.visits.append({'PC':hex(a),'bytes_hex':raw.hex()})
  assert len(self.visits)<10000
  if a==R.COPY:self.copies.append({'PC':hex(a),'arguments3':list(map(hex,self.regs()[:3])),'return_PC':hex(self.regs()[30]),'visit':self.current})
  if i.mnemonic in ['mrs','msr']:
   before=dict(self.system);parts=i.op_str.split(', ')
   if i.mnemonic=='mrs':reg,name=parts;self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+reg.upper()),self.system[name])
   else:
    name,reg=parts;self.system[name]=0 if reg=='xzr' else self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+reg.upper()))
   self.events.append({'visit':self.current,'PC':hex(a),'kind':'logical_system','mnemonic':i.mnemonic,'operands':i.op_str,'before':before,'after':dict(self.system)})
   u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic in ['pacibsp','autibsp','pacda','retab']:
   self.events.append({'visit':self.current,'PC':hex(a),'kind':'logical_PAC','mnemonic':i.mnemonic,'operands':i.op_str})
   u.reg_write(ar.UC_ARM64_REG_PC,self.regs()[30] if i.mnemonic=='retab' else a+4);return
 def run(self):
  self.u.emu_start(self.start,0,count=10000);self.finish();assert self.stop is not None
  return {'configuration':self.c,'start':hex(self.start),'mutated_PC':hex(self.mutate) if self.mutate else None,
   'initial_system':self.initial_system,'initial_registers':list(map(hex,self.initial_registers)),'initial_SP':hex(self.initial_SP),
   'initial_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],
   'source_visits':self.visits,'reads':self.reads,'writes':self.writes,'logical_effects':self.events,'declared_models':self.models,'original_copy_entries':self.copies,'epochs':self.epochs,
   'boundary':self.stop,'final_system':self.system,'final_pages':[{'address':hex(pg),'bytes_hex':bytes(self.u.mem_read(pg,4096)).hex()} for pg in sorted(self.pages)]}

def cases():
 rows=[]
 for ordinal,physical,cluster,magic,dfr in [(0,0x100,1,0,0),(1,0x200,2,0,0x123456789),(15,0x105,1,0,1),(1,0xffff,3,0x0100000c,0)]:
  rows.append(dict(phase='bootstrap',ordinal=ordinal,physical=physical,cluster=cluster,virt_base=0xfffffe0007000000,phys_base=0x80000000,magic=magic,dfr=dfr,cpu_low48=0))
 for boot,magic,nibble,dfr in [(False,0,12,0),(False,0,14,0x123456789),(False,0,15,0),(False,0x0100000c,15,1),(True,0,12,0)]:rows.append(dict(phase='caller',boot=boot,ordinal=15,magic=magic,cap_nibble=nibble,dfr=dfr))
 for length in [1,2,4,8,0,3,16]:rows.append(dict(phase='scalar',present=True,length=length,fallback=0x123456789abcdef0,value_hex='efcdab8967452301'))
 for fallback in [0,0x123456789abcdef0,MASK]:rows.append(dict(phase='scalar',present=False,length=0,fallback=fallback,value_hex='efcdab8967452301'))
 for old,value,ro,context in [(0xabcd123456789abc,0xffff112233445566,0xffffffffffffffff,0x123456789abcdef0),(0,0,0,0)]:rows.append(dict(phase='setter',tpidr0=old,cpu_low48=value,ro=ro,context=context))
 return rows
