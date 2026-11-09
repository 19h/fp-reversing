#!/usr/bin/env python3
"""Independent fresh CPU/read/write/branch-boundary replay of cache profiles.
Declared helpers and intercepted SVC returns are models, never native effects.
O(visits+effects) time, O(private map+journals) space. Uses no probe executor.
"""
import struct
from collections import Counter,defaultdict
import unicorn as uc
from unicorn import arm64_const as ar
from bootpolicy_cache_reader import CS
STACK=0x6000000000;BUFFER=0x6100000000;TLS=0x6200000000;VOUCHER=0x6300000000;HALT=0x6400000000;LOGGER=HALT+0x200
class Replay:
 def __init__(self,cache,p):
  self.cache=cache;self.p=p;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.seq=0;self.current=None;self.pending=[];self.counts=Counter();self.rc=self.wc=0;self.cbi=0;self.svci=0;self.callbacks=p['callback_models'];self.svcs=[e for e in p['events']if e['kind']=='intercepted_svc'];self.reads=defaultdict(list);self.writes=defaultdict(list)
  for e in p['source_reads']:self.reads[e['source_visit_index']].append(e)
  for e in p['source_writes']:self.writes[e['source_visit_index']].append(e)
  for address in p['source_code_pages']:
   a=int(address,16);self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC);self.u.mem_write(a,cache.read(a,4096))
  for a,n in [(STACK,0x10000),(BUFFER,4096),(TLS,4096),(VOUCHER,4096),(HALT,4096),(0x1ed83e000,4096),(0x1eb065000,4096),(0x18057d000,4096)]:self.u.mem_map(a,n)
  self.u.mem_write(0x18057d000,cache.read(0x18057d000,4096));self.u.mem_write(0x1eb065de0,cache.read(0x1eb065de0,8));self.u.mem_write(0x1eb065e48,struct.pack('<Q',LOGGER if p['input_seeds']['syscall_logger_nonnull']else 0));self.u.mem_write(0x1ed83e8d8,struct.pack('<Q',VOUCHER));self.u.mem_write(TLS+8,struct.pack('<Q',TLS+0x100));self.u.reg_write(ar.UC_ARM64_REG_TPIDRRO_EL0,TLS);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf000)
  for j,value in enumerate(p['initial_args']):self.set(j,int(value,16))
  self.set(30,HALT);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def set(self,j,value):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),value)
 def finish(self):
  for e in self.pending:assert bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()==e['after_hex'];self.counts['writes_checked']+=1;self.counts['write_bytes_checked']+=e['size_bytes']
  self.pending=[]
  if self.current is not None:assert self.rc==len(self.reads[self.current])and self.wc==len(self.writes[self.current])
  self.current=None
 def read(self,u,t,a,n,v,d):
  e=self.reads[self.current][self.rc];self.rc+=1;assert e['address']==hex(a)and e['size_bytes']==n and e['bytes_hex']==bytes(u.mem_read(a,n)).hex();self.counts['reads_checked']+=1;self.counts['read_bytes_checked']+=n
 def write(self,u,t,a,n,v,d):
  e=self.writes[self.current][self.wc];self.wc+=1;assert e['address']==hex(a)and e['size_bytes']==n;self.pending.append(e)
 def code(self,u,a,n,d):
  self.finish()
  if self.cbi<len(self.callbacks)and a==int(self.callbacks[self.cbi]['pc'],16):
   e=self.callbacks[self.cbi];self.cbi+=1;assert self.reg(30)==int(e['return_pc'],16)
   for j,value in enumerate(e['arguments8']):assert self.reg(j)==int(value,16)
   for j,value in enumerate(e['after_registers31']):
    if j<18:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(value,16))
    else:assert self.reg(j)==int(value,16)
   u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['return_pc'],16));self.counts['declared_callbacks_checked']+=1;return
  if self.seq==len(self.p['source_visits']):
   event=self.p['events'][-1]
   if self.p['stop_reason']=='returned':assert a==HALT and self.reg(0)==int(event['x0'],16)and u.reg_read(ar.UC_ARM64_REG_SP)==STACK+0xf000
   else:
    assert self.p['stop_reason']=='mach2_request_frontier'and a==int(event['pc'],16)
    for j,value in enumerate(event['arguments8']):assert self.reg(j)==int(value,16)
    assert bytes(u.mem_read(int(self.p['request']['buffer'],16),48)).hex()==event['request_bytes_hex']
   self.counts['final_boundaries_checked']+=1;return u.emu_stop()
  e=self.p['source_visits'][self.seq];assert e['pc']==hex(a)and bytes(u.mem_read(a,4)).hex()==e['bytes_hex']and bytes(u.mem_read(a,4))==self.cache.read(a,4);ins=next(CS.disasm(bytes(u.mem_read(a,4)),a));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1
  if ins.mnemonic=='svc':
   event=self.svcs[self.svci];self.svci+=1;assert event['pc']==hex(a)and self.reg(16)==int(event['x16_bits'],16)and event['x16_signed']==-12
   for j,value in enumerate(event['args']):assert self.reg(j)==int(value,16)
   self.counts['intercepted_trap_boundaries_checked']+=1
   if'private_result_u32'not in event:assert self.p['stop_reason']=='svc_boundary'and self.seq==len(self.p['source_visits']);self.counts['final_boundaries_checked']+=1;return u.emu_stop()
   self.set(0,int(event['private_result_u32'],16));u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if ins.mnemonic in ['pacibsp','autibsp']:
   self.counts['logical_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if ins.mnemonic=='retab':self.counts['logical_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30));return
  if ins.mnemonic=='blraaz':assert a==0x180549844 and self.reg(8)==LOGGER;self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,LOGGER);self.counts['logical_authenticated_calls_checked']+=1;return
  assert ins.mnemonic not in ['hvc','smc','brk','blraa']
 def run(self):
  self.u.emu_start(int(self.p['entry'],16),0,count=5000);self.finish();assert self.seq==len(self.p['source_visits'])and self.cbi==len(self.callbacks)and self.svci==len(self.svcs)and self.counts['final_boundaries_checked']==1;return dict(self.counts)
