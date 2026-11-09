#!/usr/bin/env python3
"""Independent startup/constructor stream replay and logical data-authentication.
O(visits+effects), O(unique PCs+critical effects+RAM); no probe executor reuse.
"""
import hashlib
from unicorn import arm64_const as ar
from replay_kext_provider_initialize import Replay as Parent
HALT=0x65000e0000;OUT=0x6500081000;OUTSLOT=0x65000eff78
FLAGS={0xfffffe000cccea88:1,0xfffffe000ccca078:1,0xfffffe000ccceb00:1,0xfffffe000ccceb08:8,0xfffffe000ccceb10:8,0xfffffe000ccc7848:8,0xfffffe000cccca58:8}
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p);self.phase=p['entry_phase'];self.auth=p['logical_data_authentication'];self.ai=0;self.bi=0;self.bridge=[];self.bridge_reads=[];self.lock_cookies={int(a,16)for a,v in p['initial_lock_owners'].items()if v['alive']}
  for j,v in enumerate(p['initial_Q32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_FPCR,p['initial_FPCR']);self.u.reg_write(ar.UC_ARM64_REG_FPSR,p['initial_FPSR'])
 def read(self,u,t,a,n,v,d):
  super().read(u,t,a,n,v,d)
  if any(a<x+z and x<a+n for x,z in [(OUTSLOT,4),*FLAGS.items()]):self.bridge_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.streams['visits'].count-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'phase':self.phase})
 def finish(self):
  pending=list(self.pending);super().finish()
  for e in pending:
   a=int(e['address'],16);n=e['size_bytes']
   if any(a<t+z and t<a+n for t,z in [(OUT,8),(OUTSLOT,4),*FLAGS.items()]):self.bridge.append({**e,'phase':self.phase})
 def code(self,u,a,n,d):
  self.finish();seq=self.streams['visits'].count
  if self.bi<len(self.p['AES_boundaries']):
   e=self.p['AES_boundaries'][self.bi]
   if a==int(e['pc'],16)and seq==e['before_source_visit_index']:
    self.bi+=1;sp=u.reg_read(ar.UC_ARM64_REG_SP);assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['SP']==hex(sp)and e['stack24_hex']==bytes(u.mem_read(sp,24)).hex()and e['IV16_hex']==bytes(u.mem_read(self.reg(4),16)).hex()and e['buffer32_sha256']==hashlib.sha256(bytes(u.mem_read(0x65000b0000,32))).hexdigest();self.counts['AES_argument_frame_boundaries_checked']+=1
  if a==HALT and self.ri<len(self.p['returns']):
   e=self.p['returns'][self.ri]
   if seq==e['before_source_visit_index']:self.regs_match(e);self.ri+=1;self.counts['wrapper_returns_checked']+=1
   if self.phase==0:
    s=self.p['startup_snapshot'];assert seq==s['before_source_visit_index']and s['Q32']==[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and u.reg_read(ar.UC_ARM64_REG_FPCR)==s['FPCR']and u.reg_read(ar.UC_ARM64_REG_FPSR)==s['FPSR'];assert bytes(u.mem_read(OUTSLOT,4)).hex()==s['output_slot4_hex'];self.counts['source_produced_startup_snapshots_checked']+=1
  if self.mi<len(self.p['API_models']):
   e=self.p['API_models'][self.mi]
   if a==int(e['pc'],16)and seq==e['before_source_visit_index']and e['symbol']=='memcpy_model':
    dst,src,size=[self.reg(j)for j in range(3)];assert len(e['memory_effects'])==1 and e['memory_effects'][0]['address']==hex(dst)and e['memory_effects'][0]['after_hex']==bytes(u.mem_read(src,size)).hex();self.counts['source_byte_memcpy_effects_checked']+=1
  if self.ai<len(self.auth):
   e=self.auth[self.ai]
   if a==int(e['pc'],16)and seq==e['before_source_visit_index']:
    self.ai+=1;raw=bytes(u.mem_read(a,4));assert raw==self.im.k.read(a,4)and raw.hex()==self.words[a]['bytes_hex'];i=next(self.im.k.cs.disasm(raw,a));assert(i.mnemonic,i.op_str)==('autda','x16, x17')and self.reg(16)==int(e['pointer'],16)and self.reg(17)==int(e['modifier'],16);self.streams['visits'].append({'pc':hex(a),'bytes_hex':raw.hex()});self.counts['logical_data_authentication_steps_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
 def run(self):
  counts=super().run();assert self.ai==len(self.auth)and self.bi==len(self.p['AES_boundaries'])and self.bridge==self.p['bridge_effects']and self.bridge_reads==self.p['bridge_reads'];self.counts['bridge_memory_effects_checked']+=len(self.bridge);self.counts['bridge_memory_reads_checked']+=len(self.bridge_reads)
  for a,h in self.p['final_flags_hex'].items():self.ensure(int(a,16),len(h)//2);assert bytes(self.u.mem_read(int(a,16),len(h)//2)).hex()==h
  for a,key in [(OUT,'final_output8_hex'),(OUTSLOT,'final_output_slot4_hex'),(0x65000b0000,'final_buffer32_hex'),(0x6500025000,'final_params104_hex')]:
   b=bytes.fromhex(self.p[key]);assert bytes(self.u.mem_read(a,len(b)))==b
  return dict(self.counts)
