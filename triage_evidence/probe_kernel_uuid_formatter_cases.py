#!/usr/bin/env python3
"""Original snprintf on explicit UUID-format varargs and guarded private output.
Linear source visits, journals and mapped bytes. No modeled formatter result.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_rpc502_vm_handoff import compressed
from probe_kernel_vm_mig import Probe as Core,P,SIZE,SP,HALT
import recover_kernel_uuid_formatter_execution as R
OUTPUT=P+0x20000;BUFFER=OUTPUT+32;EXTENT=128

class Probe(Core):
 def ensure(self,a,n=1):
  super().ensure(a,n)
  if hasattr(self,'initial_pages'):
   for pg in self.pages-self.initial_pages.keys():self.initial_pages[pg]=bytes(self.u.mem_read(pg,4096))
 def __init__(self,image,c,mutate=None):
  super().__init__(image,'init',c);self.entry=R.FORMAT;self.mutate=mutate;self.entries=[];self.returns=[];self.active=[];self.logical=[];self.system={};self.initial=[];self.image_initial=[]
  self.fixture(OUTPUT,bytes([0xa5])*EXTENT);data=bytes.fromhex(c['UUID_bytes_hex']);assert len(data)==16;self.fixture(SP,struct.pack('<16Q',*data));self.set(0,0 if c.get('null_zero_capacity') else BUFFER);self.set(1,c['capacity_bytes']);self.set(2,0xfffffe00070d7f36)
  self.entry_regs=[hex(self.reg(j)) for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.before=bytes(self.u.mem_read(P,SIZE));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in e['functions']]
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==HALT:return self.stop('original_formatter_returned')
  if a in [R.FORMAT,R.ENGINE,R.EMIT]:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4))
  if i.mnemonic=='pacia':
   assert i.op_str=='x16, x17';self.logical.append({'PC':hex(a),'kind':'pacia','operands':i.op_str,'before_visit':len(self.visits),'X16':hex(self.reg(16)),'X17':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if i.mnemonic=='blraa':
   assert R.ENGINE<=a<0xfffffe000bd15408 and i.op_str=='x21, x17' and self.reg(21)==R.EMIT and self.reg(17)==0xae56
   self.logical.append({'PC':hex(a),'kind':'blraa','scope':'original_formatter_byte_output','operands':i.op_str,'before_visit':len(self.visits),'system_before':{},'system_after':{},'target':hex(self.reg(21)),'modifier_X17':hex(self.reg(17)),'character_W0':hex(self.reg(0)&0xffffffff),'context_X1':hex(self.reg(1))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,R.EMIT);return
  if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return Core.code(self,u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100000);self.flush();assert self.reason=='original_formatter_returned' and not self.active
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':[],'initial_private_RAM':compressed(self.before),'final_private_RAM':compressed(bytes(self.u.mem_read(P,SIZE))),'initial_image_pages':[{'address':hex(pg),'bytes_hex':raw.hex()} for pg,raw in sorted(self.initial_pages.items())],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_effects':self.logical,'original_API_entries':self.entries,'original_API_returns':self.returns,'unfinished_API_entry_indices':self.active,'final_page_sha256':{hex(pg):sha256(bytes(self.u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)},'final_vectors':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))) for j in range(32)],'boundary':self.boundary,'output_guarded_region':{'address':hex(OUTPUT),'size_bytes':EXTENT,'bytes_hex':bytes(self.u.mem_read(OUTPUT,EXTENT)).hex()},'source_word_mutated_to_NOP':hex(self.mutate) if self.mutate else None,'native_formatter_executed':False}

def cases():
 out=[]
 for label,data in [('zero',bytes(16)),('full_byte',bytes([255])*16),('mixed',bytes(range(0,256,17)))]:
  for n in [0,1,2,17,36,37,38]:out.append({'label':label+'_capacity'+str(n),'UUID_bytes_hex':data.hex(),'capacity_bytes':n,'null_zero_capacity':n==0})
 return out
