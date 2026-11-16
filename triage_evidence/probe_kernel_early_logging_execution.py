#!/usr/bin/env python3
"""Continuous original logging with explicit source-proved block projection.
Linear journal/source/RAM work; no DAIF value or callback return is supplied.
"""
import json
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_tunable_batch_execution import complement,merge
import probe_kernel_longterm_bootstrap_execution as B
import recover_kernel_early_logging_execution as R

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,None);self.mutate=mutate;self.join_checkpoint=None;self.joins=[];self.logging_entries=[];self.logging_returns=[];self.logging_active=[];self.character_calls=[]
  self.logging_e=json.loads(read(ROOT/(R.P+'_checks.json')));self.logging_regions=complement(R.REGIONS,self.regions);self.regions=merge(self.regions+self.logging_regions)
  for a,n in self.logging_regions:
   raw=b''.join(image.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));self.image_fixture(a,raw[a&4095:(a&4095)+n],'Original logical logging storage before main; native lifetime unknown')
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.logging_e['functions']];self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'logging_regions'):row['logging_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.logging_regions]
  return row
 def code(self,u,a,n,d):
  self.flush()
  if a==R.MRS:
   self.join_checkpoint=self.full_snapshot(a);self.join_checkpoint['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}
   phase=int.from_bytes(u.mem_read(R.C.PHASE,4),'little');assert phase<19 and 'daif' not in self.system and not self.joins
   for lo,hi in [(R.C.START,R.C.START+16),(R.C.SECOND,R.C.JOIN)]:assert bytes(u.mem_read(lo,hi-lo))==self.image.k.read(lo,hi-lo)
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4) and raw.hex()=='28423bd5'
   event={'PC':hex(a),'kind':'source_proved_early_logging_join','before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'proof_audit_sha256':self.logging_e['join_contract_audit_sha256'],'phase_address':hex(R.C.PHASE),'phase_bytes_hex':phase.to_bytes(4,'little').hex(),'phase_u32':phase,'join_PC':hex(R.JOIN),'contracted_original_words':9,'DAIF_value_supplied':False}
   self.joins.append(event);self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(8,0xfffffe0007f34000);self.set(9,phase);self.set(24,1);u.reg_write(ar.UC_ARM64_REG_NZCV,0x80000000);u.reg_write(ar.UC_ARM64_REG_PC,R.JOIN);return
  if self.joins and a==0xfffffe000c48fc98:
   return self.stop('before_unestablished_logging_configuration_dereference',{'pointer_slot':'0xfffffe0007f8b528','pointer_X8':hex(self.reg(8)),'field_offset_bytes':12,'read_width_bytes':4})
  while self.logging_active and self.logging_entries[self.logging_active[-1]]['return_PC']==hex(a) and self.logging_entries[self.logging_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   index=self.logging_active.pop();self.logging_returns.append({'entry_index':index,'before_visit':len(self.visits),'return_X0':hex(self.reg(0))})
  if self.joins and a in [R.C.B.LOCK,R.C.UNLOCK,R.TIMESTAMP,R.C.FORMAT,R.C.CORE,R.C.WAKE,R.C.B.PRINTF]:
   e={'PC':hex(a),'before_visit':len(self.visits),'arguments6':[hex(self.reg(j)) for j in range(6)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30)),'preemption_u32':int.from_bytes(u.mem_read(self.system['tpidr_el1']+0x1c8,4),'little')};self.logging_active.append(len(self.logging_entries));self.logging_entries.append(e)
  if self.joins and a==R.C.PUTC:self.character_calls.append({'PC':hex(a),'before_visit':len(self.visits),'character_u32':self.reg(0)&0xffffffff,'context':hex(self.reg(1)),'preemption_u32':int.from_bytes(u.mem_read(self.system['tpidr_el1']+0x1c8,4),'little'),'return_PC':hex(self.reg(30))})
  if self.joins and any(int(f['start'],16)<=a<int(f['end'],16) for f in self.logging_e['functions'] if f['start']==hex(R.C.CORE)):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='blraa':
    assert i.op_str=='x21, x17' and self.reg(21)==R.C.PUTC and self.reg(17)==0xae56
    event={'PC':hex(a),'kind':'blraa','scope':'original_formatter_character_callback','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(21)),'modifier_X17':hex(self.reg(17)),'argument_X0':hex(self.reg(0)),'context_X1':hex(self.reg(1))};self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(21));return
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(early_logging_join_checkpoint=self.join_checkpoint,proved_logging_joins=self.joins,original_logging_entries=self.logging_entries,original_logging_returns=self.logging_returns,unfinished_logging_entry_indices=self.logging_active,original_character_calls=self.character_calls);return row
def cases():return [{'label':'continuous_longterm_one_proved_logging_join','CPUs':[{}],'boot_text':'longterm=1'}]
