#!/usr/bin/env python3
"""Continuous main with declared initial boot-word precedence and source lookup.
Linear source/journal/page work. No mid-execution repair or new API result.
"""
from hashlib import sha256
from unicorn import arm64_const as ar
import probe_kernel_early_logging_execution as B
import recover_kernel_boot_logging_handoff as R
class Probe(B.Probe):
 def __init__(self,image,c=None,mutate=None):
  super().__init__(image,c or {**B.cases()[0],'label':'boot_words_to_longterm_logging'});self.mutate=mutate;self.handoff=[];self.consumer=None;self.lookup_entries=[];self.lookup_returns=[];self.helper_active=[];self.printf_return=None;self.logging_checkpoints=[]
  self.handoff_timer_regions=B.complement([(0xfffffe000ca921c8,16)],self.regions);self.regions=B.merge(self.regions+self.handoff_timer_regions)
  for a,n in self.handoff_timer_regions:
   raw=image.logical_page(a&~4095);self.image_fixture(a,raw[a&4095:(a&4095)+n],'Original timer-vector destination before main; nonzero threshold later executes its original store')
  for a,value in image.globals.items():
   self.ensure(a,8);before=bytes(self.u.mem_read(a,8));raw=value.to_bytes(8,'little');self.image_fixture(a,raw,'Returned boot word, exact digest-bound source execution; declared precedence before main');self.handoff.append({'address':hex(a),'prior_fixture_bytes_hex':before.hex(),'boot_bytes_hex':raw.hex()})
  self.allowed += [(R.LOOKUP,0xfffffe000c478fa4),(R.CONTAINS,0xfffffe000be76434),(R.CONSOLE,0xfffffe000c5e7534)]
  for a in [R.LOOKUP,R.CONTAINS,R.CONSOLE,R.FRONTIER]:self.ensure(a,4)
  self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'handoff_timer_regions'):row['handoff_timer_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.handoff_timer_regions]
  return row
 def code(self,u,a,n,d):
  self.flush()
  if a==B.R.MRS:
   if not self.joins:
    result=super().code(u,a,n,d);self.logging_checkpoints.append(self.join_checkpoint);return result
   c=self.full_snapshot(a);c['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};self.logging_checkpoints.append(c);phase=int.from_bytes(u.mem_read(B.R.C.PHASE,4),'little');assert phase<19 and 'daif' not in self.system
   for lo,hi in [(B.R.C.START,B.R.C.START+16),(B.R.C.SECOND,B.R.C.JOIN)]:assert bytes(u.mem_read(lo,hi-lo))==self.image.k.read(lo,hi-lo)
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4) and raw.hex()=='28423bd5';event={'PC':hex(a),'kind':'source_proved_early_logging_join','before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'proof_audit_sha256':self.logging_e['join_contract_audit_sha256'],'phase_address':hex(B.R.C.PHASE),'phase_bytes_hex':phase.to_bytes(4,'little').hex(),'phase_u32':phase,'join_PC':hex(B.R.JOIN),'contracted_original_words':9,'DAIF_value_supplied':False};self.joins.append(event);self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(8,0xfffffe0007f34000);self.set(9,phase);self.set(24,1);u.reg_write(ar.UC_ARM64_REG_NZCV,0x80000000);u.reg_write(ar.UC_ARM64_REG_PC,B.R.JOIN);return
  if self.mutate==R.FRONTIER and self.consumer is not None and a in [0xfffffe000c48fca4,0xfffffe000c48fd48]:return self.stop('control_header_gate_boundary')
  while self.helper_active and self.lookup_entries[self.helper_active[-1]]['return_PC']==hex(a) and self.lookup_entries[self.helper_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   index=self.helper_active.pop();self.lookup_returns.append({'entry_index':index,'before_visit':len(self.visits),'X0':hex(self.reg(0))})
   if self.mutate==0xfffffe000c478f68:return self.stop('control_lookup_return_boundary')
  if a in [R.LOOKUP,R.CONTAINS]:
   self.helper_active.append(len(self.lookup_entries));self.lookup_entries.append({'PC':hex(a),'before_visit':len(self.visits),'arguments2':[hex(self.reg(j)) for j in range(2)],'return_PC':hex(self.reg(30)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if self.printf_calls and a==int(self.printf_calls[0]['return_PC'],16):self.printf_return=self.full_snapshot(a)
  if a==R.FRONTIER:
   if self.consumer is None:self.consumer=self.full_snapshot(a);self.consumer['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}
   if a==self.mutate:
    self.visits.append({'pc':hex(a),'bytes_hex':'1f2003d5'});return
   return B.B.Probe.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(boot_word_initial_precedence=self.handoff,configuration_consumer_checkpoint=self.consumer,original_image_lookup_entries=self.lookup_entries,original_image_lookup_returns=self.lookup_returns,unfinished_image_lookup_entry_indices=self.helper_active,printf_return_checkpoint=self.printf_return,logging_join_checkpoints=self.logging_checkpoints);return row
