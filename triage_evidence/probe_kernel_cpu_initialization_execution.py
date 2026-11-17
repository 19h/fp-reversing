#!/usr/bin/env python3
"""Original continuous CPU/cache/context execution with declared register inputs.
Linear journals/pages; inherited main includes quadratic fileset rescans.
"""
import json
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as Core
from probe_kernel_tunable_batch_execution import complement,merge
import probe_kernel_main_pointer_signing as B
import recover_kernel_cpu_initialization_execution as R
class Probe(B.Probe):
 def __init__(self,im,mutate=None):
  super().__init__(im);self.cpu_mutate=mutate;self.cpu_e=json.loads(read(ROOT/(R.P+'_checks.json')));self.system.update(R.PROFILE['registers']);self.profile=dict(R.PROFILE);self.cpu_checkpoint=None;self.cpu_return=None;self.cpu_entries=[];self.cpu_returns=[];self.cpu_active=[];self.hardware_reads=[];self.frontier=None
  self.cpu_regions=complement(R.REGIONS,self.regions);self.regions=merge(self.regions+self.cpu_regions)
  for a,n in self.cpu_regions:self.ensure(a,n)
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.cpu_e['functions']]
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'cpu_regions'):row['CPU_initializer_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.cpu_regions]
  return row
 def code(self,u,a,n,d):
  self.flush()
  while self.cpu_active and self.cpu_entries[self.cpu_active[-1]]['return_PC']==hex(a) and self.cpu_entries[self.cpu_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   j=self.cpu_active.pop();self.cpu_returns.append({'entry_index':j,'before_visit':len(self.visits),'X0':hex(self.reg(0))})
  if a==R.STOP:
   self.cpu_return=self.full_snapshot(a);return self.stop('original_CPU_initializer_return_before_scheduler_initializer_BL')
  if a==R.CALL:
   self.mutate=self.cpu_mutate;self.cpu_checkpoint=self.full_snapshot(a);self.cpu_checkpoint['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};return Core.code(self,u,a,n,d)
  if a==B.B.B.R.MRS:
   phase=int.from_bytes(u.mem_read(B.B.B.R.C.PHASE,4),'little');assert phase<19;c=self.full_snapshot(a);c['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};self.logging_checkpoints.append(c)
   if not self.joins:self.join_checkpoint=c
   for lo,hi in [(B.B.B.R.C.START,B.B.B.R.C.START+16),(B.B.B.R.C.SECOND,B.B.B.R.C.JOIN)]:assert bytes(u.mem_read(lo,hi-lo))==self.image.k.read(lo,hi-lo)
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4) and raw.hex()=='28423bd5';event={'PC':hex(a),'kind':'source_proved_early_logging_join','before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'proof_audit_sha256':self.logging_e['join_contract_audit_sha256'],'phase_address':hex(B.B.B.R.C.PHASE),'phase_bytes_hex':phase.to_bytes(4,'little').hex(),'phase_u32':phase,'join_PC':hex(B.B.B.R.JOIN),'contracted_original_words':9,'DAIF_value_supplied':False};self.joins.append(event);self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(8,0xfffffe0007f34000);self.set(9,phase);self.set(24,1);u.reg_write(ar.UC_ARM64_REG_NZCV,0x80000000);u.reg_write(ar.UC_ARM64_REG_PC,B.B.B.R.JOIN);return
  if a in [R.INIT,*R.ADDITIONS]:self.cpu_active.append(len(self.cpu_entries));self.cpu_entries.append({'PC':hex(a),'before_visit':len(self.visits),'arguments6':[hex(self.reg(j)) for j in range(6)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30))})
  if self.cpu_checkpoint is not None:
   if not any(lo<=a<hi for lo,hi in self.allowed):self.frontier={'PC':hex(a),'kind':'uncaptured_original_code'};return self.stop('before_unestablished_CPU_subroutine',self.frontier)
   raw=bytes(u.mem_read(a,4));decoded=list(self.image.k.cs.disasm(raw,a))
   if not decoded:self.frontier={'PC':hex(a),'kind':'opaque_original_word','bytes_hex':raw.hex()};return self.stop('before_opaque_CPU_instruction',self.frontier)
   i=decoded[0]
   if i.mnemonic in ['mrs','msr','isb','dsb','dmb']:
    assert raw==(bytes.fromhex('1f2003d5') if a==self.mutate else self.image.k.read(a,4));event={'PC':hex(a),'kind':i.mnemonic,'operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system)}
    if i.mnemonic=='mrs':
     reg,name=i.op_str.split(', ')
     if name=='ccsidr_el1':
      selector=str(self.system['csselr_el1'])
      if selector not in self.profile['CCSIDR_by_CSSELR']:self.frontier={'PC':hex(a),'kind':'undeclared_CCSIDR_bank','CSSELR':selector};return self.stop('before_undeclared_CPU_register_read',self.frontier)
      value=self.profile['CCSIDR_by_CSSELR'][selector];event['bank_selector']=int(selector)
     elif name in self.system:value=self.system[name]
     else:self.frontier={'PC':hex(a),'kind':'undeclared_system_register','register':name};return self.stop('before_undeclared_CPU_register_read',self.frontier)
     self.set(int(reg[1:]),value);event['read_value']=hex(value);self.hardware_reads.append({'PC':hex(a),'before_visit':len(self.visits),'register':name,'value':hex(value),**({'CSSELR':event['bank_selector']} if 'bank_selector' in event else {})})
    elif i.mnemonic=='msr':
     name,reg=i.op_str.split(', ')
     if reg.startswith('#'):
      immediate=int(reg[1:],0);assert name in ['daifset','daifclr'];self.system['daif']=(self.system['daif']|(immediate<<6)) if name=='daifset' else (self.system['daif']&~(immediate<<6))
     else:self.system[name]=0 if reg=='xzr' else self.reg(int(reg[1:]))
    event['system_after']=dict(self.system);self.logical.append(event);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
   if i.mnemonic in ['brk','svc','hvc','smc','wfe']:self.frontier={'PC':hex(a),'kind':i.mnemonic,'operands':i.op_str};return self.stop('before_unexecuted_CPU_architectural_effect',self.frontier)
   if a==self.mutate:self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row['initial_system']={**row['initial_system'],**R.PROFILE['registers']};row.update(architectural_input_profile=self.profile,CPU_entry_checkpoint=self.cpu_checkpoint,CPU_return_checkpoint=self.cpu_return,original_CPU_entries=self.cpu_entries,original_CPU_returns=self.cpu_returns,unfinished_CPU_entry_indices=self.cpu_active,architectural_register_reads=self.hardware_reads,CPU_frontier=self.frontier);return row
if __name__=='__main__':
 im=R.B.B.BootImage();row=Probe(im).run();from replay_kernel_early_logging_execution import publication_row
 (ROOT/(R.P+'_probe.json')).write_text(json.dumps(publication_row(row,im),indent=2)+'\n');print({'visits':len(row['source_visits']),'models':len(row['API_models']),'boundary':row['boundary']},flush=True)
