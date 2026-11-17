#!/usr/bin/env python3
"""Continuous original scheduler bootstrap under two explicit tree inputs.
Linear journals/pages; inherited main fileset traversal may be quadratic.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
from probe_kernel_vm_mig import Probe as Core
from probe_kernel_tunable_batch_execution import complement,merge
import probe_kernel_platform_environment_execution as ENV
import probe_kernel_cpu_initialization_execution as B
import recover_kernel_scheduler_bootstrap_execution as R
class Probe(B.Probe):
 def __init__(self,im,kind='missing',mutate=None):
  super().__init__(im);self.scheduler_kind=kind;self.scheduler_mutate=mutate;self.scheduler_entry=None;self.scheduler_return=None;self.scheduler_frontier=None;self.scheduler_entries=[];self.scheduler_returns=[];self.scheduler_active=[];self.scheduler_e=json.loads(read(ROOT/(R.P+'_checks.json')))
  self.scheduler_regions=complement(R.REGIONS,self.regions);self.regions=merge(self.regions+self.scheduler_regions)
  for a,n in self.scheduler_regions:self.ensure(a,n)
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.scheduler_e['functions']]
  if kind!='missing':
   assert kind=='E';cfg={**self.c,'CPUs':[{'cluster-type':0x45}]};blob,nodes=ENV.serialize(ENV.fixture(cfg));self.fixture(ENV.TREE,bytes(max(len(self.blob),len(blob))));self.fixture(ENV.TREE,blob);self.blob,self.nodes=blob,nodes;self.c.update(CPUs=cfg['CPUs'],extent=len(blob),label='declared_E_type_to_scheduler');args=bytearray(self.u.mem_read(ENV.INPUT,1152));struct.pack_into('<I',args,0x68,len(blob));self.fixture(ENV.INPUT,bytes(args))
  self.before=bytes(self.u.mem_read(0x6500000000,1048576));self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'scheduler_regions'):row['scheduler_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.scheduler_regions]
  return row
 def code(self,u,a,n,d):
  self.flush()
  while self.scheduler_active and self.scheduler_entries[self.scheduler_active[-1]]['return_PC']==hex(a) and self.scheduler_entries[self.scheduler_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   j=self.scheduler_active.pop();self.scheduler_returns.append({'entry_index':j,'before_visit':len(self.visits),'X0':hex(self.reg(0))})
  if a==R.CALL:
   while self.cpu_active and self.cpu_entries[self.cpu_active[-1]]['return_PC']==hex(a) and self.cpu_entries[self.cpu_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
    j=self.cpu_active.pop();self.cpu_returns.append({'entry_index':j,'before_visit':len(self.visits),'X0':hex(self.reg(0))})
   self.cpu_return=self.full_snapshot(a);self.scheduler_entry=self.full_snapshot(a);self.scheduler_entry['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};self.mutate=self.scheduler_mutate;return Core.code(self,u,a,n,d)
  if a==R.STOP:self.scheduler_return=self.full_snapshot(a);return self.stop('original_scheduler_bootstrap_return_before_main_continuation')
  if self.scheduler_entry is not None:
   if a==R.PANIC:self.scheduler_frontier={'PC':hex(a),'kind':'original_diagnostic_entry','format_X0':hex(self.reg(0))};return self.stop('before_original_scheduler_diagnostic',self.scheduler_frontier)
   if not any(lo<=a<hi for lo,hi in self.allowed):self.scheduler_frontier={'PC':hex(a),'kind':'uncaptured_original_code'};return self.stop('before_unestablished_scheduler_subroutine',self.scheduler_frontier)
   if a in R.ADDITIONS:self.scheduler_active.append(len(self.scheduler_entries));self.scheduler_entries.append({'PC':hex(a),'before_visit':len(self.visits),'arguments6':[hex(self.reg(j)) for j in range(6)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30))})
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='autia':
    assert raw==self.image.k.read(a,4) and i.op_str=='x16, x17';self.logical.append({'PC':hex(a),'kind':'autia','scope':'original_scheduler_callout_pointer','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'X16':hex(self.reg(16)),'X17':hex(self.reg(17)),'logical_identity':True});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(scheduler_input_case=self.scheduler_kind,scheduler_input_property=None if self.scheduler_kind=='missing' else {'name':'cluster-type','scalar_u32':0x45,'declared_before_main':True},scheduler_entry_checkpoint=self.scheduler_entry,scheduler_return_checkpoint=self.scheduler_return,scheduler_frontier=self.scheduler_frontier,original_scheduler_entries=self.scheduler_entries,original_scheduler_returns=self.scheduler_returns,unfinished_scheduler_entry_indices=self.scheduler_active);return row
if __name__=='__main__':
 import sys
 from replay_kernel_early_logging_execution import publication_row
 kind=sys.argv[1] if len(sys.argv)>1 else 'missing';im=R.B.B.B.BootImage();row=Probe(im,kind).run();(ROOT/(R.P+'_'+kind+'_probe.json')).write_text(json.dumps(publication_row(row,im),indent=2)+'\n');print({'case':kind,'visits':len(row['source_visits']),'models':len(row['API_models']),'boundary':row['boundary']},flush=True)
