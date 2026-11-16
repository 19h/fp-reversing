#!/usr/bin/env python3
"""Continuous original startup through post-lock timer or logging frontier.
Linear source visits and RAM; no new callback-result models or epochs.
"""
import json
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
import probe_kernel_lock_bootstrap_execution as B
import recover_kernel_longterm_bootstrap_execution as R

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,None);self.mutate=mutate;self.longterm_checkpoint=None;self.longterm_returned=False
  self.system_frontier=None;self.printf_calls=[];self.longterm_e=json.loads(read(ROOT/(R.P+'_checks.json')));self.timer_regions=B.B.B.B.complement(R.REGIONS,self.regions);self.regions=B.B.B.B.merge(self.regions+self.timer_regions)
  for a,n in self.timer_regions:
   raw=b''.join(image.logical_page(pg) for pg in range(a&~4095,(a+n+4095)&~4095,4096));self.image_fixture(a,raw[a&4095:(a&4095)+n],'Original logical timer/logging destinations before main; native lifetime unknown')
  for record in self.longterm_e['records']:self.ensure(int(record['address'],16),len(bytes.fromhex(record['bytes_hex'])))
  self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.longterm_e['functions']];self.initial_pages={pg:bytes(self.u.mem_read(pg,4096)) for pg in self.pages}
  if mutate is not None:self.ensure(mutate,4);self.u.mem_write(mutate,bytes.fromhex('1f2003d5'))
 def full_snapshot(self,a):
  row=super().full_snapshot(a)
  if hasattr(self,'timer_regions'):row['timer_image_globals']=[{'address':hex(p),'bytes_hex':bytes(self.u.mem_read(p,n)).hex()} for p,n in self.timer_regions]
  return row
 def code(self,u,a,n,d):
  if a==R.PRINTF:self.printf_calls.append({'PC':hex(a),'before_visit':len(self.visits),'format_X0':hex(self.reg(0)),'u64_vararg_at_SP':int.from_bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),8),'little'),'return_PC':hex(self.reg(30)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if a==R.CALL:
   self.flush();self.longterm_checkpoint=self.full_snapshot(a);self.longterm_checkpoint['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)};return B.B.Probe.code(self,u,a,n,d)
  if a==R.STOP:
   self.flush();self.longterm_returned=True;return self.stop('original_timer_return_before_CPU_initializer_BL')
  if self.longterm_checkpoint is not None and not any(lo<=a<hi for lo,hi in self.allowed):
   self.flush();return self.stop('before_unestablished_original_logging_subroutine')
  if self.longterm_checkpoint is not None:
   ins=next(self.image.k.cs.disasm(bytes(u.mem_read(a,4)),a))
   if ins.mnemonic=='mrs' and ins.op_str.split(', ')[1] not in self.system:
    self.flush();self.system_frontier={'PC':hex(a),'operands':ins.op_str,'register':ins.op_str.split(', ')[1]};return self.stop('before_unestablished_logging_system_register')
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(longterm_entry_checkpoint=self.longterm_checkpoint,longterm_initializer_returned=self.longterm_returned,logging_frontier_reached=not self.longterm_returned,logging_system_register_frontier=self.system_frontier,original_printf_calls=self.printf_calls,native_timer_executed=False);return row

def cases():return [B.cases()[0],{'label':'longterm_explicit_zero','CPUs':[{}],'boot_text':'longterm=0'},{'label':'longterm_nonzero_logging_frontier','CPUs':[{}],'boot_text':'longterm=1'}]
