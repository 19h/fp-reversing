#!/usr/bin/env python3
"""Independent scheduler checkpoints, helper edges and pointer projection.
Linear journal/page work; no scheduler producer executor import.
"""
from unicorn import arm64_const as ar
import replay_kernel_cpu_initialization_execution as B
import recover_kernel_scheduler_bootstrap_execution as R
class Replay(B.Replay):
 def __init__(self,im,row):
  super().__init__(im,row);self.scheduler_seen=False;self.scheduler_entries=[];self.scheduler_returns=[];self.scheduler_active=[]
 def code(self,u,a,n,d):
  self.finish()
  while self.scheduler_active and self.scheduler_entries[self.scheduler_active[-1]]['return_PC']==hex(a) and self.scheduler_entries[self.scheduler_active[-1]]['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   j=self.scheduler_active.pop();self.scheduler_returns.append({'entry_index':j,'before_visit':self.seq,'X0':hex(self.reg(0))})
  if a==R.CALL:self.check_handoff_checkpoint(self.p['scheduler_entry_checkpoint']);self.scheduler_seen=True
  if a==R.STOP:self.check_handoff_checkpoint(self.p['scheduler_return_checkpoint'])
  if self.seq==len(self.p['source_visits']):return super().code(u,a,n,d)
  if self.scheduler_seen:
   if a in R.ADDITIONS:self.scheduler_active.append(len(self.scheduler_entries));self.scheduler_entries.append({'PC':hex(a),'before_visit':self.seq,'arguments6':[hex(self.reg(j)) for j in range(6)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'return_PC':hex(self.reg(30))})
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='autia':
    assert i.op_str=='x16, x17' and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};event={'PC':hex(a),'kind':'autia','scope':'original_scheduler_callout_pointer','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'X16':hex(self.reg(16)),'X17':hex(self.reg(17)),'logical_identity':True};assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;self.counts['scheduler_AUTIA_operands_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  out=super().run();assert self.scheduler_seen and self.scheduler_entries==self.p['original_scheduler_entries'] and self.scheduler_returns==self.p['original_scheduler_returns'] and self.scheduler_active==self.p['unfinished_scheduler_entry_indices'];out.update(scheduler_entries_checked=len(self.scheduler_entries),scheduler_returns_checked=len(self.scheduler_returns),scheduler_entry_checkpoint_checked=1,scheduler_return_checkpoint_checked=int(self.p['scheduler_return_checkpoint'] is not None));return out
