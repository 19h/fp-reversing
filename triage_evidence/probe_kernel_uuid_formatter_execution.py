#!/usr/bin/env python3
"""Continuous original startup through UUID formatter and phase-one return.
Linear visits/journals/mapped bytes. No new callback-result models.
"""
import json,struct
from hashlib import sha256
from unicorn import arm64_const as ar
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read
import probe_kernel_tunable_batch_execution as B
from probe_kernel_vm_mig import Probe as Core
import recover_kernel_uuid_formatter_execution as R
NEW_APIS=[R.FORMAT,R.EMIT,R.ENGINE]

class Probe(B.Probe):
 def __init__(self,image,c,mutate=None):
  super().__init__(image,c,mutate);self.e=json.loads(read(ROOT/(R.P+'_checks.json')));self.allowed=[(int(f['start'],16),int(f['end'],16)) for f in self.e['functions']];self.formatter_boundary=None;self.formatter_return=None;self.phase_two_boundary=None
 def outputs(self,target,arg):
  extra={R.IMAGE:[(0xfffffe000cb51120,8),(0xfffffe000cb2a1a0,37),(0xfffffe000caceea8,4),(0xfffffe0007f8b5ec,4),(0xfffffe0007e5ca28,4)],R.PERCPU:[(arg+0x10,8)],R.STACK:[(0xfffffe0007f30770,8),(0xfffffe0007e64500,16)],R.CAPABILITY:[(0xfffffe0007e62bc8,2)],R.FLAGS:[(0xfffffe0007f18be0,4)],R.PLATFORM:[(0xfffffe0007f8b640,1)],R.NOOP:[]}
  return extra[target] if target in extra else super().outputs(target,arg)
 def code(self,u,a,n,d):
  self.flush()
  while self.active and self.entries[self.active[-1]]['return_PC']==hex(a) and self.entries[self.active[-1]]['entry_SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP)):
   self.returns.append({'entry_index':self.active.pop(),'before_visit':len(self.visits),'return_value':hex(self.reg(0))})
  if a==R.B.STOP:
   assert self.formatter_boundary is None;self.formatter_boundary=self.full_snapshot(a);self.formatter_boundary['mapped_page_sha256']={hex(pg):sha256(bytes(u.mem_read(pg,4096))).hexdigest() for pg in sorted(self.pages)}
   return B.B.Probe.code(self,u,a,n,d)
  if a==R.B.STOP+4:self.formatter_return=self.full_snapshot(a)
  if a==R.PHASE2_CALL:
   cursor=int.from_bytes(u.mem_read(R.B.B.CURSOR,8),'little');phase,rank,target,arg=struct.unpack('<IIQQ',u.mem_read(cursor,24))
   if phase!=1:
    self.phase_two_boundary={'cursor':hex(cursor),'phase_u32':phase,'rank_u32':rank,'target':hex(target),'argument':hex(arg)};return self.stop('before_first_phase_two_callback_BLRAA')
  raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
  if R.ENGINE<=a<0xfffffe000bd15408 and i.mnemonic=='blraa':
   assert raw==self.image.k.read(a,4) and i.op_str=='x21, x17' and self.reg(21)==R.EMIT and self.reg(17)==0xae56
   self.logical.append({'PC':hex(a),'kind':'blraa','scope':'original_formatter_byte_output','operands':i.op_str,'before_visit':len(self.visits),'system_before':dict(self.system),'system_after':dict(self.system),'target':hex(self.reg(21)),'modifier_X17':hex(self.reg(17)),'character_W0':hex(self.reg(0)&0xffffffff),'context_X1':hex(self.reg(1))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,R.EMIT);return
  if a in NEW_APIS:
   self.active.append(len(self.entries));self.entries.append({'PC':hex(a),'entry_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'arguments6':[hex(self.reg(j)) for j in range(6)],'return_PC':hex(self.reg(30)),'before_visit':len(self.visits)})
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(formatter_call_boundary=self.formatter_boundary,formatter_return_checkpoint=self.formatter_return,phase_two_dispatch_boundary=self.phase_two_boundary)
  for key in R.TRUE:row.pop(key,None)
  return {**row,**{n:False for n in R.FALSE},'UUID_output_produced':self.formatter_return is not None,'all_phase_one_callbacks_executed':len(self.callback_returns)==392}

def cases():return B.cases()+[{'label':'stack_rounding_and_debugger_name_option','CPUs':[{}],'boot_text':'kernel_stack_pages=3 kdp_match_name=probe'}]
