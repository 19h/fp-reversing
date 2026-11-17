#!/usr/bin/env python3
"""Independent original main pointer-custody checkpoints and PAC projection.
Linear journal and RAM/page work. No new producer executor import.
"""
from unicorn import arm64_const as ar
import replay_kernel_boot_logging_handoff as B
import recover_kernel_main_pointer_signing as R
class Replay(B.Replay):
 def __init__(self,im,row):super().__init__(im,row);self.walk_entered=False;self.walk_returned=False;self.signer_entries=[]
 def code(self,u,a,n,d):
  self.finish()
  if self.seq==len(self.p['source_visits']):return super().code(u,a,n,d)
  if a==R.S.WALK:self.check_handoff_checkpoint(self.p['module_walker_entry_checkpoint']);assert not self.walk_entered;self.walk_entered=True
  if a==R.RETURN and self.walk_entered and not self.walk_returned:self.check_handoff_checkpoint(self.p['module_walker_return_checkpoint']);self.walk_returned=True
  if a==R.S.SIGN:self.signer_entries.append({'before_visit':self.seq,'PC':hex(a),'argument':hex(self.reg(0)),'return_PC':hex(self.reg(30)),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if R.S.WALK<=a<0xfffffe000c47ce2c or R.S.SIGN<=a<R.S.SIGN_END:
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in ['xpaci','pacia1716']:
    assert self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};event={'PC':hex(a),'kind':i.mnemonic,'scope':'original_main_module_pointer_signing','operands':i.op_str,'before_visit':self.seq,'system_before':dict(self.system),'system_after':dict(self.system),'X16':hex(self.reg(16)),'X17':hex(self.reg(17)),'logical_identity':True};assert event==self.p['logical_effects'][len(self.logical)];self.logical.append(event);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_effects_checked']+=1;self.counts['module_pointer_PAC_operands_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  out=super().run();assert self.walk_entered and self.walk_returned and self.signer_entries==self.p['original_module_signer_entries'] and not self.p['unfinished_module_walker'];out.update(original_module_signer_entries_checked=len(self.signer_entries),module_walker_checkpoints_checked=2);return out
