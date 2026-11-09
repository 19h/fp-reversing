#!/usr/bin/env python3
"""Independent fresh source replay, including maintenance frames and PACIZA.
O(visits+effects), O(journals+private RAM); no probe dispatcher reuse/native effects.
"""
from unicorn import arm64_const as ar
from replay_aes_command_gate import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.mfi=0;self.sri=0;self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(p['initial_TPIDR_EL1'],16))
 def code(self,u,a,n,d):
  self.finish()
  if a==0xfffffe000c51a398:
   e=self.p['system_context_reads'][self.sri];self.sri+=1;assert e=={'pc':hex(a),'source_visit_index':self.seq,'TPIDR_EL1':hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1))};self.counts['emulated_system_context_reads_checked']+=1
  if self.mfi<len(self.p['maintenance_frames']):
   e=self.p['maintenance_frames'][self.mfi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['inner_gate48_hex']==bytes(u.mem_read(0x6500018048,8)).hex()and e['return_pc']==hex(self.reg(30));self.mfi+=1;self.counts['maintenance_frames_checked']+=1
  if a in [0xfffffe000c51a718,0xfffffe000c51a74c,0xfffffe000c51a814,0xfffffe000c51a848]:
   e=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));assert e=={'pc':hex(a),'bytes_hex':raw.hex()}and raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));assert(i.mnemonic,i.op_str)==('paciza','x16');self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;r=self.p['logical_authentication'][self.ai];self.ai+=1;assert r=={'pc':hex(a),'source_visit_index':self.seq-1,'mnemonic':i.mnemonic,'operands':i.op_str,'registers18':[hex(self.reg(j))for j in range(18)]};self.counts['logical_authentication_steps_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.mfi==len(self.p['maintenance_frames'])and self.sri==len(self.p['system_context_reads']);return dict(self.counts)
