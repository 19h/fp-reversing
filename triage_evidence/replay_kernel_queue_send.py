#!/usr/bin/env python3
"""Fresh source/effect replay with declared system register and logical PACDA.
O(visits+effects) time, O(one private map+journals) space. No probe reuse.
No native authentication, queue or scheduler effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):
  super().__init__(image,p);self.sign=p['logical_data_signing'];self.si=0;self.cuts={e['source_visit_index']:e for e in p['source_return_cuts']};self.ci=0
  for e in p['private_system_register_fixtures']:assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  if self.seq in self.cuts and a==int(self.cuts[self.seq]['pc'],16):assert self.reg(0)==int(self.cuts[self.seq]['X0'],16);self.ci+=1;self.counts['source_return_cuts_checked']+=1
  raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a))if a>=0xfffffe0000000000 else None
  if ins and ins.mnemonic=='pacda'and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   self.finish();e=self.p['source_visits'][self.seq];event=self.sign[self.si];self.si+=1;assert event['pc']==hex(a)and self.reg(17)==int(event['pointer'],16)and self.reg(16)==int(event['modifier'],16);assert raw.hex()==e['bytes_hex']and raw==self.image.k.read(a,4);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.si==len(self.sign)and self.ci==len(self.cuts);return r
