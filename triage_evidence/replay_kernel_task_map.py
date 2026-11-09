#!/usr/bin/env python3
"""Independent original CPU replay with private TPIDR and logical data PAC.
O(visits) time, O(private RAM+journals) space. No probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):
  super().__init__(image,p);self.sign=p['logical_data_signing'];self.si=0
  for e in p['private_system_register_fixtures']:assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  if self.si<len(self.sign)and self.sign[self.si]['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   self.finish();e=self.sign[self.si];self.si+=1;v=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacda'and raw==self.image.k.read(a,4)and raw.hex()==v['bytes_hex']and self.reg(17)==int(e['pointer'],16)and self.reg(16)==int(e['modifier'],16);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.si==len(self.sign);return r
