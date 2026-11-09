#!/usr/bin/env python3
"""Fresh source/read/write replay with explicit logical AUTDA semantics.
The inherited replayer does not reuse the probe. Readable guest pointer
fixtures already contain logical targets; no native PAC/tag is validated.
O(visits+effects) time, O(one private map+journals) space.
"""
from unicorn import arm64_const as ar
from replay_kernel_vm_mig import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):super().__init__(image,p);self.auth=p['logical_data_authentication'];self.ai=0
 def code(self,u,a,n,d):
  raw=bytes(u.mem_read(a,4));ins=next(self.image.k.cs.disasm(raw,a))if a>=0xfffffe0000000000 else None
  if ins and ins.mnemonic=='autda'and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   self.finish();e=self.p['source_visits'][self.seq];event=self.auth[self.ai];self.ai+=1;assert event['pc']==hex(a)and self.reg(16)==int(event['pointer'],16)and self.reg(17)==int(event['modifier'],16);assert e['bytes_hex']==raw.hex()and raw==self.image.k.read(a,4);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_data_auth_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.ai==len(self.auth);return r
