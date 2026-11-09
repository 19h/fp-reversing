#!/usr/bin/env python3
"""Independent original CPU/read/write replay with private TPIDR fixture.
O(visits) time, O(private RAM+journals) space. No probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):
  super().__init__(image,p);self.ia=p['logical_instruction_authentication'];self.ii=0;self.cuts=p['parser_entries'];self.ci=0
  for e in p['private_system_register_fixtures']:assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  if a==0xfffffe000c5e48a4:
   e=self.cuts[self.ci];self.ci+=1;assert e['source_visit_index']==self.seq and e['arguments5']==[hex(self.reg(j))for j in range(5)]and[self.reg(j)for j in range(5)]==[0x650000606c,0xfffffe000ca881a0,0xfffffe0007e6a01c,4,0];self.counts['startup_parser_arguments_checked']+=1
  if self.ii<len(self.ia)and self.ia[self.ii]['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   self.finish();e=self.ia[self.ii];self.ii+=1;v=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic==e['operation']and raw==self.image.k.read(a,4)and raw.hex()==v['bytes_hex'];target=self.reg(16 if i.mnemonic=='pacia'else 19);assert target==int(e['target'],16)==0xfffffe000c5e4f50 and self.reg(17)==int(e['modifier'],16)==0xba5;self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_instruction_auth_steps_checked']+=1
   if i.mnemonic=='blraa':u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
   else:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.ii==len(self.ia)and self.ci==len(self.cuts);return r
