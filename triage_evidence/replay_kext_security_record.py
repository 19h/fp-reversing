#!/usr/bin/env python3
"""Independent original CPU replay with declared TPIDR and logical call edges.
O(visits+effects), O(private RAM+journals). No probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kernel_vm_mig import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):super().__init__(image,p);self.edges=p['logical_edges'];self.ei=0;self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(p['private_TPIDR_EL1'],16))
 def code(self,u,a,n,d):
  if self.ei<len(self.edges)and self.edges[self.ei]['pc']==hex(a)and self.seq==self.edges[self.ei]['visit']:
   self.finish();e=self.edges[self.ei];self.ei+=1;v=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4)and raw.hex()==v['bytes_hex'];i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic==e['kind']and i.mnemonic in ['braa','blraa'];target=self.reg(int(i.op_str.split(',')[0][1:]));assert target==int(e['target'],16)and self.reg(17)==int(e['modifier'],16);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_PAC_steps_checked']+=1;self.counts['logical_indirect_edges_checked']+=1
   if i.mnemonic=='blraa':u.reg_write(ar.UC_ARM64_REG_X30,a+4)
   u.reg_write(ar.UC_ARM64_REG_PC,target);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.ei==len(self.edges)
  for a,n,key in [(0x6500004000,152,'final_record152_hex'),(0x6500009000,160,'final_C160_hex')]:assert bytes(self.u.mem_read(a,n)).hex()==self.p[key]
  return r
