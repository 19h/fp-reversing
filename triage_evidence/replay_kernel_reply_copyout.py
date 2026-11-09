#!/usr/bin/env python3
"""Independent CPU/effect replay; every private effect rebuilt from live arguments.
O(visits+effect bytes) time; O(private map+journals) space. No probe import.
"""
import struct
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):
  super().__init__(image,p);self.effects=p['declared_effects'];self.ei=0;self.switches=0
  for e in p['private_system_register_fixtures']:assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  if self.ei<len(self.effects)and self.effects[self.ei]['pc']==hex(a)and self.effects[self.ei]['before_source_visit_index']==self.seq:
   self.finish();e=self.effects[self.ei];self.ei+=1;c=self.p['configuration'];want=[];P=0x6500000000
   if a==0xfffffe000bdc76b4:
    assert self.reg(0)==P+0x3000 and self.reg(1)==P+0x10000 and self.reg(2)==((c['extent']+16383)//16384)*16384 and self.reg(3)==0 and self.reg(4)==0x6000000000000000 and all(self.reg(j)==0 for j in [5,6,7]);assert e['stack_prefix12_hex']==bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex()==struct.pack('<3I',3,7,1).hex()
    if c['allocation_result']==0:want=[(self.reg(1),struct.pack('<Q',P+0x50000))]
   elif a==0xfffffe000be7798c:
    assert self.reg(0)==P+0x70000 and self.reg(1)==P+0x50000 and self.reg(2)==c['extent']
    if c['copy_result']==0:want=[(self.reg(1),bytes(u.mem_read(self.reg(0),self.reg(2))))]
   elif a==0xfffffe000c6480c0:assert self.reg(0)==P+0x68000 and self.reg(1)==48;want=[(self.reg(0),bytes(self.reg(1)))]
   elif a==0xfffffe000be63ea0:
    assert not c['same_map']and self.reg(0)==P+0x4000 and self.reg(1)==P+(0x3000 if self.switches==0 else 0x5000);self.switches+=1;want=[(self.reg(0)+0x428,struct.pack('<Q',self.reg(1)))]
   else:raise AssertionError(hex(a))
   assert len(want)==len(e['patches'])
   for (address,b),saved in zip(want,e['patches'],strict=True):
    assert saved['address']==hex(address)and saved['before_hex']==bytes(u.mem_read(address,len(b))).hex()and saved['after_hex']==b.hex();u.mem_write(address,b);self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=len(b)
   self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.ei==len(self.effects);return r
