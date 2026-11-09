#!/usr/bin/env python3
"""Independent type2 consumer CPU replay and argument-derived resolver effect.
O(visits+RAM+effects), O(image+RAM+journals). No probe import or native effects.
"""
from replay_kernel_vm_entry_copy import Replay as Parent
DEST=0x6500030000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.tci=0
 def code(self,u,a,n,d):
  self.finish()
  if self.tci<len(self.p['type2_consumer_frames']):
   e=self.p['type2_consumer_frames'][self.tci]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    self.tci+=1;assert e['arguments']==[hex(self.reg(j))for j in range(len(e['arguments']))];assert e['new_entry64_hex']==bytes(u.mem_read(0xfffffe0001000040,64)).hex()and e['copy_header48_hex']==bytes(u.mem_read(0x6500068000,48)).hex();self.counts['type2_consumer_frames_checked']+=1
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and self.seq==e['before_source_visit_index']and a==0xfffffe000bdde9ac:
    self.ei+=1;assert e['symbol']=='declared_type2_destination_resolver';result=int(self.models[self.mi]['return_value'],16);wanted=[]if result else[(self.reg(7),DEST.to_bytes(8,'little'))];assert len(e['patches'])==len(wanted)
    for patch,(ptr,b)in zip(e['patches'],wanted,strict=True):
     assert patch['address']==hex(ptr)and patch['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and patch['after_hex']==b.hex();u.mem_write(ptr,b);self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=len(b)
    self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert self.tci==len(self.p['type2_consumer_frames']);return dict(self.counts)
