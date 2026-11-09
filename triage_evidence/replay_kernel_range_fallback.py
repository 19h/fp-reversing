#!/usr/bin/env python3
"""Fresh fallback/reservation-abort replay with argument-derived zeroing effects.
O(visits+RAM+effects), O(image+RAM+journals). No probe import or native effects.
"""
from replay_kernel_range_resolver import Replay as Parent
ROOTPAGE=0xfffffe0003000000;REC=0xfffffe00010000c0
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.fi={k:0 for k in ['fallback_frames','lower_allocator_return_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.fi.items()):
   if j==len(self.p[key]):continue
   e=self.p[key][j]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:self.fi[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))];self.counts[key+'_checked']+=1
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and self.seq==e['before_source_visit_index']and e['symbol']=='declared_store_or_record_zeroing':
    self.ei+=1;ptr,size=[self.reg(j)for j in range(2)];assert a==0xfffffe000c6480c0 and((ROOTPAGE<=ptr and ptr+size<=ROOTPAGE+256)or(ptr==REC and size==64))and self.models[self.mi]['return_value']=='0x0'and len(e['patches'])==1;patch=e['patches'][0];assert patch['address']==hex(ptr)and patch['before_hex']==bytes(u.mem_read(ptr,size)).hex()and patch['after_hex']=='00'*size;u.mem_write(ptr,bytes(size));self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=size;self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert all(j==len(self.p[k])for k,j in self.fi.items());return dict(self.counts)
