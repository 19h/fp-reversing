#!/usr/bin/env python3
"""Fresh map-constructor/store CPU replay with independently derived model effects.
O(visits+RAM+effects), O(image+RAM+journals). No probe import or native effects.
"""
from replay_kernel_type2_copyout import Replay as Parent
ROOTPAGE=0xfffffe0003000000;KMAP=0x650002e000;EXTSTORE=0x65000b4000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.mci=0
 def code(self,u,a,n,d):
  self.finish()
  if self.mci<len(self.p['map_constructor_frames']):
   e=self.p['map_constructor_frames'][self.mci]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    self.mci+=1;assert e['arguments']==[hex(self.reg(j))for j in range(len(e['arguments']))]and e['map256_hex']==bytes(u.mem_read(KMAP,256)).hex()
    if e['root256_hex']is not None:assert e['root256_hex']==bytes(u.mem_read(ROOTPAGE,256)).hex()
    self.counts['map_constructor_frames_checked']+=1
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and self.seq==e['before_source_visit_index']and(e['symbol']in['declared_zeroed_map_or_root_allocation','declared_auxiliary_store_allocation','declared_store_memmove']or(a==0xfffffe000c6480c0 and self.reg(0)==0x650006a000)):
    self.ei+=1
    if e['symbol']=='declared_zeroed_map_or_root_allocation':
     assert a==0xfffffe000bd75c64 and self.reg(30)in[0xfffffe000bdc6f14,0xfffffe000bdc6f3c];ptr=KMAP if self.reg(30)==0xfffffe000bdc6f14 else ROOTPAGE;self.ensure(ptr,256);want=[(ptr,bytes(256))];result=ptr
    elif e['symbol']=='declared_auxiliary_store_allocation':assert a==0xfffffe000bcfefc8;want=[(EXTSTORE,bytes(64))];result=EXTSTORE
    elif e['symbol']=='declared_store_memmove':assert a==0xfffffe000c647f10;ptr,src,count=[self.reg(j)for j in range(3)];want=[(ptr,bytes(u.mem_read(src,count)))];result=ptr
    else:assert a==0xfffffe000c6480c0 and self.reg(0)==0x650006a000 and self.reg(1)==48 and e['symbol']=='header_bzero_model';want=[(self.reg(0),bytes(48))];result=0
    assert self.models[self.mi]['return_value']==hex(result)and len(e['patches'])==len(want)
    for patch,(ptr,b)in zip(e['patches'],want,strict=True):
     assert patch['address']==hex(ptr)and patch['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and patch['after_hex']==b.hex();u.mem_write(ptr,b);self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=len(b)
    self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert self.mci==len(self.p['map_constructor_frames']);return dict(self.counts)
