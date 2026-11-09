#!/usr/bin/env python3
"""Fresh CPU replay with checked namespace/VM model outputs and payload effects.
O(visits+effects) time, O(one private map+journals) space. No probe reuse.
"""
import struct
from unicorn import arm64_const as ar
from replay_kernel_receive_delivery import Replay as Parent
P=0x6500000000;OOL=P+0x70000;ENTRY=P+0x74000
class Replay(Parent):
 def __init__(self,image,p):super().__init__(image,p);self.effects=p['bridge_effects'];self.effect_index=0
 def code(self,u,a,n,d):
  if self.effect_index<len(self.effects)and a==int(self.effects[self.effect_index]['pc'],16)and self.seq==self.effects[self.effect_index]['before_source_visit_index']:
   self.finish();e=self.effects[self.effect_index];self.effect_index+=1;args=[self.reg(j)for j in range(6)];assert [hex(x)for x in args]==e['arguments6'];cfg=self.p['configuration'];patches=[];status=e['return_value'];payload=b'/tmp/fp'+b'A'*(cfg['length']-8)+b'\0'+bytes(cfg['copy_extent']-cfg['length'])
   if e['symbol']=='reply_name_entry_model':patches=[(args[2],struct.pack('<I',0x203)),(args[3],struct.pack('<Q',ENTRY))]
   elif e['symbol']=='VM_receiver_allocate_model'and status==0:patches=[(args[1],struct.pack('<Q',OOL))]
   elif e['symbol']in ['VM_copyout_model','VM_overwrite_model']and status==0:
    assert args[3]==len(payload)
    if e['symbol']=='VM_copyout_model':patches=[(args[1],struct.pack('<Q',OOL)),(OOL,payload)]
    else:patches=[(args[1],payload)]
   assert len(patches)==len(e['patches'])
   for (address,data),patch in zip(patches,e['patches'],strict=True):assert hex(address)==patch['address']and data.hex()==patch['after_hex']and bytes(u.mem_read(address,len(data))).hex()==patch['before_hex'];u.mem_write(address,data);self.counts['declared_namespace_VM_patch_bytes_checked']+=len(data)
   assert int(self.models[self.mi]['return_value'],16)==status
   if 'second_return_register'in e:assert self.models[self.mi]['after_registers31'][1]==e['second_return_register']
   self.counts['namespace_VM_effect_models_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.effect_index==len(self.effects);return r
