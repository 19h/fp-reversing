#!/usr/bin/env python3
"""Fresh original range/cache/bitmap/store CPU and effect replay.
O(visits+RAM+effects), O(image+RAM+journals). No probe import/native effects.
"""
from replay_kernel_map_store_init import Replay as Parent
REC=0xfffffe00010000c0
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.ri={k:0 for k in ['range_allocator_frames','range_result_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.ri.items()):
   if j==len(self.p[key]):continue
   e=self.p[key][j]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    self.ri[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
    if 'out_pair16_hex'in e:assert e['out_pair16_hex']==bytes(u.mem_read(int(e['out_address'],16),16)).hex()and e['record32_hex']==bytes(u.mem_read(REC,32)).hex()
    self.counts[key+'_checked']+=1
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and self.seq==e['before_source_visit_index']and e['symbol']=='declared_zeroed_range_record_allocation':
    self.ei+=1;assert a==0xfffffe000bd75c64 and self.reg(30)==0xfffffe000bddef60 and self.models[self.mi]['return_value']==hex(REC)and len(e['patches'])==1;patch=e['patches'][0];assert patch['address']==hex(REC)and patch['before_hex']==bytes(u.mem_read(REC,64)).hex()and patch['after_hex']=='00'*64;u.mem_write(REC,bytes(64));self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=64;self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert all(j==len(self.p[k])for k,j in self.ri.items());return dict(self.counts)
