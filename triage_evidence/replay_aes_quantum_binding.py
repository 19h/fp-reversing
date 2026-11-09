#!/usr/bin/env python3
"""Fresh independent original A64 with carrier/job, range and segment frames.
O(visits+effects), O(journals+private RAM); no probe executor or native device.
"""
from replay_aes_hardware_job import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.extra={k:0 for k in ['quantum_calls','enable_calls','configuration_calls','transfer_calls','binding_calls','cache_operation_calls','clear_calls','segment_calls','effect_frontiers']};self.pfi=self.psi=0
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.extra.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.extra[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]and e['carrier144_hex']==bytes(u.mem_read(0x6500031f00,144)).hex()and e['job64_hex']==bytes(u.mem_read(0x6500041f00,64)).hex()
   if key=='segment_calls':assert e['input_offset']==int.from_bytes(bytes(u.mem_read(self.reg(1),8)),'little')and e['input_count']==int.from_bytes(bytes(u.mem_read(self.reg(3),4)),'little')
   self.counts[key+'_checked']+=1
  if self.pfi<len(self.p['pool_frames']):
   e=self.p['pool_frames'][self.pfi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:self.pfi+=1;assert e['arguments5']==[hex(self.reg(k))for k in range(5)]and e['gate48_hex']==bytes(u.mem_read(0x650001c048,8)).hex();self.counts['outer_pool_frames_checked']+=1
  if self.psi<len(self.p['pool_action_statuses']):
   e=self.p['pool_action_statuses'][self.psi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:self.psi+=1;assert self.reg(21)==0x650001c000 and e['raw_X0']==hex(self.reg(0));self.counts['outer_pool_action_statuses_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.extra.items())and self.pfi==len(self.p['pool_frames'])and self.psi==len(self.p['pool_action_statuses']);return dict(self.counts)
