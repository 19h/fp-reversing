#!/usr/bin/env python3
"""Independent declared-return/callback/wakeup frame checks with fresh replay.
O(visits+effects), O(journals+RAM); no probe dispatcher or native operations.
"""
from replay_aes_provider_queue import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.sui=self.cbi=self.wui=0
 def code(self,u,a,n,d):
  self.finish()
  for key,index,kind in [('submission_return_frames','sui','submission_return_frames_checked'),('completion_callback_frames','cbi','completion_callback_frames_checked'),('completion_wakeup_frontiers','wui','completion_wakeup_frontiers_checked')]:
   j=getattr(self,index)
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   setattr(self,index,j+1)
   if key=='completion_wakeup_frontiers':assert e['arguments3']==[hex(self.reg(k))for k in range(3)]
   else:assert e['arguments2']==[hex(self.reg(k))for k in range(2)]
   assert e['carrier144_hex']==bytes(u.mem_read(0x6500031f00,144)).hex()
   if key=='completion_callback_frames':assert e['pool_head_hex']==bytes(u.mem_read(0x6500014010,8)).hex()
   self.counts[kind]+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.sui==len(self.p['submission_return_frames'])and self.cbi==len(self.p['completion_callback_frames'])and self.wui==len(self.p['completion_wakeup_frontiers']);return dict(self.counts)
