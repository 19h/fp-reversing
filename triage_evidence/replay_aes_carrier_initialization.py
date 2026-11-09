#!/usr/bin/env python3
"""Independent fresh original A64 replay and typed/constructor/counter frame checks.
O(visits+effects), O(journals+private RAM); no probe dispatcher/native effects.
"""
from replay_aes_command_pool import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.indices={k:0 for k in ['allocation_frames','backend_frontiers','constructor_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.indices.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.indices[key]+=1;args='arguments4'if key=='backend_frontiers'else'arguments2';assert e[args]==[hex(self.reg(k))for k in range(len(e[args]))]
   if key=='constructor_frames':assert e['before144_hex']==bytes(u.mem_read(self.reg(0),144)).hex()
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.indices.items());assert bytes(self.u.mem_read(0xfffffe000cb5b638,8)).hex()==self.p['final_counter_hex'];self.counts['final_allocation_counter_checked']+=1;return dict(self.counts)
