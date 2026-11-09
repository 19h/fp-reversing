#!/usr/bin/env python3
"""Fresh original A64 and hardware-pool/factory/options/global frame verification.
O(visits+effects), O(journals+private RAM); no probe executor or native DMA.
"""
from replay_workloop_gate_attachment import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.indices={k:0 for k in ['DMA_factory_frames','DMA_options_frames','inner_pool_frames','job_base_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.indices.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.indices[key]+=1;args='arguments8'if key=='DMA_factory_frames'else'arguments6'if key=='DMA_options_frames'else'arguments5'if key=='inner_pool_frames'else'arguments2';assert e[args]==[hex(self.reg(k))for k in range(len(e[args]))]
   if key=='DMA_options_frames':assert e['options40_hex']==bytes(u.mem_read(self.reg(2),40)).hex()
   if key=='inner_pool_frames':assert e['gate48_hex']==bytes(u.mem_read(0x6500026048,8)).hex()
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.indices.items())
  for e in self.p['final_source_globals']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_source_globals_checked']+=1
  return dict(self.counts)
