#!/usr/bin/env python3
"""Fresh original converter/registry CPU replay and field/frame verification.
O(visits+effects), O(journals+private RAM); no probe executor/native registry.
"""
from replay_iorpc_remote import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.oi={k:0 for k in ['object_conversion_frames','object_reference_frames','port_lock_frames','object_allocation_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.oi.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.oi[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))];self.counts[key+'_checked']+=1
  if self.ri['conversion_frames']<len(self.p['conversion_frames']):
   e=self.p['conversion_frames'][self.ri['conversion_frames']]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']and'packet_hex'in e:assert e['packet_hex']==bytes(u.mem_read(self.reg(1),len(e['packet_hex'])//2)).hex();self.counts['conversion_packet_frames_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.oi.items())
  for e in self.p['final_registry_globals']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_registry_globals_checked']+=1
  return dict(self.counts)
