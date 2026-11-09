#!/usr/bin/env python3
"""Independent driver-entry/frame readback over fresh original A64 replay.
O(visits+effects), O(journals+private RAM); no probe dispatcher/native effects.
"""
from unicorn import arm64_const as ar
from replay_aes_command_pool import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.qi=0
 def code(self,u,a,n,d):
  self.finish()
  if self.qi<len(self.p['driver_quantum_frontiers']):
   e=self.p['driver_quantum_frontiers'][self.qi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    assert e['arguments2']==[hex(self.reg(j))for j in range(2)]and e['carrier144_hex']==bytes(u.mem_read(self.reg(1),144)).hex()and e['provider_busy_byte']==bytes(u.mem_read(0x6500010110,1)).hex()and e['provider_gate48_hex']==bytes(u.mem_read(0x6500011048,8)).hex()and e['pool_gate48_hex']==bytes(u.mem_read(0x650001c048,8)).hex();self.qi+=1;self.counts['driver_quantum_frontiers_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.qi==len(self.p['driver_quantum_frontiers']);return dict(self.counts)
