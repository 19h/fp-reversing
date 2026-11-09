#!/usr/bin/env python3
"""Independent pool/action/status/sleep-frame readback over fresh A64 replay.
O(visits+effects), O(journals+private RAM); no probe dispatcher/native effects.
"""
from unicorn import arm64_const as ar
from replay_workloop_gate_attachment import Replay as Parent
PGATE=0x650001c000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.pfi=self.psi=self.sfi=0
 def code(self,u,a,n,d):
  self.finish()
  if self.pfi<len(self.p['pool_frames']):
   e=self.p['pool_frames'][self.pfi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['gate48_hex']==bytes(u.mem_read(PGATE+0x48,8)).hex();self.pfi+=1;self.counts['pool_action_frames_checked']+=1
  if self.psi<len(self.p['pool_action_statuses']):
   e=self.p['pool_action_statuses'][self.psi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    assert self.reg(21)==PGATE and e['raw_X0']==hex(self.reg(0));self.psi+=1;self.counts['pool_action_statuses_checked']+=1
  if self.sfi<len(self.p['pool_sleep_frontiers']):
   e=self.p['pool_sleep_frontiers'][self.sfi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    assert e['arguments3']==[hex(self.reg(j))for j in range(3)]and e['gate48_hex']==bytes(u.mem_read(PGATE+0x48,8)).hex();self.sfi+=1;self.counts['pool_sleep_frontiers_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.pfi==len(self.p['pool_frames'])and self.psi==len(self.p['pool_action_statuses'])and self.sfi==len(self.p['pool_sleep_frontiers']);return dict(self.counts)
