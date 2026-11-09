#!/usr/bin/env python3
"""Fresh independent A64 replay with sleep/wakeup/saved-stack context oracles.
O(visits+effects), O(journals+private RAM); no probe executor/native scheduling.
"""
from unicorn import arm64_const as ar
from replay_aes_provider_queue import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.indices={k:0 for k in ['submission_frames','kernel_sleep_frames','kernel_wakeup_frames','wake_count_frames']};self.ssi=0
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.indices.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.indices[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]and e['lock_owner_hex']==bytes(u.mem_read(0x650001a018,8)).hex()and e['lock_depth_hex']==bytes(u.mem_read(0x650001a020,4)).hex()and e['carrier144_hex']==bytes(u.mem_read(0x6500031f00,144)).hex();self.counts[key+'_checked']+=1
  if a==0xfffffe000c519b38:
   e=self.p['resume_system_context_reads'][self.ssi];self.ssi+=1;assert e=={'pc':hex(a),'source_visit_index':self.seq,'TPIDR_EL1':hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1))};self.counts['resume_emulated_system_context_reads_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.indices.items())and self.ssi==len(self.p['resume_system_context_reads'])
  if self.p['suspended_stack']:
   e=self.p['suspended_stack'];assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['source_suspended_stack_checked']+=1;self.counts['suspended_stack_bytes_checked']+=len(e['bytes_hex'])//2
  return dict(self.counts)
