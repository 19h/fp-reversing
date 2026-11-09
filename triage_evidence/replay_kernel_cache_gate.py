#!/usr/bin/env python3
"""Independent original publication/policy/lock/cursor and allocator CPU replay.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from replay_kernel_zone_startup import Replay as Parent
P=0x6500000000;THREAD=P+0x2c000;GATE=0xfffffe000ca92380
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p);self.gf=p['gate_policy_frames'];self.gi=0;self.ensure(GATE)
  for e in p['final_image_globals']:self.ensure(int(e['address'],16),len(e['bytes_hex'])//2)
 def code(self,u,a,n,d):
  self.finish()
  if self.gi<len(self.gf):
   e=self.gf[self.gi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['zone192_hex']==bytes(u.mem_read(int(self.p['zone_address'],16),192)).hex()and e['statistics32_hex']==bytes(u.mem_read(int(self.p['selected_statistics_address'],16),32)).hex()and e['gate_u8']==int.from_bytes(bytes(u.mem_read(GATE,1)),'little')and e['thread_nesting']==int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little');self.gi+=1;self.counts['gate_policy_and_allocation_frames_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert self.gi==len(self.gf);return dict(self.counts)
