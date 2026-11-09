#!/usr/bin/env python3
"""Independent original refill/fill/bitmap and outer allocation continuation.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from replay_kernel_zone_startup import Replay as Parent
from unicorn import arm64_const as ar
P=0x6500000000;THREAD=P+0x2c000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.ff=p['refill_frames'];self.fi=0
 def code(self,u,a,n,d):
  self.finish()
  if self.fi<len(self.ff):
   e=self.ff[self.fi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['zone192_hex']==bytes(u.mem_read(int(self.p['zone_address'],16),192)).hex()and e['cache64_hex']==bytes(u.mem_read(int(self.p['selected_cache_address'],16),64)).hex()and e['stats32_hex']==bytes(u.mem_read(int(self.p['selected_statistics_address'],16),32)).hex()and e['metadata16_hex']==bytes(u.mem_read(P+0xc0000,16)).hex()and e['bitmap8_hex']==bytes(u.mem_read(P+0xc1000,8)).hex()and e['thread_nesting']==int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little');self.fi+=1;self.counts['refill_fill_selection_frames_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert self.fi==len(self.ff);return dict(self.counts)
