#!/usr/bin/env python3
"""Fresh original constructor/cache/zero-check and notification CPU replay.
O(visits+RAM+effects), O(image+RAM+journals). No probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kernel_notification_send import Replay as Parent
P=0x6500000000;THREAD=P+0x2c000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.af=p['allocation_frames'];self.afi=0;self.sign=p['logical_data_signing'];self.si=0
 def code(self,u,a,n,d):
  self.finish()
  if self.afi<len(self.af):
   e=self.af[self.afi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments4']==[hex(self.reg(j))for j in range(4)]and e['cache64_hex']==bytes(u.mem_read(int(self.p['selected_cache_address'],16),64)).hex()and e['stats16_hex']==bytes(u.mem_read(int(self.p['selected_statistics_address'],16),16)).hex()and e['thread_nesting']==int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little');self.afi+=1;self.counts['original_allocation_and_cache_frames_checked']+=1
  if self.si<len(self.sign):
   e=self.sign[self.si]
   if e['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacda'and raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex']and e['pointer']==hex(self.reg(17))and e['modifier']==hex(self.reg(16));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.si+=1;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.afi==len(self.af)and self.si==len(self.sign)
  for a,k in[(P+0xb0000,'final_zone256_hex'),(int(self.p['selected_cache_address'],16),'final_cache64_hex'),(int(self.p['selected_statistics_address'],16),'final_statistics16_hex'),(P+0xb3000,'final_slots16_hex'),(P+0xb3100,'final_spare_slots16_hex'),(P+0xd0000,'final_raw_kmsg256_hex')]:b=bytes.fromhex(self.p[k]);assert bytes(self.u.mem_read(a,len(b)))==b
  assert bytes(self.u.mem_read(P+0xd0100,1)).hex()==self.p['raw_kmsg_guard_hex'];return dict(self.counts)
