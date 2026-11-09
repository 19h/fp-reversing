#!/usr/bin/env python3
"""Fresh original A64 with remote queue/port/conversion/transport ABI frames.
O(visits+effects), O(journals+private RAM); no probe executor/native IPC.
"""
from replay_platform_iorpc import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.ri={k:0 for k in ['remote_frames','queue_lookup_frames','port_copy_frames','conversion_frames','transport_frames','release_frames','reply_cleanup_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.ri.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.ri[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if key=='remote_frames':assert e['rpc_address']==hex(self.reg(1))and e['rpc32_hex']==bytes(u.mem_read(self.reg(1),32)).hex()and e['packet_hex']==bytes(u.mem_read(int(e['message_address'],16),e['reply_capacity'])).hex()
   if key=='transport_frames':assert e['packet_hex']==bytes(u.mem_read(self.reg(0),self.p['rpc_frames'][0]['reply_capacity'])).hex()
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert all(j==len(self.p[k])for k,j in self.ri.items());return dict(self.counts)
