#!/usr/bin/env python3
"""Fresh original CPU replay of IORPC contexts, packet buffers and local frames.
O(visits+effects), O(journals+private RAM); no probe executor/native transport.
"""
import struct
from unicorn import arm64_const as ar
from replay_aes_platform_gate import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.rpi={k:0 for k in ['rpc_frames','dispatch_frames','invoke_frames','thunk_frames','thread_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.rpi.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.rpi[key]+=1
   if key=='thread_frames':assert e['TPIDR_EL1']==hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1))and e['saved_thread_word_hex']==bytes(u.mem_read(0x650001b378,8)).hex()
   else:
    assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
    if key!='thunk_frames':
     q=self.reg(0 if key=='invoke_frames'else 1);b=bytes(u.mem_read(q,32));message,reply,send,capacity,content=struct.unpack('<QQIIQ',b);assert e['rpc_address']==hex(q)and e['rpc32_hex']==b.hex()and[e['message_address'],e['reply_address'],e['send_size'],e['reply_capacity'],e['content_address']]==[hex(message),hex(reply),send,capacity,hex(content)]and e['packet_hex']==bytes(u.mem_read(message,capacity)).hex()
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.rpi.items())
  for e in self.p['final_rpc_buffers']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_RPC_buffers_checked']+=1
  return dict(self.counts)
