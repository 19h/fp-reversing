#!/usr/bin/env python3
"""Fresh original A64 parser/collection/callback/reconstructed-adapter replay.
O(visits+effects), O(journals+private RAM). No probe executor/native effects.
"""
from replay_iorpc_ool_serialization import Replay as Parent
D=0x6500090000;V=0x6500090100;PAIRS=0x6500091000;BYTES=0x6500092000
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p);self.bi={k:0 for k in ['binary_parser_frames','binary_parser_allocation_frames','binary_parser_symbol_frames','binary_parser_reference_frames','binary_parser_handler_frames','binary_parser_filter_frames','binary_parser_return_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.bi.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.bi[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if 'bytes_hex'in e:assert e['bytes_hex']==bytes(u.mem_read(self.reg(0),self.reg(1))).hex()
   if 'string_hex'in e:assert bytes(u.mem_read(self.reg(0),len(e['string_hex'])//2+1)).hex()==e['string_hex']+'00'
   if 'dictionary64_hex'in e:assert e['dictionary64_hex']==bytes(u.mem_read(self.reg(1),64)).hex()and e['pair16_hex']==bytes(u.mem_read(PAIRS,16)).hex()and e['data64_hex']==bytes(u.mem_read(V,64)).hex()
   if 'payload_hex'in e:assert e['payload_hex']==bytes(u.mem_read(BYTES,int.from_bytes(bytes(u.mem_read(V+0xc,4)),'little'))).hex()
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert all(j==len(self.p[k])for k,j in self.bi.items());return dict(self.counts)
