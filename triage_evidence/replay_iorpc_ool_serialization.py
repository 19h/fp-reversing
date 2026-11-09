#!/usr/bin/env python3
"""Fresh original A64 replay of serialization, VM ABI and parser-entry frames.
O(visits+effects), O(journals+private RAM). No probe executor/native VM/parser.
"""
from replay_iorpc_object_conversion import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p);self.si={k:0 for k in ['serialization_frames','serialization_records','serialization_VM_frames','SetProperties_handler_frames','serialization_parser_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.si.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.si[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if 'bytes_hex'in e:
    ptr,size=(self.reg(1),self.reg(2))if key=='serialization_records'else(self.reg(0),self.reg(1));assert bytes(u.mem_read(ptr,size)).hex()==e['bytes_hex'];self.counts['serialization_byte_frames_checked']+=1
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.si.items())
  for e in self.p['final_serialization_globals']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_serialization_globals_checked']+=1
  return dict(self.counts)
