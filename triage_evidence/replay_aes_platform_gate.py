#!/usr/bin/env python3
"""Fresh independent original A64, typed cast and two-level platform ABI replay.
O(visits+effects), O(journals+private RAM); no probe executor/native effects.
"""
from replay_aes_hardware_job import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.extra={k:0 for k in ['cast_frames','property_frames','device_method_frames','controller_method_frames','clock_return_frames','trace_frames','device_enable_frames','AES_enable_frames']}
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.extra.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.extra[key]+=1
   if key=='clock_return_frames':assert e['raw_X0']==hex(self.reg(0))
   else:assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if key=='property_frames':self.ensure(self.reg(1),14);assert e['key14_hex']==bytes(u.mem_read(self.reg(1),14)).hex()
   self.counts[key+'_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert all(j==len(self.p[k])for k,j in self.extra.items())
  for e in self.p['final_environment_globals']:
   a=int(e['address'],16);n=len(e['bytes_hex'])//2;self.ensure(a,n);assert bytes(self.u.mem_read(a,n)).hex()==e['bytes_hex'];self.counts['final_environment_globals_checked']+=1
  return dict(self.counts)
