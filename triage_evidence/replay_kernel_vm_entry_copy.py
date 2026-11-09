#!/usr/bin/env python3
"""Fresh original entry-copy/list/discard replay with held context restoration.
O(visits+RAM+effects), O(image+RAM+journals). No probe import/native effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_vm_range_cursor import Replay as Parent
from replay_rpc502_vm_handoff import decode
NEW=0xfffffe0001000040
class Replay(Parent):
 def __init__(self,im,p):
  q=dict(p)
  if p['initial_state_transfer']is not None:q['initial_private_fixtures']=[{'address':'0x6500000000','bytes_hex':decode(p['initial_state_transfer']).hex()}]+p['initial_private_fixtures']
  super().__init__(im,q);self.ec={k:0 for k in ['entry_copy_frames','entry_copy_return_frames']}
  if p['entry_Q_registers32']is not None:
   for j,v in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
 def code(self,u,a,n,d):
  self.finish()
  for key,j in list(self.ec.items()):
   if j>=len(self.p[key]):continue
   e=self.p[key][j]
   if a!=int(e['pc'],16)or self.seq!=e['before_source_visit_index']:continue
   self.ec[key]+=1;assert e['arguments']==[hex(self.reg(k))for k in range(len(e['arguments']))]
   if 'new_entry64_hex'in e:assert e['new_entry64_hex']==bytes(u.mem_read(NEW,64)).hex()and e['copy_header48_hex']==bytes(u.mem_read(0x6500068000,48)).hex()
   self.counts[key+'_checked']+=1
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq and a==0xfffffe000c6480c0 and self.reg(0)==NEW:
    self.ei+=1;assert self.reg(1)==64 and len(e['patches'])==1 and self.models[self.mi]['return_value']=='0x0';saved=e['patches'][0];assert saved['address']==hex(NEW)and saved['before_hex']==bytes(u.mem_read(NEW,64)).hex()and saved['after_hex']=='00'*64;u.mem_write(NEW,bytes(64));self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=64;self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):super().run();assert all(j==len(self.p[k])for k,j in self.ec.items());return dict(self.counts)
