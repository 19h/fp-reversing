#!/usr/bin/env python3
"""Independent replay with checked caller handover and declared private copyout.
Recompute copy bytes from fresh CPU source memory, not probe implementation.
O(visits+effects) time, O(one private map+journals) space. No native copyout.
"""
from unicorn import arm64_const as ar
from replay_kernel_queue_receive import Replay as Parent
class Replay(Parent):
 def __init__(self,image,p):
  super().__init__(image,p);self.handovers=p['caller_handovers'];self.handover_index=0;self.copyouts=p['declared_copyouts'];self.copyi=0;self.delivery_cuts={e['source_visit_index']:e for e in p['delivery_entry_cuts']};self.delivery_ci=0;self.completions={e['source_visit_index']:e for e in p['completion_snapshots']};self.completion_ci=0
 def code(self,u,a,n,d):
  if self.seq in self.completions and a==int(self.completions[self.seq]['pc'],16):
   self.finish();e=self.completions[self.seq];assert u.reg_read(ar.UC_ARM64_REG_SP)+0x10==int(e['address'],16)and bytes(u.mem_read(int(e['address'],16),40)).hex()==e['bytes_hex']and self.reg(19)==int(e['published_pointer'],16);self.completion_ci+=1;self.counts['completion_record_snapshots_checked']+=1
  if self.handover_index<len(self.handovers):
   e=self.handovers[self.handover_index]
   if a==int(e['from_PC'],16)and self.seq==e['before_source_visit_index']:
    self.finish();assert self.reg(0)==int(e['before_X0'],16)and u.reg_read(ar.UC_ARM64_REG_SP)==int(e['SP'],16);u.reg_write(ar.UC_ARM64_REG_X0,int(e['after_X0'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['to_PC'],16));self.handover_index+=1;self.counts['declared_caller_handovers_checked']+=1;return
  if self.seq in self.delivery_cuts and a==int(self.delivery_cuts[self.seq]['pc'],16):
   e=self.delivery_cuts[self.seq]
   for j,value in enumerate(e['arguments6']):assert self.reg(j)==int(value,16)
   self.delivery_ci+=1;self.counts['delivery_entry_cuts_checked']+=1
  if a==0xfffffe000be7798c and self.copyi<len(self.copyouts):
   self.finish();e=self.copyouts[self.copyi];self.copyi+=1;assert self.seq==e['before_source_visit_index'];src,dst,count=[self.reg(j)for j in range(3)];assert (hex(src),hex(dst),count)==(e['source'],e['destination'],e['size_bytes']);payload=bytes(u.mem_read(src,count));assert payload.hex()==e['source_hex']and bytes(u.mem_read(dst,count)).hex()==e['before_hex'];assert int(self.models[self.mi]['return_value'],16)==e['return_value']
   if e['return_value']==0:u.mem_write(dst,payload);self.counts['declared_private_copy_bytes_checked']+=count
   self.counts['declared_copyout_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  result=super().run();assert self.handover_index==len(self.handovers)and self.copyi==len(self.copyouts)and self.delivery_ci==len(self.delivery_cuts)and self.completion_ci==len(self.completions);return result
