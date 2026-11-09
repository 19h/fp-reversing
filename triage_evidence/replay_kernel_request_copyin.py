#!/usr/bin/env python3
"""Independent VM adapter/factory, actual caller return and request replay.
O(image+visits+RAM+effects), O(image+RAM+journals); no probe executor import.
"""
from unicorn import arm64_const as ar
from replay_kernel_rpc_request import Replay as Parent
from replay_rpc502_vm_handoff import decode,P,SIZE
HEADER=P+0x88010;BACK=P+0x8c000;STAGING=P+0x70000
class Replay(Parent):
 def __init__(self,im,p):
  q={**p,'kind':'constructor_RPC_request'};super().__init__(im,q);self.vmframes=p['VM_copyin_frames'];self.vfi=0;self.vmhs=p['VM_full_CPU_RAM_handoffs'];self.vhi=0;self.vmraw=p['VM_raw_storage_contracts'];self.vri=0;self.vmcopies=p['VM_lower_copy_contracts'];self.vci=0
 def code(self,u,a,n,d):
  self.finish()
  if self.vfi<len(self.vmframes):
   e=self.vmframes[self.vfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['copy48_hex']==bytes(u.mem_read(HEADER,48)).hex()and e['backing_hex']==bytes(u.mem_read(BACK,self.p['configuration']['length']+1)).hex()and e['staging_hex']==bytes(u.mem_read(STAGING,self.p['configuration']['length']+1)).hex()
    if e['published_pointer_hex']is not None:assert e['published_pointer_hex']==bytes(u.mem_read(int(self.p['VM_copy_output_address'],16),8)).hex()
    self.vfi+=1;self.counts['original_VM_copyin_ABI_and_object_frames_checked']+=1
  if self.vhi<len(self.vmhs):
   e=self.vmhs[self.vhi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['NZCV']==hex(u.reg_read(ar.UC_ARM64_REG_NZCV))and e['Q_registers32']==[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.vhi+=1;self.counts['VM_factory_and_actual_caller_full_CPU_RAM_handoffs_checked']+=1
  if self.vri<len(self.vmraw):
   e=self.vmraw[self.vri]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    at=int(e['returned_pointer'],16);b=bytes.fromhex(e['object_before_hex']);assert e['arguments4']==[hex(self.reg(j))for j in range(4)]and e['returned_pointer']==self.models[self.mi]['return_value']and bytes(u.mem_read(at,len(b)))==b;self.vri+=1;self.counts['VM_raw_allocator_ABI_and_before_record_contracts_checked']+=1
  if self.vci<len(self.vmcopies):
   e=self.vmcopies[self.vci]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['source_hex']==bytes(u.mem_read(self.reg(1),self.reg(3))).hex()and e['destination_before_hex']==bytes(u.mem_read(self.reg(2),self.reg(3))).hex();m=self.models[self.mi];assert m['symbol']=='declared_copyin_map_byte_effect'and m['return_value']=='0x0'and len(m['memory_effects'])==1 and m['memory_effects'][0]['address']==hex(self.reg(2))and m['memory_effects'][0]['after_hex']==e['source_hex'];self.vci+=1;self.counts['independent_lower_map_copy_source_and_effect_oracles_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.vfi==len(self.vmframes)and self.vhi==len(self.vmhs)and self.vri==len(self.vmraw)and self.vci==len(self.vmcopies)and self.p['VM_final_copy48_hex']==bytes(self.u.mem_read(HEADER,48)).hex()and self.p['VM_final_backing_hex']==bytes(self.u.mem_read(BACK,self.p['configuration']['length']+1)).hex()and self.p['VM_copy_guard_hex']==bytes(self.u.mem_read(HEADER+48,1)).hex()and self.p['VM_backing_guard_hex']==bytes(self.u.mem_read(BACK+self.p['configuration']['length']+1,1)).hex();return dict(self.counts)
