#!/usr/bin/env python3
"""Independent receiver delivery replay and VM/user effect oracles.
O(image+visits+RAM+effects), O(image+RAM+journals); no probe executor import.
"""
from unicorn import arm64_const as ar
from replay_kernel_request_receive import Replay as Parent
from replay_rpc502_vm_handoff import decode,P,SIZE
HEADER=P+0x88010;BACK=P+0x8c000;OOL=P+0x4000;USER=P+0x1000;KMSG=P+0xd0000
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p);self.df=p['delivery_frames'];self.dfi=0;self.dh=p['delivery_full_CPU_RAM_handoffs'];self.dhi=0;self.effects=p['declared_delivery_effects'];self.dei=0;self.copies=p['user_byte_copy_contracts'];self.dci=0;self.allocs=p['VM_allocation_contracts'];self.dai=0;self.ret=p['raw_VM_kmsg_retirement_contracts'];self.dri=0
 def code(self,u,a,n,d):
  self.finish()
  if self.dfi<len(self.df):
   e=self.df[self.dfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))
    for at,size,key in[(HEADER,48,'copy48_hex'),(BACK,29,'backing29_hex'),(OOL,29,'OOL29_hex'),(USER,148,'user148_hex'),(KMSG,256,'kmsg256_hex')]:assert e[key]==bytes(u.mem_read(at,size)).hex()
    self.dfi+=1;self.counts['descriptor_VM_user_delivery_ABI_and_complete_record_frames_checked']+=1
  if self.dhi<len(self.dh):
   e=self.dh[self.dhi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['NZCV']==hex(u.reg_read(ar.UC_ARM64_REG_NZCV))and e['Q_registers32']==[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.dhi+=1;self.counts['descriptor_validation_VM_and_packing_full_CPU_RAM_handoffs_checked']+=1
  if self.dci<len(self.copies):
   e=self.copies[self.dci]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:assert e['arguments3']==[hex(self.reg(j))for j in range(3)]and e['source_hex']==bytes(u.mem_read(self.reg(0),self.reg(2))).hex()and e['destination_before_hex']==bytes(u.mem_read(self.reg(1),self.reg(2))).hex();self.dci+=1;self.counts['independent_user_copy_argument_source_and_before_images_checked']+=1
  if self.dai<len(self.allocs):
   e=self.allocs[self.dai]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['stack_prefix12_hex']==bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex();self.dai+=1;self.counts['VM_allocation_register_and_stack_contracts_checked']+=1
  if self.dri<len(self.ret):
   e=self.ret[self.dri]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    assert e['arguments4']==[hex(self.reg(j))for j in range(4)]
    if 'object_hex'in e:assert e['object_hex']==bytes(u.mem_read(self.reg(2),len(e['object_hex'])//2)).hex()
    else:assert e['copy48_hex']==bytes(u.mem_read(HEADER,48)).hex()
    self.dri+=1;self.counts['raw_VM_and_kmsg_retirement_ABI_and_records_checked']+=1
  if self.dei<len(self.effects):
   e=self.effects[self.dei]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['symbol']==self.models[self.mi]['symbol']
    for patch in e['patches']:
     at=int(patch['address'],16);b=bytes.fromhex(patch['after_hex']);assert bytes(u.mem_read(at,len(b))).hex()==patch['before_hex']
     if e['symbol']=='declared_receiver_user_byte_copy':assert at==self.reg(1)and b==bytes(u.mem_read(self.reg(0),self.reg(2)))
     elif e['symbol']=='declared_receiver_VM_allocation':assert at==self.reg(1)and b==OOL.to_bytes(8,'little')
     else:assert e['symbol']=='declared_current_map_leaf'and at==self.reg(0)+0x428 and b==self.reg(1).to_bytes(8,'little')
     u.mem_write(at,b);self.counts['independent_delivery_primitive_patches_checked']+=1;self.counts['delivery_primitive_patch_bytes_checked']+=len(b)
    self.dei+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.dfi==len(self.df)and self.dhi==len(self.dh)and self.dei==len(self.effects)and self.dci==len(self.copies)and self.dai==len(self.allocs)and self.dri==len(self.ret)
  for at,key,size in[(USER,'final_user8192_hex',8192),(OOL,'final_OOL16384_hex',16384),(HEADER,'final_copy_header48_hex',48),(BACK,'final_backing29_hex',29)]:assert self.p[key]==bytes(self.u.mem_read(at,size)).hex()
  assert self.p['final_OOL_guard_hex']==bytes(self.u.mem_read(OOL+16384,1)).hex();return dict(self.counts)
