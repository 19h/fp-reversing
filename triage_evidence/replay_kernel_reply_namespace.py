#!/usr/bin/env python3
"""Independent source/read/write replay of reply-right namespace components.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
from replay_rpc502_vm_handoff import decode,P,SIZE
TABLE=0x400000100000;RECV=P+0x60000;PORT=P+0xc0000;REPLY=P+0x80070;SPACE=P+0xdd000;KMSG=P+0xd0000
class Replay(Parent):
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
 def __init__(self,im,p):
  q=dict(p);q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_state_transfer']).hex()}]+p['initial_private_fixtures'];super().__init__(im,q);self.sign=p['logical_data_signing'];self.si=0;self.frames=p['namespace_frames'];self.fi=0;self.hashes=p['opaque_hash_inputs'];self.hi2=0
  for j,v in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,RECV);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|int(p['entry_DAIF_mask'],16))
 def code(self,u,a,n,d):
  self.finish()
  if self.fi<len(self.frames):
   e=self.frames[self.fi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['port144_hex']==bytes(u.mem_read(PORT,144)).hex()and e['reply144_hex']==bytes(u.mem_read(REPLY,144)).hex()and e['space128_hex']==bytes(u.mem_read(SPACE,128)).hex()and e['entry24_hex']==bytes(u.mem_read(TABLE+self.p['configuration']['index']*24,24)).hex()and e['header88_hex']==bytes(u.mem_read(KMSG+0x40,88)).hex()and e['nesting']==int.from_bytes(bytes(u.mem_read(RECV+0x1c8,4)),'little');self.fi+=1;self.counts['original_namespace_ABI_and_record_frames_checked']+=1
  if self.hi2<len(self.hashes):
   e=self.hashes[self.hi2]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:assert e['arguments4']==[hex(self.reg(j))for j in range(4)]and e['bytes_hex']==bytes(u.mem_read(self.reg(0),self.reg(1))).hex();self.hi2+=1;self.counts['opaque_hash_inputs_checked']+=1
  if self.si<len(self.sign):
   e=self.sign[self.si]
   if e['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacda'and i.op_str=='x17, x16'and raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex']and e['pointer']==hex(self.reg(17))and e['modifier']==hex(self.reg(16));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.si+=1;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.si==len(self.sign)and self.fi==len(self.frames)and self.hi2==len(self.hashes)and bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_image_globals_checked']+=1
  assert self.p['final_DAIF_mask']==hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)and self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==RECV and self.p['final_Q_registers32']==[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.counts['CPU_system_and_SIMD_final_states_checked']+=1;return dict(self.counts)
