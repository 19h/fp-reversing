#!/usr/bin/env python3
"""Fresh original CPU replay, byte-copy oracle and exact state/frame audit.
O(visits+RAM+effects), O(image+RAM+journals); no probe executor reuse or IPC.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as CPU
from replay_rpc502_vm_handoff import decode,P,SIZE
THREAD=P+0x2c000
class Replay(CPU):
 def __init__(self,im,p):
  q=dict(p);q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_state_transfer']).hex()}]+p['initial_private_fixtures'];super().__init__(im,q);self.fi=self.ei=self.hi=0;self.effects=p['declared_effects'];self.frames=p['entry_frames'];self.hashes=p['opaque_hash_inputs']
  for j,x in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
 def code(self,u,a,n,d):
  self.finish()
  if self.hi<len(self.hashes):
   e=self.hashes[self.hi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    assert e['arguments4']==[hex(self.reg(j))for j in range(4)]and e['bytes_hex']==bytes(u.mem_read(self.reg(0),self.reg(1))).hex();self.hi+=1;self.counts['opaque_hash_inputs_checked']+=1
  if self.fi<len(self.frames):
   e=self.frames[self.fi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['header32_hex']==bytes(u.mem_read(int(self.p['header_address'],16),32)).hex()and e['body12_hex']==bytes(u.mem_read(int(self.p['body_address'],16),12)).hex()and e['accepted_u32']==int.from_bytes(bytes(u.mem_read(P+0xdc000,4)),'little');self.fi+=1;self.counts['original_entry_and_return_frames_checked']+=1
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    assert a==0xfffffe000c647f10 and e['symbol']=='declared_byte_copy'and len(e['patches'])==1;ptr=self.reg(0);b=bytes(u.mem_read(self.reg(1),self.reg(2)));saved=e['patches'][0]
    assert self.models[self.mi]['return_value']==hex(ptr)and saved['address']==hex(ptr)and saved['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and saved['after_hex']==b.hex();u.mem_write(ptr,b);self.ei+=1;self.counts['independent_byte_copy_calls_checked']+=1;self.counts['independent_byte_copy_bytes_checked']+=len(b)
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.ei==len(self.effects)and self.fi==len(self.frames)and self.hi==len(self.hashes)and bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_image_globals_checked']+=1
  assert self.p['final_Q_registers32']==[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==THREAD;self.counts['final_SIMD_system_states_checked']+=1
  return dict(self.counts)
