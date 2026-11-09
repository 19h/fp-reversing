#!/usr/bin/env python3
"""Fresh CPU/read/write replay of original send-reference components.
O(visits+RAM+globals), O(image+RAM+journals); no probe executor reuse or IPC.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as CPU
from replay_rpc502_vm_handoff import decode,P,SIZE
THREAD=P+0x2c000
class Replay(CPU):
 def __init__(self,im,p):
  q=dict(p)
  if p['initial_state_transfer']is not None:q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_state_transfer']).hex()}]+p['initial_private_fixtures']
  super().__init__(im,q)
  if p['entry_Q_registers32']is not None:
   for j,x in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
  for e in p['private_system_register_fixtures']:assert e=={'register':'TPIDR_EL1','value':hex(THREAD)};self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
 def run(self):
  super().run();assert bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_image_globals_checked']+=1
  assert self.p['final_Q_registers32']==[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==THREAD;self.counts['final_SIMD_system_states_checked']+=1
  self.ensure(0xfffffe000cad0240,8);assert bytes(self.u.mem_read(0xfffffe000cad0240,8)).hex()==self.p['final_host_lock8_hex']
  if self.p['notification_packet']is not None:
   e=self.p['notification_packet'];assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['bytes44_hex']==bytes(self.u.mem_read(self.reg(0),44)).hex()and e['call_site']==hex(self.reg(30)-4);self.counts['notification_frontier_packet_checked']+=1
  return dict(self.counts)
