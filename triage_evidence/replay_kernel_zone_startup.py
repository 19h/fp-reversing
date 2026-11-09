#!/usr/bin/env python3
"""Independent original fixed-zone startup and actual-zone allocation replay.
O(image+visits+RAM+effects), O(image+RAM+journals). Models are explicit;
no probe executor import, native startup/IPC or hardware PAC effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_reply_send import Replay as Parent
from replay_rpc502_vm_handoff import decode
P=0x6500000000;SIZE=0x100000;THREAD=P+0x2c000
class Replay(Parent):
 def __init__(self,im,p):
  super().__init__(im,p)
  if 'initial_state_transfer'in p:
   self.u.mem_write(P,decode(p['initial_state_transfer']))
   for e in p['initial_private_fixtures']+p['initial_image_fixtures']:self.u.mem_write(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  for j,x in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
  for e in p.get('private_system_register_fixtures',[]):assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
  self.sf=p['startup_frames'];self.sfi=0;self.af=p.get('allocation_frames',[]);self.afi=0;self.sign=p['logical_data_signing'];self.si=0
 def code(self,u,a,n,d):
  self.finish()
  if self.sfi<len(self.sf):
   e=self.sf[self.sfi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments5']==[hex(self.reg(j))for j in range(5)]and e['zone192_hex']==bytes(u.mem_read(int(self.p['zone_address'],16),192)).hex();self.sfi+=1;self.counts['startup_frames_checked']+=1
  if self.afi<len(self.af):
   e=self.af[self.afi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments4']==[hex(self.reg(j))for j in range(4)]and e['cache64_hex']==bytes(u.mem_read(int(self.p['selected_cache_address'],16),64)).hex()and e['stats16_hex']==bytes(u.mem_read(int(self.p['selected_statistics_address'],16),16)).hex()and e['thread_nesting']==int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little');self.afi+=1;self.counts['allocation_frames_checked']+=1
  if self.si<len(self.sign):
   e=self.sign[self.si]
   if e['pc']==hex(a)and self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacda'and raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex']and e['pointer']==hex(self.reg(17))and e['modifier']==hex(self.reg(16));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.si+=1;self.counts['source_visits_checked']+=1;self.counts['logical_data_sign_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.sfi==len(self.sf)and self.afi==len(self.af)and self.si==len(self.sign)
  b=decode(self.p['final_private_RAM']);assert len(b)==SIZE and bytes(self.u.mem_read(P,SIZE))==b;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_global_bytes_checked']+=len(b)
  assert [hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]==self.p['final_Q_registers32'];self.counts['final_SIMD_registers_checked']+=32
  for e in self.p.get('private_system_register_fixtures',[]):assert self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==int(e['value'],16);self.counts['final_system_registers_checked']+=1
  return dict(self.counts)
