#!/usr/bin/env python3
"""Independent source/effect and full-state receiver replay, no probe import.
O(image+visits+RAM+effects), O(image+RAM+journals). Logical PAC only.
"""
from unicorn import arm64_const as ar
from replay_kernel_vm_mig import Replay as CPU
from replay_rpc502_vm_handoff import decode,P,SIZE
TABLE=0x400000100000
class Replay(CPU):
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
 def __init__(self,im,p):
  q=dict(p);q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_state_transfer']).hex()}]+p['initial_private_fixtures'];super().__init__(im,q);self.pac=sorted([(e['visit'],kind,e)for kind,key in[('autda','logical_data_authentication'),('pacda','logical_data_signing')]for e in p[key]],key=lambda x:x[0]);self.pi=0;self.frames=p['receive_frames'];self.fi=0;self.handoffs=p['continuous_receive_handoffs'];self.hi=0;self.hashes=p['opaque_hash_inputs'];self.hsi=0;self.raw=p['raw_storage_contracts'];self.ri=0;self.retire=p['raw_retirement_contracts'];self.rti=0
  for j,v in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(p['current_thread'],16));self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|int(p['entry_DAIF_mask'],16))
 def code(self,u,a,n,d):
  self.finish()
  if self.fi<len(self.frames):
   e=self.frames[self.fi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))
    for at,sz,key in[(P+0x60000,1536,'sender1536_hex'),(P+0x64000,1536,'receiver1536_hex'),(int(self.p['destination'],16),144,'destination144_hex'),(P+0x80070,144,'reply144_hex'),(P+0xa8040,96,'turnstile96_hex'),(P+0xd0000,256,'kmsg256_hex'),(P+0xdd000,128,'space128_hex'),(TABLE+48,24,'entry24_hex')]:assert e[key]==bytes(u.mem_read(at,sz)).hex()
    self.fi+=1;self.counts['complete_receive_ABI_and_object_frames_checked']+=1
  if self.hi<len(self.handoffs):
   e=self.handoffs[self.hi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['NZCV']==hex(u.reg_read(ar.UC_ARM64_REG_NZCV))and e['Q_registers32']==[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and decode(e['private_RAM'])==bytes(u.mem_read(P,SIZE));self.hi+=1;self.counts['continuous_receiver_full_CPU_RAM_handoffs_checked']+=1
  for events,index,field in[(self.hashes,'hsi','hash'),(self.raw,'ri','raw'),(self.retire,'rti','retire')]:
   j=getattr(self,index)
   if j<len(events):
    e=events[j]
    if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
     assert e['arguments4']==[hex(self.reg(k))for k in range(4)]
     if field=='hash':assert e['bytes_hex']==bytes(u.mem_read(self.reg(0),self.reg(1))).hex()
     elif field=='raw':assert e['returned_pointer']==self.models[self.mi]['return_value']and e['object_before_hex']==bytes(u.mem_read(int(e['returned_pointer'],16),96)).hex()
     else:assert e['turnstile96_hex']==bytes(u.mem_read(P+0xa8040,96)).hex()
     setattr(self,index,j+1);self.counts[field+'_primitive_argument_and_record_contracts_checked']+=1
  if self.pi<len(self.pac):
   visit,kind,e=self.pac[self.pi]
   if visit==self.seq and e['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));rr=[int(v.strip()[1:])for v in i.op_str.split(',')];assert i.mnemonic==kind and raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex']and rr==e['registers']and e['pointer']==hex(self.reg(rr[0]))and e['modifier']==hex(self.reg(rr[1]));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.pi+=1;self.counts['source_visits_checked']+=1;self.counts['logical_data_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.pi==len(self.pac)and self.fi==len(self.frames)and self.hi==len(self.handoffs)and self.hsi==len(self.hashes)and self.ri==len(self.raw)and self.rti==len(self.retire)and bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_image_globals_checked']+=1
  assert self.p['final_DAIF_mask']==hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)and self.p['final_Q_registers32']==[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==int(self.p['current_thread'],16);self.counts['CPU_system_and_SIMD_final_states_checked']+=1;return dict(self.counts)
