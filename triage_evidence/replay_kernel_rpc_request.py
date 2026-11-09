#!/usr/bin/env python3
"""Independent complete-state replay of constructor -> RPC request-prefix CPU.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
Logical PAC, private bootstrap/call epochs and declared primitive effects only.
"""
from unicorn import arm64_const as ar
from replay_kext_constructor_request import Replay as Parent
from replay_rpc502_vm_handoff import decode,P,SIZE
TABLE=0x400000100000
class Replay(Parent):
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
 def __init__(self,im,p):
  q={**p,'logical_edges':p.get('logical_edges',[]),'snapshots':p.get('snapshots',[])};q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_state_transfer']).hex()}]+p['initial_private_fixtures'];super().__init__(im,q);self.pac=sorted([(e.get('visit',-1),kind,e)for kind,key in[('autda','logical_data_authentication'),('pacda','logical_data_signing')]for e in p[key]],key=lambda x:x[0]) if p['kind']=='constructor_RPC_request'else[];self.pi=0;self.environment_auth={key:list(p[key])for key in['logical_data_authentication','logical_data_signing']};self.ai={'autda':0,'pacda':0};self.frames=p.get('request_frames',[]);self.fi=0;self.handoff=p.get('continuous_constructor_handoff');self.hi=0
  for j,v in enumerate(p['entry_Q_registers32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(p['current_thread'],16));self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|int(p['entry_DAIF_mask'],16))
 def code(self,u,a,n,d):
  self.finish()
  if self.fi<len(self.frames):
   e=self.frames[self.fi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))
    for at,sz,key in[(P+0x60000,1536,'thread1536_hex'),(P+0xc0070,144,'destination0_144_hex'),(P+0xc0100,144,'destination1_144_hex'),(P+0x80070,144,'reply144_hex'),(P+0xa8040,96,'turnstile96_hex'),(P+0xd0000,256,'kmsg256_hex')]:assert e[key]==bytes(u.mem_read(at,sz)).hex()
    self.fi+=1;self.counts['request_ABI_and_complete_object_frames_checked']+=1
  if self.handoff and a==int(self.handoff['pc'],16)and self.seq==self.handoff['source_visit_index']:
   e=self.handoff;assert e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['NZCV']==hex(u.reg_read(ar.UC_ARM64_REG_NZCV))and e['Q_registers32']==[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and e['DAIF_mask']==hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)and e['TPIDR_EL1']==hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1))and bytes(u.mem_read(P,SIZE))==decode(e['private_RAM'])and e['message_address']==hex(self.reg(0))and e['message88_hex']==bytes(u.mem_read(self.reg(0),88)).hex()and e['handoff_overlays']==[];self.hi+=1;self.counts['continuous_constructor_to_RPC_full_CPU_RAM_handoffs_checked']+=1
  if self.seq<len(self.p['source_visits'])and self.p['source_visits'][self.seq]['pc']==hex(a):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in['autda','pacda']:
    if self.p['kind']=='constructor_RPC_request':v,kind,e=self.pac[self.pi];self.pi+=1;assert v==self.seq and kind==i.mnemonic
    else:key='logical_data_authentication'if i.mnemonic=='autda'else'logical_data_signing';e=self.environment_auth[key][self.ai[i.mnemonic]];self.ai[i.mnemonic]+=1
    rr=[int(s.strip()[1:])for s in i.op_str.split(',')];assert raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex']and rr==e['registers']and e['pointer']==hex(self.reg(rr[0]))and e['modifier']==hex(self.reg(rr[1]));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_data_PAC_steps_checked']+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if self.mi<len(self.models):
   m=self.models[self.mi]
   if m['pc']==hex(a)and m['before_source_visit_index']in[self.seq,self.seq+1]and m['symbol']in['memcpy_model','declared_byte_copy']:
    dst,src,size=[int(v,16)for v in m['arguments8'][:3]];assert m['arguments8'][:3]==[hex(self.reg(j))for j in range(3)]and len(m['memory_effects'])==1 and m['memory_effects'][0]['address']==hex(dst)and m['memory_effects'][0]['after_hex']==bytes(u.mem_read(src,size)).hex();self.counts['independent_byte_copy_argument_and_source_oracles_checked']+=1
  # Direct primitive calls use independent before-image/effect application.
  if self.mi<len(self.models):
   e=self.models[self.mi]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    for eff in e.get('memory_effects',[]):
     at=int(eff['address'],16);b=bytes.fromhex(eff['after_hex']);assert bytes(u.mem_read(at,len(b))).hex()==eff['before_hex'];u.mem_write(at,b);self.counts['declared_model_memory_effects_checked']+=1;self.counts['declared_model_write_bytes_checked']+=len(b)
  return super().code(u,a,n,d)
 def run(self):
  # Parent.run assumes the old constructor-only terminal fields; use CPU runner.
  from replay_kernel_vm_mig import Replay as CPU
  CPU.run(self);assert self.ei==len(self.edges)and self.si==len(self.snapshots)and self.fi==len(self.frames)
  if self.p['kind']=='constructor_RPC_request':assert self.pi==len(self.pac)and self.hi==int(self.handoff is not None)
  else:assert self.ai['autda']==len(self.p['logical_data_authentication'])and self.ai['pacda']==len(self.p['logical_data_signing'])
  assert bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_image_globals_checked']+=1
  assert self.p['final_DAIF_mask']==hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)and self.p['final_Q_registers32']==[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]and self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==int(self.p['current_thread'],16);self.counts['CPU_system_and_SIMD_final_states_checked']+=1;return dict(self.counts)
