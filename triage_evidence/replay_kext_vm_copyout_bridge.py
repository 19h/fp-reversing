#!/usr/bin/env python3
"""Fresh original-instruction replay of kext/kernel call and return components.
O(visits+RAM+effects) time, O(image+RAM+journals) space. No probe executor reuse.
Primitive effects are reconstructed from actual argument registers and memory.
"""
import struct
from unicorn import arm64_const as ar
from replay_rpc502_vm_handoff import Replay as VMParent, decode, P, SIZE, MAP, KMAP, THREAD, SOURCES
from replay_kext_constructor_request import Replay as KextParent
BACK=P+0x78000; MAPPED=P+0xa8000

def restore_simd(u,p):
 if p['entry_Q_registers32'] is not None:
  for j,x in enumerate(p['entry_Q_registers32']):u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))

def final_simd(obj):
 assert obj.p['final_Q_registers32']==[hex(obj.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
 obj.counts['final_SIMD_states_checked']+=1

class VMReplay(VMParent):
 def __init__(self,im,p):
  super().__init__(im,p);restore_simd(self.u,p);self.bridge_edges=p['logical_adapter_edges'];self.bi=0
 def code(self,u,a,n,d):
  self.finish()
  if self.bi<len(self.bridge_edges):
   e=self.bridge_edges[self.bi]
   if e['pc']==hex(a)and e['source_visit_index']==self.seq:
    raw=bytes(u.mem_read(a,4));v=self.p['source_visits'][self.seq];i=next(self.image.k.cs.disasm(raw,a))
    assert v['pc']==hex(a)and raw==self.image.k.read(a,4)and raw.hex()==v['bytes_hex']and i.mnemonic=='braa'and i.op_str=='x16, x17'
    assert e['target']==hex(self.reg(16))and e['modifier']==hex(self.reg(17))
    self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.bi+=1
    self.counts['source_visits_checked']+=1;self.counts['logical_adapter_tail_edges_checked']+=1
    u.reg_write(ar.UC_ARM64_REG_PC,self.reg(16));return
  if self.ei<len(self.effects):
   e=self.effects[self.ei]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq and a in[0xfffffe000bcfe5b8,0xfffffe000bdc2fc0,0xfffffe000bdc76b4,0xfffffe000be7798c]:
    c=self.p['configuration'];want=[];result=0
    if a==0xfffffe000bcfe5b8:
     assert c['stage']=='copyin'and self.active==0 and[self.reg(j)for j in range(4)]==[0xfffffe0007f8bfb0,4096,0,0];result=BACK
    elif a==0xfffffe000bdc2fc0:
     assert c['stage']=='copyin'and[self.reg(j)for j in range(5)]==[MAP,SOURCES[0],BACK,4096,1];want=[(BACK,bytes(u.mem_read(SOURCES[0],4096)))]
    elif a==0xfffffe000bdc76b4:
     assert c['stage']=='copyout'and[self.reg(j)for j in range(8)]==[KMAP,int(self.p['bridge_output_address'],16),16384,0,0x6000000000000000,0,0,0]
     assert e['stack_prefix12_hex']==bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),12)).hex()==struct.pack('<III',3,7,1).hex()
     result=c.get('allocation_result',0)
     if not result:want=[(self.reg(1),struct.pack('<Q',MAPPED))]
    else:
     assert c['stage']=='copyout'and[self.reg(j)for j in range(3)]==[BACK,MAPPED,4096];want=[(MAPPED,bytes(u.mem_read(BACK,4096)))]
    assert int(self.models[self.mi]['return_value'],16)==result and len(want)==len(e['patches'])
    for (ptr,b),saved in zip(want,e['patches'],strict=True):
     assert saved['address']==hex(ptr)and saved['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and saved['after_hex']==b.hex()
     u.mem_write(ptr,b);self.counts['declared_effect_patches_checked']+=1;self.counts['declared_effect_bytes_checked']+=len(b)
    self.ei+=1;self.counts['declared_effect_calls_checked']+=1
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.bi==len(self.bridge_edges);final_simd(self);return dict(self.counts)

class KextReplay(KextParent):
 def __init__(self,im,p):
  q=dict(p)
  if p['initial_private_RAM_transfer']is not None:q['initial_private_fixtures']=[{'address':hex(P),'bytes_hex':decode(p['initial_private_RAM_transfer']).hex()}]+p['initial_private_fixtures']
  super().__init__(im,q);restore_simd(self.u,p);self.state_snapshots=p['state_snapshots'];self.state_si=0
  for e in p['private_system_register_fixtures']:
   assert e['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(e['value'],16))
 def code(self,u,a,n,d):
  if self.state_si<len(self.state_snapshots):
   e=self.state_snapshots[self.state_si]
   if e['pc']==hex(a)and e['before_source_visit_index']==self.seq:
    self.finish();assert e['registers31']==[hex(self.reg(j))for j in range(31)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP));self.state_si+=1;self.counts['state_snapshots_checked']+=1
  if self.mi<len(self.models):
   m=self.models[self.mi]
   if m['pc']==hex(a)and m['before_source_visit_index']==self.seq and a in[0xfffffe000bcf5e28,0xfffffe000a508e4c]:
    self.finish();assert m['arguments8']==[hex(self.reg(j))for j in range(8)]and self.reg(30)==int(m['return_pc'],16)and m['return_value']=='0x0'
    if a==0xfffffe000bcf5e28:
     b=bytearray(392);struct.pack_into('<IIQQII',b,0,0x80000000,392,0,0,0,602);struct.pack_into('<I',b,32,2);struct.pack_into('<QII',b,36,P+0x68000,0x01000101,4096);struct.pack_into('<QII',b,52,0,0x01000101,0);b[68:76]=bytes.fromhex('0000000001000000');struct.pack_into('<I',b,76,0xbeefed02);struct.pack_into('<II',b,384,4096,0);want=[(self.reg(0),bytes(b))]
     assert bytes(u.mem_read(self.reg(0),88)).hex()==self.p['transport_request88_hex']and bytes(b).hex()==self.p['declared_reply392_hex']
    else:assert[self.reg(j)for j in range(3)]==[P+0x85000,P+0x70000,16384];want=[]
    assert len(want)==len(m['memory_effects'])
    for (ptr,b),saved in zip(want,m['memory_effects'],strict=True):
     assert saved['address']==hex(ptr)and saved['before_hex']==bytes(u.mem_read(ptr,len(b))).hex()and saved['after_hex']==b.hex()
     u.mem_write(ptr,b);self.counts['declared_model_memory_effects_checked']+=1;self.counts['declared_model_write_bytes_checked']+=len(b)
    self.mi+=1
    for j,x in enumerate(m['after_registers31']):
     if j<18:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(x,16))
     else:assert self.reg(j)==int(x,16)
    u.reg_write(ar.UC_ARM64_REG_NZCV,int(m['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(m['return_pc'],16));self.counts['declared_API_models_checked']+=1;self.counts['entry_ABI_models_checked']+=1;return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.state_si==len(self.state_snapshots)
  assert bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_final_RAM_images_checked']+=1;self.counts['whole_final_RAM_bytes_checked']+=SIZE
  for e in self.p['final_image_globals']:
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));assert bytes(self.u.mem_read(a,len(b)))==b;self.counts['final_image_globals_checked']+=1
  assert self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)==THREAD;final_simd(self);return dict(self.counts)
