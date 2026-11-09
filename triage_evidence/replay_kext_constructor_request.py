#!/usr/bin/env python3
"""Independent fresh CPU replay, API-effect and constructor-snapshot audit.
O(visits+effects), O(private RAM+journals); no probe executor reuse.
"""
from unicorn import arm64_const as ar
from replay_kernel_vm_mig import Replay as CPU
class Replay(CPU):
 def __init__(self,im,p):super().__init__(im,p);self.edges=p['logical_edges'];self.ei=0;self.snapshots=p['snapshots'];self.si=0
 def code(self,u,a,n,d):
  if self.si<len(self.snapshots):
   s=self.snapshots[self.si]
   if s['pc']==hex(a)and s['before_source_visit_index']==self.seq:
    self.finish();self.si+=1;assert s['registers31']==[hex(self.reg(j))for j in range(31)]and s['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP));self.counts['constructor_snapshots_checked']+=1
  if self.ei<len(self.edges)and self.edges[self.ei]['pc']==hex(a)and self.edges[self.ei]['visit']==self.seq:
   self.finish();e=self.edges[self.ei];self.ei+=1;v=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4)and raw.hex()==v['bytes_hex'];i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic==e['kind'];target=self.reg(int(i.op_str.split(',')[0][1:]));assert target==int(e['target'],16)and self.reg(17)==int(e['modifier'],16);self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts['logical_PAC_steps_checked']+=1;self.counts['logical_indirect_edges_checked']+=1
   if i.mnemonic=='blraa':u.reg_write(ar.UC_ARM64_REG_X30,a+4)
   if self.mi<len(self.models)and self.models[self.mi]['pc']==hex(a)and self.models[self.mi]['before_source_visit_index']==self.seq:
    m=self.models[self.mi];self.mi+=1;assert i.mnemonic=='blraa'and m['arguments8']==[hex(self.reg(j))for j in range(8)]and self.reg(30)==int(m['return_pc'],16)
    for effect in m['memory_effects']:
     address=int(effect['address'],16);b=bytes.fromhex(effect['after_hex']);assert bytes(u.mem_read(address,len(b))).hex()==effect['before_hex'];u.mem_write(address,b);self.counts['declared_model_memory_effects_checked']+=1;self.counts['declared_model_write_bytes_checked']+=len(b)
    for j,value in enumerate(m['after_registers31']):
     if j<18:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(value,16))
     else:assert self.reg(j)==int(value,16)
    u.reg_write(ar.UC_ARM64_REG_NZCV,int(m['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(m['return_pc'],16));self.counts['declared_API_models_checked']+=1
   else:u.reg_write(ar.UC_ARM64_REG_PC,target)
   return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();assert self.ei==len(self.edges)and self.si==len(self.snapshots)
  for a,key in [(0x6500070000,'staging_final_hex'),(0x6500090000,'name_final_hex'),(0x6500081000,'output_handle_final_hex')]:
   b=bytes.fromhex(self.p[key]);assert bytes(self.u.mem_read(a,len(b)))==b
  if self.p['message88_hex']is not None:assert bytes(self.u.mem_read(self.reg(0),88)).hex()==self.p['message88_hex']
  return dict(self.counts)
