#!/usr/bin/env python3
"""Independent source/event replay; API effects and logical PAC are explicit.
O(visits+effects), O(source journals+RAM). No probe dispatcher is reused.
"""
import hashlib
from unicorn import arm64_const as ar
from replay_kernel_vm_mig import Replay as Parent
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.ai=self.ei=self.fi=0
 def code(self,u,a,n,d):
  self.finish()
  if self.fi<len(self.p['action_frames']):
   e=self.p['action_frames'][self.fi]
   if a==int(e['pc'],16)and self.seq==e['before_source_visit_index']:
    assert e['arguments8']==[hex(self.reg(j))for j in range(8)]and e['gate48_hex']==bytes(u.mem_read(0x6500011048,8)).hex()and e['return_pc']==hex(self.reg(30));self.fi+=1;self.counts['action_frames_checked']+=1
  if self.mi<len(self.models)and a==int(self.models[self.mi]['pc'],16):
   e=self.models[self.mi];self.mi+=1;assert self.seq==e['before_source_visit_index']and self.reg(30)==int(e['return_pc'],16)and e['arguments8']==[hex(self.reg(j))for j in range(8)]
   for effect in e['memory_effects']:
    address=int(effect['address'],16);b=bytes.fromhex(effect['after_hex']);assert bytes(u.mem_read(address,len(b))).hex()==effect['before_hex'];u.mem_write(address,b);self.counts['declared_model_memory_effects_checked']+=1;self.counts['declared_model_write_bytes_checked']+=len(b)
   for j,v in enumerate(e['after_registers31']):
    if j<18:u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
    else:assert self.reg(j)==int(v,16)
   u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['after_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_PC,int(e['return_pc'],16));self.counts['declared_API_models_checked']+=1;return
  if self.seq==len(self.p['source_visits']):
   b=self.p['boundary'];assert a==int(b['pc'],16)and u.reg_read(ar.UC_ARM64_REG_SP)==int(b['SP'],16)and u.reg_read(ar.UC_ARM64_REG_NZCV)==int(b['NZCV'],16)and b['registers31']==[hex(self.reg(j))for j in range(31)];self.counts['final_boundaries_checked']+=1;return u.emu_stop()
  e=self.p['source_visits'][self.seq];raw=bytes(u.mem_read(a,4));assert e['pc']==hex(a)and raw.hex()==e['bytes_hex']and raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1
  if i.mnemonic in ['pacibsp','autibsp','autda','autia','pacia','pacda','xpaci','xpacd']:
   r=self.p['logical_authentication'][self.ai];self.ai+=1;assert r=={'pc':hex(a),'source_visit_index':self.seq-1,'mnemonic':i.mnemonic,'operands':i.op_str,'registers18':[hex(self.reg(j))for j in range(18)]};self.counts['logical_authentication_steps_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if i.mnemonic=='retab':self.counts['logical_return_steps_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if i.mnemonic in ['braa','blraa']:
   x,y=[int(t.strip()[1:])for t in i.op_str.split(',')];r=self.p['indirect_edges'][self.ei];self.ei+=1;target=self.reg(x);assert r=={'pc':hex(a),'source_visit_index':self.seq-1,'kind':i.mnemonic,'target':hex(target),'modifier':hex(self.reg(y))}
   if i.mnemonic=='blraa':u.reg_write(ar.UC_ARM64_REG_X30,a+4)
   self.counts['logical_indirect_edges_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in ['svc','hvc','smc','brk']
 def run(self):
  super().run();assert self.ai==len(self.p['logical_authentication'])and self.ei==len(self.p['indirect_edges'])and self.fi==len(self.p['action_frames'])
  for e in self.p['final_objects']:assert bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex()==e['bytes_hex'];self.counts['final_objects_checked']+=1
  assert hashlib.sha256(bytes(self.u.mem_read(self.lo,self.hi-self.lo))).hexdigest()==self.p['final_RAM_sha256'];return dict(self.counts)
