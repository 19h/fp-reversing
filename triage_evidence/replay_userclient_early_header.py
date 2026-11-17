#!/usr/bin/env python3
"""Independent pre-entry byte custody, CCMP and logical flag effects.
No producer/Unicorn import. O(V+E+M) work/space per case.
"""
from replay_userclient_fpttlv_entry import Replay as Base,PRIVATE
from capstone.arm64 import ARM64_OP_REG
class Replay(Base):
 def __init__(self,k,r,mutation=None):
  super().__init__(k,r,mutation);b=bytes.fromhex(r['input']['input_fixture_hex']);a=r['input']['inputs8'][0];assert a==PRIVATE+0x2000 and len(b)<=64
  self.input_initial={a+j:v for j,v in enumerate(b)};self.initial.update(self.input_initial);self.known.update(self.input_initial)
 def step(self,i):
  if i.mnemonic in ['lsl','lsr']and i.operands[2].type==ARM64_OP_REG:
   n=32 if i.reg_name(i.operands[0].reg).startswith('w')else 64;a=self.operand(i,i.operands[1],n);shift=self.operand(i,i.operands[2],n)&(n-1);self.set(i.reg_name(i.operands[0].reg),a<<shift if i.mnemonic=='lsl'else a>>shift);return self.pc+4
  if i.mnemonic in ['ldrh','strh']:
   o=i.operands;assert not i.writeback and not o[1].mem.index;a=(self.reg(i.reg_name(o[1].mem.base))+o[1].mem.disp)&((1<<64)-1);name=i.reg_name(o[0].reg)
   if i.mnemonic=='ldrh':self.set(name,self.load(a,2,name=='wzr'))
   else:self.store(a,2,self.reg(name))
   return self.pc+4
  if i.mnemonic=='ccmp':
   take=self.condition(i.op_str.rsplit(',',1)[1].strip())
   if not take:self.nzcv=i.operands[2].imm<<28
   else:
    n=32 if i.reg_name(i.operands[0].reg).startswith('w')else 64;a=self.operand(i,i.operands[0],n);b=self.operand(i,i.operands[1],n);v=(a-b)&((1<<n)-1);self.nzcv=((v>>(n-1))<<31)|((v==0)<<30)|((a>=b)<<29)|((((a^b)&(a^v))>>(n-1))<<28)
   return self.pc+4
  if i.mnemonic=='tst':
   n=32 if i.reg_name(i.operands[0].reg).startswith('w')else 64;v=self.operand(i,i.operands[0],n)&self.operand(i,i.operands[1],n);self.nzcv=(v>>(n-1))<<31|int(v==0)<<30;return self.pc+4
  return super().step(i)
 def run(self):
  out=super().run();s=self.r['declared_input'];a=int(s['address'],16);n=s['size_bytes'];assert self.at(a,n).hex()==s['bytes_hex']and s['known_mask_hex']=='01'*n
  assert all(a+j not in self.state for j in range(n))and s['provenance_hex']=='02'*n and self.r['initial_input_bytes_declared']==n
  out['declared_input_bytes_checked']=n;return out
