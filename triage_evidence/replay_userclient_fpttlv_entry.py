#!/usr/bin/env python3
"""Independent concrete continuation: third allocator cut, CMN and object bytes.
O(V+E+M) time/space per case. No producer or Unicorn executor is imported.
"""
from replay_userclient_entry_execution import Replay as Base,PRIVATE,M
class Replay(Base):
 def step(self,i):
  if self.ix in self.models and self.pc==0xfffffe000a636404:
   e=self.models[self.ix];result=self.r['input']['FPTTLV_result_fixture'];target=self.reg(i.reg_name(i.operands[0].reg))
   assert i.mnemonic=='blraa' and e['target']==hex(target)==hex(0xfffffe000c4ba154)and e['kind']=='earlier_FPTTLV16_register_return'
   assert e['arguments8']==[hex(v) for v in self.g[:8]]and self.g[0]==0xfffffe000847bb60 and e['result_X0_fixture']==hex(result)and result in [0,PRIVATE+0xe000]and not e['target_executed'] and e['model_memory_writes']==0
   self.g[0]=result
   for j in range(1,18):self.g[j]=0xf000000000000000+j*0x1111
   self.nzcv=0xf0000000;self.g[30]=self.pc+4;self.count['register_only_API_models_checked']+=1;return self.pc+4
  if i.mnemonic=='cmn':
   n=32 if i.reg_name(i.operands[0].reg).startswith('w')else 64;mask=(1<<n)-1;a=self.operand(i,i.operands[0],n);b=self.operand(i,i.operands[1],n);v=(a+b)&mask;N=v>>(n-1);Z=int(v==0);C=int(a+b>mask);V=int((~(a^b)&(a^v)&(1<<(n-1)))!=0);self.nzcv=N<<31|Z<<30|C<<29|V<<28;return self.pc+4
  return super().step(i)
 def run(self):
  out=super().run();s=self.r['earlier_FPTTLV_object'];a=int(s['address'],16);n=s['size_bytes'];assert n==16 and self.at(a,n).hex()==s['bytes_hex']and bytes(int(j in self.known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(int(j in self.known)for j in range(a,a+n)).hex()==s['provenance_hex'];out['earlier_object_bytes_checked']=n;return out
