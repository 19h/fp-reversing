#!/usr/bin/env python3
"""Independent fourth register-return cut and all 32 node byte epochs.
No producer/Unicorn import. O(V+E+M) time/space per case.
"""
from replay_userclient_early_header import Replay as Base,PRIVATE
class Replay(Base):
 def step(self,i):
  if self.ix in self.models and self.pc==0xfffffe000a661664:
   e=self.models[self.ix];result=self.r['input']['node_result_fixture'];target=self.reg(i.reg_name(i.operands[0].reg))
   assert i.mnemonic=='blraa'and e['target']==hex(target)==hex(0xfffffe000c4ba154)and e['kind']=='earlier_FPTTLVNode32_register_return'
   assert e['arguments8']==[hex(v)for v in self.g[:8]]and self.g[0]==0xfffffe000847b4a0 and e['result_X0_fixture']==hex(result)and result in [0,PRIVATE+0xe100]and not e['target_executed']and e['model_memory_writes']==0
   self.g[0]=result
   for j in range(1,18):self.g[j]=0xf000000000000000+j*0x1111
   self.nzcv=0xf0000000;self.g[30]=self.pc+4;self.count['register_only_API_models_checked']+=1;return self.pc+4
  return super().step(i)
 def run(self):
  out=super().run();s=self.r['earlier_node'];a=int(s['address'],16);n=s['size_bytes'];assert n==32 and self.at(a,n).hex()==s['bytes_hex']and bytes(int(j in self.known)for j in range(a,a+n)).hex()==s['known_mask_hex']and s['known_mask_hex']==s['provenance_hex'];out['node_snapshot_bytes_checked']=n;return out
