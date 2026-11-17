#!/usr/bin/env python3
"""Independent fifth return cut and all 64 early data byte epochs.
No producer/Unicorn import. O(V+E+M) work/space per case.
"""
from replay_userclient_early_node import Replay as Base,PRIVATE
class Replay(Base):
 def step(self,i):
  if self.ix in self.models and self.pc==0xfffffe000a661848:
   e=self.models[self.ix];result=self.r['input']['data_result_fixture'];target=self.reg(i.reg_name(i.operands[0].reg))
   assert i.mnemonic=='blraa'and e['target']==hex(target)==hex(0xfffffe000c4ba60c)and e['kind']=='earlier_TLV_data_register_return'
   assert e['arguments8']==[hex(v)for v in self.g[:8]]and self.g[0]==10+self.r['input']['wire_length32']and e['result_X0_fixture']==hex(result)and result in [0,PRIVATE+0xe200]and not e['target_executed']and e['model_memory_writes']==0
   self.g[0]=result
   for j in range(1,18):self.g[j]=0xf000000000000000+j*0x1111
   self.nzcv=0xf0000000;self.g[30]=self.pc+4;self.count['register_only_API_models_checked']+=1;return self.pc+4
  return super().step(i)
 def run(self):
  out=super().run();s=self.r['earlier_data'];a=int(s['address'],16);n=s['size_bytes'];assert n==64 and self.at(a,n).hex()==s['bytes_hex']and bytes(int(j in self.known)for j in range(a,a+n)).hex()==s['known_mask_hex']and s['known_mask_hex']==s['provenance_hex'];out['data_snapshot_bytes_checked']=n
  requirements=[]
  for i in self.cs.disasm(self.k.read(0xfffffe000a654ad8,0xb4),0xfffffe000a654ad8):
   if i.mnemonic not in ['ldr','ldrh']:continue
   base=i.reg_name(i.operands[1].mem.base)
   if base not in ['x3','x11']:continue
   assert not i.operands[1].mem.index;root='C'if base=='x11'else'S';off=i.operands[1].mem.disp;n=2 if i.mnemonic=='ldrh'else 4 if i.reg_name(i.operands[0].reg).startswith('w')else 8;requirements.append((hex(i.address),root,hex(off),PRIVATE+(0xc000 if root=='C'else 0x8000)+off,n))
  assert len(requirements)==len(self.r['writer_input_cells'])==12
  total=0
  for (pc,root,off,a,n),s in zip(requirements,self.r['writer_input_cells']):
   assert(s['source_PC'],s['root'],s['offset'],s['address'],s['size_bytes'])==(pc,root,off,hex(a),n)
   assert self.at(a,n).hex()==s['bytes_hex']and bytes(int(j in self.known)for j in range(a,a+n)).hex()==s['known_mask_hex']==s['provenance_hex'];total+=n
  assert total==64;out['writer_input_snapshot_bytes_checked']=total;return out
