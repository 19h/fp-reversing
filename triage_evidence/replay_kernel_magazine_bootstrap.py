#!/usr/bin/env python3
"""Fresh CPU/source journals and explicit string/PAC envelope checks.
O(visits + RAM + journals) time/space; no probe import or native effects.
"""
from unicorn import arm64_const as ar
from replay_kernel_vm_mig import Replay as Parent
from replay_rpc502_vm_handoff import decode
P=0x6500000000;SIZE=0x100000
class Replay(Parent):
 def __init__(self,image,p,parent=None):
  super().__init__(image,p);self.envelopes=p['logical_envelopes'];self.ei=0;self.leaves=p['string_leaf_inputs'];self.li=0
  expected=bytearray(decode(parent['final_private_RAM']) if parent is not None else bytes(SIZE))
  for row in p['initial_private_fixtures']:
   at=int(row['address'],16)-P;b=bytes.fromhex(row['bytes_hex']);expected[at:at+len(b)]=b
  assert bytes(expected)==decode(p['initial_private_RAM']);self.u.mem_write(P,bytes(expected))
  for row in p['private_system_registers']:assert row['register']=='TPIDR_EL1';self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,int(row['value'],16))
 def string(self,a):
  out=bytearray()
  for j in range(4096):
   self.ensure(a+j);b=bytes(self.u.mem_read(a+j,1))
   if b==bytes(1):return bytes(out)
   out.extend(b)
  raise AssertionError('unterminated replay string')
 def code(self,u,a,n,d):
  self.finish()
  if self.mi<len(self.models) and a==int(self.models[self.mi]['pc'],16) and self.models[self.mi]['symbol'] in ['declared_strncmp','declared_strlen']:
   row=self.leaves[self.li];self.li+=1;m=self.models[self.mi];left=self.string(self.reg(0));right=self.string(self.reg(1)) if m['symbol']=='declared_strncmp' else None
   assert row['pc']==hex(a) and row['left_hex']==left.hex() and row['right_hex']==(right.hex() if right is not None else None)
   if right is None:result=len(left)
   else:
    size=self.reg(2);result=0
    for j in range(size):
     l=left[j] if j<len(left) else 0;r=right[j] if j<len(right) else 0
     if l!=r:result=1 if l>r else -1;break
     if l==0:break
   assert int(m['return_value'],16)==int(row['return_u64'],16)==result&((1<<64)-1);self.counts['string_model_inputs_and_results_checked']+=1
  if self.ei<len(self.envelopes):
   row=self.envelopes[self.ei]
   if row['source_visit_index']==self.seq and row['pc']==hex(a):
    raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert raw==self.image.k.read(a,4) and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex'] and i.mnemonic==row['mnemonic']
    assert row['registers31']==[hex(self.reg(j)) for j in range(31)];self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.ei+=1;self.counts['source_visits_checked']+=1;self.counts['logical_envelopes_checked']+=1
    if i.mnemonic=='blraa':
     target=self.reg(int(i.op_str.split(',')[0][1:]));u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
    else:assert i.mnemonic in ['pacia','pacda'];u.reg_write(ar.UC_ARM64_REG_PC,a+4)
    return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.ei==len(self.envelopes) and self.li==len(self.leaves)
  assert bytes(self.u.mem_read(P,SIZE))==decode(self.p['final_private_RAM']);self.counts['whole_RAM_bytes_checked']+=SIZE
  for row in self.p['final_image_globals']:
   at=int(row['address'],16);b=bytes.fromhex(row['bytes_hex']);assert bytes(self.u.mem_read(at,len(b)))==b;self.counts['global_bytes_checked']+=len(b)
  return dict(self.counts)
