#!/usr/bin/env python3
"""Independent original block/continuation CPU, stack-auth and edge replay.
O(image+visits+RAM+effects), O(image+RAM+journals). No probe executor import.
"""
from unicorn import arm64_const as ar
from replay_kernel_waitq_enqueue import Replay as Parent,SenderReplay
RECV=0x6500060000
class Replay(Parent):
 def __init__(self,im,p):super().__init__(im,p);self.code_sign=p.get('logical_code_signing',[]);self.ci=0;self.stack_auth=p.get('logical_stack_authentication',[]);self.sai=0;self.edges=p.get('logical_continuation_edges',[]);self.ei=0;self.bframes=p.get('block_frames',[]);self.bfi=0;self.dframes=p.get('dispatch_frames',[]);self.dfi=0
 def code(self,u,a,n,d):
  self.finish()
  for name,index in[('bframes','bfi'),('dframes','dfi')]:
   rows=getattr(self,name);j=getattr(self,index)
   if j<len(rows):
    e=rows[j]
    if e['pc']==hex(a)and e['source_visit_index']==self.seq:
     assert e['arguments8']==[hex(self.reg(k))for k in range(8)]and e['SP']==hex(u.reg_read(ar.UC_ARM64_REG_SP))and e['receiver1536_hex']==bytes(u.mem_read(RECV,1536)).hex()and e['DAIF_mask']==hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)
     if'FP'in e:assert e['FP']==hex(self.reg(29))
     setattr(self,index,j+1);self.counts['original_block_storage_and_dispatch_frames_checked']+=1
  if self.ci<len(self.code_sign)and self.code_sign[self.ci]['pc']==hex(a):
   e=self.code_sign[self.ci];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacia'and i.op_str=='x16, x17'and e['pointer']==hex(self.reg(16))and e['modifier']==hex(self.reg(17));self.ci+=1;self.logical_step(u,a,raw,'logical_continuation_sign_steps_checked');return
  if self.sai<len(self.stack_auth)and self.stack_auth[self.sai]['pc']==hex(a):
   e=self.stack_auth[self.sai];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='autda'and i.op_str=='x5, x6'and e['pointer']==hex(self.reg(5))and e['modifier']==hex(self.reg(6));self.sai+=1;self.logical_step(u,a,raw,'logical_saved_stack_auth_steps_checked');return
  if self.ei<len(self.edges)and self.edges[self.ei]['pc']==hex(a):
   e=self.edges[self.ei];raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='blraa'and i.op_str=='x20, x21'and e['target']==hex(self.reg(20))and e['modifier']==hex(self.reg(21))and e['arguments2']==[hex(self.reg(0)),hex(self.reg(1))];self.ei+=1;self.logical_step(u,a,raw,'logical_authenticated_continuation_edges_checked');u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,int(e['target'],16));return
  return super().code(u,a,n,d)
 def logical_step(self,u,a,raw,count):
  assert raw==self.image.k.read(a,4)and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.rc=self.wc=0;self.counts['source_visits_checked']+=1;self.counts[count]+=1;u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def run(self):super().run();assert self.ci==len(self.code_sign)and self.sai==len(self.stack_auth)and self.ei==len(self.edges)and self.bfi==len(self.bframes)and self.dfi==len(self.dframes);return dict(self.counts)
