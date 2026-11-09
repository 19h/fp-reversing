#!/usr/bin/env python3
"""Observe original exported-block reads and verifier predicates in three uses.

Extends frozen LateProbe;no internal PC/frame/record/gate or result changes.
Actual full callback/worker predecessor,external file inputs and API/PAC
models are inherited. Byte-read windows open only after actual export return.
O(B+V+E+S) work/space plus bounded post-export data-read/branch journals.
No native target/API or IDB action.
"""
import hashlib,struct
from pathlib import Path
from probe_rpc502_late import LateProbe,ROOT,SOURCE,ar
from daemon_receive_tools import CS,IMAGE

class PaddingProbe(LateProbe):
 def __init__(self,*args):
  self.padding_stages=[];self.padding_active=None;self.padding_points=[];self.padding_reads=[];self.padding_edges=[]
  super().__init__(*args)
 def hook(self,u,a,n,d):
  self.flush()
  if a==0x100657488:
   p=self.reg(0);raw=bytes.fromhex(self.observe(p,80));output=struct.unpack_from('<Q',raw,56)[0];sp=u.reg_read(ar.UC_ARM64_REG_SP);C=struct.unpack('<I',bytes.fromhex(self.observe(sp+0x68,4)))[0]^0x8b3dc651
   self.padding_stages.append({'entry_step':self.steps,'argument':hex(p),'argument80_hex':raw.hex(),'SP':hex(sp),'export_output':hex(output),'encoded_extent':C,'digest_extent':self.reg(19)&0xffffffff,'post_export':False,'complete_end':False});self.padding_active=len(self.padding_stages)-1
  if self.padding_active is not None:
   idx=self.padding_active;s=self.padding_stages[idx]
   if a==0x100b8d3e8:s.update(export_call_step=self.steps,export_argument=self.view(self.reg(0),64))
   if a==0x100b8d3ec:s.update(post_export=True,export_return_step=self.steps,exported_view=self.view(int(s['export_output'],16),s['encoded_extent']))
   if s['post_export']:
    if a in[0x100b8d3ec,0x100950fd8,0x10095103c,0x100896930,0x1008969a8]:
     p=self.point(a);p.update(stage_index=idx,registers31=self.registers());self.padding_points.append(p)
    if 0x100000000<=a<0x102000000:
     i=next(CS.disasm(IMAGE.read(a,4),a))
     if i.mnemonic in['braa','brab','br','b','blraa','blrab','blr','bl']:
      target=int(i.op_str[1:],16)if i.mnemonic in['b','bl']else self.reg(int(i.op_str.split(',')[0][1:]));self.padding_edges.append({'stage_index':idx,'pc':hex(a),'step':self.steps,'target':hex(target),'registers31':self.registers(),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
    if a==0x10095103c:s['first_reduction_result']=hex(self.reg(14)&0xffffffff)
    if a==0x1008969a8 or(a==0x10095103c and self.reg(14)&0xffffffff!=0x8b3dc651):s.update(complete_end=True,end_pc=hex(a),end_step=self.steps);self.padding_active=None
  return super().hook(u,a,n,d)
 def read_hook(self,u,access,a,n,value,d):
  if self.padding_active is not None:
   s=self.padding_stages[self.padding_active]
   if s['post_export']:
    p=int(s['export_output'],16);self.padding_reads.append({'stage_index':self.padding_active,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'size_bytes':n,'bytes_hex':self.observe(a,n),'within_export':p<=a and a+n<=p+s['encoded_extent'],'registers31':self.registers(),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'owner_view':self.view(a,n)})
  return super().read_hook(u,access,a,n,value,d)
 def finish(self,r):
  r=super().finish(r);r.update(padding_scope=__doc__,padding_generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),padding_stages=self.padding_stages,padding_points=self.padding_points,padding_reads=self.padding_reads,padding_edges=self.padding_edges,padding_active_at_stop=self.padding_active);return r
