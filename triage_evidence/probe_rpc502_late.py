#!/usr/bin/env python3
"""Observe late carrier data/control/call interfaces from original predecessor.

Extends frozen PolicyContractProbe. All changes are observer-only;two file
inputs are fixed before all guest instructions. No internal PC/record/frame,
readiness,branch or arithmetic intervention. API/PAC models inherited.
O(B+V+E+S) bounded work/space plus captured late calls/selected-cell accesses.
No native target,loader,IOKit,Mach,credential,synchronization or IDB action.
"""
import hashlib,struct
from pathlib import Path
from probe_rpc502_policy_cases import PolicyContractProbe,ROOT,SOURCE
from probe_rpc502_startup import ar
from daemon_receive_tools import IMAGE,CS
POINTS={0x100747f6c,0x100747f90,0x100a8b838,0x100a8b860,0x100a8b880,0x100a8b8b0,0x100a21aac,0x100a21ac0,0x100a21ae4,0x10065730c,0x10065731c,0x100657368,0x1006573c4,0x100950fd8,0x10095103c,0x100a4fbac,0x10098731c,0x10065986c,0x100919330,0x100919334,0x100a0a5dc}
CELLS=[(0x68,4),(0xec,4),(0x110,4),(0x138,8),(0x154,4),(0x178,4),(0x238,8),(0x338,8),(0x3a0,8),(0x6b8,64)]
class LateProbe(PolicyContractProbe):
 def __init__(self,*args):
  self.late_active=False;self.late_frame=None;self.late_points=[];self.late_reads=[];self.late_writes=[];self.late_calls=[];self.active_late_calls=[]
  super().__init__(*args)
 def late_point(self,a):
  p=self.point(a);p['registers31']=self.registers();p['frame700_hex']=self.observe(self.u.reg_read(ar.UC_ARM64_REG_SP),0x700);p['pointed_views']={str(j):v for j in[0,1,2,3,8,9,10,11,20,25,26]if(v:=self.view(self.reg(j),0x400))is not None};return p
 def hook(self,u,a,n,d):
  self.flush()
  if a==0x100747f6c:self.late_active=True;self.late_frame=u.reg_read(ar.UC_ARM64_REG_SP)
  if self.late_active:
   if self.active_late_calls and a==int(self.late_calls[self.active_late_calls[-1]]['return_pc'],16):
    idx=self.active_late_calls.pop();c=self.late_calls[idx];c.update(return_step=self.steps,returned_registers31=self.registers(),return_SP=hex(u.reg_read(ar.UC_ARM64_REG_SP)))
   if a in POINTS:self.late_points.append(self.late_point(a))
   if 0x100000000<=a<0x102000000:
    i=next(CS.disasm(IMAGE.read(a,4),a))
    if i.mnemonic in ['bl','blr','blraa','blrab']:
     target=int(i.op_str[1:],16)if i.mnemonic=='bl'else self.reg(int(i.op_str.split(',')[0][1:]));views={str(j):v for j in range(8)if(v:=self.view(self.reg(j),0x100))is not None};c={'pc':hex(a),'step':self.steps,'target':hex(target),'import_name':self.imports.get(target),'return_pc':hex(a+4),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':self.registers(),'pointed_views':views};self.late_calls.append(c);self.active_late_calls.append(len(self.late_calls)-1)
  return super().hook(u,a,n,d)
 def selected_cell(self,a,n):
  if self.late_frame is None:return []
  return[off for off,size in CELLS if a<self.late_frame+off+size and a+n>self.late_frame+off]
 def read_hook(self,u,access,a,n,value,d):
  if self.late_active and(self.selected_cell(a,n)or 0x5200000000<=a<0x5200040000):self.late_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'size_bytes':n,'cells':self.selected_cell(a,n),'bytes_hex':self.observe(a,n),'registers31':self.registers(),'owner_view':self.view(a,n)})
  return super().read_hook(u,access,a,n,value,d)
 def write_hook(self,u,access,a,n,value,d):
  if self.late_active and self.selected_cell(a,n):
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'size_bytes':n,'cells':self.selected_cell(a,n)};self.late_writes.append(e);self.pending_owner_stores.append(e)
  return super().write_hook(u,access,a,n,value,d)
 def finish(self,r):
  r=super().finish(r);r.update(late_scope=__doc__,late_generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),late_frame=hex(self.late_frame)if self.late_frame is not None else None,late_points=self.late_points,late_cell_reads=self.late_reads,late_cell_writes=self.late_writes,late_calls=self.late_calls,incomplete_late_call_indices=self.active_late_calls);return r
