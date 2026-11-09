#!/usr/bin/env python3
"""Observe original certificate-selection/status continuations after startup.

Extends the frozen original callback/worker engine;no PC/frame/register/gate
intervention. API declarations and guard rules are inherited. Byte windows
are observer data with explicit definedness limits,not injected inputs.
No native target,loader,file,Mach,IOKit or synchronization API execution.
O(B+V+E+S) bounded time/space plus compressed phase journals.
"""
import hashlib
from pathlib import Path
from probe_rpc502_startup import StartupProbe,ROOT,SOURCE,ar,STACK
POINTS={0x100950fd8,0x100951038,0x10095103c,0x100896930,0x1008969a4,0x1008969a8,0x100a06bbc,0x100a06bc8,0x10065f11c,0x100a448b0,0x10064b420,0x100a46fc0,0x10076d108,0x10076d170,0x1009752e0,0x10097531c,0x10069cae8}

class AuthProbe(StartupProbe):
 def __init__(self,raw,fixture):
  self.auth_points=[];self.auth_reads=[];self.multiply_visits=0;self.multiply_samples=[]
  super().__init__(raw,fixture)
 def view(self,p,n=256):
  for h in self.heap_allocations:
   if h['address']<=p<h['address']+h['size']:
    off=p-h['address'];n=min(n,h['size']-off);return {'address':hex(p),'owner':hex(h['address']),'role':'private_heap','bytes_hex':self.observe(p,n),'known_mask_hex':bytes(h['initialized'][off:off+n]).hex(),'retired':p in self.retired}
  if STACK<=p<STACK+0x80000:
   n=min(n,STACK+0x80000-p);return {'address':hex(p),'role':'private_stack','bytes_hex':self.observe(p,n),'definedness_unknown':True}
  if 0x100000000<=p<0x102000000:
   return {'address':hex(p),'role':'guest_image_observation','bytes_hex':self.observe(p,n),'original_raw_bytes_hex':self.original_view(p,n),'runtime_normalization_or_writes_possible':True}
  return None
 def original_view(self,p,n):
  from daemon_receive_tools import IMAGE
  try:return IMAGE.read(p,n).hex()
  except ValueError:return None
 def point(self,a):
  sp=self.u.reg_read(ar.UC_ARM64_REG_SP);return {'pc':hex(a),'phase':self.execution_phase,'step':self.steps,'sp':hex(sp),'registers':[hex(self.reg(j))for j in range(29)],'frame_prefix500_hex':self.observe(sp,0x500),'register_views':{str(j):v for j in [0,1,2,8,9,19,20,21,23,24,25]if(v:=self.view(self.reg(j)))is not None},'certificate_tail_view':self.view(self.reg(9)+0x490,0x120)if a==0x10097531c else None}
 def hook(self,u,a,n,d):
  self.flush()
  if a in POINTS:self.auth_points.append(self.point(a))
  if self.execution_phase=='worker'and a==0x1005fc0d0:
   self.multiply_visits+=1
   if self.multiply_visits<=4 or self.multiply_visits&(self.multiply_visits-1)==0:self.multiply_samples.append(self.point(a))
  return super().hook(u,a,n,d)
 def read_hook(self,u,access,a,n,value,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC)
  if pc in [0x100a46fc0,0x100a46fc8,0x100975324,0x10097532c]:self.auth_reads.append({'pc':hex(pc),'phase':self.execution_phase,'step':self.steps,'address':hex(a),'size_bytes':n,'bytes_hex':self.observe(a,n),'owner_view':self.view(a,n)})
  return super().read_hook(u,access,a,n,value,d)
 def finish(self,r):
  r=super().finish(r);r.update(auth_scope=__doc__,auth_generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),auth_points=self.auth_points,auth_reads=self.auth_reads,multiply_visits=self.multiply_visits,multiply_samples=self.multiply_samples);return r
