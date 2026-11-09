#!/usr/bin/env python3
"""Typed free models for source-verified field and object cleanup call sites.
Void X0,volatile GPR/SIMD/NZCV remain arbitrary; owned identities retire without
native calls. O(source effects+expression DAG), no source PC/byte mutation.
"""
import z3
from daemon_mode471c_lifecycle_symbolic import Lifecycle
from daemon_context_lock_symbolic import APIS
from daemon_import_bindings import binding
from probe_daemon_descriptor_producers import P,IMPORTS
from daemon_receive_tools import FIXUPS
from lskd_values_symbolic import resize
FREE_CALLS={0x100bdf330:('free',0x10109ff30,0x46a2),0x100be0e80:('free',0x10109ff30,0x46a2),0x100bd9d88:('free',0x10109ff30,0x46a2)}
class Consumers(Lifecycle):
 input_configuration=None
 def configure(self,cfg):
  super().configure(cfg);c=self.input_configuration;self.input_cfg=c;self.free_owners={P+0x1000:8,P+0x20000:4096}
  if c['chain']!='head':self.free_owners[P+0x24000]=4096
  if c['fields']in['310','both']:self.free_owners[P+0x30000]=8
  if c['fields']in['d8','both']:self.free_owners[P+0x34000]=8
 def model_api(self,pc,target,modifier):return self.free_return(pc,target,modifier)if pc in FREE_CALLS else super().model_api(pc,target,modifier)
 def store(self,address,n,value,pc):
  a=self.concrete(address,'unknown-dependent write address');assert not any(h<a+n and a<h+extent for h,extent in self.retired_owners),('write to retired private owner',hex(a),n);return super().store(address,n,value,pc)
 def free_return(self,pc,target,modifier):
  assert target==IMPORTS[FIXUPS[0x10109ff30]['target']]and modifier==0x46a2;ptr=self.concrete(self.read('x0'),'free input');assert ptr in self.free_owners and not any(h==ptr for h,n in self.retired_owners),(hex(pc),hex(ptr));extent=self.free_owners[ptr];args=[self.shape(self.read('x'+str(j)),8)for j in range(8)];before={n:self.shape(self.read(n),8)for n in ['sp']+['x'+str(j)for j in range(18,30)]};self.retired_owners.append((ptr,extent));self.write('x0',self.fresh(8,'void_return_x0'))
  for j in range(1,18):self.write('x'+str(j),self.fresh(8,'caller_GPR_clobber'))
  for j in range(32):
   n='q'+str(j);low=z3.Extract(63,0,self.read(n))if 8<=j<16 else None;self.write(n,z3.Concat(self.fresh(8,'caller_SIMD_upper_clobber'),low)if low is not None else self.fresh(16,'caller_SIMD_clobber'))
  self.write('x30',z3.BitVecVal(pc+4,64));flags=[];sources=[]
  for flag in['N','Z','C','V']:
   value=self.fresh(1,'caller_NZCV_clobber');sources.append(self.shape(value,1)['terms'][0]['origin']);flags.append((value&1)==1)
  self.n,self.z,self.carry,self.overflow=flags;assert before=={n:self.shape(self.read(n),8)for n in before};model={'pc':hex(pc),'name':'free','binding':binding(0x10109ff30),'arguments8':args,'memory_effects':[],'owner_effects':[{'kind':'retire','address':hex(ptr),'size_bytes':extent}],'NZCV_origin_bytes':sources,'preserved':before,'native_target_executed':False};self.api_models.append(model);return model
APIS.update(FREE_CALLS)
