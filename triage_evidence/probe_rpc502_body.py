#!/usr/bin/env python3
"""Original supplemental body parser with observed helper records and epochs.

Extends the frozen complete worker without parser PC/register/frame overrides.
Captures original helper calls,argument/pointed byte observations and actual
source stores. External APIs and PAC remain inherited explicit models. No
native target,IOKit,Mach,loader,file or synchronization API executes.
O(B+V+E+S) bounded time/space;observer prefixes are not guest input schemas.
"""
import copy,hashlib,json,struct
from pathlib import Path
from probe_rpc502_supp import Supplemental,ROOT,SOURCE,IMAGE,ar,uc,STACK

HELPERS={0x10044dd40:'item_parser',0x10045c4f0:'container_helper',0x100440be4:'container_continuation'}
SCHEMA_BASE=0x1010389a0
SCHEMA_CALLBACKS={0x10040f7a4,0x10044f7a4,0x10041f768,0x10040f1d4,0x1004150f0,0x100413254,0x10043cf70,0x10043fdb0,0x10000cd38,0x10000aecc,0x100411e10,0x10043ed6c,0x10044c204,0x10043e878,0x100421ec4}
POINTS={0x1008c2d7c,0x1009e5648,0x1009e565c,0x100315ae8,0x10022cb78,0x100a657d4,0x10044ddc4,0x10044ddf0,0x10044de08,0x10045c570,0x100440c6c}

class BodyProbe(Supplemental):
 def __init__(self,raw,fixture=None):
  self.body_calls=[];self.active_body=[];self.body_reads=[];self.body_writes=[];self.body_points=[];self.body_mapping_reads=[];self.item_outputs={};self.item_output_reads=[];self.schema_reads=[];self.schema_callbacks=[];self.digest_contexts={};self.digest_reads=[];self.digest_writes=[];self.digest_snapshots=[];self.active_schema=[];self.core_stack_stores=[];self.atomic_points=[];self.item_span_reads=[]
  self.body_cpu_model=(fixture or {}).get('body_cpu_model','A72');assert self.body_cpu_model in ['A72','MAX']
  if self.body_cpu_model=='MAX':
   # Configure the new private CPU before the frozen constructor maps memory.
   original_factory=uc.Uc;constructed=[]
   def factory(*args,**kwargs):
    instance=original_factory(*args,**kwargs);instance.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);constructed.append(instance);return instance
   uc.Uc=factory
   try:super().__init__(raw,fixture)
   finally:uc.Uc=original_factory
   assert constructed==[self.u]
  else:super().__init__(raw,fixture)
  assert self.u.ctl_get_cpu_model()==(ar.UC_CPU_ARM64_MAX if self.body_cpu_model=='MAX'else ar.UC_CPU_ARM64_A72)
  self.body_instruction_budget=(fixture or {}).get('body_instruction_budget',1000000);assert 200000<=self.body_instruction_budget<=2000000
  original_start=self.u.emu_start
  def declared_budget(begin,until,timeout=0,count=0):
   assert begin==0x100422d48 and count==200000
   return original_start(begin,until,timeout=timeout,count=self.body_instruction_budget)
  self.u.emu_start=declared_budget
 def registers(self):return [hex(self.reg(j))for j in range(29)]+[hex(self.u.reg_read(ar.UC_ARM64_REG_X29)),hex(self.reg(30))]
 def observe(self,p,n):
  try:return bytes(self.u.mem_read(p,n)).hex()
  except uc.UcError:return None
 def record_view(self,p):
  b=self.observe(p,64);out={'address':hex(p),'prefix64_hex':b,'pointed_views':[],'observer_only_definedness_unknown':True}
  if b:
   raw=bytes.fromhex(b)
   for off in range(8,64,8):
    ptr=struct.unpack_from('<Q',raw,off)[0]
    if STACK<=ptr<STACK+0x80000:
     n=min(128,STACK+0x80000-ptr);v=self.observe(ptr,n);out['pointed_views'].append({'slot_offset':off,'pointer':hex(ptr),'size_bytes':n,'bytes_hex':v})
  return out
 def hook(self,u,a,n,d):
  self.flush()
  if self.active_schema and a==int(self.schema_callbacks[self.active_schema[-1]]['return_pc'],16):
   idx=self.active_schema.pop();call=self.schema_callbacks[idx];call['return_step']=self.steps;call['return_registers']=self.registers();call['x0_after256_hex']=self.observe(int(call['registers'][0],16),256);call['digest_context_snapshots']={hex(p):self.observe(p,100)for p,v in self.digest_contexts.items()if v.get('schema_call')==idx}
   for p,v in self.digest_contexts.items():
    if v.get('schema_call')==idx:v['retired_at_step']=self.steps
  if self.active_body and a==int(self.body_calls[self.active_body[-1]]['return_pc'],16):
   idx=self.active_body.pop();call=self.body_calls[idx];call['return_step']=self.steps;call['returned_view']=self.record_view(int(call['argument_pointer'],16));call['return_registers']=self.registers()
  if self.active_core and a in [0x100a04c58,0x100a04c5c]:
   ptr=self.reg(19);self.atomic_points.append({'pc':hex(a),'step':self.steps,'address':hex(ptr),'memory32_hex':self.observe(ptr,4),'registers':self.registers()})
  if self.active_core and a==0x10065f11c:
   self.digest_snapshots.append({'pc':hex(a),'step':self.steps,'contexts':{hex(p):self.observe(p,100)for p in self.digest_contexts}})
  if self.supp_phase and a in HELPERS:
   if self.digest_contexts:self.digest_snapshots.append({'pc':hex(a),'step':self.steps,'contexts':{hex(p):self.observe(p,100)for p in self.digest_contexts}})
   p=self.reg(0);call={'helper':HELPERS[a],'entry':hex(a),'entry_step':self.steps,'argument_pointer':hex(p),'return_pc':hex(self.reg(30)),'entry_registers':self.registers(),'entry_view':self.record_view(p),'stack_pointer':hex(u.reg_read(ar.UC_ARM64_REG_SP))};self.body_calls.append(call);self.active_body.append(len(self.body_calls)-1)
   if a==0x10045c4f0:
    raw=bytes.fromhex(call['entry_view']['prefix64_hex']);ptr=struct.unpack_from('<Q',raw,16)[0];self.digest_contexts[ptr]={'introduced_at_call':len(self.body_calls)-1,'schema_call':self.active_schema[-1]if self.active_schema else None}
   if a==0x10044dd40:
    raw=bytes.fromhex(call['entry_view']['prefix64_hex'])
    for off,width in [(24,4),(32,8),(48,4),(56,4)]:
     ptr=struct.unpack_from('<Q',raw,off)[0];self.item_outputs[ptr]={'slot_offset':off,'width':width,'call_index':len(self.body_calls)-1}
  if self.active_core and a in SCHEMA_CALLBACKS:
   self.schema_callbacks.append({'return_pc':hex(self.reg(30)),'entry':hex(a),'step':self.steps,'registers':self.registers(),'x0_view':self.record_view(self.reg(0)),'x1_view':self.record_view(self.reg(1)),'x0_prefix256_hex':self.observe(self.reg(0),256)})
   self.active_schema.append(len(self.schema_callbacks)-1)
  if self.active_core and a in POINTS:
   self.body_points.append({'pc':hex(a),'step':self.steps,'sp':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers':self.registers()})
  return super().hook(u,a,n,d)
 def watched(self,a,n):
  if not self.active_body:return None
  idx=self.active_body[-1];call=self.body_calls[idx];p=int(call['argument_pointer'],16)
  regions=[('argument',p,64)]+[('pointed_'+str(e['slot_offset']),int(e['pointer'],16),e['size_bytes'])for e in call['entry_view']['pointed_views']]
  for role,p,size in regions:
   if a<p+size and a+n>p:return idx,role,p
  return None
 def read_hook(self,u,access,a,n,value,d):
  if self.active_core:
   for p,v in self.digest_contexts.items():
    if 'retired_at_step'in v:continue
    if a<p+100 and a+n>p:self.digest_reads.append({'context_pointer':hex(p),'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'offset_bytes':a-p,'size_bytes':n,'bytes_hex':self.observe(a,n),'registers':self.registers()})
  if self.active_core and SCHEMA_BASE<=a<SCHEMA_BASE+26*48:self.schema_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'row':(a-SCHEMA_BASE)//48,'offset_bytes':(a-SCHEMA_BASE)%48,'size_bytes':n,'bytes_hex':self.observe(a,n),'registers':self.registers()})
  if self.active_core:
   for p,owner in self.item_outputs.items():
    if a<p+owner['width']and a+n>p:self.item_output_reads.append({**owner,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'bytes_hex':self.observe(a,n),'size_bytes':n,'registers':self.registers()})
  watch=self.watched(a,n)
  if watch:
   idx,role,p=watch;self.body_reads.append({'call_index':idx,'role':role,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'offset_bytes':a-p,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'registers':self.registers()})
  if self.active_body and self.body_calls[self.active_body[-1]]['helper']=='item_parser'and 0x5300000000<=a<0x5300040000:
   call=self.body_calls[self.active_body[-1]];p=int(call['argument_pointer'],16);raw=bytes.fromhex(call['entry_view']['prefix64_hex']);key=((p^0xe732d262)*0xba209ef7)&0xffffffff;base=struct.unpack_from('<Q',raw,8)[0];extent=(struct.unpack_from('<I',raw,40)[0]+key-0x67ac8198)&0xffffffff;self.item_span_reads.append({'call_index':self.active_body[-1],'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'offset_bytes':a-base,'size_bytes':n,'declared_span_bytes':extent,'within_span':base<=a and a+n<=base+extent,'bytes_hex':self.observe(a,n)})
  if self.active_core and 0x5300000000<=a<0x5300040000:self.body_mapping_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'offset_bytes':a-0x5300000000,'size_bytes':n,'bytes_hex':self.observe(a,n)})
  return super().read_hook(u,access,a,n,value,d)
 def write_hook(self,u,access,a,n,value,d):
  if self.active_core:
   for p,v in self.digest_contexts.items():
    if 'retired_at_step'in v:continue
    if a<p+100 and a+n>p:
     e={'context_pointer':hex(p),'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'offset_bytes':a-p,'size_bytes':n};self.digest_writes.append(e);self.pending_owner_stores.append(e)
  watch=self.watched(a,n)
  if watch:
   idx,role,p=watch;e={'call_index':idx,'role':role,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'step':self.steps,'address':hex(a),'offset_bytes':a-p,'size_bytes':n};self.body_writes.append(e);self.pending_owner_stores.append(e)
  answer=super().write_hook(u,access,a,n,value,d)
  if self.active_core and STACK<=a and a+n<=STACK+0x80000:self.core_stack_stores.append(self.stack_stores[-1])
  return answer
 def run(self):
  r=super().run();r.update(scope=__doc__,body_instruction_budget=self.body_instruction_budget,body_cpu_model=self.body_cpu_model,body_helper_calls=self.body_calls,body_helper_reads=self.body_reads,body_helper_writes=self.body_writes,body_points=self.body_points,body_mapping_reads=self.body_mapping_reads,item_output_reads=self.item_output_reads,schema_reads=self.schema_reads,schema_callbacks=self.schema_callbacks,atomic_points=self.atomic_points,item_span_reads=self.item_span_reads,core_stack_stores=self.core_stack_stores,digest_context_lifetimes=self.digest_contexts,digest_context_reads=self.digest_reads,digest_context_writes=self.digest_writes,digest_snapshots=self.digest_snapshots,body_probe_generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest());return r

def file_for_body(body,v=2,A=0,C=128,n=512):
 from probe_rpc502_supp_cases import make
 raw=bytearray(make(v,n,A,len(body),C));D=(32 if v==1 else 12)+32*A if v in[1,4]else 12+A;assert D+len(body)<=n;raw[D:D+len(body)]=body;return bytes(raw)

if __name__=='__main__':
 r=BodyProbe(file_for_body(bytes.fromhex('3003020100'))).run();Path('/tmp/rpc502-body-first.json').write_text(json.dumps(r));print(r['steps'],r['stop_reason'],r['records'][-1]);print([(e['helper'],e['entry_view'],e.get('returned_view'))for e in r['body_helper_calls']])
