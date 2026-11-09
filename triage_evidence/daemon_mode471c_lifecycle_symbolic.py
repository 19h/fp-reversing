#!/usr/bin/env python3
"""Mode471C lock creation with disjoint API origins and opaque initializer bytes.
O(snapshot+source visits+effects+expression DAG) time/space. API effects are
declared; no native allocation,initialization,Mach,IOKit or PAC executes.
"""
import z3
from continue_daemon_descriptor_producers import Copies
from daemon_context_lock_symbolic import ContextLock,APIS
from daemon_callback_revisit_symbolic import ALLOWED_CALLS
from daemon_receive_tools import FIXUPS
from daemon_receive_tools import IMAGE
from daemon_import_bindings import binding
from daemon_seed_material_symbolic import decode
from lskd_values_symbolic import resize
from probe_daemon_descriptor_producers import IMPORTS,P,SIZE
HEAP=0x6900001000;MODEL_ORIGIN=0x6b00000000;CELL=0x1010c67c0
ONCE=0x1010b8cd0;CALLBACK=0x10040ebd4;CALLBACK_RETURN=P+0xff300
SYNC={0x10043e508:('pthread_once',0x10109fe80,0x8489),0x100442650:('pthread_once',0x10109fe80,0x8489),0x100361df4:('pthread_rwlock_wrlock',0x1010a0a00,0x4c4d),0x100208efc:('pthread_rwlock_unlock',0x1010a0d78,0x5431)}
FREE_PC=0x10039c988;FREE_SLOT=0x10109ff30
ALLOWED_CALLS.update({0x10043a240,0x10043e280,0x1004423f8,0x10044fc34,0x10046faf8})
class Lifecycle(Copies):
 def configure(self,cfg):
  self.cfg=cfg;self.api_models=[];self.api_origins=[];self.model_cursor=0;self.alloc_count=0;self.heaps={};self.current_heap=None;self.current_outcome=None;self.completed_once=bool(cfg.get('once_completed',True));self.callback_pending=None;self.retired_owners=[];self.borrowed_owners={cfg['old_cell']:200}if cfg.get('old_cell')else{}
  for h,extent in self.borrowed_owners.items():
   for j in range(extent):self.bytes[h+j]=z3.BitVec('unknown_'+hex(h+j),8)
 def fresh(self,n,kind):
  values=[]
  for j in range(n):
   a=MODEL_ORIGIN+self.model_cursor;self.model_cursor+=1;self.api_origins.append({'offset':a-self.F,'kind':kind,'API_index':len(self.api_models)});values.append(z3.BitVec('unknown_'+hex(a),8))
  return values[0]if n==1 else z3.Concat(*reversed(values))
 def load(self,address,n):
  a=self.concrete(resize(address,64),'unknown-dependent read address')
  assert not any(h<a+n and a<h+extent for h,extent in self.retired_owners),('read from retired private owner',hex(a),n)
  if any(h<=a<a+n<=h+extent for h,extent in {**self.heaps,**self.borrowed_owners}.items()):
   assert all(a+j in self.bytes for j in range(n));vals=[self.bytes[a+j]for j in range(n-1,-1,-1)];value=vals[0]if n==1 else z3.simplify(z3.Concat(*vals));shape=self.shape(value,n);self.events.append({'kind':'read','address':hex(a),'size_bytes':n,'value':shape});return value
  return super().load(address,n)
 def store(self,address,n,value,pc):
  a=self.concrete(address,'unknown-dependent write address')
  if any(h<=a<a+n<=h+extent for h,extent in {**self.heaps,**self.borrowed_owners}.items()):
   self.events.append({'kind':'write','address':hex(a),'size_bytes':n,'value':self.shape(resize(value,n*8),n)})
   for j in range(n):
    if self.transaction:self.undo_bytes.setdefault(a+j,(a+j in self.bytes,self.bytes.get(a+j),a+j in self.changed))
    self.bytes[a+j]=z3.simplify(z3.Extract(j*8+7,j*8,resize(value,n*8)));self.changed.add(a+j)
   return
  return super().store(address,n,value,pc)
 def model_api(self,pc,target,modifier):
  name,slot,div=APIS[pc];assert modifier==div and target==IMPORTS[FIXUPS[slot]['target']];args=[self.shape(self.read('x'+str(j)),8)for j in range(8)];preserved={n:self.shape(self.read(n),8)for n in ['sp']+['x'+str(j)for j in range(18,30)]};effects=[]
  if name=='malloc':
   extent=200 if pc==0x10019385c else 960;assert self.concrete(self.read('x0'),'malloc extent')==extent;self.current_outcome=self.cfg['outcomes'][self.alloc_count];self.current_heap=HEAP+4096*self.alloc_count;self.alloc_count+=1;ptr=self.current_heap if self.current_outcome['malloc_nonnull']else 0;ret=z3.BitVecVal(ptr,64)
   if ptr:self.heaps[ptr]=extent;value=self.fresh(extent,'uninitialized_allocation');effects.append({'kind':'write','address':hex(ptr),'size_bytes':extent,'value':self.shape(value,extent),'interpretation':'arbitrary API allocation bytes; no source definition'})
  else:
   extent=200;assert self.concrete(self.read('x0'),'initializer pointer')==self.current_heap and self.concrete(self.read('x1'),'initializer attributes')==0;assert all(z3.is_true(z3.simplify(self.bytes[self.current_heap+j]==0))for j in range(8));ret=z3.Concat(self.fresh(4,'int_return_upper32'),z3.BitVecVal(self.current_outcome['init_status'],32));value=self.fresh(200,'opaque_initializer_object');effects.append({'kind':'write','address':hex(self.current_heap),'size_bytes':200,'value':self.shape(value,200),'interpretation':'opaque post-initializer bytes for either status'})
  for e in effects:
   value=decode(e['value'],self.F);a=int(e['address'],16)
   for j in range(e['size_bytes']):self.bytes[a+j]=z3.simplify(z3.Extract(j*8+7,j*8,value));self.changed.add(a+j)
  self.write('x0',ret)
  for j in range(1,18):self.write('x'+str(j),self.fresh(8,'caller_GPR_clobber'))
  for j in range(32):
   nameq='q'+str(j);low=z3.Extract(63,0,self.read(nameq))if 8<=j<16 else None;self.write(nameq,z3.Concat(self.fresh(8,'caller_SIMD_upper_clobber'),low)if low is not None else self.fresh(16,'caller_SIMD_clobber'))
  self.write('x30',z3.BitVecVal(pc+4,64));flags=[];sources=[]
  for nameflag in['N','Z','C','V']:
   value=self.fresh(1,'caller_NZCV_clobber');sources.append(self.shape(value,1)['terms'][0]['origin']);flags.append((value&1)==1)
  self.n,self.z,self.carry,self.overflow=flags;assert preserved=={n:self.shape(self.read(n),8)for n in preserved};model={'pc':hex(pc),'name':name,'binding':binding(slot),'arguments8':args,'configuration':self.current_outcome.copy(),'allocation_index':self.alloc_count-1,'allocation_address':hex(self.current_heap),'memory_effects':effects,'NZCV_origin_bytes':sources,'preserved':preserved,'native_target_executed':False};self.api_models.append(model);return model
 def sync_return(self,pc):
  name,slot,div=SYNC[pc];args=[self.shape(self.read('x'+str(j)),8)for j in range(8)];before={n:self.shape(self.read(n),8)for n in ['sp']+['x'+str(j)for j in range(18,30)]};effects=[]
  if name=='pthread_once':
   assert self.concrete(self.read('x0'),'once control')==ONCE;value=self.fresh(16,'opaque_once_control');effects.append({'kind':'write','address':hex(ONCE),'size_bytes':16,'value':self.shape(value,16),'interpretation':'opaque native once-control bytes; SDK-sized16-byte owner premise'})
  else:
   ptr=self.concrete(self.read('x0'),'lock pointer');assert ptr!=0
   owners={**self.heaps,**self.borrowed_owners}
   if ptr in owners:
    extent=owners[ptr];value=self.fresh(extent,'opaque_lock_primitive_object');effects.append({'kind':'write','address':hex(ptr),'size_bytes':extent,'value':self.shape(value,extent),'interpretation':'opaque post-lock-operation bytes'})
  for e in effects:
   value=decode(e['value'],self.F);a=int(e['address'],16)
   for j in range(e['size_bytes']):self.bytes[a+j]=z3.simplify(z3.Extract(j*8+7,j*8,value));self.changed.add(a+j)
  status=0 if name=='pthread_once'else self.cfg.get('primitive_status',0);self.write('x0',z3.Concat(self.fresh(4,'int_return_upper32'),z3.BitVecVal(status,32)))
  for j in range(1,18):self.write('x'+str(j),self.fresh(8,'caller_GPR_clobber'))
  for j in range(32):
   nq='q'+str(j);low=z3.Extract(63,0,self.read(nq))if 8<=j<16 else None;self.write(nq,z3.Concat(self.fresh(8,'caller_SIMD_upper_clobber'),low)if low is not None else self.fresh(16,'caller_SIMD_clobber'))
  self.write('x30',z3.BitVecVal(pc+4,64));flags=[];sources=[]
  for flag in ['N','Z','C','V']:
   byte=self.fresh(1,'caller_NZCV_clobber');sources.append(self.shape(byte,1)['terms'][0]['origin']);flags.append((byte&1)==1)
  self.n,self.z,self.carry,self.overflow=flags;assert before=={n:self.shape(self.read(n),8)for n in before};self.completed_once|=name=='pthread_once';return {'pc':hex(pc),'name':name,'binding':binding(slot),'arguments8':args,'returned_status32':status,'memory_effects':effects,'NZCV_origin_bytes':sources,'preserved':before,'native_target_executed':False}
 def free_return(self,pc,target,modifier):
  assert target==IMPORTS[FIXUPS[FREE_SLOT]['target']]and modifier==0x46a2;ptr=self.concrete(self.read('x0'),'free input');assert ptr==self.physical.TOKEN;args=[self.shape(self.read('x'+str(j)),8)for j in range(8)];before={n:self.shape(self.read(n),8)for n in ['sp']+['x'+str(j)for j in range(18,30)]};self.retired_owners.append((ptr,8));self.write('x0',self.fresh(8,'void_return_x0'))
  for j in range(1,18):self.write('x'+str(j),self.fresh(8,'caller_GPR_clobber'))
  for j in range(32):
   n='q'+str(j);low=z3.Extract(63,0,self.read(n))if 8<=j<16 else None;self.write(n,z3.Concat(self.fresh(8,'caller_SIMD_upper_clobber'),low)if low is not None else self.fresh(16,'caller_SIMD_clobber'))
  self.write('x30',z3.BitVecVal(pc+4,64));flags=[];sources=[]
  for f in ['N','Z','C','V']:
   byte=self.fresh(1,'caller_NZCV_clobber');sources.append(self.shape(byte,1)['terms'][0]['origin']);flags.append((byte&1)==1)
  self.n,self.z,self.carry,self.overflow=flags;assert before=={n:self.shape(self.read(n),8)for n in before};model={'pc':hex(pc),'name':'free','binding':binding(FREE_SLOT),'arguments8':args,'memory_effects':[],'owner_effects':[{'kind':'retire','address':hex(ptr),'size_bytes':8}],'NZCV_origin_bytes':sources,'preserved':before,'native_target_executed':False};self.api_models.append(model);return model
 def run_lifecycle(self,start,limit=100000):
  pc=start
  for _ in range(limit):
   if pc not in self.cache:self.cache[pc]=next(self.dec.disasm(IMAGE.read(pc,4),pc))
   i=self.cache[pc];self.pc=pc;self.events=[];self.written={};self.flag_change=False;row={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic};self.pool[hex(pc)]={**row,'operands':i.op_str};oldregs=self.regs.copy();oldflags=(self.n,self.z,self.carry,self.overflow);olddefs=len(self.definitions);self.undo_bytes={};self.transaction=True
   try:
    m=i.mnemonic;nextpc=pc+4
    if m in ['braa','blraa','b','bl','br','blr','ret','retaa','retab']:
     direct=m in ['b','bl'];ret=m in ['ret','retaa','retab'];target=i.operands[0].imm if direct else self.concrete(self.read('x30'if ret else i.reg_name(i.operands[0].reg)),'unknown-dependent branch target');call=m in ['bl','blr','blraa'];modifier=self.concrete(self.read(i.reg_name(i.operands[1].reg)),'modifier')if m in ['braa','blraa']else None
     if call and pc in APIS:
      if APIS[pc][0]=='malloc'and self.alloc_count>=len(self.cfg['outcomes']):self.transaction=False;return self.boundary('before_next_context_allocation',pc,target=hex(target),modifier16=hex(modifier))
      row['api_model']=self.model_api(pc,target,modifier);nextpc=pc+4
     elif call and pc==FREE_PC:row['api_model']=self.free_return(pc,target,modifier);nextpc=pc+4
     elif call and pc in SYNC:
      name,slot,div=SYNC[pc];assert target==IMPORTS[FIXUPS[slot]['target']]and modifier==div
      if name=='pthread_once'and not self.completed_once:
       assert self.callback_pending is None and self.concrete(self.read('x0'),'once control')==ONCE and self.concrete(self.read('x1'),'once callback')==CALLBACK;sp=self.read('sp');saved={n:self.shape(self.read(n),8)for n in ['x'+str(j)for j in range(19,30)]};self.callback_pending={'pc':pc,'SP':sp,'saved':saved,'arguments8':[self.shape(self.read('x'+str(j)),8)for j in range(8)]};self.write('sp',sp-self.cfg.get('callback_gap',256));self.write('x30',z3.BitVecVal(CALLBACK_RETURN,64));row['callback_invocation_model']={'pc':hex(pc),'binding':binding(slot),'arguments8':self.callback_pending['arguments8'],'entry_SP':hex(self.concrete(self.read('sp'),'callback SP')),'return_token':hex(CALLBACK_RETURN),'model_transition_not_original_branch':True};nextpc=CALLBACK
      else:
       model=self.sync_return(pc);row['api_model']=model;self.api_models.append(model);nextpc=pc+4
     elif ret and target==CALLBACK_RETURN and self.callback_pending is not None:
      pending=self.callback_pending;assert z3.is_true(z3.simplify(self.read('sp')==pending['SP']-self.cfg.get('callback_gap',256)))and pending['saved']=={n:self.shape(self.read(n),8)for n in pending['saved']};self.callback_pending=None;self.write('sp',pending['SP']);self.write('x0',decode(pending['arguments8'][0],self.F));self.write('x1',decode(pending['arguments8'][1],self.F));model=self.sync_return(pending['pc']);model['arguments8']=pending['arguments8'];model['callback_invoked']=True;row['after_callback_api_model']=model;self.api_models.append(model);nextpc=pending['pc']+4
     else:
      if call and target not in ALLOWED_CALLS:self.transaction=False;return self.boundary('before_uninspected_call',pc,target=hex(target),modifier16=hex(modifier)if modifier is not None else None)
      try:IMAGE.read(target,4)
      except(ValueError,AssertionError):self.transaction=False;return self.boundary('return_outside_source_image'if ret else'branch_outside_source_image',pc,target=hex(target))
      if call:self.write('x30',z3.BitVecVal(pc+4,64))
      nextpc=target
     row['target']=hex(target)
     if modifier is not None:row['modifier16']=hex(modifier)
    elif m.startswith('b.'):
     condition=z3.simplify(self.condition(m[2:]));assert z3.is_true(condition)or z3.is_false(condition),('unknown-dependent conditional branch',hex(pc));nextpc=i.operands[0].imm if z3.is_true(condition)else pc+4;row['target']=hex(nextpc)
    elif m in ['cbz','cbnz','tbz','tbnz']:
     reg=self.read(i.reg_name(i.operands[0].reg));test=reg==0 if m in ['cbz','cbnz']else(z3.LShR(reg,i.operands[1].imm)&1)==0;test=z3.simplify(test);assert z3.is_true(test)or z3.is_false(test),('unknown-dependent tested branch',hex(pc));take=z3.is_true(test)if m in ['cbz','tbz']else z3.is_false(test);nextpc=i.operands[-1].imm if take else pc+4;row['target']=hex(nextpc)
    elif m in ['pacibsp','paciza']:row['return_auth_abstraction']='logical unchanged authenticated token; native signing/authentication not executed'
    elif m in ['svc','hvc','smc','paciasp','autibsp','autiasp','mrs','msr','brk']:raise AssertionError(('unmodeled system/auth instruction',m))
    else:self.one(i)
    row['events']=self.events;row['registers_after']={n:self.shape(v,16 if n.startswith('q')else 8)for n,v in self.written.items()}
    if self.flag_change:
     flags=[z3.simplify(x)for x in [self.n,self.z,self.carry,self.overflow]];assert all(z3.is_true(x)or z3.is_false(x)for x in flags),('unknown flags',hex(pc));row['NZCV_after']=sum(1<<(31-j)for j,x in enumerate(flags)if z3.is_true(x))
    self.steps.append(row);pc=nextpc;self.transaction=False
   except(AssertionError,ValueError)as error:
    diagnostics={'reason':str(error),'mnemonic':i.mnemonic,'operands':i.op_str,'uncommitted_events':self.events};self.regs=oldregs;self.n,self.z,self.carry,self.overflow=oldflags;del self.definitions[olddefs:]
    for a,(existed,value,changed)in self.undo_bytes.items():
     if existed:self.bytes[a]=value
     else:self.bytes.pop(a,None)
     if not changed:self.changed.discard(a)
    self.transaction=False;return self.boundary('before_unresolved_source_effect',pc,**diagnostics)
  return self.boundary('visit_limit',pc)
