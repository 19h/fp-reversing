#!/usr/bin/env python3
"""Original-source context lock continuation with arbitrary AAPCS clobbers.
O(snapshot+source visits+effects) time/space. malloc/init returns are declared;
initializer object bytes are opaque after the call. Unknown-dependent source
arithmetic/control/addresses stop. Native APIs/PAC never execute.
"""
import z3
from daemon_callback_revisit_symbolic import Revisit,ALLOWED_CALLS
from daemon_context_transfer_symbolic import P,WRITABLE
from daemon_seed_material_symbolic import decode
from daemon_import_bindings import binding
from daemon_receive_tools import IMAGE
from lskd_values_symbolic import resize
APIS={0x10019385c:('malloc',0x10109ff58,0x6aa4),0x100130fcc:('pthread_rwlock_init',0x1010a0dd0,0xa027),0x10038eb5c:('malloc',0x10109ff58,0x6aa4)}
HEAP=0x6600001000;EXTENT=200;MODEL_ORIGIN=0x6800000000
class ContextLock(Revisit):
 def configure(self,cfg):self.cfg=cfg;self.api_models=[];self.api_origins=[];self.active_heap=False;self.model_cursor=0;self.alloc_count=0;self.heaps={};self.current_heap=HEAP;self.current_outcome=None
 def fresh(self,n,kind):
  terms=[]
  for j in range(n):
   a=MODEL_ORIGIN+self.model_cursor;self.model_cursor+=1;self.api_origins.append({'offset':a-self.F,'kind':kind,'API_index':len(self.api_models)});terms.append(z3.BitVec('unknown_'+hex(a),8))
  return terms[0]if n==1 else z3.Concat(*reversed(terms))
 def store(self,address,n,value,pc):
  a=self.concrete(address,'unknown-dependent write address')
  if any(h<=a<a+n<=h+size for h,size in self.heaps.items()):
   assert self.active_heap;shape=self.shape(resize(value,n*8),n);self.events.append({'kind':'write','address':hex(a),'size_bytes':n,'value':shape})
   for j in range(n):
    if self.transaction:self.undo_bytes.setdefault(a+j,(a+j in self.bytes,self.bytes.get(a+j),a+j in self.changed))
    self.bytes[a+j]=z3.simplify(z3.Extract(8*j+7,8*j,resize(value,n*8)));self.changed.add(a+j)
   return
  return super().store(address,n,value,pc)
 def load(self,address,n):
  a=self.concrete(address,'unknown-dependent read address')
  if any(h<=a<a+n<=h+size for h,size in self.heaps.items()):
   assert self.active_heap
   for at in range(a,a+n):
    if at not in self.bytes:self.bytes[at]=z3.BitVec('unknown_'+hex(at),8);self.origins[at]={'first_read_pc':hex(self.pc),'offset':at-self.F}
  return super().load(address,n)
 def model_api(self,pc,target,modifier):
  name,slot,div=APIS[pc];assert target==0x7c100000 and modifier==div;args=[self.shape(self.read('x'+str(j)),8)for j in range(8)];preserved={n:self.shape(self.read(n),8)for n in ['sp']+['x'+str(j)for j in range(18,30)]};effects=[]
  if name=='malloc':
   self.current_extent=200 if pc==0x10019385c else 960;assert self.concrete(self.read('x0'),'malloc extent')==self.current_extent;self.current_outcome=self.cfg['outcomes'][self.alloc_count];self.current_heap=HEAP+self.alloc_count*0x1000;self.alloc_count+=1;value=self.current_heap if self.current_outcome['malloc_nonnull']else 0;ret=z3.BitVecVal(value,64);self.active_heap=bool(self.heaps)or bool(value)
   if value:self.heaps[value]=self.current_extent
   if value:
    b=self.fresh(self.current_extent,'uninitialized_allocation');effects.append({'kind':'write','address':hex(self.current_heap),'size_bytes':self.current_extent,'value':self.shape(b,self.current_extent),'interpretation':'arbitrary uninitialized allocation bytes, not source-defined writes'})
  else:
   assert self.concrete(self.read('x0'),'initializer pointer')==self.current_heap and self.concrete(self.read('x1'),'initializer attributes')==0 and all(z3.is_true(z3.simplify(self.bytes[self.current_heap+j]==0))for j in range(8));status=self.current_outcome['init_status'];ret=z3.Concat(self.fresh(4,'int_return_upper32'),z3.BitVecVal(status,32));b=self.fresh(EXTENT,'opaque_initializer_object');effects.append({'kind':'write','address':hex(self.current_heap),'size_bytes':EXTENT,'value':self.shape(b,EXTENT),'interpretation':'arbitrary post-initializer object bytes for either return status'})
  for e in effects:
   b=decode(e['value'],self.F);a=int(e['address'],16)
   for j in range(e['size_bytes']):self.bytes[a+j]=z3.simplify(z3.Extract(8*j+7,8*j,b));self.changed.add(a+j)
  self.write('x0',ret)
  for j in range(1,18):self.write('x'+str(j),self.fresh(8,'caller_GPR_clobber'))
  for j in range(32):
   n='q'+str(j);low=z3.Extract(63,0,self.read(n))if 8<=j<16 else None;self.write(n,z3.Concat(self.fresh(8,'caller_SIMD_upper_clobber'),low)if low is not None else self.fresh(16,'caller_SIMD_clobber'))
  self.write('x30',z3.BitVecVal(pc+4,64));sources=[];flags=[]
  for n in ['N','Z','C','V']:
   byte=self.fresh(1,'caller_NZCV_clobber');sources.append(self.shape(byte,1)['terms'][0]['origin']);flags.append((byte&1)==1)
  self.n,self.z,self.carry,self.overflow=flags;assert preserved=={n:self.shape(self.read(n),8)for n in preserved}
  model={'pc':hex(pc),'name':name,'binding':binding(slot),'arguments8':args,'configuration':self.current_outcome.copy(),'allocation_index':self.alloc_count-1,'allocation_address':hex(self.current_heap),'memory_effects':effects,'NZCV_origin_bytes':sources,'preserved':preserved,'native_target_executed':False};self.api_models.append(model);return model
 def run_context_lock(self,start,limit=100000):
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
     else:
      if call and target not in ALLOWED_CALLS|{0x10043a240}:self.transaction=False;return self.boundary('before_uninspected_call',pc,target=hex(target),modifier16=hex(modifier)if modifier is not None else None)
      try:IMAGE.read(target,4)
      except (ValueError,AssertionError):self.transaction=False;return self.boundary('return_outside_source_image'if ret else'branch_outside_source_image',pc,target=hex(target))
      if call:self.write('x30',z3.BitVecVal(pc+4,64))
      nextpc=target
     row['target']=hex(target)
     if modifier is not None:row['modifier16']=hex(modifier)
    elif m.startswith('b.'):
     condition=z3.simplify(self.condition(m[2:]));assert z3.is_true(condition)or z3.is_false(condition),('unknown-dependent conditional branch',hex(pc));nextpc=i.operands[0].imm if z3.is_true(condition)else pc+4;row['target']=hex(nextpc)
    elif m in ['cbz','cbnz','tbz','tbnz']:
     reg=self.read(i.reg_name(i.operands[0].reg));test=reg==0 if m in ['cbz','cbnz']else(z3.LShR(reg,i.operands[1].imm)&1)==0;test=z3.simplify(test);assert z3.is_true(test)or z3.is_false(test),('unknown-dependent tested branch',hex(pc));take=z3.is_true(test)if m in ['cbz','tbz']else z3.is_false(test);nextpc=i.operands[-1].imm if take else pc+4;row['target']=hex(nextpc)
    elif m=='pacibsp':row['return_auth_abstraction']='logical unchanged return token; native authentication not executed'
    elif m in ['svc','hvc','smc','paciasp','autibsp','autiasp','mrs','msr','brk']:raise AssertionError(('unmodeled system/auth instruction',m))
    else:self.one(i)
    row['events']=self.events;row['registers_after']={n:self.shape(v,16 if n.startswith('q')else 8)for n,v in self.written.items()}
    if self.flag_change:
     flags=[z3.simplify(x)for x in [self.n,self.z,self.carry,self.overflow]];assert all(z3.is_true(x)or z3.is_false(x)for x in flags),('unknown flags',hex(pc));row['NZCV_after']=sum(1<<(31-j)for j,x in enumerate(flags)if z3.is_true(x))
    self.steps.append(row);pc=nextpc;self.transaction=False
   except (AssertionError,ValueError)as e:
    diagnostics={'reason':str(e),'mnemonic':i.mnemonic,'operands':i.op_str,'uncommitted_events':self.events};self.regs=oldregs;self.n,self.z,self.carry,self.overflow=oldflags;del self.definitions[olddefs:]
    for a,(existed,value,changed)in self.undo_bytes.items():
     if existed:self.bytes[a]=value
     else:self.bytes.pop(a,None)
     if not changed:self.changed.discard(a)
    self.transaction=False;return self.boundary('before_unresolved_source_effect',pc,**diagnostics)
  return self.boundary('visit_limit',pc)
