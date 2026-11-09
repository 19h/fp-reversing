#!/usr/bin/env python3
"""Restore a sealed CPU boundary and preserve unknown byte identities through copies.
O(snapshot bytes+source visits+byte effects) time/space. Unknown-dependent
addresses, branches, arithmetic and uninspected calls stop; no native API/PAC.
"""
import base64,zlib,struct
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import IMAGE,FIXUPS
from daemon_context_transfer_symbolic import P,WRITABLE
from daemon_seed_material_symbolic import Material,decode
from lskd_values_symbolic import Lift,resize
ALLOWED_CALLS={0x100427514,0x10041a5e0,0x100444d6c,0x100add594,0x100acd9c4}
def unpack_bytes(text):return zlib.decompress(base64.b64decode(text))
class Revisit(Material):
 def width(self,name):return {'s':32,'h':16,'b':8}[name[0]]if name[:1]in ['s','h','b']and name[1:].isdigit()else super().width(name)
 def key(self,name):return 'q'+name[1:]if name[:1]in ['s','h','b']and name[1:].isdigit()else super().key(name)
 @classmethod
 def from_snapshot(cls,snapshot):
  v=cls.__new__(cls);Lift.__init__(v,{'spans':[]});v.F=int(snapshot['frame_SP'],16);v.H=int(snapshot['arena_owner'],16);v.bytes={};v.origins={};v.steps=[];v.pool={};v.fixups=set();v.zero_reads=[];v.changed=set();v.dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);v.dec.detail=True;v.cache={};v.definitions=[];v.definition_stage='source';v.api_models=[];v.phases=[];v.events=[];v.written={};v.flag_change=False;v.unknown_inputs_used={};v.undo_bytes={};v.transaction=False
  private_mask=unpack_bytes(snapshot['private_owner']['known_mask_zlib_base64']);heap_mask=unpack_bytes(snapshot['heap_owner']['known_mask_zlib_base64']);aliases={int(a,16):off for a,off in snapshot['unknown_stack_aliases'].items()};image_mask={int(a,16):known for a,known in snapshot['image_known_overrides'].items()};assert all(image_mask.values()),'unknown image source values require an explicit origin map'
  for region in snapshot['regions']:
   a=int(region['address'],16);raw=unpack_bytes(region['bytes_zlib_base64']);assert len(raw)==region['size_bytes']
   for j,b in enumerate(raw,a):
    private=P<=j<P+0x10000;heap=v.H<=j<v.H+90000
    if private or heap:
     known=private_mask[j-P]if private else heap_mask[j-v.H]
     if known:v.bytes[j]=z3.BitVecVal(b,8)
     elif j in aliases:v.bytes[j]=z3.BitVec('unknown_'+hex(v.F+aliases[j]),8)
    elif any(va<=j<va+size for va,size in WRITABLE):v.bytes[j]=z3.BitVecVal(b,8)
  for reg,shape in snapshot['logical_registers'].items():v.regs[v.key(reg)]=decode(shape,v.F)
  flags=int(snapshot['NZCV'],16);v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(flags&(1<<(31-j))))for j in range(4)]
  return v
 def one(self,i):
  from daemon_callback_simd import apply
  if apply(self,i):return
  if i.mnemonic=='ldurh':
   self.pc=i.address;assert not i.writeback;o=i.operands;self.write(i.reg_name(o[0].reg),self.load(self.address(i,o[1]),2));return
  if i.mnemonic in ['stp','ldp']and i.writeback:
   self.pc=i.address;o=i.operands;base=i.reg_name(o[2].mem.base);assert base=='sp';address=self.address(i,o[2]);n=self.width(i.reg_name(o[0].reg))//8
   for j in range(2):
    reg=i.reg_name(o[j].reg)
    if i.mnemonic=='stp':self.store(z3.simplify(address+j*n),n,self.read(reg),i.address)
    else:self.write(reg,self.load(z3.simplify(address+j*n),n))
   self.write(base,self.read(base)+o[3].imm if len(o)>3 else address);return
  if i.mnemonic=='sturh':
   self.pc=i.address;assert not i.writeback;o=i.operands;self.store(self.address(i,o[1]),2,self.read(i.reg_name(o[0].reg)),i.address);return
  if i.mnemonic=='mvn':
   self.pc=i.address;o=i.operands;reg=i.reg_name(o[0].reg);self.write(reg,~self.operand(i,o[1],self.width(reg)));return
  return super().one(i)
 def load(self,address,n):
  address=z3.simplify(resize(address,64));a=self.concrete(address,'unknown-dependent read address')
  if n==8 and a in FIXUPS:self.fixups.add(a)
  if all(a+j in self.bytes for j in range(n)):
   parts=[self.bytes[a+j]for j in range(n-1,-1,-1)];value=parts[0]if n==1 else z3.simplify(z3.Concat(*parts));self.events.append({'kind':'read','address':hex(a),'size_bytes':n,'value':self.shape(value,n)})
  else:value=super().load(address,n)
  shape=self.shape(value,n)
  for term in shape.get('terms',[]):
   if isinstance(term,dict):self.unknown_inputs_used.setdefault(term['origin'],{'first_read_pc':hex(self.pc),'source_visit_index':len(self.steps)})
  return value
 def store(self,address,n,value,pc):
  a=self.concrete(address,'unknown-dependent write address')
  if self.transaction:
   for j in range(a,a+n):self.undo_bytes.setdefault(j,(j in self.bytes,self.bytes.get(j),j in self.changed))
  return super().store(address,n,value,pc)
 def boundary(self,kind,pc,**kwargs):return {'kind':kind,'pc':hex(pc),'registers31':[self.shape(self.read('x'+str(j)),8)for j in range(31)],'SP':hex(self.concrete(self.read('sp'),'SP')),**kwargs}
 def run_revisit(self,start,limit=100000):
  pc=start
  for _ in range(limit):
   if pc not in self.cache:self.cache[pc]=next(self.dec.disasm(IMAGE.read(pc,4),pc))
   i=self.cache[pc];self.pc=pc;self.events=[];self.written={};self.flag_change=False;row={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic};self.pool[hex(pc)]={**row,'operands':i.op_str};before_regs=self.regs.copy();before_flags=(self.n,self.z,self.carry,self.overflow);before_definitions=len(self.definitions);self.undo_bytes={};self.transaction=True
   try:
    m=i.mnemonic;nextpc=pc+4
    if m in ['braa','blraa','b','bl','br','blr','ret','retaa','retab']:
     direct=m in ['b','bl'];ret=m in ['ret','retaa','retab'];target=i.operands[0].imm if direct else self.concrete(self.read('x30'if ret else i.reg_name(i.operands[0].reg)),'unknown-dependent branch target');call=m in ['bl','blr','blraa']
     if call and target not in ALLOWED_CALLS:
      self.transaction=False;return self.boundary('before_uninspected_call',pc,target=hex(target),modifier16=hex(self.concrete(self.read(i.reg_name(i.operands[1].reg)),'modifier'))if m=='blraa'else None)
     try:IMAGE.read(target,4)
     except (ValueError,AssertionError):
      self.transaction=False;return self.boundary('return_outside_source_image'if ret else'branch_outside_source_image',pc,target=hex(target))
     row['target']=hex(target)
     if m in ['braa','blraa']:row['modifier16']=hex(self.concrete(self.read(i.reg_name(i.operands[1].reg)),'modifier'))
     if call:self.write('x30',z3.BitVecVal(pc+4,64))
     nextpc=target
    elif m.startswith('b.'):
     condition=z3.simplify(self.condition(m[2:]));assert z3.is_true(condition)or z3.is_false(condition),('unknown-dependent conditional branch',hex(pc));nextpc=i.operands[0].imm if z3.is_true(condition)else pc+4;row['target']=hex(nextpc)
    elif m in ['cbz','cbnz','tbz','tbnz']:
     reg=self.read(i.reg_name(i.operands[0].reg));test=reg==0 if m in ['cbz','cbnz']else(z3.LShR(reg,i.operands[1].imm)&1)==0;test=z3.simplify(test);assert z3.is_true(test)or z3.is_false(test),('unknown-dependent tested branch',hex(pc));take=z3.is_true(test)if m in ['cbz','tbz']else z3.is_false(test);nextpc=i.operands[-1].imm if take else pc+4;row['target']=hex(nextpc)
    elif m=='pacibsp':row['return_auth_abstraction']='PACIBSP represented by an abstract unchanged return token; native signing not executed'
    elif m in ['svc','hvc','smc','paciasp','autibsp','autiasp','mrs','msr','brk']:raise AssertionError(('unmodeled system/auth instruction',m))
    else:self.one(i)
    row['events']=self.events;row['registers_after']={name:self.shape(value,16 if name.startswith('q')else 8)for name,value in self.written.items()}
    if self.flag_change:
     values=[z3.simplify(x)for x in [self.n,self.z,self.carry,self.overflow]];assert all(z3.is_true(x)or z3.is_false(x)for x in values),('unknown flags',hex(pc));row['NZCV_after']=sum(1<<(31-j)for j,x in enumerate(values)if z3.is_true(x))
    self.steps.append(row);pc=nextpc;self.transaction=False
   except (AssertionError,ValueError)as error:
    diagnostics={'reason':str(error),'mnemonic':i.mnemonic,'operands':i.op_str,'uncommitted_events':self.events};self.regs=before_regs;self.n,self.z,self.carry,self.overflow=before_flags;del self.definitions[before_definitions:]
    for a,(existed,old,changed)in self.undo_bytes.items():
     if existed:self.bytes[a]=old
     else:self.bytes.pop(a,None)
     if not changed:self.changed.discard(a)
    self.transaction=False;return self.boundary('before_unresolved_source_effect',pc,**diagnostics)
  self.transaction=False;return self.boundary('visit_limit',pc)
