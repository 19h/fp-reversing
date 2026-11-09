#!/usr/bin/env python3
"""Symbolic u32 entropy return and arbitrary ABI caller clobbers.
O(V+byte events+expression DAG) time/space. Original instructions only;
imports and pointer authentication never execute. Fail closed on a
symbol-dependent effective address, control target, or unsupported opcode.
"""
import z3
from capstone.arm64 import ARM64_OP_IMM
from daemon_context_transfer_symbolic import Transfer,HELPER,IMAGE,P,WRITABLE
from lskd_values_symbolic import resize
CALL=0x100409574
class EntropyReturn(Transfer):
 def shape(self,value,n):
  value=z3.simplify(resize(value,8*n))
  if z3.is_bv_value(value):return {'hex':value.as_long().to_bytes(n,'little').hex()}
  terms=[]
  for j in range(n):
   byte=z3.simplify(z3.Extract(8*j+7,8*j,value))
   if z3.is_bv_value(byte):terms.append(byte.as_long())
   elif z3.is_const(byte)and byte.decl().name().startswith('unknown_'):terms.append({'origin':int(byte.decl().name()[8:],16)-self.F})
   else:break
  if len(terms)==n:return {'terms':terms}
  pending=[value];syms={};seen=set()
  while pending:
   x=pending.pop();key=x.get_id()
   if key in seen:continue
   seen.add(key)
   if z3.is_const(x)and x.decl().kind()==z3.Z3_OP_UNINTERPRETED:
    name=x.decl().name();assert name.startswith(('api_','incoming_','unknown_','value_'));syms[name]=x.size()if z3.is_bv(x)else'Bool'
   pending.extend(x.children())
  return {'expr':value.sexpr(),'bits':8*n,'symbols':sorted(syms.items())}
 def write(self,name,value):
  if name in ['xzr','wzr']:return
  n=self.width(name);value=z3.simplify(resize(value,n));shape=self.shape(value,n//8)
  if 'expr'in shape:assert all(not name.startswith('unknown_')for name,b in shape['symbols']),('transformed private unknown',hex(self.pc))
  if 'expr'in shape and not z3.is_const(value):
   if not hasattr(self,'definitions'):self.definitions=[]
   var='value_'+str(len(self.definitions));self.definitions.append({'name':var,'bits':n,'pc':hex(self.pc),'stage':getattr(self,'definition_stage','source'),'expression':shape});value=z3.BitVec(var,n)
  super().write(name,value)
 def store(self,a,n,value,pc):
  a=self.concrete(a,'unknown-dependent write address');value=resize(value,n*8);shape=self.shape(value,n)
  assert P<=a<a+n<=P+0x10000 or self.H<=a<a+n<=self.H+90000 or any(va<=a<a+n<=va+vs for va,vs in WRITABLE)
  # API-derived output may occupy writable image storage; unrelated unknown
  # private bytes may not leave the private stack through this extension.
  if 'expr'in shape:assert all(not name.startswith('unknown_')for name,b in shape['symbols'])or P<=a<a+n<=P+0x10000
  elif'terms'in shape:assert P<=a<a+n<=P+0x10000
  self.events.append({'kind':'write','address':hex(a),'size_bytes':n,'value':shape})
  for j in range(n):self.bytes[a+j]=z3.simplify(z3.Extract(8*j+7,8*j,value));self.changed.add(a+j)
 def model_return(self):
  self.pc=CALL;self.written={};self.events=[];self.flag_change=False;self.definitions=[];self.definition_stage='API'
  self.write('x0',z3.Concat(z3.BitVec('api_x0_upper32',32),z3.BitVec('api_entropy_u32',32)))
  for j in range(1,18):self.write('x'+str(j),z3.BitVec('api_x'+str(j),64))
  for j in range(32):
   if 8<=j<16:
    low=z3.Extract(63,0,self.read('q'+str(j)))if self.key('q'+str(j))in self.regs else z3.BitVec('incoming_d'+str(j),64)
    self.write('q'+str(j),z3.Concat(z3.BitVec('api_q'+str(j)+'_upper',64),low))
   else:self.write('q'+str(j),z3.BitVec('api_q'+str(j),128))
  self.write('x30',z3.BitVecVal(CALL+4,64))
  self.n,self.z,self.carry,self.overflow=[z3.Bool('api_'+x)for x in ['N','Z','C','V']]
  self.api_effects={k:self.shape(v,16 if k.startswith('q')else 8)for k,v in self.written.items()}
 def run_return(self,limit=100000):
  pc=CALL+4;self.definition_stage='source';self.steps=[];self.pool={};self.fixups=set();self.zero_reads=[];self.changed=set()
  for step in range(limit):
   if pc not in self.cache:self.cache[pc]=next(self.dec.disasm(IMAGE.read(pc,4),pc))
   i=self.cache[pc];self.pc=pc;self.events=[];self.written={};self.flag_change=False;row={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic};self.pool[hex(pc)]={**row,'operands':i.op_str}
   if i.mnemonic in ['braa','blraa','b','ret']:
    target=i.operands[0].imm if i.mnemonic=='b'else self.concrete(self.read('x30'if i.mnemonic=='ret'else i.reg_name(i.operands[0].reg)),'unknown-dependent branch target')
    if i.mnemonic=='blraa'and target!=HELPER:
     return {'pc':hex(pc),'target':hex(target),'registers31':[self.shape(self.read('x'+str(j)),8)for j in range(31)],'SP':hex(self.concrete(self.read('sp'),'SP'))}
    row['target']=hex(target)
    if i.mnemonic in ['braa','blraa']:row['modifier16']=hex(self.concrete(self.read(i.reg_name(i.operands[1].reg)),'modifier'))
    if i.mnemonic=='blraa':self.write('x30',z3.BitVecVal(pc+4,64))
    nextpc=target
   else:self.one(i);nextpc=pc+4
   row['events']=self.events;row['registers_after']={k:self.shape(v,16 if k.startswith('q')else 8)for k,v in self.written.items()}
   if self.flag_change:
    vals=[z3.simplify(x)for x in [self.n,self.z,self.carry,self.overflow]];assert all(z3.is_true(x)or z3.is_false(x)for x in vals),('unknown flags',hex(pc));row['NZCV_after']=sum((1<<(31-j))for j,x in enumerate(vals)if z3.is_true(x))
   self.steps.append(row);pc=nextpc
  raise AssertionError(('visit budget',hex(pc)))
