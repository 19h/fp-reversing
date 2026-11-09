#!/usr/bin/env python3
"""Bounded source-instruction lift for response records, metadata getters and conditional publication.

Only listed pure instructions and fixed memory cells are supported. The tag
slice uses low16 projections: every operation there is low-bit preserving.
O(I) DAG construction/space; solver complexity is separate. No target executes.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_SFT_LSL,ARM64_SFT_LSR
def resize(v,n):
 if isinstance(v,int):return z3.BitVecVal(v,n)
 return z3.ZeroExt(n-v.size(),v)if v.size()<n else z3.Extract(n-1,0,v)if v.size()>n else v
class Lift:
 def __init__(self,c,narrow=False):self.c=c;self.narrow=narrow;self.regs={};self.memory={};self.stores=[];self.count=0
 def width(self,name):return 16 if self.narrow else 32 if name.startswith('w')else 64
 def key(self,name):return'x'+name[1:]if name.startswith('w')else name
 def read(self,name):
  w=self.width(name)
  if name in['wzr','xzr']:return z3.BitVecVal(0,w)
  assert self.key(name)in self.regs,('undefined symbolic register',name);return resize(self.regs[self.key(name)],w)
 def write(self,name,v):
  if name in['wzr','xzr']:return
  assert not self.narrow or name.startswith('w');v=resize(v,self.width(name));self.regs[self.key(name)]=v if self.narrow else resize(v,64)
 def seed(self,name,v):self.regs[self.key(name)]=resize(v,16 if self.narrow else 64)
 def operand(self,i,o,n):
  v=resize(self.read(i.reg_name(o.reg)),n)if o.type==ARM64_OP_REG else resize(o.imm,n)if o.type==ARM64_OP_IMM else None;assert v is not None
  if o.shift.type:
   assert o.shift.type in[ARM64_SFT_LSL,ARM64_SFT_LSR];v=v<<o.shift.value if o.shift.type==ARM64_SFT_LSL else z3.LShR(v,o.shift.value)
  return v
 def address(self,i,o):
  v=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
  if o.mem.index:
   x=resize(self.read(i.reg_name(o.mem.index)),64);v=v+(x<<o.shift.value)
  return z3.simplify(v)
 def load(self,a,n):
  key=(z3.simplify(a).sexpr(),n);assert key in self.memory,('undefined symbolic cell',key);return self.memory[key]
 def store(self,a,n,v,pc):
  v=resize(v,n*8);self.stores.append({'pc':pc,'address':a,'size_bytes':n,'value':v})
  self.memory[(z3.simplify(a).sexpr(),n)]=v
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,int(row['start'],16)));assert sum(i.size for i in ins)==len(raw)
  for i in ins:
   m=i.mnemonic;ops=i.operands;self.count+=1
   if m=='cmp':
    n=self.width(i.reg_name(ops[0].reg));self.equal=self.operand(i,ops[0],n)==self.operand(i,ops[1],n);continue
   if m=='cset':
    condition=i.op_str.rsplit(',',1)[1].strip();assert condition in['eq','ne'];self.write(i.reg_name(ops[0].reg),z3.If(self.equal if condition=='eq'else z3.Not(self.equal),z3.BitVecVal(1,32),z3.BitVecVal(0,32)));continue
   if m in['ldr','ldrh']:
    dest=i.reg_name(ops[0].reg);n=2 if m=='ldrh'else self.width(dest)//8;self.write(dest,self.load(self.address(i,ops[1]),n));continue
   if m in['str','strb','strh']:
    src=i.reg_name(ops[0].reg);n=1 if m=='strb'else 2 if m=='strh'else self.width(src)//8;self.store(self.address(i,ops[1]),n,self.read(src),i.address);continue
   if m in['ldp','stp']:
    a=self.address(i,ops[2]);n=self.width(i.reg_name(ops[0].reg))//8
    for j in range(2):
     reg=i.reg_name(ops[j].reg);at=z3.simplify(a+j*n)
     if m=='ldp':self.write(reg,self.load(at,n))
     else:self.store(at,n,self.read(reg),i.address)
    continue
   dest=i.reg_name(ops[0].reg);n=self.width(dest)
   if m=='mov':v=self.operand(i,ops[1],n)
   elif m=='movk':
    shift=ops[1].shift.value;mask=(0xffff<<shift)&((1<<n)-1);v=(self.read(dest)&~mask)|resize(ops[1].imm<<shift,n)
   elif m in['add','sub','and','orr','eor','orn','bic','mul','madd','msub']:
    a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n)
    v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a|~b if m=='orn'else a&~b if m=='bic'else a*b if m=='mul'else a*b+self.operand(i,ops[3],n)if m=='madd'else self.operand(i,ops[3],n)-a*b
   elif m=='ubfiz':v=(self.operand(i,ops[1],n)&((1<<ops[3].imm)-1))<<ops[2].imm
   elif m=='neg':v=-self.operand(i,ops[1],n)
   elif m in['lsl','lsr']:
    a=self.operand(i,ops[1],n);shift=ops[2].imm;v=a<<shift if m=='lsl'else z3.LShR(a,shift)
   else:raise AssertionError(('unsupported symbolic instruction',hex(i.address),m,i.op_str))
   self.write(dest,z3.simplify(v))
  return self
def mem(obj,a,n,value):obj.memory[(z3.simplify(resize(a,64)).sexpr(),n)]=resize(value,n*8)
def cell(obj,a,n):return obj.load(z3.simplify(resize(a,64)),n)
def part(c,label,start,end):
 source=next(s for s in c['spans']if int(s['start'],16)<=start<end<=int(s['end'],16));raw=bytes.fromhex(source['bytes_hex']);a=int(source['start'],16);return {'spans':[{'label':label,'start':hex(start),'bytes_hex':raw[start-a:end-a].hex()}]}
def queries(c):
 R=z3.BitVec('workspace_subrecord64',64);Q=z3.BitVec('request_pointer64',64);A=z3.BitVec('auxiliary_begin64',64);B=z3.BitVec('workspace_begin64',64);E=z3.BitVec('workspace_end64',64);Z=z3.BitVec('response_pointer64',64);F=0x7100000000;D=0x7200000000;V=0x7300000000;H=z3.BitVec('request_header32',32);OP=z3.BitVec('operation32',32);S=z3.BitVec('raw_result_status32',32);SEED=z3.BitVec('displacement_seed64',64);CELL=z3.BitVec('displacement_cell32',32)
 allocation=Lift(part(c,'allocation_gate',0xfffffe000a52486c,0xfffffe000a52488c))
 for n,v in [('x0',Z),('w25',0x5e561849),('w22',0x99c)]:allocation.seed(n,v)
 allocation.run('allocation_gate')
 enc_key=Lift(part(c,'enc_key',0xfffffe000a5617b8,0xfffffe000a5617e8));enc_key.seed('x20',R);enc_key.run('enc_key');dk=Lift(part(c,'dec_key',0xfffffe000a571024,0xfffffe000a571050));dk.seed('x0',R);dk.run('dec_key');ko=enc_key.read('w8');kd=dk.read('w13')
 pack=Lift(c)
 for n,v in [('x20',R),('x21',0x5e561849),('x22',Q),('x24',Z),('sp',F)]:pack.seed(n,v)
 for off,v in [(0x18,E),(0x10,A),(0x20,B),(0x28,A+0x1000)]:mem(pack,F+off,8,v)
 pack.run('record_symbolic');key=ko*0xaed3b63b;record_bad=z3.Or(cell(pack,R,8)!=B,cell(pack,R+8,8)!=A,cell(pack,R+16,8)!=E,cell(pack,R+24,4)+key!=0x3be,cell(pack,R+32,8)!=Q,cell(pack,R+40,8)!=Z,cell(pack,R+48,8)!=A+0x1000,cell(pack,F+40,8)!=Z)
 K=z3.BitVec('shared_inner_key_basis32',32);dec=Lift(part(c,'decode',0xfffffe000a571050,0xfffffe000a571074))
 for n,v in [('x0',R),('w13',K),('w17',0xaed3b63b),('sp',F)]:dec.seed(n,v)
 for off,n in [(0,8),(8,8),(16,8),(24,4),(32,8),(48,8)]:mem(dec,R+off,n,(0x3be-K*0xaed3b63b)if off==24 else cell(pack,R+off,n))
 dec.run('decode');decoded=z3.Or(dec.read('w28')!=0x3be,dec.read('x24')!=B,dec.read('x16')!=B+0x140,dec.read('x19')!=A+0xc0,dec.read('x1')!=E,dec.read('x22')!=A+0x1000,dec.read('x27')!=Q)
 G=z3.BitVec('metadata_record64',64);getter=Lift(c)
 for n,v in [('sp',F),('x19',G),('x27',Q),('x22',D)]:getter.seed(n,v)
 mem(getter,F+0x1a0,4,0x3be);getter.run('getter_record_symbolic');gk=getter.read('w9');gdec=Lift(part(c,'gkey',0xfffffe000a54f560,0xfffffe000a54f594));gdec.seed('x0',G);gdec.run('gkey')
 copy=Lift(part(c,'copy',0xfffffe000a53533c,0xfffffe000a535344));copy.seed('x8',Q);copy.seed('x9',D);mem(copy,Q+4,4,OP);copy.run('copy');getter_bad=z3.Or((cell(getter,G,4)^gk)!=0x6ef,cell(getter,G+8,8)!=Q,cell(getter,G+16,8)!=D,cell(copy,D,4)!=OP)
 gate=Lift(part(c,'header',0xfffffe000a56b43c,0xfffffe000a56b46c));gate.seed('x8',Q);gate.seed('w10',0x688);mem(gate,Q,4,H);gate.run('header')
 pm=Lift(part(c,'probe_madd',0xfffffe000a58a2a8,0xfffffe000a58a2b8));pm.seed('x19',D);mem(pm,D,8,SEED);pm.run('probe_madd');ps=Lift(part(c,'probe_size',0xfffffe000a58a2f8,0xfffffe000a58a304));ps.seed('x9',pm.read('x9'));ps.run('probe_size');size=ps.read('x8')
 delta=Lift(c);delta.seed('x20',D);delta.seed('x19',V);delta.seed('w21',z3.Extract(31,0,SEED));mem(delta,D,4,CELL);delta.run('delta_symbolic')
 di=Lift(part(c,'delta_init',0xfffffe000a58a324,0xfffffe000a58a32c));di.seed('x21',SEED);di.seed('x20',D);di.run('delta_init');da=Lift(part(c,'delta_add',0xfffffe000a571018,0xfffffe000a571024));da.seed('x1',D);mem(da,D,8,cell(di,D,8));da.run('delta_add')
 result=Lift(part(c,'result',0xfffffe000a5618d4,0xfffffe000a561904))
 for n,v in [('x20',R),('sp',F),('w21',0x5e561849)]:result.seed(n,v)
 mem(result,R+56,4,S);mem(result,F+4,4,0x378);result.run('result')
 O=z3.BitVec('output_reference64',64);pub=Lift(part(c,'publish',0xfffffe000a522e3c,0xfffffe000a522e48));pub.seed('sp',F);mem(pub,F+8,8,O);mem(pub,F+40,8,Z);pub.run('publish')
 qs=[('allocation_null_state',allocation.read('w8')!=z3.If(Z==0,z3.BitVecVal(0x9a2,32),z3.BitVecVal(0x99c,32))),('record_key32',ko!=kd),('workspace_record_fields',record_bad),('inner_selector_and_fields',decoded),('metadata_key32',gk!=gdec.read('w8')),('metadata_record_and_word_copy',getter_bad),('header_validation_state',gate.read('w10')!=z3.If(H==1,z3.BitVecVal(0x688,32),z3.BitVecVal(0x68c,32))),('probe_extent',z3.Or(z3.ULT(size,16),z3.UGT(size,256),(size&15)!=0)),('displacement_formula',cell(delta,V,8)!=(z3.ZeroExt(32,(CELL-z3.Extract(31,0,SEED))&0xffff)<<4)),('seed_adjustment_roundtrip',cell(da,D,8)!=SEED),('publication_status_partition',result.read('w8')!=z3.If(S==0x5e561849,z3.BitVecVal(0x38c,32),z3.BitVecVal(0x3a8,32))),('publication_pointer_store',cell(pub,O,8)!=Z)]
 counts={'allocation_gate':allocation.count,'encoder_key':enc_key.count,'decoder_key':dk.count,'record_pack':pack.count,'inner_decode':dec.count,'getter_record':getter.count,'getter_decoder_key':gdec.count,'word_copy':copy.count,'header_gate':gate.count,'probe_madd':pm.count,'probe_size':ps.count,'delta':delta.count,'delta_init':di.count,'delta_add':da.count,'result_gate':result.count,'publication_store':pub.count};return qs,counts
