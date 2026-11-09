#!/usr/bin/env python3
"""Bounded source-instruction lift for workspace record fields and first dispatch state.

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
    assert i.op_str.rsplit(',',1)[1].strip()=='eq';self.write(i.reg_name(ops[0].reg),z3.If(self.equal,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));continue
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
   elif m in['add','sub','and','orr','eor','orn','bic','mul','madd']:
    a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n)
    v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a|~b if m=='orn'else a&~b if m=='bic'else a*b if m=='mul'else a*b+self.operand(i,ops[3],n)
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
 R=z3.BitVec('workspace64',64);A=z3.BitVec('auxiliary64',64);Q=z3.BitVec('request64',64);O=z3.BitVec('response_reference64',64);S=z3.BitVec('raw_status32',32);F=0x7100000000;G=0x7200000000;pack=Lift(c)
 for name,v in [('x21',R),('x22',A),('x23',R+0x40),('x24',R+0x4000),('sp',F)]:pack.seed(name,v)
 for off,v in [(0x20,0x7300000000),(0x28,O),(0x30,Q)]:mem(pack,F+off,8,v)
 pack.run('record_encode');ko=pack.read('w9');decoder_key=Lift(part(c,'key',0xfffffe000a55f6e4,0xfffffe000a55f720));decoder_key.seed('x19',R);decoder_key.run('key');kd=decoder_key.read('w11')
 fields=z3.Or(cell(pack,R,8)!=Q,cell(pack,R+8,8)!=R+0x40,cell(pack,R+16,4)!=(ko^0x563),cell(pack,R+24,8)!=A,cell(pack,R+32,8)!=R+0x4000,cell(pack,R+40,8)!=A+0x1000,cell(pack,R+56,8)!=O)
 K=z3.BitVec('shared_workspace_key32',32);dec=Lift(part(c,'decoded_fields',0xfffffe000a55f720,0xfffffe000a55f744))
 for name,v in [('x19',R),('x0',R),('sp',G),('w11',K)]:dec.seed(name,v)
 for off,n in [(8,8),(16,4),(24,8),(32,8),(40,8),(56,8)]:mem(dec,R+off,n,(K^0x563)if off==16 else cell(pack,R+off,n))
 dec.run('decoded_fields');decoded=z3.Or(dec.read('w22')!=0x563,dec.read('x20')!=R+0x40,dec.read('x0')!=R+0x80,dec.read('x1')!=R+0x4000,cell(dec,G+16,8)!=A,cell(dec,G+40,8)!=A+0x1000,dec.read('x24')!=O)
 state=Lift(part(c,'state_index',0xfffffe000a55f7e0,0xfffffe000a55f808))
 for name,v in [('x24',O),('w22',0x563),('sp',G)]:state.seed(name,v)
 state.run('state_index');tail=Lift(c);tail.seed('w26',S);tail.run('status_return')
 start=Lift(part(c,'start',0xfffffe000a50c754,0xfffffe000a50c758));start.seed('x21',R);start.run('start');end=Lift(part(c,'end',0xfffffe000a50c788,0xfffffe000a50c78c));end.seed('x21',R);end.run('end')
 ranges=z3.And(z3.ULE(R,z3.BitVecVal((1<<64)-1-0x4000,64)),z3.Or(z3.UGT(start.read('x23'),end.read('x24')),z3.UGT(dec.read('x0'),dec.read('x1'))))
 qs=[('workspace_key32',z3.Or(ko!=kd,ko!=((z3.Extract(31,0,R)^0xae0701e7)*0x952f3cb7))),('workspace_record_fields',fields),('dispatcher_decoded_fields',decoded),('output_reference_first_state',z3.Or(state.read('w9')!=z3.If(O==0,z3.BitVecVal(0x563,32),z3.BitVecVal(0x57f,32)),cell(state,G+8,8)!=O)),('wrapper_status_subtraction',tail.read('w0')!=S-0x5e561849),('workspace_ranges_nonwrapping',ranges)]
 counts={'record_encode':pack.count,'decoder_key':decoder_key.count,'record_decode':dec.count,'first_state':state.count,'status_return':tail.count,'first_range_start':start.count,'first_range_end':end.count};return qs,counts
