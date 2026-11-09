#!/usr/bin/env python3
"""Bounded source-instruction lift for LSKD constructor and initializer fields.

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
   if m in['ldr','ldrh']:
    dest=i.reg_name(ops[0].reg);n=2 if m=='ldrh'else self.width(dest)//8;self.write(dest,self.load(self.address(i,ops[1]),n));continue
   if m in['str','strb']:
    src=i.reg_name(ops[0].reg);n=1 if m=='strb'else self.width(src)//8;self.store(self.address(i,ops[1]),n,self.read(src),i.address);continue
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
   elif m in['add','sub','and','orr','eor','mul','madd']:
    a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n)
    v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a*b if m=='mul'else a*b+self.operand(i,ops[3],n)
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
def key_forms(c):
 R=z3.BitVec('constructor_record64',64);enc=Lift(part(c,'key',0xfffffe000a50c158,0xfffffe000a50c194));enc.seed('sp',R-8);enc.run('key');dec=Lift(c);dec.seed('x0',R);dec.run('ctor_key');return R,enc.read('w5'),resize(dec.read('x20'),32),enc.count+dec.count
def queries(c):
 R,ko,kd,key_count=key_forms(c);I=z3.BitVec('initializer_record64',64);A=z3.BitVec('allocated_object64',64);O=z3.BitVec('output_reference64',64);op=z3.BitVec('operation32',32);n=z3.BitVec('entry_limit32',32);b=z3.BitVec('payload_budget32',32);k0=z3.BitVec('constructor_shared_key32',32);k1=z3.BitVec('initializer_shared_key32',32)
 pre=Lift(part(c,'pre',0xfffffe000a50c140,0xfffffe000a50c158));pre.seed('w1',n);pre.run('pre');outer=Lift(part(c,'pack',0xfffffe000a50c194,0xfffffe000a50c1f4))
 for name,v in [('w0',op),('w1',pre.read('w1')),('w2',b),('w4',pre.read('w4')),('w5',k0),('x3',O),('sp',R-8)]:outer.seed(name,v)
 outer.run('pack');epayload=cell(outer,R+20,4)-k0;en=cell(outer,R+28,4)+k0;ecmd=cell(outer,R,4)+k0
 arithmetic=Lift(part(c,'arith',0xfffffe000a52174c,0xfffffe000a521800))
 for name,v in [('w27',en),('w21',0x31c),('x20',A),('sp',I-0x38)]:arithmetic.seed(name,v)
 mem(arithmetic,I-0x38+0x24,4,ecmd);mem(arithmetic,I-0x38+0x20,4,epayload);mem(arithmetic,I-0x38+0xc,4,0x5c0);arithmetic.run('arith')
 ikey=Lift(part(c,'ikey',0xfffffe000a521800,0xfffffe000a521844));ikey.seed('sp',I-0x38);ikey.run('ikey');standard=resize((I^0x2bf25469f26d6f2a)*0xeac8f755,32)
 nested=Lift(part(c,'ipack',0xfffffe000a521844,0xfffffe000a52187c))
 for name,v in [('w8',arithmetic.read('w8')),('w9',arithmetic.read('w9')),('w10',arithmetic.read('w10')),('w11',arithmetic.read('w11')),('w12',k1),('x20',A),('sp',I-0x38)]:nested.seed(name,v)
 mem(nested,I-0x38+0x20,4,epayload);nested.run('ipack');fields=Lift(c)
 for name,v in [('x19',I),('x24',A),('w8',k1),('w9',0x34b)]:fields.seed(name,v)
 for off,width in [(8,4),(16,4),(20,4)]:mem(fields,I+off,width,cell(nested,I+off,width))
 fields.run('init_fields_symbolic')
 qs=[('constructor_key_aligned8',z3.And((R&7)==0,ko!=kd)),('constructor_decoded_fields',z3.Or(epayload!=b*0x1e384257+0x35477df4,en!=n+0x6a910f23,ecmd!=(op^0x5bb8dd29),cell(outer,R+24,4)-k0!=0x6a5,cell(outer,R+8,8)!=O)),('initializer_key32',ikey.read('w12')!=standard),('initializer_selector',z3.Or((cell(nested,I+24,4)^k1)!=0x542,cell(nested,I,8)!=A)),('carrier_fields32',z3.Or(cell(fields,A,4)!=1,cell(fields,A+4,4)!=op,cell(fields,A+8,4)!=n,cell(fields,A+12,4)!=b+4*n,cell(fields,A+144,8)!=A+16))]
 counts={'constructor_key_pair':key_count,'constructor_entry_prekey':pre.count,'constructor_pack':outer.count,'initializer_prekey':arithmetic.count,'initializer_key':ikey.count,'initializer_pack':nested.count,'initializer_fields':fields.count}
 return qs,counts
