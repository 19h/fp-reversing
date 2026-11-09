#!/usr/bin/env python3
"""Bounded source-instruction lift for LSKD span/u32 fields and variable-length headers.

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
   elif m in['add','sub','and','orr','eor','orn','mul','madd']:
    a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n)
    v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a|~b if m=='orn'else a*b if m=='mul'else a*b+self.operand(i,ops[3],n)
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
def queries(c,tlv):
 merged={'spans':c['spans']+tlv['spans']};R=z3.BitVec('field_record64',64);I=z3.BitVec('inner_record64',64);A=z3.BitVec('field_carrier64',64);D=z3.BitVec('span_source64',64);T=z3.BitVec('field_tag32',32);L=z3.BitVec('span_length32',32);X=z3.BitVec('scalar32',32);K=z3.BitVec('shared_field_key32',32)
 sk=Lift(c);sk.seed('sp',R-8);sk.run('span_key');kd=Lift(part(merged,'generic_key',0xfffffe000a55e9a0,0xfffffe000a55e9f0));kd.seed('x0',R);kd.run('generic_key')
 sp=Lift(c)
 for name,v in [('sp',R-8),('x0',A),('w1',T),('x2',D),('w3',L),('w17',K)]:sp.seed(name,v)
 sp.run('span_pack');loK=z3.Extract(15,0,K);loT=z3.Extract(15,0,T);loL=z3.Extract(15,0,L)
 span_fields=z3.Or(cell(sp,R,8)!=D,cell(sp,R+24,8)!=A,(cell(sp,R+12,4)^K)!=0x224,(cell(sp,R+10,2)-loK)^0x8151!=loT,cell(sp,R+8,2)+loK-0x6601!=loL)
 uk=Lift(part(c,'u32_key',0xfffffe000a50e034,0xfffffe000a50e074));uk.seed('sp',R-16);uk.run('u32_key');ud=Lift(part(c,'u32_dkey',0xfffffe000a54dbf4,0xfffffe000a54dc30));ud.seed('x19',R);ud.run('u32_dkey')
 pre=Lift(part(c,'u32_tag_pre',0xfffffe000a50e024,0xfffffe000a50e034));pre.seed('w1',T);pre.run('u32_tag_pre');up=Lift(part(c,'u32_pack',0xfffffe000a50e074,0xfffffe000a50e0a8))
 for name,v in [('sp',R-16),('x0',A),('w1',pre.read('w1')),('w16',pre.read('w16')),('w2',X),('w3',0x32f2189f),('w4',K)]:up.seed(name,v)
 up.run('u32_pack');payload=Lift(part(c,'payload',0xfffffe000a54dc30,0xfffffe000a54ddac))
 for name,v in [('sp',I-24),('x19',R),('w1',K),('w17',0xfffffffe)]:payload.seed(name,v)
 for off,width in [(0,2),(8,8),(16,4),(20,4)]:mem(payload,R+off,width,cell(up,R+off,width))
 payload.run('payload');bytes4=[s['value']for s in payload.stores if s['size_bytes']==1];assert len(bytes4)==4
 pack=Lift(part(c,'ipack',0xfffffe000a54ddac,0xfffffe000a54dec4))
 for name,v in [('sp',I-24),('x0',payload.read('x0')),('w1',payload.read('w1')),('w2',payload.read('w2')),('w3',payload.read('w3')),('w17',0xfffffffe)]:pack.seed(name,v)
 pack.run('ipack');inner_key=pack.read('w17');sel=Lift(part(c,'isel',0xfffffe000a54dec4,0xfffffe000a54decc))
 for name,v in [('sp',I-24),('w1',pack.read('w1')),('w17',inner_key)]:sel.seed(name,v)
 sel.run('isel');gkd=Lift(part(merged,'generic_key',0xfffffe000a55e9a0,0xfffffe000a55e9f0));gkd.seed('x0',I);gkd.run('generic_key')
 inner_fields=z3.Or(cell(pack,I,8)!=I-12,cell(pack,I+24,8)!=A,(cell(pack,I+10,2)-z3.Extract(15,0,inner_key))^0x8151!=loT,cell(pack,I+8,2)+z3.Extract(15,0,inner_key)-0x6601!=4,(cell(sel,I+12,4)^inner_key)!=0x224)
 cursor=z3.BitVec('field_cursor32',32);count=z3.BitVec('field_count32',32);H=0x7100001000;O=0x7100002000;B=0x7100003000;length=z3.BitVec('wire_length16',16);tag=z3.BitVec('wire_tag16',16);key=z3.BitVec('generic_shared_key32',32);header=Lift(merged)
 for name,v in [('x0',H),('x20',O),('x15',B),('w22',0x2bf),('w14',key),('w3',cursor),('w16',z3.ZeroExt(16,z3.BitVecVal(0x6601,16)+length-z3.Extract(15,0,key))+key)]:header.seed(name,v)
 mem(header,H+10,2,(tag^0x8151)+z3.Extract(15,0,key));mem(header,O+156,4,cursor);mem(header,O+144,8,B);header.run('header_symbolic');bs=[s for s in header.stores if s['size_bytes']==1];assert len(bs)==4;wanted=[z3.Extract(15,8,tag),z3.Extract(7,0,tag),z3.Extract(15,8,length),z3.Extract(7,0,length)];bad=[]
 for j,s in enumerate(bs):bad.extend([s['address']!=z3.BitVecVal(B,64)+z3.ZeroExt(32,cursor+j),s['value']!=wanted[j]])
 bad.append(cell(header,O+156,4)!=cursor+4);tail=Lift(merged)
 for name,v in [('x20',O),('x23',H),('w19',z3.ZeroExt(16,length))]:tail.seed(name,v)
 mem(tail,O+152,4,count);mem(tail,O+156,4,cursor+4);tail.run('counter_symbolic')
 qs=[('span_record_key32',sk.read('w17')!=kd.read('w14')),('span_decoded_fields',span_fields),('u32_record_key32',uk.read('w4')!=ud.read('w1')),('u32_payload_big_endian32',z3.Concat(*bytes4)!=X),('u32_inner_record_key32',inner_key!=gkd.read('w14')),('u32_tag_selector_and_length',inner_fields),('variable_header_four_bytes',z3.Or(*bad)),('variable_counter_updates32',z3.Or(cell(tail,O+152,4)!=count+1,cell(tail,O+156,4)!=cursor+4+z3.ZeroExt(16,length)))]
 counts={'span_key':sk.count,'generic_key':kd.count,'span_pack':sp.count,'u32_outer_key':uk.count,'u32_decoder_key':ud.count,'u32_tag_pre':pre.count,'u32_pack':up.count,'u32_payload':payload.count,'u32_inner_pack':pack.count,'u32_inner_selector':sel.count,'generic_inner_key':gkd.count,'variable_header':header.count,'variable_counter':tail.count}
 return qs,counts
