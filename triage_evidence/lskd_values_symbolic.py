#!/usr/bin/env python3
"""Bounded original-source lift for value consumption and query publication.

Fixed symbolic cells and source phases; source key lemmas qualify the query
appender composition. O(I) DAG construction/space; solver complexity is
separate. No target executes."""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_SFT_LSL,ARM64_SFT_LSR,ARM64_EXT_UXTH,ARM64_EXT_UXTW
def resize(v,n):
 if isinstance(v,int):return z3.BitVecVal(v,n)
 return z3.ZeroExt(n-v.size(),v)if v.size()<n else z3.Extract(n-1,0,v)if v.size()>n else v
class Lift:
 def __init__(self,c,narrow=False):self.c=c;self.narrow=narrow;self.regs={};self.memory={};self.stores=[];self.count=0;self.values={}
 def width(self,name):return 16 if self.narrow else 32 if name.startswith('w')else 64
 def key(self,name):return'x'+name[1:]if name.startswith('w')else {'fp':'x29','lr':'x30'}.get(name,name)
 def read(self,name):
  w=self.width(name)
  if name in['wzr','xzr']:return z3.BitVecVal(0,w)
  assert self.key(name)in self.regs,('undefined symbolic register',name);return resize(self.regs[self.key(name)],w)
 def write(self,name,v):
  if name in['wzr','xzr']:return
  assert not self.narrow or name.startswith('w');v=getattr(self,'overrides',{}).get((getattr(self,'pc',0),name),v);v=resize(v,self.width(name));self.values[(getattr(self,'pc',0),name)]=v;self.regs[self.key(name)]=v if self.narrow else resize(v,64)
 def seed(self,name,v):self.regs[self.key(name)]=resize(v,16 if self.narrow else 64)
 def operand(self,i,o,n):
  v=resize(self.read(i.reg_name(o.reg)),n)if o.type==ARM64_OP_REG else resize(o.imm,n)if o.type==ARM64_OP_IMM else None;assert v is not None
  if o.ext:
   assert o.ext in [ARM64_EXT_UXTH,ARM64_EXT_UXTW];v=v&((1<<(16 if o.ext==ARM64_EXT_UXTH else 32))-1)
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
   self.pc=i.address
   m=i.mnemonic;ops=i.operands;self.count+=1
   if m=='ccmp':
    n=self.width(i.reg_name(ops[0].reg));a=self.operand(i,ops[0],n);b=self.operand(i,ops[1],n);cond=i.op_str.rsplit(',',1)[1].strip();assert cond in ['eq','ne'];take=self.equal if cond=='eq'else z3.Not(self.equal);self.equal=z3.If(take,a==b,z3.BoolVal(bool(ops[2].imm&4)));continue
   if m=='cmp':
    n=self.width(i.reg_name(ops[0].reg));self.cmp_left=self.operand(i,ops[0],n);self.cmp_right=self.operand(i,ops[1],n);self.equal=self.cmp_left==self.cmp_right;continue
   if m=='cset':
    condition=i.op_str.rsplit(',',1)[1].strip();assert condition in['eq','ne','lt','ge','lo'];self.condition=self.equal if condition=='eq'else z3.Not(self.equal)if condition=='ne'else self.cmp_left<self.cmp_right if condition=='lt'else z3.ULT(self.cmp_left,self.cmp_right)if condition=='lo'else self.cmp_left>=self.cmp_right;self.condition_name=condition;self.write(i.reg_name(ops[0].reg),z3.If(self.condition,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));continue
   if m in['ldr','ldrh','ldrb','ldur']:
    dest=i.reg_name(ops[0].reg);n=1 if m=='ldrb'else 2 if m=='ldrh'else self.width(dest)//8;self.write(dest,self.load(self.address(i,ops[1]),n));continue
   if m in['str','strb','strh','stur']:
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
   elif m in['add','sub','and','orr','eor','eon','orn','bic','mul','madd','msub']:
    a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n)
    v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a^~b if m=='eon'else a|~b if m=='orn'else a&~b if m=='bic'else a*b if m=='mul'else a*b+self.operand(i,ops[3],n)if m=='madd'else self.operand(i,ops[3],n)-a*b
   elif m=='mvn':v=~self.operand(i,ops[1],n)
   elif m in ['bfi','bfxil']:
    shift,width=ops[2].imm,ops[3].imm;mask=((1<<width)-1)<<(shift if m=='bfi'else 0);src=self.operand(i,ops[1],n);value=src<<shift if m=='bfi'else z3.LShR(src,shift);v=(self.read(dest)&~mask)|(value&mask)
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



def queries(c,handlers,fields,response):
 merged={'spans':c['spans']+handlers['spans']+fields['spans']+response['spans']};qs=[];counts={};F=0x51000000;S=z3.BitVec('lookup_status32',32)
 v=Lift(part(merged,'gate',0xfffffe000a52f26c,0xfffffe000a52f284))
 for reg,val in [('sp',F),('w21',0x5e561849),('w20',0x148)]:v.seed(reg,val)
 mem(v,F+0x20,4,S);v.run('gate');counts['common_lookup_status_gate']=v.count
 qs.append(('common_lookup_status_gate',v.read('w8')!=z3.If(S==0x5e561849,z3.BitVecVal(0x410,32),z3.BitVecVal(0x148,32))))
 D=z3.BitVec('payload_pointer64',64);L=z3.BitVec('payload_length16',16);v=Lift(part(merged,'length',0xfffffe000a519b78,0xfffffe000a519b9c));v.seed('sp',F);v.seed('w20',0x148);mem(v,F+0x10,8,D);mem(v,F+0xe,2,L);v.run('length');counts['common_pointer_length_gate']=v.count;good=z3.And(D!=0,L==8)
 qs.append(('common_pointer_length_gate',v.read('w9')!=z3.If(good,z3.BitVecVal(0x270,32),z3.BitVecVal(0x148,32))))
 W=z3.BitVec('wire_scalar64',64);R,O=z3.BitVecs('value_record64 value_output64',64)
 class Bytes(Lift):
  def __init__(self,*a):super().__init__(*a);self.byte_reads=[]
  def load(self,a,n):
   if n==1:
    j=len(self.byte_reads);assert j<8;self.byte_reads.append(a);return z3.Extract(63-8*j,56-8*j,W)
   return super().load(a,n)
 v=Bytes(part(merged,'decode',0xfffffe000a54f41c,0xfffffe000a54f4f8));v.seed('x8',D);v.seed('x19',R);mem(v,R+0x18,8,O);v.run('decode');counts['big_endian_value64']=v.count
 qs.append(('big_endian_value64',z3.Or(cell(v,O,8)!=W,*[a!=D+j for j,a in enumerate(v.byte_reads)])))
 v=Lift(part(merged,'raw',0xfffffe000a571ee4,0xfffffe000a571ee8));v.seed('x19',R);v.seed('w9',S);v.run('raw');counts['common_raw_status_store']=v.count;qs.append(('common_raw_status_store',cell(v,R+8,4)!=S))
 v=Lift(part(merged,'norm',0xfffffe000a549e08,0xfffffe000a549e1c));v.seed('sp',F);v.seed('x19',R);mem(v,F+0x10,4,S);v.run('norm');counts['span_status_normalization']=v.count;qs.append(('span_status_normalization',cell(v,R+12,4)!=S-0x5e561849))
 # The query appender uses the same record key as the frozen u32 bridge.
 v=Lift(part(merged,'qkey',0xfffffe000a525cc0,0xfffffe000a525cfc));v.seed('sp',F);mem(v,F+0x128,8,R);v.run('qkey');dk=Lift(part(merged,'dkey',0xfffffe000a54dbf4,0xfffffe000a54dc30));dk.seed('x19',R);dk.run('dkey');counts['query_append_key']=v.count;counts['u32_append_decoder_key']=dk.count;qs.append(('query_append_key',v.read('w8')!=dk.read('w1')))
 K=z3.BitVec('query_append_shared_key32',32);C,I=z3.BitVecs('query_candidate64 inner_append_record64',64);pack=Lift(part(merged,'qpack',0xfffffe000a525cfc,0xfffffe000a525d2c))
 for reg,val in [('x19',R),('w8',K),('w20',0x3be),('x28',C)]:pack.seed(reg,val)
 pack.run('qpack');counts['query_append_record_pack']=pack.count
 payload=Lift(part(merged,'payload',0xfffffe000a54dc30,0xfffffe000a54ddac))
 for reg,val in [('sp',I-24),('x19',R),('w1',K),('w17',0xfffffffe)]:payload.seed(reg,val)
 for off,n in [(0,2),(8,8),(16,4),(20,4)]:mem(payload,R+off,n,cell(pack,R+off,n))
 payload.run('payload');counts['query_payload_decoder']=payload.count;bs=[s['value']for s in payload.stores if s['size_bytes']==1];assert len(bs)==4;qs.append(('query_payload_word',z3.Concat(*bs)!=0x13180000))
 inner=Lift(part(merged,'inner',0xfffffe000a54ddac,0xfffffe000a54dec4))
 for reg,val in [('sp',I-24),('x0',payload.read('x0')),('w1',payload.read('w1')),('w2',payload.read('w2')),('w3',payload.read('w3')),('w17',0xfffffffe)]:inner.seed(reg,val)
 inner.run('inner');ik=inner.read('w17');sel=Lift(part(merged,'select',0xfffffe000a54dec4,0xfffffe000a54decc))
 for reg,val in [('sp',I-24),('w1',inner.read('w1')),('w17',ik)]:sel.seed(reg,val)
 sel.run('select');counts['query_inner_record_pack']=inner.count;counts['query_inner_selector']=sel.count
 qs.append(('query_append_fields',z3.Or(cell(inner,I+24,8)!=C,resize(cell(inner,I+10,2)-resize(ik,16),16)^0x8151!=0x65,resize(cell(inner,I+8,2)+resize(ik,16)-0x6601,16)!=4,(cell(sel,I+12,4)^ik)!=0x224)))
 v=Lift(part(merged,'append_status',0xfffffe000a54df58,0xfffffe000a54df60));v.seed('sp',F);v.seed('x19',R);mem(v,F+0x28,4,S);v.run('append_status');counts['query_append_raw_status']=v.count;qs.append(('query_append_raw_status',cell(v,R+4,4)!=S))
 # Local query status comparison and original inner-return slot selection.
 v=Lift(part(merged,'query_gate',0xfffffe000a51c02c,0xfffffe000a51c058))
 for reg,val in [('x22',R),('w19',0x30c),('w20',0x3be),('w21',0x3be)]:v.seed(reg,val)
 mem(v,R+12,4,S);v.run('query_gate');counts['query_initializer_status_gate']=v.count;qs.append(('query_initializer_status_gate',z3.Or(v.condition!=(S==0x5e561849),v.read('w9')!=z3.If(S==0x5e561849,z3.BitVecVal(0x630,32),z3.BitVecVal(0x30c,32)))))
 TABLE=0xfffffe000846c420;v=Lift(part(merged,'inner_return',0xfffffe000a525d78,0xfffffe000a525d80));v.seed('x19',R);v.seed('x23',TABLE);v.seed('w20',0x3be);mem(v,R+4,4,S);mem(v,TABLE+8*0x3be,8,0xfffffe000a52e4b0);v.run('inner_return');counts['query_inner_status_forward']=v.count;qs.append(('query_inner_status_forward',z3.Or(v.read('w8')!=S,v.read('x9')!=0xfffffe000a52e4b0)))
 v=Lift(part(merged,'publish',0xfffffe000a522e3c,0xfffffe000a522e48));v.seed('sp',F);mem(v,F+8,8,O);mem(v,F+0x28,8,C);v.run('publish');counts['source_candidate_publication']=v.count;qs.append(('source_candidate_publication',cell(v,O,8)!=C))
 A,LP,SCR=z3.BitVecs('span_auxiliary64 span_length_cell64 span_scratch64',64)
 v=Lift(part(merged,'shape',0xfffffe000a50fff8,0xfffffe000a510044))
 for reg,val in [('sp',F),('w20',0x30c),('x19',LP)]:v.seed(reg,val)
 mem(v,F+0x160,8,A);mem(v,A+0x18,8,D);mem(v,LP,2,L);mem(v,F+0x98,8,SCR);v.run('shape');counts['span_shape_and_auxiliary_field']=v.count
 qs.append(('span_shape_and_auxiliary_field',z3.Or(v.condition!=(L==37),v.read('w8')!=z3.If(L==37,z3.BitVecVal(0x982,32),z3.BitVecVal(0x30c,32)),cell(v,A+0x90,8)!=SCR,v.read('x23')!=D,v.read('w26')!=0xe)))
 v=Lift(part(merged,'span_random_args',0xfffffe000a5296d8,0xfffffe000a5296e0));v.seed('sp',F);mem(v,F+0x118,8,D);v.run('span_random_args');counts['span_random_call_arguments']=v.count;qs.append(('span_random_call_arguments',z3.Or(v.read('x0')!=D,v.read('w1')!=41)))
 return qs,counts
