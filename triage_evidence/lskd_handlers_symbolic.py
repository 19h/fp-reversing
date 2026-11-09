#!/usr/bin/env python3
"""Bounded original-source lift for handler records and compact field lookup.

Fixed symbolic cells and source-entry bindings; per-key composition lemmas
qualify single-register key abstractions. O(I) DAG construction/space; solver
complexity is separate. No target executes."""
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


def seed_context(v,row):
 for j,x in enumerate(row['registers31']):v.seed('x'+str(j),int(x,16))
 v.seed('sp',int(row['SP'],16));return v

def queries(c,p,request):
 qs=[];counts={};R,Q,C=z3.BitVecs('handler_record64 request64 candidate64',64);K=resize((R^0xc410a4c0)*0xaed3b63b,32)
 for h in c['handlers']:
  op=int(h['operation'],16)
  if op in [0x1b59,0x1b5a]:continue
  row=next(r for r in p['cases']if r['input']['operation32']==op and r['handler_entry']is not None);en=row['handler_entry'];start=int(en['pc'],16)+4;ce=next(x for x in row['source_reads']if x['source_visit_index']>=en['source_visit_index']and start<=int(x['pc'],16)<int(h['end'],16)and 0xfffffe000ccc2000<=int(x['address'],16)<0xfffffe000ccc3000);cut=int(ce['pc'],16)
  v=seed_context(Lift(part(c,'encoder',start,cut)),en)
  for x in row['source_reads']:
   if en['source_visit_index']<=x['source_visit_index']<ce['source_visit_index'] and 0x6300000000<=int(x['address'],16)<0x6300020000:mem(v,int(x['address'],16),x['size_bytes'],int.from_bytes(bytes.fromhex(x['bytes_hex']),'little'))
  mem(v,int(en['SP'],16)+0x128,8,R);mem(v,int(en['SP'],16)+0x120,8,R-0x28)
  if op==0x1b5c:v.seed('x19',Q)
  elif op==0x1b5b:v.seed('x3',C)
  else:v.seed('x26',Q)
  initial_regs=dict(v.regs);initial_memory=dict(v.memory);v.run('encoder');counts['encoder_'+hex(op)]=v.count
  if op==0x1b5c:
   bad=[cell(v,R+8,4)!=(0x526-K-0xb7647540),resize(cell(v,R+16,2),16)!=resize(K^0x66,16),cell(v,R+32,8)!=Q]
  elif op==0x1b5b:
   actual=z3.simplify(v.values[(0xfffffe000a51bf88,'w10')]);standard=resize((R^0x2bf25469f26d6f2a)*0xeac8f755,32);qs.append(('query_encoder_key',actual!=standard));ik=z3.BitVec('query_shared_key32',32);av=Lift(v.c);av.regs=initial_regs;av.memory=initial_memory;av.overrides={(0xfffffe000a51bf88,'w10'):ik};av.run('encoder');counts['query_abstracted_encoder']=av.count;v=av;abstract=lambda value:value;bad=[cell(v,R,8)!=C,(abstract(cell(v,R+24,4))^ik)!=0x542]
   f=Lift(request)
   for reg,value in [('x19',R),('x24',C),('w8',ik),('w9',0x34b)]:f.seed(reg,value)
   for off in [8,16,20]:mem(f,R+off,4,abstract(cell(v,R+off,4)))
   f.run('init_fields_symbolic');counts['query_initializer_fields']=f.count
   bad.extend([cell(f,C,4)!=1,cell(f,C+4,4)!=0x1b5b,cell(f,C+8,4)!=1,cell(f,C+12,4)!=8,cell(f,C+144,8)!=C+16])
  else:bad=[cell(v,R,8)!=Q,cell(v,R+12,4)!=K+0x148,cell(v,R+16,2)!=resize(K^0x4411,16)]
  qs.append(('record_'+hex(op),z3.Or(*bad)))
 G=z3.BitVec('generic_record64',64);T=z3.BitVec('wanted_tag16',16);LP,DP,B=z3.BitVecs('length_output64 pointer_output64 packet_base64',64);K2=resize((G^0xae0701e7)*0x952f3cb7,32)
 ka,kb=z3.BitVecs('access_shared_key32 generic_shared_key32',32)
 v=Lift(part(c,'scalar_k1',0xfffffe000a52f128,0xfffffe000a52f15c));v.seed('x19',R);v.run('scalar_k1');counts['scalar_key1']=v.count;qs.append(('scalar_key1',v.read('w17')!=K))
 v=Lift(part(c,'scalar_k2',0xfffffe000a52f17c,0xfffffe000a52f1b4));v.seed('sp',G-0x20);v.run('scalar_k2');counts['scalar_key2']=v.count;qs.append(('scalar_key2',v.read('w2')!=K2))
 v=Lift(part(c,'scalar_pack',0xfffffe000a52f128,0xfffffe000a52f1dc));v.seed('sp',G-0x20);v.seed('x19',R);v.overrides={(0xfffffe000a52f158,'w17'):ka,(0xfffffe000a52f1b0,'w2'):kb}
 for off,n,val in [(0,8,Q),(12,4,ka+0x148),(16,2,ka^0x4411)]:mem(v,R+off,n,val)
 v.run('scalar_pack');counts['scalar_decoder_and_pack']=v.count
 qs.append(('scalar_generic_record',z3.Or(cell(v,G+24,4)!=(kb^0x526),cell(v,G+4,2)!=resize(kb+0x72+0x12bd,16),cell(v,G+32,8)!=Q,cell(v,G+8,8)!=G-0x12,cell(v,G+16,8)!=G-0x10,cell(v,G-0x12,2)!=0,cell(v,G-0x10,8)!=0)))
 v=Lift(part(c,'span_k1',0xfffffe000a549cec,0xfffffe000a549d04));v.seed('x19',R);v.run('span_k1');counts['span_key1']=v.count;qs.append(('span_key1',v.read('w16')!=K))
 v=Lift(part(c,'span_k2',0xfffffe000a549d38,0xfffffe000a549d54));v.seed('sp',G-0x10);v.run('span_k2');counts['span_key2']=v.count;qs.append(('span_key2',v.read('w0')!=K2))
 v=Lift(part(c,'span_pack',0xfffffe000a549cec,0xfffffe000a549d78));v.seed('sp',G-0x10);v.seed('x19',R);v.overrides={(0xfffffe000a549d00,'w16'):ka,(0xfffffe000a549d50,'w0'):kb}
 for off,n,val in [(0,8,DP),(8,4,0x526-ka-0xb7647540),(16,2,ka^resize(T,32)),(24,8,LP),(32,8,Q)]:mem(v,R+off,n,val)
 v.run('span_pack');counts['span_decoder_and_pack']=v.count
 qs.append(('span_generic_record',z3.Or(cell(v,G+24,4)!=(kb^0x526),cell(v,G+4,2)!=resize(kb+resize(T,32)+0x12bd,16),cell(v,G+32,8)!=Q,cell(v,G+8,8)!=LP,cell(v,G+16,8)!=DP)))
 v=Lift(part(c,'key_formula',0xfffffe000a52ef3c,0xfffffe000a52ef78));v.seed('x0',G);v.seed('x8',~G);v.run('key_formula');counts['generic_key32']=v.count;qs.append(('generic_key32',resize(v.read('x10'),32)!=K2))
 v=Lift(part(c,'key',0xfffffe000a52ef3c,0xfffffe000a52ef84));v.seed('x0',G);v.seed('x8',~G);v.overrides={(0xfffffe000a52ef74,'x10'):resize(kb,64)};mem(v,G+24,4,kb^0x526);mem(v,G+32,8,Q);v.run('key');counts['generic_decoder_key']=v.count
 qs.append(('generic_selector',z3.Or(v.read('w17')!=0x526,v.read('x9')!=Q)))
 v=Lift(part(c,'clear',0xfffffe000a52ef80,0xfffffe000a52ef90));v.seed('x0',G)
 for off,val in [(32,Q),(8,LP),(16,DP)]:mem(v,G+off,8,val)
 v.run('clear');counts['generic_output_clear']=v.count;qs.append(('generic_output_clear',z3.Or(cell(v,LP,2)!=0,cell(v,DP,8)!=0,v.read('x9')!=Q)))
 # The four dynamic loads are symbolic wire header bytes. Their exact source
 # addresses are proved simultaneously, with u32 cursor arithmetic preserved.
 rawtag,L=z3.BitVecs('wire_tag16 wire_length16',16);cursor,count,capacity=z3.BitVecs('cursor32 ordinal32 capacity32',32)
 class Header(Lift):
  def __init__(self,*a):super().__init__(*a);self.dynamic=[]
  def load(self,a,n):
   if n==1:
    values=[z3.Extract(15,8,rawtag),z3.Extract(7,0,rawtag),z3.Extract(15,8,L),z3.Extract(7,0,L)];value=values[len(self.dynamic)];self.dynamic.append(a);return value
   return super().load(a,n)
 sample=next(r for r in p['cases']if r['input'].get('provider')=='scalar64');br=next(b for b in sample['source_dispatches']if b['target']=='0xfffffe000a5466b8');en={'registers31':br['registers31'],'SP':sample['field_search_return']['SP']};v=seed_context(Header(part(c,'header',0xfffffe000a5466bc,0xfffffe000a5467a4)),en)
 for reg,value in [('x0',G),('x9',Q),('x10',kb),('w19',cursor),('w13',count),('x11',LP),('x8',DP)]:v.seed(reg,value)
 mem(v,G+4,2,kb+resize(T,32)+0x12bd);mem(v,Q+0x90,8,B);v.run('header');counts['wire_header_and_compare']=v.count
 bad=[a!=B+resize(cursor+j,64)for j,a in enumerate(v.dynamic)];bad.extend([v.condition!=(rawtag==T),resize(v.read('w19'),16)!=L,v.read('w6')!=cursor+4]);qs.append(('wire_header_and_tag',z3.Or(*bad)))
 advance=Lift(part(c,'advance',0xfffffe000a532d44,0xfffffe000a532d6c));advance.regs=dict(v.regs);advance.memory=dict(v.memory);mem(advance,Q+12,4,capacity);advance.run('advance');counts['nonmatch_advance']=advance.count;nextcur=cursor+4+resize(L,32)
 qs.append(('nonmatch_advance',z3.Or(advance.read('w19')!=nextcur,advance.read('w13')!=count+1,advance.condition!=z3.ULT(nextcur,capacity))))
 v=Lift(part(c,'found',0xfffffe000a531a4c,0xfffffe000a531a5c))
 for reg,val in [('x11',LP),('x8',DP),('x9',Q),('w19',resize(L,32)),('w6',cursor+4)]:v.seed(reg,val)
 mem(v,Q+0x90,8,B);v.run('found');counts['matching_output_stores']=v.count;qs.append(('matching_output_stores',z3.Or(cell(v,LP,2)!=L,cell(v,DP,8)!=B+resize(cursor+4,64))))
 S=z3.BitVec('raw_status32',32);v=Lift(part(c,'status',0xfffffe000a50f098,0xfffffe000a50f09c));v.seed('x0',G);v.seed('w6',S);v.run('status');counts['raw_status_store']=v.count;qs.append(('raw_status_store',z3.Or(cell(v,G,4)!=S,v.read('x0')!=G)))
 v=Lift(part(c,'random_args',0xfffffe000a50fd04,0xfffffe000a50fd0c));v.seed('x27',B);v.run('random_args');counts['random_call_arguments']=v.count;qs.append(('random_call_arguments',z3.Or(v.read('x0')!=B+0x1c,v.read('w1')!=4)))
 return qs,counts
