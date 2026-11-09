#!/usr/bin/env python3
"""Byte-addressed symbolic transfer with explicit unknown and loader origins.
O(V+byte events+expression DAG) time/space; selected source path, fail closed.
No target import, host operation or native pointer authentication executes.
"""
import base64,hashlib,struct,zlib
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *
from daemon_receive_tools import IMAGE,FIXUPS,block
from resolve_kernel_collection_interfaces import commands
from lskd_values_symbolic import Lift,resize
P=0x6400000000;ENTRY=0x1003ecb8c;HELPER=0x10041a5e0
EXT={ARM64_EXT_UXTB:(8,False),ARM64_EXT_UXTH:(16,False),ARM64_EXT_UXTW:(32,False),ARM64_EXT_UXTX:(64,False),ARM64_EXT_SXTB:(8,True),ARM64_EXT_SXTH:(16,True),ARM64_EXT_SXTW:(32,True),ARM64_EXT_SXTX:(64,True)}
def segments():
 out=[]
 for at,cmd,size in commands(IMAGE.data,0):
  if cmd==0x19:
   va,vs,fo,fs=struct.unpack_from('<QQQQ',IMAGE.data,at+24)
   if struct.unpack_from('<I',IMAGE.data,at+60)[0]&1:out.append((va,vs,fo,fs))
 return out
SEGMENTS=segments()
WRITABLE=[struct.unpack_from('<QQ',IMAGE.data,at+24)for at,cmd,size in commands(IMAGE.data,0)if cmd==0x19 and struct.unpack_from('<I',IMAGE.data,at+60)[0]&2]
def loaded_bytes(a,n):
 for va,vs,fo,fs in SEGMENTS:
  if va<=a<a+n<=va+vs:
   return bytes(IMAGE.data[fo+j-va]if j<va+fs else 0 for j in range(a,a+n))
 raise AssertionError(('outside original mapped image',hex(a),n))
class Transfer(Lift):
 def __init__(self,row):
  super().__init__({'spans':[]});self.row=row;self.F=int(row['frame_SP'],16);self.H=int(row['heap_snapshot']['address'],16);self.bytes={};self.origins={};self.steps=[];self.pool={};self.fixups=set();self.zero_reads=[];self.changed=set();self.dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.dec.detail=True;self.cache={}
  s=row['frame_snapshots'][-1]['frame']
  for j,(b,k)in enumerate(zip(bytes.fromhex(s['bytes_hex']),bytes.fromhex(s['known_mask_hex']))):
   if k:self.bytes[self.F+j]=z3.BitVecVal(b,8)
  h=row['heap_snapshot'];raw=zlib.decompress(base64.b64decode(h['bytes_zlib_base64']));mask=zlib.decompress(base64.b64decode(h['known_mask_zlib_base64']))
  for j,(b,k)in enumerate(zip(raw,mask)):
   if k:self.bytes[self.H+j]=z3.BitVecVal(b,8)
  for w in row['initial_image_fixtures']+row['source_writes']:
   a=int(w['address'],16)
   if a<P:
    for j,b in enumerate(bytes.fromhex(w.get('bytes_hex',w.get('after_hex',''))),a):self.bytes[j]=z3.BitVecVal(b,8)
  for j,x in enumerate(row['boundary']['registers31']):self.seed('x'+str(j),int(x,16))
  self.seed('sp',self.F)
 def width(self,name):return 128 if name.startswith(('q','v'))else 64 if name.startswith('d')else super().width(name)
 def key(self,name):return 'q'+name[1:]if name.startswith(('q','v','d'))else super().key(name)
 def write(self,name,value):
  if name in ['xzr','wzr']:return
  n=self.width(name);value=z3.simplify(resize(value,n));key=self.key(name);self.regs[key]=resize(value,128 if key.startswith('q')else 64);self.written[key]=self.regs[key]
 def operand(self,i,o,n):
  v=self.read(i.reg_name(o.reg))if o.type==ARM64_OP_REG else z3.BitVecVal(o.imm&((1<<n)-1),n)if o.type==ARM64_OP_IMM else None;assert v is not None
  if o.ext:
   w,signed=EXT[o.ext];v=resize(v,w);v=z3.SignExt(n-w,v)if signed and n>w else resize(v,n)
  else:v=resize(v,n)
  if o.shift.type:
   assert o.shift.type in [ARM64_SFT_LSL,ARM64_SFT_LSR];v=v<<o.shift.value if o.shift.type==ARM64_SFT_LSL else z3.LShR(v,o.shift.value)
  return v
 def address(self,i,o):
  a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
  if o.mem.index:
   x=self.read(i.reg_name(o.mem.index))
   if o.ext:
    w,signed=EXT[o.ext];x=resize(x,w);x=z3.SignExt(64-w,x)if signed else resize(x,64)
   a+=resize(x,64)<<o.shift.value
  return z3.simplify(a)
 def concrete(self,x,kind):
  x=z3.simplify(x);assert z3.is_bv_value(x),(kind,hex(self.pc),str(x)[:200]);return x.as_long()
 def shape(self,value,n):
  value=z3.simplify(resize(value,8*n))
  if z3.is_bv_value(value):return {'hex':value.as_long().to_bytes(n,'little').hex()}
  terms=[]
  for j in range(n):
   b=z3.simplify(z3.Extract(8*j+7,8*j,value))
   if z3.is_bv_value(b):terms.append(b.as_long())
   else:
    assert z3.is_const(b)and b.decl().name().startswith('unknown_'),('non-copy unknown expression',hex(self.pc),str(b));terms.append({'origin':int(b.decl().name()[8:],16)-self.F})
  return {'terms':terms}
 def load(self,a,n):
  a=self.concrete(a,'unknown-dependent read address');private=P<=a<a+n<=P+0x10000 or self.H<=a<a+n<=self.H+90000
  if private:
   for j in range(a,a+n):
    if j not in self.bytes:self.bytes[j]=z3.BitVec('unknown_'+hex(j),8);self.origins[j]={'first_read_pc':hex(self.pc),'offset':j-self.F}
  else:
   if n==8 and a in FIXUPS:
    target=FIXUPS[a]['target'];raw=struct.pack('<Q',target if isinstance(target,int)else 0x7c100000);self.fixups.add(a)
   else:
    raw=loaded_bytes(a,n)
    if not any(va<=a<a+n<=va+fs for va,vs,fo,fs in SEGMENTS):self.zero_reads.append({'pc':hex(self.pc),'address':hex(a),'size_bytes':n})
   for j,b in enumerate(raw,a):
    if j not in self.bytes:self.bytes[j]=z3.BitVecVal(b,8)
  value=z3.simplify(z3.Concat(*[self.bytes[j]for j in reversed(range(a,a+n))]))if n>1 else self.bytes[a];self.events.append({'kind':'read','address':hex(a),'size_bytes':n,'value':self.shape(value,n)});return value
 def store(self,a,n,value,pc):
  a=self.concrete(a,'unknown-dependent write address');value=resize(value,n*8);shape=self.shape(value,n);assert P<=a<a+n<=P+0x10000 or self.H<=a<a+n<=self.H+90000 or any(va<=a<a+n<=va+vs for va,vs in WRITABLE),('outside declared writable storage',hex(pc),hex(a),n)
  assert 'hex'in shape or P<=a<a+n<=P+0x10000,('unknown write outside private stack',hex(pc),hex(a))
  self.events.append({'kind':'write','address':hex(a),'size_bytes':n,'value':shape})
  for j in range(n):self.bytes[a+j]=z3.simplify(z3.Extract(8*j+7,8*j,value));self.changed.add(a+j)
 def flags(self,a,b,result,sub):
  n=a.size();sa=z3.Extract(n-1,n-1,a);sb=z3.Extract(n-1,n-1,b);sr=z3.Extract(n-1,n-1,result);self.z=result==0;self.n=sr==1;self.carry=z3.UGE(a,b)if sub else z3.ULT(result,a);self.overflow=z3.And(sa!=sb if sub else sa==sb,sr!=sa);self.flag_change=True
 def condition(self,cc):
  return {'eq':self.z,'ne':z3.Not(self.z),'lo':z3.Not(self.carry),'hs':self.carry,'hi':z3.And(self.carry,z3.Not(self.z)),'ls':z3.Or(z3.Not(self.carry),self.z),'lt':self.n!=self.overflow,'ge':self.n==self.overflow,'gt':z3.And(z3.Not(self.z),self.n==self.overflow),'le':z3.Or(self.z,self.n!=self.overflow)}[cc]
 def one(self,i):
  m=i.mnemonic;o=i.operands;self.pc=i.address
  if m in ['cmp','cmn']:
   n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);self.flags(a,b,a-b if m=='cmp'else a+b,m=='cmp');return
  if m=='tst':
   n=self.width(i.reg_name(o[0].reg));v=self.operand(i,o[0],n)&self.operand(i,o[1],n);self.z=v==0;self.n=z3.Extract(n-1,n-1,v)==1;self.carry=self.overflow=z3.BoolVal(False);self.flag_change=True;return
  if m=='casal':
   er,dr=i.reg_name(o[0].reg),i.reg_name(o[1].reg);a=self.address(i,o[2]);old=self.load(a,4);test=z3.simplify(old==self.read(er));assert z3.is_true(test)or z3.is_false(test)
   if z3.is_true(test):self.store(a,4,self.read(dr),i.address)
   self.write(er,old);return
  if m in ['cset','csel']:
   cc=i.op_str.rsplit(',',1)[1].strip();dest=i.reg_name(o[0].reg);n=self.width(dest);v=z3.If(self.condition(cc),z3.BitVecVal(1,n),z3.BitVecVal(0,n))if m=='cset'else z3.If(self.condition(cc),self.operand(i,o[1],n),self.operand(i,o[2],n));self.write(dest,v);return
  if m in ['ldr','ldur','ldrb','ldrh','ldursw','ldrsw']:
   assert not i.writeback;dest=i.reg_name(o[0].reg);n=1 if m=='ldrb'else 2 if m=='ldrh'else 4 if m in ['ldursw','ldrsw']else self.width(dest)//8;v=self.load(self.address(i,o[1]),n);self.write(dest,z3.SignExt(32,v)if m in ['ldursw','ldrsw']else v);return
  if m in ['str','stur','strb','strh']:
   assert not i.writeback;src=i.reg_name(o[0].reg);n=1 if m=='strb'else 2 if m=='strh'else self.width(src)//8;self.store(self.address(i,o[1]),n,self.read(src),i.address);return
  if m in ['ldp','stp']:
   assert not i.writeback;a=self.address(i,o[2]);n=self.width(i.reg_name(o[0].reg))//8
   for j in range(2):
    reg=i.reg_name(o[j].reg)
    if m=='ldp':self.write(reg,self.load(z3.simplify(a+j*n),n))
    else:self.store(z3.simplify(a+j*n),n,self.read(reg),i.address)
   return
  dest=i.reg_name(o[0].reg);n=self.width(dest)
  if m=='movi':assert '.16b,'in i.op_str;v=z3.BitVecVal(o[1].imm*((1<<128)-1)//255,128)
  elif m=='adrp':v=z3.BitVecVal(o[1].imm,64)
  elif m=='mov':v=self.operand(i,o[1],n)
  elif m=='movk':
   sh=o[1].shift.value;mask=(0xffff<<sh)&((1<<n)-1);v=(self.read(dest)&~mask)|z3.BitVecVal(o[1].imm<<sh,n)
  elif m in ['add','adds','sub','subs','eor','and','orr','bic','eon','orn','mul','msub','madd']:
   assert not dest.startswith(('v','q'))or m in ['eor','and','orr','bic','eon','orn'];a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);v=a+b if m in ['add','adds']else a-b if m in ['sub','subs']else a^b if m=='eor'else a&b if m=='and'else a|b if m=='orr'else a&~b if m=='bic'else a^~b if m=='eon'else a|~b if m=='orn'else a*b if m=='mul'else self.operand(i,o[3],n)-a*b if m=='msub'else a*b+self.operand(i,o[3],n)
   if m in ['adds','subs']:self.flags(a,b,v,m=='subs')
  elif m in ['lsl','lsr','asr']:
   a=self.operand(i,o[1],n);b=self.operand(i,o[2],n)&(n-1);v=a<<b if m=='lsl'else z3.LShR(a,b)if m=='lsr'else a>>b
  elif m in ['bfxil','bfi']:
   sh,w=o[2].imm,o[3].imm;mask=((1<<w)-1)<<(sh if m=='bfi'else 0);a=self.operand(i,o[1],n);v=(self.read(dest)&~mask)|((a<<sh if m=='bfi'else z3.LShR(a,sh))&mask)
  elif m=='ubfiz':v=(self.operand(i,o[1],n)&((1<<o[3].imm)-1))<<o[2].imm
  elif m=='neg':v=-self.operand(i,o[1],n)
  elif m=='umulh':v=z3.Extract(127,64,z3.ZeroExt(64,self.operand(i,o[1],64))*z3.ZeroExt(64,self.operand(i,o[2],64)))
  elif m=='udiv':
   a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);v=z3.If(b==0,z3.BitVecVal(0,n),z3.UDiv(a,b))
  else:raise AssertionError(('unsupported source instruction',hex(i.address),m,i.op_str))
  self.write(dest,v)
 def run_path(self,limit=100000):
  pc=ENTRY;boundary=None
  for step in range(limit):
   if pc not in self.cache:self.cache[pc]=next(self.dec.disasm(IMAGE.read(pc,4),pc))
   i=self.cache[pc];self.pc=pc;self.events=[];self.written={};self.flag_change=False;row={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic};self.pool[hex(pc)]={'pc':hex(pc),'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
   if i.mnemonic in ['braa','blraa','b','ret']:
    target=i.operands[0].imm if i.mnemonic=='b'else self.concrete(self.read('x30'if i.mnemonic=='ret'else i.reg_name(i.operands[0].reg)),'unknown-dependent branch target')
    if i.mnemonic=='blraa'and target!=HELPER:
     boundary={'pc':hex(pc),'target':hex(target),'registers31':[self.shape(self.read('x'+str(j)),8)for j in range(31)],'SP':hex(self.concrete(self.read('sp'),'SP'))};break
    row['target']=hex(target)
    if i.mnemonic in ['braa','blraa']:row['modifier16']=hex(self.concrete(self.read(i.reg_name(i.operands[1].reg)),'modifier'))
    if i.mnemonic=='blraa':self.write('x30',z3.BitVecVal(pc+4,64))
    nextpc=target
   else:self.one(i);nextpc=pc+4
   row['events']=self.events;row['registers_after']={k:self.shape(v,16 if k.startswith('q')else 8)for k,v in self.written.items()}
   if self.flag_change:
    vals=[z3.simplify(x)for x in [self.n,self.z,self.carry,self.overflow]];assert all(z3.is_true(x)or z3.is_false(x)for x in vals),('unknown flags',hex(pc));row['NZCV_after']=sum((1<<(31-j))for j,x in enumerate(vals)if z3.is_true(x))
   self.steps.append(row);pc=nextpc
  assert boundary is not None,('visit budget',hex(pc));return boundary
