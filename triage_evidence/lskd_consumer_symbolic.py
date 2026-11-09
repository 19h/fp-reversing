#!/usr/bin/env python3
"""Bounded source-instruction lift for operation classifier and shared-frame preparation.

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
    n=self.width(i.reg_name(ops[0].reg));self.cmp_left=self.operand(i,ops[0],n);self.cmp_right=self.operand(i,ops[1],n);self.equal=self.cmp_left==self.cmp_right;continue
   if m=='cset':
    condition=i.op_str.rsplit(',',1)[1].strip();assert condition in['eq','ne','lt','ge'];self.condition=self.equal if condition=='eq'else z3.Not(self.equal)if condition=='ne'else self.cmp_left<self.cmp_right if condition=='lt'else self.cmp_left>=self.cmp_right;self.condition_name=condition;self.write(i.reg_name(ops[0].reg),z3.If(self.condition,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));continue
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
   elif m in['add','sub','and','orr','eor','eon','orn','bic','mul','madd','msub']:
    a=self.operand(i,ops[1],n);b=self.operand(i,ops[2],n)
    v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a^~b if m=='eon'else a|~b if m=='orn'else a&~b if m=='bic'else a*b if m=='mul'else a*b+self.operand(i,ops[3],n)if m=='madd'else self.operand(i,ops[3],n)-a*b
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

# These cells describe the epoch immediately before the tag/operation reload.
def preparation_cells(B,A,G1,G2):
 return {0x178:G1,0x180:G2,0x30:B+0x120,0x38:B+0x10,
  0x20:B+0xc8,0x28:B+0xb0,0x40:A+0x18,0x60:A+0x60,0x68:A+0x10,
  0x88:B+0x128,0x70:A+0x30,0xd8:A+0xa8,0xe0:A+0x88,
  0xe8:A+0x40,0xf0:A+0x58,0xf8:A+0x98,0xc0:B+0xfc,0xc8:A+0x70,
  0x80:B+0xa0,0x100:B+0x90,0x50:B+0x9c,0x90:A+0x78,0x98:B+0xd0,
  0x58:B+0xa8,0x48:B+0xc0,0xd0:A+0x50}

def written_registers(i):
 # Explicit alias-safe destinations; Capstone regs_access treats some aliases
 # as destination reads. This bounded instruction set rejects unknown writes.
 if i.mnemonic in ['bti','cmp','tst','ccmp','braa','str','stp','stur','strb','strh']:return []
 allowed=['mov','movk','add','sub','and','orr','eor','eon','orn','bic','mul','madd','msub','lsl','lsr','ubfiz','neg','cset','ldr','ldrh','ldrb','ldp','mvn']
 assert i.mnemonic in allowed,(hex(i.address),i.mnemonic)
 assert not i.writeback
 return [i.reg_name(o.reg) for o in i.operands[:2 if i.mnemonic=='ldp'else 1]]

def queries(c):
 OP=z3.BitVec('operation32',32);F=0x51000000;counts={};qs=[];lifted={}
 for n in c['nodes']:
  label=n['label'];v=Lift(c);v.seed('w8',OP);v.seed('sp',F)
  for r,x in n['input_constants'].items():v.seed(r,int(x,16))
  mem(v,F+0x1a0,4,0x3be);v.run('arithmetic_'+label);counts['arithmetic_'+label]=v.count;lifted[label]=v
  pred=OP<int(n['threshold32']) if n['condition']=='lt'else OP>=int(n['threshold32'])if n['condition']=='ge'else OP==n['threshold32']
  index=resize(v.read(n['index_register']),32)
  qs.append(('index_'+label,z3.Or(v.cmp_left!=OP,v.cmp_right!=n['threshold32'],index!=z3.If(pred,z3.BitVecVal(n['true_index'],32),z3.BitVecVal(n['false_index'],32)))))
 byaddr={n['start']:n for n in c['nodes']};violations=[]
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for n in c['nodes']:
  raw=next(s for s in c['spans']if s['label']=='node_'+n['label']);ins=list(cs.disasm(bytes.fromhex(raw['bytes_hex']),int(n['start'],16)))
  writers={}
  table_values={n['table_register']:'original_table'}
  seeded={'x8',*('x'+r[1:]for r in n['input_constants'])}
  for i in ins:
   dests=written_registers(i)
   if i.address<int(n['arithmetic_start'],16):assert not seeded.intersection(('x'+r[1:])if r.startswith('w')else r for r in dests)
   copied=table_values.get(i.reg_name(i.operands[1].reg))if i.mnemonic=='mov'and i.operands[1].type==ARM64_OP_REG else None
   for r in dests:
    key=('x'+r[1:])if r.startswith('w')else r;writers[key]=i.address;table_values[key]=copied
  for edge in n['edges']:
   child=byaddr.get(edge['original_pointer']['target'])
   if child is None:continue
   assert table_values.get(child['table_register'])=='original_table',('unproved table continuity',n['label'],child['label'])
   assert writers.get('x8',0)<int(n['table_load_pc'],16),('operation overwritten in tail',n['label'])
   violations.append(resize(lifted[n['label']].read('w8'),32)!=OP)
   for reg,value in child['input_constants'].items():
    last=writers.get('x'+reg[1:]);guard=resize(lifted[n['label']].read(n['index_register']),32)==edge['index32']
    if last==int(n['table_load_pc'],16):val=z3.BitVecVal(int(edge['original_pointer']['target'],16)&0xffffffff,32)
    else:
     assert last is None or last<int(n['table_load_pc'],16),('unsupported tail seed writer',n['label'],reg,last)
     val=resize(lifted[n['label']].read(reg),32)
    violations.append(z3.And(guard,val!=int(value,16)))
 qs.append(('edge_phase_continuity',z3.Or(*violations)))
 def tree(addr,seen=()):
  if addr not in byaddr:return z3.BitVecVal(int(addr,16),64)
  assert addr not in seen;n=byaddr[addr];es={e['condition_outcome']:e for e in n['edges']};idx=resize(lifted[n['label']].read(n['index_register']),32)
  return z3.If(idx==n['true_index'],tree(es['true']['original_pointer']['target'],(*seen,addr)),tree(es['false']['original_pointer']['target'],(*seen,addr)))
 expected=z3.BitVecVal(int(c['default_leaf'],16),64)
 for op,target in c['leaf_map'].items():expected=z3.If(OP==int(op,16),z3.BitVecVal(int(target,16),64),expected)
 qs.append(('complete_word_partition',tree(c['nodes'][0]['start'])!=expected))
 B,A,Q,G1,G2=z3.BitVecs('workspace_base64 auxiliary_base64 request64 global1_64 global2_64',64)
 v=Lift(part(c,'prepare',0xfffffe000a59bf7c,0xfffffe000a59c040))
 for r,x in [('sp',F),('x24',B),('x27',Q),('x25',G1),('x21',G2)]:v.seed(r,x)
 mem(v,F+0x160,8,A);v.run('prepare');counts['shared_frame_preparation']=v.count
 bad=[cell(v,F+off,8)!=x for off,x in preparation_cells(B,A,G1,G2).items()]
 bad.extend(v.read(r)!=x for r,x in [('x19',Q),('x20',A+0x20),('x27',A+0x28),('x25',B+0x18)])
 qs.append(('shared_frame_pointers',z3.Or(*bad)))
 T=int(c['table_address'],16);v=Lift(part(c,'reload',0xfffffe000a59c040,0xfffffe000a59c060))
 for r,x in [('sp',F),('x22',B+0x98),('x24',B),('x23',T)]:v.seed(r,x)
 mem(v,F+0x1a0,4,0x3be);mem(v,B+0x98,4,OP);mem(v,T+8*0x3b5,8,int(c['nodes'][0]['start'],16));v.run('reload');counts['source_operation_reload']=v.count
 qs.append(('source_operation_reload',z3.Or(v.read('w8')!=OP,v.read('x10')!=int(c['nodes'][0]['start'],16),v.read('x22')!=B+4,cell(v,F+0x78,8)!=B+0x20,cell(v,F+0x120,8)!=B)))
 bad=[]
 for j,(a,z)in enumerate([(0xfffffe000a5230fc,0xfffffe000a523104),(0xfffffe000a5269f4,0xfffffe000a5269fc),(0xfffffe000a546da8,0xfffffe000a546db0)]):
  v=Lift(part(c,'status',a,z)).run('status');counts['default_status_'+str(j)]=v.count;bad.append(v.read('w8')!=0x5e5571af)
 qs.append(('default_status_preparation',z3.Or(*bad)))
 return qs,counts
