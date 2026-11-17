#!/usr/bin/env python3
"""Independent concrete A64 integer interpreter and byte-epoch checker.

Does not import the producing executor and does not run Unicorn. Decodes the
original words, computes GPR/NZCV/control/memory effects and compares every
recorded epoch. D-register saves and the visited FMOV are checked. O(V+E+M)
time/space; M is the delivered snapshot extents. PAC is logical only.
"""
import struct
from collections import Counter,defaultdict
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM,ARM64_OP_FP,ARM64_EXT_SXTW,ARM64_EXT_UXTB,ARM64_EXT_UXTW,ARM64_SFT_LSL,ARM64_SFT_LSR
from kext_port_tools import ROOT,IMAGE
from verify_daemon_reader_record_payloads_publication import read
M=(1<<64)-1;PRIVATE=0x6300000000
class Replay:
 def __init__(self,k,row,mutation=None):
  self.k=k;self.r=row;self.mutation=mutation;self.g=[int(v,16) for v in row['entry_registers31']];self.sp=int(row['entry_SP'],16);self.pc=int(row['entry_PC'],16);self.nzcv=int(row['entry_NZCV'],16);self.d=[int(v,16)&M for v in row['entry_Q_registers32']];self.initial={};self.state={};self.known=set();self.events=defaultdict(lambda:{'read':[],'write':[]});self.count=Counter();self.edges=[]
  old=__import__('json').loads(read(ROOT/'legacy_stack_contracts.json'))
  for j,g in enumerate(old['mutable_globals']):
   a=int(g['address'],16);c=row['input'];v=int.from_bytes(bytes.fromhex(g['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M;self.initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
  for x in row['extra_initial_globals']+[old['guard']]:
   a=int(x['address'],16);self.initial.update({a+j:b for j,b in enumerate(bytes.fromhex(x.get('bytes_hex',x.get('original8_hex'))))})
  self.allowed=[(int(g['address'],16),int(g['address'],16)+8) for g in old['mutable_globals']]+[(0xfffffe000ccc30d0,0xfffffe000ccc30d8),(0xfffffe000ccc32f8,0xfffffe000ccc3300)]
  for key,kind in [('source_reads','read'),('source_writes','write')]:
   for e in row[key]:self.events[e['source_visit_index']][kind].append(e)
  self.models={x['source_visit_index']:x for x in row['API_models']};self.cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.cs.detail=True
 def reg(self,name):
  name={'fp':'x29','lr':'x30'}.get(name,name)
  if name in ['xzr','wzr']:return 0
  if name=='sp':return self.sp
  if name.startswith('d'):return self.d[int(name[1:])]
  assert name[0]in'wx',name;return self.g[int(name[1:])] & (0xffffffff if name[0]=='w' else M)
 def set(self,name,v):
  name={'fp':'x29','lr':'x30'}.get(name,name)
  if name in ['xzr','wzr']:return
  if name=='sp':self.sp=v&M;return
  if name.startswith('d'):self.d[int(name[1:])]=v&M;return
  assert name[0]in'wx',name;self.g[int(name[1:])]=v&(0xffffffff if name[0]=='w' else M)
 def operand(self,i,o,n=64):
  v=self.reg(i.reg_name(o.reg))if o.type==ARM64_OP_REG else o.imm if o.type==ARM64_OP_IMM else None;assert v is not None
  if o.ext:
   assert o.ext in [ARM64_EXT_SXTW,ARM64_EXT_UXTB,ARM64_EXT_UXTW]
   if o.ext==ARM64_EXT_UXTB:v&=255
   else:
    v&=0xffffffff
    if o.ext==ARM64_EXT_SXTW and v&0x80000000:v-=1<<32
  if o.shift.type:
   assert o.shift.type in [ARM64_SFT_LSL,ARM64_SFT_LSR]
   v=v<<o.shift.value if o.shift.type==ARM64_SFT_LSL else (v&((1<<n)-1))>>o.shift.value
  return v&((1<<n)-1)
 def at(self,a,n):
  b=[]
  for j in range(a,a+n):
   if j in self.state:v=self.state[j]
   elif j in self.initial:v=self.initial[j]
   elif PRIVATE<=j<PRIVATE+0x20000:v=0xa5
   else:v=IMAGE.read(j,1)[0]
   b.append(v)
  return bytes(b)
 def load(self,a,n,discarded=False):
  e=self.actual_reads.pop(0);assert e['pc']==hex(self.pc)and e['address']==hex(a)and e['size_bytes']==n and e['bytes_hex']==self.at(a,n).hex()
  if PRIVATE<=a<a+n<=PRIVATE+0x20000 and not discarded:assert all(j in self.known for j in range(a,a+n)),('undefined read',hex(self.pc))
  assert e['probe_only']==discarded
  if discarded:assert n==1 and self.pc in [0xfffffe000a5a1cdc,0xfffffe000a5a1cf0]
  self.count['read_bytes_checked']+=n;self.count['source_reads_checked']+=1;return int.from_bytes(self.at(a,n),'little')
 def store(self,a,n,v):
  if not PRIVATE<=a<a+n<=PRIVATE+0x20000:assert any(x<=a<a+n<=z for x,z in self.allowed)
  e=self.actual_writes.pop(0);b=(v&((1<<(8*n))-1)).to_bytes(n,'little');assert e['pc']==hex(self.pc)and e['address']==hex(a)and e['size_bytes']==n and e['after_hex']==b.hex()
  self.state.update({a+j:v for j,v in enumerate(b)});self.known.update(range(a,a+n));self.count['write_bytes_checked']+=n;self.count['source_writes_checked']+=1
 def condition(self,name):
  N,Z,C,V=[bool(self.nzcv&(1<<j)) for j in [31,30,29,28]]
  return {'eq':Z,'ne':not Z,'hi':C and not Z,'lo':not C,'ls':not C or Z,'hs':C,'lt':N!=V,'ge':N==V}[name]
 def checkpoint(self,c):
  assert [hex(v) for v in self.g]==c['registers31'],('GPR epoch',hex(self.pc),[(j,hex(v),c['registers31'][j]) for j,v in enumerate(self.g)if hex(v)!=c['registers31'][j]])
  assert hex(self.sp)==c['SP']and hex(self.nzcv)==c['NZCV'],('SP/flags',hex(self.pc),hex(self.sp),hex(self.nzcv),c['SP'],c['NZCV']);self.count['GPR_values_checked']+=31;self.count['NZCV_values_checked']+=1
 def edge(self,i,target,kind):
  self.edges.append({'pc':hex(self.pc),'target':hex(target),'kind':kind,'source_visit_index':self.ix,'modifier64':hex(self.g[17]) if kind in ['blraa','braa']else None})
  if kind in ['bl','blraa']:self.g[30]=self.pc+4
  return target
 def step(self,i):
  m=i.mnemonic;o=i.operands;nextpc=self.pc+4
  if m in ['bti','pacibsp','paciasp','autibsp','autiasp','nop']:return nextpc
  if m=='b':return o[0].imm&M
  if m.startswith('b.'):return o[0].imm&M if self.condition(m[2:])else nextpc
  if m in ['ret','retab','retaa']:return self.edge(i,self.g[30],m)
  if m in ['blraa','braa']:
   target=self.reg(i.reg_name(o[0].reg))
   if self.ix in self.models:
    e=self.models[self.ix];assert e['pc']==hex(self.pc)and e['target']==hex(target)and e['arguments8']==[hex(v) for v in self.g[:8]]and e['model_memory_writes']==0 and not e['target_executed']
    assert (self.pc,target,e['kind'],e['result_X0_fixture']) in [(0xfffffe000a6353dc,0xfffffe000c4b9a08,'aligned16384_register_return',hex(PRIVATE+0x8000)),(0xfffffe000a635470,0xfffffe000c4ba154,'typed4096_register_return',hex(PRIVATE+0xc000))]
    self.g[0]=int(e['result_X0_fixture'],16)
    for j in range(1,18):self.g[j]=0xf000000000000000+j*0x1111
    self.nzcv=0xf0000000;self.g[30]=nextpc;self.count['register_only_API_models_checked']+=1;return nextpc
   return self.edge(i,target,m)
  if m in ['ldr','ldrb','ldur','stp','str','strb','stur','ldp']:
   pair=m in ['stp','ldp'];mem=o[2 if pair else 1];a=self.reg(i.reg_name(mem.mem.base))+mem.mem.disp
   if mem.mem.index:
    v=self.reg(i.reg_name(mem.mem.index))
    if mem.ext==ARM64_EXT_SXTW:v=(v&0xffffffff)-(1<<32 if v&0x80000000 else 0)
    elif mem.ext:assert mem.ext in [ARM64_EXT_UXTW,ARM64_EXT_UXTB];v&=(0xffffffff if mem.ext==ARM64_EXT_UXTW else 255)
    a+=v<<mem.shift.value
   a&=M;dest=i.reg_name(o[0].reg);width=1 if m in ['ldrb','strb']else 4 if dest.startswith('w')else 8
   for j in range(2 if pair else 1):
    name=i.reg_name(o[j].reg)
    if m.startswith('ld'):self.set(name,self.load(a+j*width,width,name in ['wzr','xzr']))
    else:self.store(a+j*width,width,self.reg(name))
   if i.writeback:
    # The delivered prefix uses pre-index stores, including the prologue.
    assert len(o)==(3 if pair else 2);self.set(i.reg_name(mem.mem.base),a)
   return nextpc
  if m=='cmp':
   n=32 if i.reg_name(o[0].reg).startswith('w')else 64;left=self.operand(i,o[0],n);right=self.operand(i,o[1],n);result=(left-right)&((1<<n)-1);self.nzcv=((result>>(n-1))<<31)|((result==0)<<30)|((left>=right)<<29)|((((left^right)&(left^result))>>(n-1))<<28);return nextpc
  dest=i.reg_name(o[0].reg);n=32 if dest.startswith('w')else 64;mask=(1<<n)-1
  if m=='cset':v=int(self.condition(i.op_str.rsplit(',',1)[1].strip()))
  elif m=='fmov':assert dest.startswith('d')and o[1].type==ARM64_OP_FP;v=int.from_bytes(struct.pack('<d',o[1].fp),'little')
  elif m=='adrp':v=o[1].imm
  elif m=='mov':v=self.operand(i,o[1],n)
  elif m=='movk':s=o[1].shift.value;v=(self.reg(dest)&~(0xffff<<s))|(o[1].imm<<s)
  elif m=='ubfiz':v=(self.operand(i,o[1],n)&((1<<o[3].imm)-1))<<o[2].imm
  elif m in ['lsl','lsr']:v=self.operand(i,o[1],n)<<o[2].imm if m=='lsl'else self.operand(i,o[1],n)>>o[2].imm
  else:
   assert m in ['add','sub','and','orr','eor','orn','mul'],('unsupported independent decode',hex(self.pc),m,i.op_str)
   a,b=self.operand(i,o[1],n),self.operand(i,o[2],n);v=a+b if m=='add'else a-b if m=='sub'else a&b if m=='and'else a|b if m=='orr'else a^b if m=='eor'else a|(~b&mask)if m=='orn'else a*b
  self.set(dest,v);return nextpc
 def run(self):
  assert len(self.r['source_visits'])==len(self.r['source_frames'])
  for self.ix,(v,f) in enumerate(zip(self.r['source_visits'],self.r['source_frames'])):
   assert v['source_visit_index']==self.ix and v['pc']==hex(self.pc)
   raw=self.k.read(self.pc,4);assert raw==IMAGE.read(self.pc,4)
   if self.mutation and self.pc==self.mutation['pc']:raw=b'\x1f\x20\x03\xd5'
   assert v['bytes_hex']==raw.hex();self.checkpoint(f);self.actual_reads=list(self.events[self.ix]['read']);self.actual_writes=list(self.events[self.ix]['write']);i=next(self.cs.disasm(raw,self.pc));self.pc=self.step(i);assert not self.actual_reads and not self.actual_writes;self.count['source_visits_checked']+=1
  assert self.r['boundary']['pc']==hex(self.pc);self.checkpoint(self.r['boundary']);assert self.edges==self.r['logical_edges'];assert [hex(v) for v in self.d]==self.r['boundary_D_registers32'];self.count['D_register_values_checked']+=32;self.count['logical_edges_checked']+=len(self.edges)
  for key in ['frame','workspace','typed_region']:
   s=self.r[key];a=int(s['address'],16);n=s['size_bytes'];assert self.at(a,n).hex()==s['bytes_hex'];assert bytes(int(j in self.known)for j in range(a,a+n)).hex()==s['known_mask_hex'];assert bytes(1 if j in self.known else 0 for j in range(a,a+n)).hex()==s['provenance_hex'];self.count['snapshot_bytes_checked']+=n
  self.count['cases_checked']+=1;return dict(self.count)
