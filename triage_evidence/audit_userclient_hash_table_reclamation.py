#!/usr/bin/env python3
"""Original entry transitions, reclamation loop and cleanup/free data flow.
O(I+256R+query DAG) construction; bounded SMT search is separate.
Synthetic source/reference replay has O(cases*N) time. No target executes.
"""
import copy
import json
import struct
from hashlib import sha256
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword
from lskd_values_symbolic import Lift, resize, mem
from audit_userclient_hash_table_initializer import DEC, IMAGE_REGIONS
from audit_userclient_hash_table_lookup import Model as Engine
from audit_userclient_uidlist_cleanup import lookup
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_userclient_hash_table_reclamation as R

MASK=(1<<64)-1
EMPTY=0x629f8775
DELETED=0x629f8776
OCCUPIED=0x629f8777
KEY0=0x1ee45f68039f9913
SUCCESS=0x31ae0066
TAG=0xffc0000000000000

def number(x):
 x=z3.simplify(x);assert z3.is_bv_value(x),str(x);return x.as_long()

def cell(v,a,n):return v.memory[(z3.simplify(resize(a,64)).sexpr(),n)]

class Model(Engine):
 def __init__(self,e):
  Lift.__init__(self,{'spans':e['spans']});self.e=e;self.reads=[];self.address_checks=[];self.visited=set()
  self.sp,self.record,self.header,self.buffer,self.payload=z3.BitVecs('HR_SP64 HR_record64 HR_header64 HR_buffer64 HR_payload64',64)
  self.capacity,self.index,self.counter,self.old_state,self.desired_state,self.next_state,self.cursor,self.current_state=z3.BitVecs('HR_capacity32 HR_index32 HR_counter32 HR_old_state32 HR_desired_state32 HR_next_state32 HR_cursor32 HR_current_state32',32)
  self.new_key,self.new_value=z3.BitVecs('HR_new_key64 HR_new_value64',64)
  self.guard0,self.guard1=z3.BitVecs('HR_guard_initial64 HR_guard_return64',64)
  self.entry=self.buffer+24*z3.ZeroExt(32,self.index)
  self.base={n:int(b['address'],16) for n,b in e['banks'].items()};self.banks={n:bytes.fromhex(b['bytes_hex']) for n,b in e['banks'].items()}
  self.bank_pc={0xfffffe000a6271bc:'UL',0xfffffe000a6271c8:'UR',0xfffffe000a6272cc:'UL',0xfffffe000a6272d8:'UR',
   0xfffffe000a62738c:'VL',0xfffffe000a62739c:'VR',0xfffffe000a6273c0:'TL',0xfffffe000a6273c8:'TR',
   0xfffffe000a5aecdc:'VL',0xfffffe000a5aecf0:'VR',0xfffffe000a6168d8:'TL',0xfffffe000a6168ec:'TR',
   0xfffffe000a616928:'VL',0xfffffe000a616940:'VR',0xfffffe000a6169e0:'TL',0xfffffe000a6169ec:'TR',
   0xfffffe000a616c78:'VL',0xfffffe000a616c88:'VR'}
  self.bank_state={};self.bank_rewrites=[]
  self.right_rule={0xfffffe000a6271c8:'caller_writer',0xfffffe000a6272d8:'caller_reclaimer',0xfffffe000a62739c:'caller_free',
   0xfffffe000a6273c8:'free_descriptor',0xfffffe000a5aecf0:'writer_table',0xfffffe000a6168ec:'table_controller_A',
   0xfffffe000a616940:'table_controller_B',0xfffffe000a6169ec:'table_table',0xfffffe000a616c88:'nested_writer'}
  self.bind={}
  def fixed(pc,a,value):self.bind[pc]=lambda:(resize(a,64),value)
  for pc,a,n in [(0xfffffe000a6271a0,0xfffffe000ccc3330,4),(0xfffffe000a6271a4,0xfffffe000ccc32f8,4),
   (0xfffffe000a6272b4,0xfffffe000ccc3330,4),(0xfffffe000a6272b8,0xfffffe000ccc32f8,4),
   (0xfffffe000a62736c,0xfffffe000ccc3330,4),(0xfffffe000a627370,0xfffffe000ccc32f8,4),
   (0xfffffe000a5aec30,0xfffffe000ccc33a0,8),(0xfffffe000a5aec38,0xfffffe000ccc32f8,8),
   (0xfffffe000a6168b4,0xfffffe000ccc3328,4),(0xfffffe000a6168bc,0xfffffe000ccc32f8,4),
   (0xfffffe000a616908,0xfffffe000ccc3328,8),(0xfffffe000a616954,0xfffffe000ccc32f8,8),
   (0xfffffe000a6169c8,0xfffffe000ccc3328,4),(0xfffffe000a6169cc,0xfffffe000ccc32f8,4),
   (0xfffffe000a616c44,0xfffffe000ccc3328,4),(0xfffffe000a616c48,0xfffffe000ccc32f8,4)]:
   fixed(pc,a,z3.BitVec('HR_controller_'+format(pc,'x'),8*n))
  for pc,a,value in [(0xfffffe000a6270ec,self.header+8,self.buffer),(0xfffffe000a6271ec,self.header+8,self.buffer),
   (0xfffffe000a6271f0,self.header+4,self.capacity),(0xfffffe000a5aed44,self.entry,self.old_state),
   (0xfffffe000a5aedcc,self.header,self.counter),(0xfffffe000a616918,POOL+0xc08,self.base['VL']+8),
   (0xfffffe000a616934,POOL+0x158,self.base['VR']+4),(0xfffffe000a61688c,0xfffffe000847c5f8,0xfffffe000cacb000),
   (0xfffffe000a616890,0xfffffe000cacb000,self.guard0),(0xfffffe000a616d24,0xfffffe000847c5f8,0xfffffe000cacb000),
   (0xfffffe000a616d28,0xfffffe000cacb000,self.guard1)]:fixed(pc,a,value)
  self.table_pc={0xfffffe000a6271dc:(TABLE,[0xf5d]),0xfffffe000a6272e8:(TABLE,[0xf56]),
   0xfffffe000a6272fc:(TABLE,[0xa8f]),0xfffffe000a627350:(TABLE,[0x4fa,0x518]),
   0xfffffe000a6273b4:(TABLE,[0xf2b]),0xfffffe000a6273e0:(POOL,[0x117]),0xfffffe000a6273f0:(TABLE,[0x39b]),
   0xfffffe000a5aed08:(POOL,[0x33]),0xfffffe000a5aed10:(TABLE,[0xc28,0xc59]),
   0xfffffe000a5aed74:(TABLE,[0xce2,0xce7]),0xfffffe000a5aedac:(TABLE,[0x279,0x523]),
   0xfffffe000a5aedd8:(TABLE,[0x279]),0xfffffe000a5aedfc:(TABLE,[0x355]),
   0xfffffe000a616904:(POOL,[0x1a8]),0xfffffe000a616950:(POOL,[0x1c]),0xfffffe000a6169fc:(POOL,[0x33]),
   0xfffffe000a616a04:(TABLE,[0x559,0x563]),0xfffffe000a616a94:(TABLE,[0x951,0xc6f]),
   0xfffffe000a616aec:(TABLE,[0x94f,0x951]),0xfffffe000a616b34:(TABLE,[0x4ef]),
   0xfffffe000a616c9c:(TABLE,[0xf5d]),0xfffffe000a616d00:(TABLE,[0x4ef,0xacf])}
  self.seed('sp',self.sp)
  for j in range(19,31):self.seed('x'+str(j),z3.BitVec('HR_saved_X'+str(j),64))

 def address(self,i,o):
  if i.writeback:
   assert i.address in [0xfffffe000a616908,0xfffffe000a616954]
   a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp;self.write(i.reg_name(o.mem.base),a);return z3.simplify(a)
  return super().address(i,o)

 def load(self,a,n):
  if self.pc in self.bank_pc:
   name=self.bank_pc[self.pc];base=self.base[name];pair=name[:-1];ix=z3.Extract(7,0,a-base)
   assert n==1
   if name.endswith('L'):
    self.address_checks.append(a==base+z3.ZeroExt(56,ix));value=lookup(self.banks[name],ix);self.bank_state[pair]=(ix,value)
   else:
    r=next(r for r in self.e['bank_rules'] if r['name']==self.right_rule[self.pc]);inp,left=self.bank_state[pair]
    self.address_checks.append(a==base+z3.ZeroExt(56,left^int(r['key'],16)))
    value=inp^int(r['constant'],16);self.bank_rewrites.append({'pc':hex(self.pc),'rule':r['name'],'checked_inputs':256})
   self.reads.append({'pc':hex(self.pc),'size_bytes':n});return value
  if self.pc in self.table_pc:
   base,choices=self.table_pc[self.pc];tests=[a==base+8*j for j in choices];self.address_checks.append(z3.Or(*tests));v=resize(qword(base+8*choices[-1]),n*8)
   for j,t in reversed(list(zip(choices[:-1],tests[:-1]))):v=z3.If(t,resize(qword(base+8*j),n*8),v)
   self.reads.append({'pc':hex(self.pc),'size_bytes':n});return v
  if self.pc in [0xfffffe000a616a7c,0xfffffe000a616be8]:
   if self.pc==0xfffffe000a616a7c:
    i=z3.If(self.index+1==self.capacity,resize(0,32),self.index+1);value=self.next_state
   else:i=self.cursor;value=self.current_state
   self.address_checks.append(a==self.buffer+24*z3.ZeroExt(32,i));self.reads.append({'pc':hex(self.pc),'size_bytes':n});assert n==4;return value
  return super(Engine,self).load(a,n)

 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic in ['csinc','umull']:
    self.pc=i.address;self.visited.add(i.address)
    self.count+=1;o=i.operands
    if i.mnemonic=='csinc':
     assert i.op_str.endswith(', eq');value=z3.If(self.equal,self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))+1)
    else:value=z3.ZeroExt(32,resize(self.read(i.reg_name(o[1].reg)),32))*z3.ZeroExt(32,resize(self.read(i.reg_name(o[2].reg)),32))
    self.write(i.reg_name(o[0].reg),value)
   else:
    old=self.e;self.e={**old,'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e=old
  return self

 def owned(self):
  length=24*z3.ZeroExt(32,self.capacity)
  ranges=[getattr(self,'frame_extent',(self.sp-0x200,0x340)),(self.record,48),(self.header,16),(self.buffer,length)]
  out=[z3.UGE(self.sp,0x200),(self.sp&15)==0,(self.record&7)==0,(self.header&7)==0,(self.buffer&7)==0,self.capacity!=0,z3.ULT(self.index,self.capacity)]
  def sep(a,n,b,m):return z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,MASK-n)])
   for b,m in ranges[j+1:]:out.append(sep(a,n,b,m))
   for b,m in IMAGE_REGIONS:out.append(sep(a,n,resize(b,64),m))
  out.append(z3.ULE(self.entry,MASK-24))
  for a,n in ranges[:-1]:out.append(sep(self.entry,24,a,n))
  for a,n in IMAGE_REGIONS:out.append(sep(self.entry,24,resize(a,64),n))
  return out

def caller(e):
 v=Model(e)
 for n,x in {'w23':0xa8f,'w22':0x4fa,'x21':v.header,'x24':v.sp+0x90,
  'x25':POOL,'x27':TABLE,'x26':0xa41a4d891208c018,'w28':0x4d08a3fb}.items():v.seed(n,x)
 for off,n in [(0x20,'UL'),(0x28,'UR'),(0x30,'VL'),(0x38,'VR'),(0x40,'TR'),(0x48,'TL')]:mem(v,v.sp+off,8,v.base[n])
 mem(v,v.sp+0x68,8,0xfffffe000ccc32f8);mem(v,v.sp+0x70,8,0xfffffe000ccc3330)
 mem(v,v.sp+0x80,4,v.index);mem(v,v.sp+0x18,8,v.payload)
 return v

def writer(e,entry_null=False):
 v=Model(e);v.frame_extent=(v.sp-0x10,0x10);v.seed('x0',v.record);v.run('writer_environment')
 # Codec prefix is split from its reads without inventing instruction bytes.
 old=v.e;row=next(s for s in old['spans'] if s['label']=='writer_codec_gate');raw=bytes.fromhex(row['bytes_hex'])
 v.e={**old,'spans':[{'label':'key','start':row['start'],'bytes_hex':raw[:0x20].hex()}]};v.run('key');v.e=old
 key=v.read('x8');mem(v,v.record,8,0 if entry_null else v.entry);mem(v,v.record+8,4,resize(key,32)+0xc28)
 mem(v,v.record+0x10,8,v.new_value);mem(v,v.record+0x18,8,v.header)
 mem(v,v.record+0x20,4,v.desired_state+resize(key,32));mem(v,v.record+0x28,8,v.new_key-key)
 v.e={**old,'spans':[{'label':'gate','start':'0xfffffe000a5aec98','bytes_hex':raw[0x20:].hex()}]};v.run('gate');v.e=old
 return v

def table(e,buffer_null=False):
 v=Model(e);v.seed('x0',v.record);v.run('table_frame').run('table_guard_save').run('table_roots')
 old=v.e;row=next(s for s in old['spans'] if s['label']=='table_codec_gate');raw=bytes.fromhex(row['bytes_hex'])
 v.e={**old,'spans':[{'label':'key','start':row['start'],'bytes_hex':raw[:0x20].hex()}]};v.run('key');v.e=old
 key=resize(v.read('x13'),32)
 mem(v,v.record,8,v.header);mem(v,v.record+8,4,v.index+0x1859e9d9-key);mem(v,v.record+0xc,4,key+0x559)
 mem(v,v.record+0x10,4,v.capacity+0x35f2763e+key);mem(v,v.record+0x18,8,0 if buffer_null else v.buffer)
 v.e={**old,'spans':[{'label':'gate','start':'0xfffffe000a6169a8','bytes_hex':raw[0x20:].hex()}]};v.run('gate');v.e=old
 return v

def part(v,label,a,z):
 old=v.e;row=next(s for s in old['spans'] if s['label']==label);start=int(row['start'],16)
 assert start<=a<z<=int(row['end_exclusive'],16)
 v.e={**old,'spans':[{'label':'part','start':hex(a),'bytes_hex':bytes.fromhex(row['bytes_hex'])[a-start:z-start].hex()}]}
 v.run('part');v.e=old;return v

def overlap(v,a,n):
 return z3.Or(*[z3.And(z3.ULT(t['address'],a+n),z3.ULT(a,t['address']+t['size_bytes'])) for t in v.stores])

def fork(v):
 x=copy.copy(v)
 for n in ['regs','memory','values','bank_state']:setattr(x,n,dict(getattr(v,n)))
 for n in ['stores','reads','address_checks','bank_rewrites']:setattr(x,n,list(getattr(v,n)))
 x.visited=set(v.visited);return x

def phase(e):
 v=Model(e);v.iteration=z3.BitVec('HR_iteration32',32);v.entry=v.buffer+24*z3.ZeroExt(32,v.cursor)
 regs={'x19':v.record,'x22':v.buffer,'x28':TABLE,'w26':0x559,'w24':v.cursor+0x1859e9d9,
  'w21':v.iteration,'w23':0xc279e948,'w25':v.capacity+0xc279e948,
  'w27':z3.If(z3.ULT(v.capacity+0xc279e948,resize(0xc279e948,32)),resize(1,32),resize(0,32)),
  'x20':((v.sp+0x48)^0x2a4f38d70e12cee6)*0x91c952ff}
 for n,x in regs.items():v.seed(n,x)
 mem(v,v.record,8,v.header);mem(v,v.sp+8,8,KEY0-v.read('x20'))
 mem(v,v.sp+0x14,4,0x4ef);mem(v,v.sp+0x18,4,v.capacity+0x1859e9d8);mem(v,v.sp+0x1c,4,v.capacity+0xc279e948)
 mem(v,v.sp+0x20,8,0xfffffe000ccc32f8);mem(v,v.sp+0x28,8,0xfffffe000ccc3328)
 mem(v,v.sp+0x30,8,v.base['VR']);mem(v,v.sp+0x38,8,v.base['VL'])
 return v

def validate_input(e):
 assert e['source_sha256']==sha(SOURCE)
 for f in [*e['functions'].values(),e['caller_region']]:
  raw=bytes.fromhex(f['bytes_hex']);assert IMAGE.read(int(f['start'],16),len(raw))==raw
 for s in e['spans']:
  raw=bytes.fromhex(s['bytes_hex']);a=int(s['start'],16);assert IMAGE.read(a,len(raw))==raw
  assert s['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in DEC.disasm(raw,a)]
 for t in e['transfers']:assert IMAGE.read(int(t['ea'],16),4).hex()==t['bytes_hex']
 for b in e['banks'].values():assert IMAGE.read(int(b['address'],16),256).hex()==b['bytes_hex']
 for r in e['bank_rules']:assert (qword(int(r['slot'],16))+int(r['bias'],16))&MASK==int(r['target'],16)
 for p in e['branch_pointers']:assert qword(int(p['slot'],16))==int(p['target'],16)
 d=e['typed_free_descriptor'];raw=IMAGE.read(int(d['address'],16),64);assert raw.hex()==d['normalized64_bytes_hex']
 assert int.from_bytes(raw[40:44],'little')==d['flags_u32']==0x6c and int.from_bytes(raw[44:48],'little')==d['size_bytes']==120
 assert d['name']=='site.FPSecureTunnel'

def proofs(e):
 out=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=(),owner=None):
  s=z3.Solver();s.set(timeout=30000);s.add(*(owner or v).owned(),*premises);assert s.check()==z3.sat,label
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)))
  result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  out.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),'certified_rewrites':list(rewrites)+[{'lemma':'exhaustive_original_bank_pair_identity','applications':copy.deepcopy(v.bank_rewrites)}]})
  coverage.append({'label':label,'source_instruction_instances':v.count,'read_instances':len(v.reads),'write_instances':len(v.stores)})
  visited.update(v.visited)
 v=caller(e);v.run('caller_entry_address');a=v.entry
 prove('original_cleanup_entry_address_and_tag_condition',v,z3.Or(v.read('x12')!=a,v.equal!=(((v.buffer^a)&TAG)==0)))
 v.run('caller_entry_retag');prove('original_cleanup_entry_alternate_top16_retag',v,v.read('x12')!=((a&((1<<48)-1))|(0xc8a2<<48)))
 v.seed('x12',a);v.run('caller_entry_request')
 stable=[((v.buffer^(v.buffer+24*z3.ZeroExt(32,v.capacity)-1))&TAG)==0]
 prove('original_cleanup_writer_call_ABI_and_raw_record_fields',v,z3.Or(v.read('x0')!=v.sp+0x90,v.read('x8')!=0xfffffe000a5aec24,
  v.read('x17')!=0x3936,v.read('w22')!=0x4fa,cell(v,v.sp+0x90,8)!=a,cell(v,v.sp+0xa0,8)!=0,cell(v,v.sp+0xa8,8)!=v.header),stable)
 d=Model(e);d.memory=dict(v.memory);d.seed('x0',v.sp+0x90);d.run('writer_environment');part(d,'writer_codec_gate',0xfffffe000a5aec78,0xfffffe000a5aec98)
 ck=v.values[(0xfffffe000a627150,'x10')];dk=d.values[(0xfffffe000a5aec88,'x8')]
 prove('cleanup_writer_pre_multiply_codec_key_equivalence',d,ck!=dk,stable,owner=v)
 d.seed('x8',v.values[(0xfffffe000a62715c,'x10')]);part(d,'writer_codec_gate',0xfffffe000a5aec98,0xfffffe000a5aed18)
 d.run('writer_increment_gate')
 prove('cleanup_record_decodes_tombstone_keyzero_payloadzero',d,z3.Or(d.read('w11')!=DELETED,
  cell(v,v.sp+0xb8,8)+d.read('x8')!=KEY0,cell(v,v.sp+0xa0,8)!=0,d.read('x15')!=0xfffffe000a5aed84),stable,
  [{'lemma':'cleanup_writer_pre_multiply_codec_key_equivalence','rewrite':'Congruence through common u64 multiply, then original state/key decoder.'}],owner=v)
 # Generic setter profile: all old/new state words and counter values.
 h=writer(e);prove('token_c28_nonnull_entry_gate_and_decoded_token',h,z3.Or(h.read('w11')!=0xc28,h.read('x12')!=0xfffffe000a5aed1c))
 h.run('writer_increment_gate');inc=z3.And(h.old_state==EMPTY,h.desired_state==OCCUPIED)
 prove('all_state32_empty_to_occupied_increment_gate',h,h.read('x15')!=z3.If(inc,resize(0xfffffe000a5aedc0,64),resize(0xfffffe000a5aed84,64)))
 for kind in ['increment','decrement','unchanged']:
  q=fork(h);premises=[inc] if kind=='increment' else [z3.Not(inc)]
  if kind!='increment':q.run('writer_decrement_gate')
  dec=z3.And(q.old_state==DELETED,q.desired_state==EMPTY)
  if kind=='decrement':premises.append(dec)
  if kind=='unchanged':premises.append(z3.Not(dec))
  if kind!='unchanged':q.run('writer_counter')
  q.run('writer_fields').run('writer_return')
  count_bad=cell(q,q.header,4)!=(q.counter+(1 if kind=='increment' else -1)) if kind!='unchanged' else overlap(q,q.header,4)
  prove('all_state32_'+kind+'_counter_and_exact_entry_stores',q,z3.Or(count_bad,cell(q,q.entry,4)!=q.desired_state,
   cell(q,q.entry+8,8)!=q.new_key,cell(q,q.entry+16,8)!=q.new_value,q.read('sp')!=q.sp,q.read('x8')!=0xfffffe000a5aee08,overlap(q,q.entry+4,4)),premises)
 q=fork(h);q.run('writer_decrement_gate')
 prove('all_state32_tombstone_to_empty_decrement_gate',q,q.read('x14')!=z3.If(z3.And(q.old_state==DELETED,q.desired_state==EMPTY),resize(0xfffffe000a5aedc0,64),resize(0xfffffe000a5aede4,64)),[z3.Not(z3.And(q.old_state==EMPTY,q.desired_state==OCCUPIED))])
 h=writer(e,entry_null=True);h.run('writer_return')
 prove('token_c28_null_entry_returns_without_entry_or_header_stores',h,z3.Or(h.read('x12')!=0xfffffe000a5aee08,h.read('sp')!=h.sp,len(h.stores)!=2))
 # Entry writer ordinary-return seam; it has no output status.
 v.returned();v.run('caller_table_request')
 prove('original_cleanup_reclaimer_call_binding_and_header_array_record',v,z3.Or(v.read('x0')!=v.sp+0x90,v.read('x8')!=0xfffffe000a616860,
  v.read('x17')!=0xaf1c,cell(v,v.sp+0x90,8)!=v.header,cell(v,v.sp+0xa8,8)!=v.buffer),stable)
 t=Model(e);t.memory=dict(v.memory);t.seed('x0',v.sp+0x90);t.run('table_frame').run('table_guard_save').run('table_roots');part(t,'table_codec_gate',0xfffffe000a616988,0xfffffe000a6169a8)
 ck=v.values[(0xfffffe000a627260,'w13')];dk=resize(t.values[(0xfffffe000a616998,'x13')],32)
 prove('cleanup_reclaimer_pre_multiply_low32_codec_key_equivalence',t,ck!=dk,stable,owner=v)
 # Only W13 consumes the decoded key before the source overwrites X13.
 # Re-run the source gate with the certified low32 product; upper bits are unused.
 row=next(s for s in e['spans'] if s['label']=='table_codec_gate');old=t.e
 t.e={**old,'spans':[{'label':'gate','start':'0xfffffe000a6169a8','bytes_hex':bytes.fromhex(row['bytes_hex'])[0x20:].hex()}]}
 t.seed('x13',v.values[(0xfffffe000a62726c,'w13')]);t.run('gate');t.e=old;t.run('table_next_gate')
 prove('cleanup_reclaimer_record_decodes_token559_index_and_capacity',t,z3.Or(t.read('w26')!=0x559,
  t.read('x22')!=v.buffer,t.read('w9')!=v.index+0x1859e9d9,t.read('w10')!=v.capacity+0x35f2763e),stable,
  [{'lemma':'cleanup_reclaimer_pre_multiply_low32_codec_key_equivalence','rewrite':'Congruence through low32 multiply; only W13 reads the product before overwrite.'}],owner=v)
 status=z3.BitVec('HR_cleanup_status32',32);v.returned();mem(v,v.sp+0xb0,4,status);v.run('caller_table_return').run('caller_free_gate')
 prove('all_status32_payload64_exact_conditional_free_gate',v,z3.Or(v.read('w19')!=0x39b,v.read('w24')!=0x980,v.read('x1')!=v.payload,
  v.read('x8')!=z3.If(z3.And(status==SUCCESS,v.payload!=0),resize(0xfffffe000a627360,64),resize(0xfffffe000a626920,64))),stable)
 v.run('caller_free_request')
 prove('original_FPSecureTunnel_typed_free_ABI',v,z3.Or(v.read('x0')!=0xfffffe000847bf60,v.read('x1')!=v.payload,
  v.read('x11')!=0xfffffe000c4ba368,v.read('x17')!=0x4d6a,v.read('w24')!=0x980),stable+[status==SUCCESS,v.payload!=0])
 v.returned();v.run('caller_free_return')
 prove('ordinary_typed_free_return_joins_UIDList_node_free',v,z3.Or(v.read('x8')!=0xfffffe000a626920,v.read('x17')!=0x678,
  v.read('x2')!=0xfffffe000ccc32f8,v.read('x3')!=0xfffffe000ccc3330),stable+[status==SUCCESS,v.payload!=0])
 for null in [False,True]:
  h=table(e,buffer_null=null)
  prove('token559_'+('null_array_gate' if null else 'nonnull_array_gate'),h,z3.Or(h.read('w26')!=0x559,h.read('w15')!=0xce515bbf,
   h.read('x8')!=(0xfffffe000a616d14 if null else 0xfffffe000a616a14)))
 h=table(e);h.run('table_next_gate')
 prove('original_next_entry_wrapped_index_and_empty_gate',h,z3.Or(h.read('w9')!=h.index+0x1859e9d9,h.read('w10')!=h.capacity+0x35f2763e,
  h.read('w15')!=SUCCESS,h.read('x12')!=z3.If(h.next_state==EMPTY,resize(0xfffffe000a616aa8,64),resize(0xfffffe000a616d14,64))))
 h.run('table_capacity_gate')
 prove('positive_capacity_backward_reclamation_gate',h,z3.Or(cell(h,h.sp-0xe0+0x1c,4)!=h.capacity+0xc279e948,h.read('x11')!=0xfffffe000a616af8))
 h.run('table_prepare')
 prove('original_backward_cursor_and_encoded_empty_key',h,z3.Or(h.read('w24')!=h.index+0x1859e9d9,h.read('w21')!=1,
  h.read('w12')!=0x4ef,h.read('x8')!=0xfffffe000a616bbc))
 inner=h.sp-0xe0+0x48
 pk=h.values[(0xfffffe000a616b8c,'x9')]
 prove('reclamation_nested_writer_pre_multiply_key_equivalence',h,pk!=(inner^0x2a4f38d70e12cee6))
 # The cursor/source phases below are universally parameterized cuts from the
 # preceding source preparation. Keep the key congruence explicit.
 p=phase(e);p.run('table_cursor');a=p.buffer+24*z3.ZeroExt(32,p.cursor)
 prove('all_cursor32_original_entry_address_and_tag_test',p,z3.Or(p.read('x8')!=a,p.equal!=(((p.buffer^a)&TAG)==0)))
 p.run('table_cursor_retag');prove('original_reclamation_cursor_alternate_top16_retag',p,p.read('x8')!=((a&((1<<48)-1))|(0xc8a2<<48)))
 p.seed('x8',a);p.run('table_state_gate');guard=[z3.ULT(p.cursor,p.capacity),((p.buffer^a)&TAG)==0]
 prove('all_state32_empty_or_occupied_stops_backward_scan',p,p.equal!=z3.Or(p.current_state==EMPTY,p.current_state==OCCUPIED),guard)
 p.run('table_clear_request')
 prove('original_reclamation_nested_writer_request',p,z3.Or(p.read('x0')!=p.sp+0x48,p.read('x8')!=0xfffffe000a5aec24,p.read('x17')!=0x3936,
  cell(p,p.sp+0x48,8)!=a,cell(p,p.sp+0x58,8)!=0,cell(p,p.sp+0x60,8)!=p.header,
  cell(p,p.sp+0x68,4)-resize(p.read('x20'),32)!=EMPTY,cell(p,p.sp+0x70,8)+p.read('x20')!=KEY0,
  cell(p,p.sp+0x50,4)-resize(p.read('x20'),32)!=0xc28),guard)
 n=Model(e);n.sp=p.sp;n.record=p.sp+0x48;n.header=p.header;n.buffer=p.buffer;n.capacity=p.capacity;n.index=p.cursor;n.entry=a;n.frame_extent=(p.sp-0x10,0x10)
 prove('nested_writer_storage_premises_follow_from_reclaimer_frame',p,z3.Not(z3.And(*n.owned())),guard)
 d=Model(e);d.memory=dict(p.memory);d.seed('x0',p.sp+0x48);d.entry=a;d.bind[0xfffffe000a5aed44]=lambda:(a,p.current_state)
 d.run('writer_environment').run('writer_codec_gate')
 prove('reclamation_nested_record_key_and_state_decoder_join',d,z3.Or(d.read('w11')!=0xc28,d.read('x9')!=a,
  d.read('x8')!=p.read('x20')),guard,owner=p)
 p.returned();p.run('table_continue')
 prove('all_bounded_iteration32_previous_cursor_and_budget_guard',p,z3.Or(p.read('w24')!=z3.If(p.cursor==0,p.capacity-1,p.cursor-1)+0x1859e9d9,
  p.read('w21')!=p.iteration+1,p.read('w15')!=0xce515bd9,
  p.read('x8')!=z3.If(z3.ULE(p.iteration+1,p.capacity),resize(0xfffffe000a616bbc,64),resize(0xfffffe000a616d14,64))),
  guard+[p.iteration!=0xffffffff])
 for value,label in [(SUCCESS,'success'),(0xce515bbf,'null_array'),(0xce515bd9,'budget_exhausted')]:
  p=Model(e);p.seed('x19',p.record);p.seed('w15',value)
  if label=='success':p.run('table_success')
  p.run('table_status');prove('original_reclamation_'+label+'_raw_status_store',p,cell(p,p.record+0x20,4)!=value)
 p=table(e);p.run('table_canary')
 prove('original_reclamation_saved_fresh_stack_guard_compare',p,p.equal!=(p.guard0==p.guard1))
 p.run('table_epilogue')
 prove('ordinary_reclamation_frame_restore_SP_X19_X30',p,z3.Or(p.read('sp')!=p.sp,*[p.read('x'+str(j))!=z3.BitVec('HR_saved_X'+str(j),64) for j in range(19,31)]),[p.guard0==p.guard1])
 return out,coverage,visited

def concrete(e,n,index,counter,sp=0xfffffe000d100000,record=0xfffffe000d200000):
 v=Model(e)
 for name,value in {'sp':sp,'record':record,'header':0xfffffe000d300000,'buffer':0xfffffe000e000000,
  'capacity':n,'index':index,'counter':counter}.items():setattr(v,name,resize(value,32 if name in ['capacity','index','counter'] else 64))
 v.entry=v.buffer+24*z3.ZeroExt(32,v.index);v.seed('sp',v.sp)
 for j in range(19,31):v.seed('x'+str(j),0x51000000+j)
 for pc,fn in list(v.bind.items()):
  a,x=fn()
  if 'controller' in str(x):v.bind[pc]=lambda a=a,pc=pc:(a,resize(pc&0xffff,64))
 v.bind[0xfffffe000a5aed44]=lambda:(v.entry,v.old_state)
 v.bind[0xfffffe000a5aedcc]=lambda:(v.header,v.counter)
 for pc in [0xfffffe000a616890,0xfffffe000a616d28]:v.bind[pc]=lambda:(resize(0xfffffe000cacb000,64),resize(0x7100000001,64))
 mem(v,v.header,4,counter);return v

def setup_writer(v,encoded=False,entry_null=False):
 v.frame_extent=(v.sp-0x10,0x10);assert all(z3.is_true(z3.simplify(x)) for x in v.owned())
 v.seed('x0',v.record);v.run('writer_environment');part(v,'writer_codec_gate',0xfffffe000a5aec78,0xfffffe000a5aec98)
 if not encoded:
  k=v.read('x8');mem(v,v.record,8,0 if entry_null else v.entry);mem(v,v.record+8,4,resize(k,32)+0xc28)
  mem(v,v.record+0x10,8,v.new_value);mem(v,v.record+0x18,8,v.header)
  mem(v,v.record+0x20,4,v.desired_state+resize(k,32));mem(v,v.record+0x28,8,v.new_key-k)
 part(v,'writer_codec_gate',0xfffffe000a5aec98,0xfffffe000a5aed18)
 labels=[]
 if number(v.read('x12'))==0xfffffe000a5aed1c:
  labels.append('writer_increment_gate');v.run('writer_increment_gate')
  if number(v.read('x15'))==0xfffffe000a5aedc0:labels.append('writer_counter');v.run('writer_counter')
  else:
   labels.append('writer_decrement_gate');v.run('writer_decrement_gate')
   if number(v.read('x14'))==0xfffffe000a5aedc0:labels.append('writer_counter');v.run('writer_counter')
  labels.append('writer_fields');v.run('writer_fields')
 labels.append('writer_return');v.run('writer_return')
 assert all(z3.is_true(z3.simplify(x)) for x in v.address_checks)
 assert number(v.read('sp'))==number(v.sp)
 return labels

def apply_array(v,data):
 b=number(v.buffer);out=bytearray(data)
 for t in v.stores:
  a=number(t['address']);n=t['size_bytes']
  if b<=a<b+len(data):
   assert a+n<=b+len(data);out[a-b:a-b+n]=number(t['value']).to_bytes(n,'little')
 return bytes(out)

def entry_array(states):
 out=bytearray(24*len(states))
 for j,state in enumerate(states):
  struct.pack_into('<IIQQ',out,24*j,state,(0xa1000000+j)&0xffffffff,KEY0+0x310+j,0x7500000000+8*j)
 return bytes(out)

def writer_replay(e):
 rows=[];visited=set();instances=0
 for old in [EMPTY,DELETED,OCCUPIED,0x10203040]:
  for new in [EMPTY,DELETED,OCCUPIED,0xa0b0c0d0]:
   for counter in [0,1,0xffffffff]:
    v=concrete(e,128,73,counter);v.old_state=resize(old,32);v.desired_state=resize(new,32)
    v.new_key=resize(0x175c0e2112233445,64);v.new_value=resize(0x8a2244668810,64)
    before=entry_array([OCCUPIED]*128);before=bytearray(before);struct.pack_into('<I',before,73*24,old);before=bytes(before)
    labels=setup_writer(v);after=apply_array(v,before)
    expected=bytearray(before);struct.pack_into('<I',expected,73*24,new);struct.pack_into('<QQ',expected,73*24+8,number(v.new_key),number(v.new_value))
    delta=1 if old==EMPTY and new==OCCUPIED else -1 if old==DELETED and new==EMPTY else 0
    result=number(cell(v,v.header,4));assert after==bytes(expected) and result==(counter+delta)&0xffffffff
    assert all(number(v.read('x'+str(j)))==0x51000000+j for j in range(19,31))
    rows.append({'old_state32':old,'new_state32':new,'counter_before32':counter,'counter_after32':result,'counter_delta':delta,
     'new_key64':number(v.new_key),'new_payload64':number(v.new_value),'source_instruction_instances':v.count,
     'source_path':labels,'entry_padding_preserved':True,'other_entries_preserved':True,'frame_preserved':True})
    visited.update(v.visited);instances+=v.count
 v=concrete(e,128,73,19);v.old_state=resize(OCCUPIED,32);v.desired_state=resize(DELETED,32)
 v.new_key=resize(KEY0,64);v.new_value=resize(0,64);before=entry_array([OCCUPIED]*128);setup_writer(v,entry_null=True)
 assert apply_array(v,before)==before and number(cell(v,v.header,4))==19
 rows.append({'null_entry':True,'source_instruction_instances':v.count,'array_and_counter_unchanged':True})
 visited.update(v.visited);instances+=v.count
 return rows,instances,visited

def reclaim_reference(data,index,counter,null_array=False):
 out=bytearray(data);n=len(data)//24;cleared=[]
 state=lambda i:struct.unpack_from('<I',out,24*i)[0]
 if null_array:return bytes(out),counter,0xce515bbf,cleared
 if state((index+1)%n)!=EMPTY:return bytes(out),counter,SUCCESS,cleared
 cursor=index;iteration=1
 while state(cursor) not in [EMPTY,OCCUPIED]:
  if state(cursor)==DELETED:counter=(counter-1)&0xffffffff
  struct.pack_into('<I',out,24*cursor,EMPTY);struct.pack_into('<QQ',out,24*cursor+8,KEY0,0);cleared.append(cursor)
  cursor=(cursor-1)%n;iteration+=1
  if iteration>n:return bytes(out),counter,0xce515bd9,cleared
 return bytes(out),counter,SUCCESS,cleared

def reclaimer_replay(e):
 configs=[]
 def add(name,n,index,changes=(),fill=OCCUPIED,counter=100,null_array=False):
  states=[fill]*n
  for i,state in changes:states[i]=state
  configs.append({'name':name,'capacity':n,'index':index,'counter_before32':counter,'null_array':null_array,'states':states})
 add('next_occupied_leaves_tombstone',128,5,[(5,DELETED)])
 add('single_tombstone_before_empty',128,5,[(5,DELETED),(6,EMPTY)])
 add('three_tombstones_then_occupied_boundary',128,5,[(3,DELETED),(4,DELETED),(5,DELETED),(6,EMPTY)])
 add('three_tombstones_then_empty_boundary',128,5,[(2,EMPTY),(3,DELETED),(4,DELETED),(5,DELETED),(6,EMPTY)])
 add('backward_wrap',128,0,[(127,DELETED),(0,DELETED),(1,EMPTY)])
 add('long_run_until_known_empty_boundary',128,127,[(0,EMPTY)],fill=DELETED,counter=127)
 add('current_occupied_stops',128,5,[(6,EMPTY)])
 add('current_empty_stops',128,5,[(5,EMPTY),(6,EMPTY)])
 add('unknown_state_clears_without_counter_adjustment',128,5,[(5,0x10203040),(6,EMPTY)])
 add('counter_underflow_is_raw_mod32',128,5,[(5,DELETED),(6,EMPTY)],counter=0)
 add('single_entry_empty',1,0,fill=EMPTY)
 add('single_entry_tombstone_next_not_empty',1,0,fill=DELETED)
 add('three_entries_backward_wrap',3,0,[(0,DELETED),(1,EMPTY),(2,DELETED)])
 add('next_tombstone_skips_reclamation',128,5,[(5,DELETED),(6,DELETED)])
 add('null_array',128,5,[(5,DELETED),(6,EMPTY)],null_array=True)
 rows=[];visited=set();instances=0
 for c in configs:
  n,i,counter=c['capacity'],c['index'],c['counter_before32'];data=entry_array(c['states']);before=data
  h=concrete(e,n,i,counter);assert all(z3.is_true(z3.simplify(x)) for x in h.owned());h.seed('x0',h.record);h.run('table_frame').run('table_guard_save').run('table_roots')
  part(h,'table_codec_gate',0xfffffe000a616988,0xfffffe000a6169a8);k=resize(h.read('x13'),32)
  mem(h,h.record,8,h.header);mem(h,h.record+8,4,i+0x1859e9d9-k);mem(h,h.record+0xc,4,k+0x559)
  mem(h,h.record+0x10,4,n+0x35f2763e+k);mem(h,h.record+0x18,8,0 if c['null_array'] else h.buffer)
  part(h,'table_codec_gate',0xfffffe000a6169a8,0xfffffe000a616a10)
  labels=[];cleared=[];children=[]
  def run(label):labels.append(label);h.run(label)
  if number(h.read('x8'))==0xfffffe000a616a14:
   h.next_state=resize(struct.unpack_from('<I',data,24*((i+1)%n))[0],32);run('table_next_gate')
   if number(h.read('x12'))==0xfffffe000a616aa8:
    run('table_capacity_gate');assert number(h.read('x11'))==0xfffffe000a616af8;run('table_prepare')
    while True:
     assert len(cleared)<=n
     cursor=(number(h.read('w24'))+0xe7a61627)&0xffffffff;assert cursor<n
     h.cursor=resize(cursor,32);h.current_state=resize(struct.unpack_from('<I',data,24*cursor)[0],32)
     run('table_cursor')
     if not z3.is_true(z3.simplify(h.equal)):run('table_cursor_retag')
     run('table_state_gate')
     if z3.is_true(z3.simplify(h.equal)):run('table_success');break
     run('table_clear_request')
     d=concrete(e,n,cursor,counter,sp=number(h.read('sp')),record=number(h.read('x0')));d.memory=dict(h.memory)
     d.old_state=h.current_state;d.new_key=resize(KEY0,64);d.new_value=resize(0,64);d.desired_state=resize(EMPTY,32)
     path=setup_writer(d,encoded=True);data=apply_array(d,data);counter=number(cell(d,d.header,4));cleared.append(cursor)
     h.memory=dict(d.memory);h.returned();children.append({'index':cursor,'source_path':path,'source_instruction_instances':d.count})
     visited.update(d.visited);instances+=d.count
     run('table_continue')
     if number(h.read('x8'))==0xfffffe000a616d14:break
  run('table_status');run('table_canary');assert z3.is_true(z3.simplify(h.equal));run('table_epilogue')
  status=number(cell(h,h.record+0x20,4));expected=reclaim_reference(before,i,c['counter_before32'],c['null_array'])
  assert (data,counter,status,cleared)==expected,c['name']
  assert all(z3.is_true(z3.simplify(x)) for x in h.address_checks)
  assert number(h.read('sp'))==number(h.sp) and all(number(h.read('x'+str(j)))==0x51000000+j for j in range(19,31))
  assert all(data[24*j+4:24*j+8]==before[24*j+4:24*j+8] for j in range(n))
  rows.append({**c,'counter_after32':counter,'status32':status,'cleared_indexes':cleared,'before_bytes_hex':before.hex(),
   'after_bytes_hex':data.hex(),'source_path':labels,'nested_writer_calls':children,'source_instruction_instances':h.count,
   'entry_padding_preserved':True,'frame_restored':True,'reference_match':True})
  visited.update(h.visited);instances+=h.count
 return rows,instances,visited

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));validate_input(e);banks=[]
 for r in e['bank_rules']:
  left=bytes.fromhex(e['banks'][r['pair']+'L']['bytes_hex']);right=bytes.fromhex(e['banks'][r['pair']+'R']['bytes_hex'])
  assert all(x^right[left[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
  banks.append({'name':r['name'],'checked_inputs':256,'constant8':int(r['constant'],16)})
 ps,coverage,visited=proofs(e);wr,wi,wv=writer_replay(e);rr,ri,rv=reclaimer_replay(e)
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected
 rechecked=[]
 labels=['original_second_cleanup_preserves_payload_and_common_lookup_binding','all_status32_flag8_second_cleanup_gate',
  'all_entry_states_first_tombstone_and_probe_successor','ordinary_frame_restore_preserves_SP_and_X19_X30']
 for p in json.loads(read(ROOT/'userclient_hash_table_lookup_audit.json'))['source_proofs']:
  if p['label'] not in labels:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  rechecked.append({'source':'userclient_hash_table_lookup_audit.json','label':p['label'],'query_sha256':sha256(p['query'].encode()).hexdigest(),'result':'unsat'})
 assert len(rechecked)==4
 altered=[]
 for what in ['instruction_byte','bank_byte','branch_target','typed_free_size']:
  bad=copy.deepcopy(e)
  if what=='instruction_byte':r=bad['spans'][0];raw=bytes.fromhex(r['bytes_hex']);r['bytes_hex']=(bytes([raw[0]^1])+raw[1:]).hex()
  elif what=='bank_byte':r=bad['banks']['UL'];raw=bytes.fromhex(r['bytes_hex']);r['bytes_hex']=(bytes([raw[0]^1])+raw[1:]).hex()
  elif what=='branch_target':bad['branch_pointers'][0]['target']=hex(int(bad['branch_pointers'][0]['target'],16)^4)
  else:bad['typed_free_descriptor']['size_bytes']=121
  try:validate_input(bad)
  except AssertionError:altered.append({'alteration':what,'rejected':True})
  else:raise AssertionError(('accepted altered evidence',what))
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),'scope':R.SCOPE,
  'source_proofs':ps,'source_coverage':coverage,'bank_audit':banks,'writer_replays':wr,'reclamation_replays':rr,
  'rechecked_prior_source_proofs':rechecked,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(ps),'prior_source_queries_unsat':4,'bank_input_cases_checked':2304,
   'distinct_source_instructions':len(visited),'source_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),
   'writer_replay_cases':len(wr),'writer_replay_instruction_instances':wi,'reclamation_replay_cases':len(rr),
   'reclamation_replay_instruction_instances':ri,'replay_distinct_instructions':len(wv|rv),
   'reclamation_nested_writer_calls':sum(len(r['nested_writer_calls']) for r in rr),'altered_evidence_rejections':4},
  'conditional_hash_table_reclamation_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
