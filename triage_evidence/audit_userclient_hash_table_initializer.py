#!/usr/bin/env python3
"""Original instruction lift, size protocol and array initialization audit.
O(I+256R+128*entry bytes+query DAG) time/space before SMT search.
30 s/query. Allocator outputs and owned-memory stability are premises.
"""
import copy
import json
import struct
from hashlib import sha256
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_EXT_UXTB, ARM64_EXT_UXTW, ARM64_EXT_SXTW
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword
from lskd_values_symbolic import Lift, resize, mem
from audit_userclient_uidlist_cleanup import lookup
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_userclient_hash_table_initializer as R

DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
MASK=(1<<64)-1
NORMALIZER=0xdf0fb929498f8c2b
ENCODE_BIAS=0x20f046d6b67073d5
SENTINEL=0xa0f046d6b67073d5
TAG_MASK=0xffc0000000000000

def image_regions():
 data=IMAGE.data;at=32;out=[]
 for _ in range(struct.unpack_from('<I',data,16)[0]):
  cmd,size=struct.unpack_from('<II',data,at)
  if cmd==0x19:
   address,n=struct.unpack_from('<QQ',data,at+24)
   assert address+n<=1<<64
   if n:out.append((address,n))
  at+=size
 return out

IMAGE_REGIONS=image_regions()

def number(x):
 x=z3.simplify(x);assert z3.is_bv_value(x);return x.as_long()

class Model(Lift):
 def __init__(self,e):
  super().__init__({'spans':e['spans']});self.e=e;self.reads=[];self.address_checks=[];self.visited=set()
  self.sp,self.record,self.header,self.buffer=z3.BitVecs('HI_SP64 HI_record64 HI_header64 HI_buffer64',64)
  self.encoded_token=z3.BitVec('HI_encoded_token32',32);self.size_n=z3.BitVec('HI_decoded_count64',64)
  self.guard0,self.guard1=z3.BitVecs('HI_guard_initial64 HI_guard_return64',64)
  self.base={n:int(b['address'],16) for n,b in e['banks'].items()}
  self.banks={n:bytes.fromhex(b['bytes_hex']) for n,b in e['banks'].items()}
  self.bank_pc={0xfffffe000a627474:'TL',0xfffffe000a627488:'TR',0xfffffe000a6274bc:'VL',0xfffffe000a6274d0:'VR',
    0xfffffe000a627610:'TL',0xfffffe000a62761c:'TR',0xfffffe000a627644:'TL',0xfffffe000a62764c:'TR',
    0xfffffe000a627698:'FL',0xfffffe000a6276ac:'FR',0xfffffe000a6276d4:'TL',0xfffffe000a6276dc:'TR',
    0xfffffe000a5b3ee8:'UL',0xfffffe000a5b3efc:'UR'}
  self.bind={}
  def fixed(pc,a,value):self.bind[pc]=lambda:(resize(a,64),value)
  for pc,slot,value in [
    (0xfffffe000a6274a0,POOL+8*0x70,0xfffffe000ccc3340),
    (0xfffffe000a6274b4,POOL+0xc08,self.base['VL']+8),(0xfffffe000a6274c8,POOL+0x158,self.base['VR']+4),
    (0xfffffe000a6274e0,POOL+8*0x1c,0xfffffe000ccc32fc),
    (0xfffffe000a627608,POOL+0x840,self.base['TL']),(0xfffffe000a627618,POOL+0xbb8,self.base['TR']),
    (0xfffffe000a62765c,POOL+8*0x33,TABLE+12),(0xfffffe000a627664,TABLE+8*0xf7a,0xfffffe000a5b3dc8),
    (0xfffffe000a62768c,POOL+0x458,self.base['FL']+8),(0xfffffe000a6276a4,POOL+0x638,self.base['FR']+12),
    (0xfffffe000a6276bc,TABLE+8*0xf35,0xfffffe000c4ba95c),(0xfffffe000a6276ec,POOL+8*0x12e,0xfffffe000ccc372c),
    (0xfffffe000a5b3f14,POOL+8*0x33,TABLE+12),(0xfffffe000a5b3fa4,TABLE+8*0x78e,0xfffffe000a5b3fb0),
    (0xfffffe000a627428,0xfffffe000847c5f8,0xfffffe000cacb000),
    (0xfffffe000a627818,0xfffffe000847c5f8,0xfffffe000cacb000)]:fixed(pc,slot,value)
  for pc,a,n in [(0xfffffe000a627438,0xfffffe000ccc3340,4),(0xfffffe000a627440,0xfffffe000ccc32f8,4),
    (0xfffffe000a6274a4,0xfffffe000ccc3340,8),(0xfffffe000a6274e4,0xfffffe000ccc32f8,8),
    (0xfffffe000a6275f4,0xfffffe000ccc3340,4),(0xfffffe000a6275f8,0xfffffe000ccc32f8,4),
    (0xfffffe000a62762c,0xfffffe000ccc3340,4),(0xfffffe000a627630,0xfffffe000ccc32f8,4),
    (0xfffffe000a627678,0xfffffe000ccc3340,4),(0xfffffe000a62767c,0xfffffe000ccc32f8,4),
    (0xfffffe000a5b3de4,0xfffffe000ccc3398,8),(0xfffffe000a5b3dec,0xfffffe000ccc32f8,8)]:fixed(pc,a,z3.BitVec('HI_controller_'+format(pc,'x'),8*n))
  fixed(0xfffffe000a627548,self.record+4,self.encoded_token);fixed(0xfffffe000a627554,self.record+8,self.header)
  fixed(0xfffffe000a62742c,0xfffffe000cacb000,self.guard0);fixed(0xfffffe000a62781c,0xfffffe000cacb000,self.guard1)
  def branch(condition,i,j):
   return (TABLE+8*z3.If(condition,z3.BitVecVal(i,64),z3.BitVecVal(j,64)),
     z3.If(condition,z3.BitVecVal(qword(TABLE+8*i),64),z3.BitVecVal(qword(TABLE+8*j),64)))
  self.bind[0xfffffe000a5b3f1c]=lambda:branch(z3.UGT(self.size_n,MASK//24),0xed9,0xed1)
  self.bind[0xfffffe000a627730]=lambda:branch(self.buffer==0,0xad0,0xabd)
  self.bind[0xfffffe000a627774]=lambda:(resize(TABLE+8*0x41d,64),resize(0xfffffe000a627788,64))
  self.bind[0xfffffe000a6277f0]=lambda:branch(z3.ULT(self.read('x9'),128),0x41d,0x436)
  self.seed('sp',self.sp)

 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTB:
   assert o.type==ARM64_OP_REG;return (resize(self.read(i.reg_name(o.reg)),n)&255)<<o.shift.value
  return super().operand(i,o,n)

 def address(self,i,o):
  a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
  if o.mem.index:
   x=self.read(i.reg_name(o.mem.index))
   if o.ext==ARM64_EXT_SXTW:x=z3.SignExt(32,resize(x,32))
   elif o.ext==ARM64_EXT_UXTW:x=z3.ZeroExt(32,resize(x,32))
   else:assert not o.ext;x=resize(x,64)
   a=a+(x<<o.shift.value)
  assert not i.writeback
  return z3.simplify(a)

 def load(self,a,n):
  key=(z3.simplify(a).sexpr(),n)
  # Controller reads conservatively admit independent values, including after
  # opaque calls. Global byte-alias arithmetic is not a business-output premise.
  if self.pc in self.bind:
   expected,value=self.bind[self.pc]();self.address_checks.append(a==expected);value=resize(value,n*8)
  elif key in self.memory:value=self.memory[key]
  elif self.pc in self.bank_pc:
   name=self.bank_pc[self.pc];base=self.base[name];ix=z3.Extract(7,0,a-base)
   self.address_checks.append(a==base+z3.ZeroExt(56,ix));assert n==1;value=lookup(self.banks[name],ix)
  else:raise AssertionError(('unknown read',hex(self.pc),n,str(a)[:100]))
  self.reads.append({'pc':hex(self.pc),'size_bytes':n});return value

 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.visited.add(i.address)
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m in ['adrp','umulh','cmn','csel','tst','ldurb'] or (m=='lsl' and o[2].type==ARM64_OP_REG):
    self.count+=1
    if m=='adrp':self.write(i.reg_name(o[0].reg),resize(o[1].imm,64))
    elif m=='umulh':self.write(i.reg_name(o[0].reg),z3.Extract(127,64,z3.ZeroExt(64,self.read(i.reg_name(o[1].reg)))*z3.ZeroExt(64,self.read(i.reg_name(o[2].reg)))))
    elif m=='cmn':
     assert o[1].imm==1;self.cmp_left=self.read(i.reg_name(o[0].reg));self.cmp_right=resize(-1,self.cmp_left.size());self.equal=self.cmp_left==self.cmp_right
    elif m=='csel':
     assert i.op_str.endswith(', gt');self.write(i.reg_name(o[0].reg),z3.If(self.cmp_left>self.cmp_right,self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))))
    elif m=='tst':self.equal=(self.operand(i,o[0],64)&self.operand(i,o[1],64))==0
    elif m=='ldurb':self.write(i.reg_name(o[0].reg),self.load(self.address(i,o[1]),1))
    else:
     n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),self.read(i.reg_name(o[1].reg))<<(resize(self.read(i.reg_name(o[2].reg)),n)&(n-1)))
   else:
    old=self.c;self.c={'spans':[{'label':'single','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('single');self.c=old
  return self

 def returned(self):
  for j in range(19):self.seed('x'+str(j),z3.BitVec('HI_return_X'+str(j),64))

 def owned(self):
  def separate(a,n,b,m):return z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))
  spans=[(self.sp-0x20,0xc0),(self.record,40),(self.header,16)]
  out=[z3.UGE(self.sp,0x20),z3.ULE(self.sp,MASK-0xa0),self.header!=0,z3.ULE(self.header,MASK-16),z3.ULE(self.record,MASK-40)]
  for j,(a,n) in enumerate(spans):
   for b,m in spans[j+1:]:out.append(separate(a,n,b,m))
  out.append(z3.Implies(self.buffer!=0,z3.ULE(self.buffer,MASK-3072)))
  protected=IMAGE_REGIONS+[(int(b['address'],16),256) for b in self.e['banks'].values()]+[(int(r['slot'],16),8) for r in self.e['bank_rules']]+[(int(p['slot'],16),8) for p in self.e['branch_pointers']]+[(0xfffffe000ccc3720,64),(0xfffffe000cacb000,8),(0xfffffe000ccc32f8,8),(0xfffffe000ccc3340,8),(0xfffffe000ccc3398,8),(0xfffffe000c4ba95c,24)]
  out.extend(z3.Implies(self.buffer!=0,separate(self.buffer,3072,z3.BitVecVal(a,64),n)) for a,n in protected)
  for a,n in spans:
   out.append(z3.Implies(self.buffer!=0,separate(a,n,self.buffer,3072)))
   out.extend(separate(a,n,z3.BitVecVal(b,64),m) for b,m in protected)
  return out

def validate_input(e):
 assert e['source_sha256']==sha(SOURCE)
 for s in e['spans']:
  raw=bytes.fromhex(s['bytes_hex']);a=int(s['start'],16)
  if s['label']!='variable_adapter':assert IMAGE.read(a,len(raw))==raw
  assert s['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in DEC.disasm(raw,a)]
 for b in e['banks'].values():assert IMAGE.read(int(b['address'],16),256).hex()==b['bytes_hex']
 d=e['variable_descriptor'];raw=IMAGE.read(int(d['address'],16),64)
 assert raw.hex()==d['normalized64_bytes_hex'] and int.from_bytes(raw[4:8],'little')==d['element_size_word_u32']==24
 for p in e['branch_pointers']:assert qword(int(p['slot'],16))==int(p['target'],16)

def proofs(e):
 out=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*premises);assert s.check()==z3.sat,label
  s.add(z3.simplify(z3.Or(*[z3.Not(x) for x in v.address_checks],bad)))
  assert s.check()==z3.unsat,(label,s.reason_unknown())
  out.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True,'certified_rewrites':list(rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'read_instances':len(v.reads),'write_instances':len(v.stores)})
  visited.update(v.visited)
 def cell(v,a,n):return v.memory[(z3.simplify(resize(a,64)).sexpr(),n)]
 v=Model(e);v.seed('x0',v.record);v.run('guard_save').run('init_roots').run('init_header')
 valid=[v.encoded_token==(v.values[(0xfffffe000a627544,'w12')]^0xabd)]
 prove('original_initializer_roots_and_valid_token_header',v,z3.Or(v.read('x25')!=0xfffffe000ccc3340,v.read('x27')!=0xfffffe000ccc32fc,
   v.read('w24')!=0xabd,v.read('x20')!=v.header,cell(v,v.header,4)!=0,cell(v,v.header+4,4)!=128),valid)
 v.run('size_request')
 prove('original_size_request_record_and_helper_binding',v,z3.Or(v.read('x0')!=v.sp+0x10,v.read('x8')!=0xfffffe000a5b3dc8,v.read('x17')!=0x2502,v.read('x26')!=TABLE),valid)
 d=Model(e);d.memory=dict(v.memory);d.seed('x0',v.sp+0x10);d.run('size_decode')
 caller_key=v.values[(0xfffffe000a627594,'x12')];callee_key=d.values[(0xfffffe000a5b3e58,'x9')]
 prove('original_size_record_pre_multiply_key_equivalence',d,caller_key!=callee_key,valid)
 decoded=z3.substitute(d.read('x10'),(callee_key,caller_key))
 token=z3.substitute(d.read('w11')-resize(d.read('x9'),32),(callee_key,caller_key))
 prove('original_size_record_decodes_count128_and_token_ed1',d,z3.Or(decoded!=128,token!=0xed1),valid,
   [{'lemma':'original_size_record_pre_multiply_key_equivalence','rewrite':'Congruence through the common u64 multiplication and record decoder.'}])
 g=Model(e);n=g.size_n;k=z3.BitVec('HI_size_key32',32);g.seed('x0',g.record);g.run('size_entry')
 for name,value in {'x10':n,'w11':k+0xed1,'w9':k}.items():g.seed(name,value)
 g.run('size_guard').run('size_dispatch')
 prove('all_decoded_count64_size_overflow_guard_and_dispatch',g,z3.Or(g.read('w9')!=0x78e,
   g.read('x12')!=z3.If(z3.UGT(n,MASK//24),z3.BitVecVal(0xfffffe000a5b3fb0,64),z3.BitVecVal(0xfffffe000a5b3f28,64))))
 overflow=copy.copy(g);overflow.regs=dict(g.regs);overflow.memory=dict(g.memory);overflow.stores=list(g.stores);overflow.values=dict(g.values);overflow.run('size_output')
 prove('overflow_original_size_output_word_and_leaf_SP_restore',overflow,z3.Or(cell(overflow,overflow.record+0x20,8)!=SENTINEL,overflow.read('sp')!=overflow.sp),[z3.UGT(n,MASK//24)])
 g.run('size_multiply');prove('all_count64_original_24_byte_multiply_and_alignment',g,z3.Or(g.read('x10')!=24*n,(g.read('x10')&7)!=0))
 enc=Model(e);size=z3.BitVec('HI_aligned_size64',64)
 for name,value in {'x10':size,'w9':0x78e,'x14':0,'x11':TABLE,'x8':SENTINEL}.items():enc.seed(name,value)
 enc.run('size_encode')
 prove('all_aligned_size64_original_signed_clamp_and_encoded_output',enc,
   enc.read('x8')+NORMALIZER!=z3.If(size>=0,size,z3.BitVecVal(1<<63,64)),[(size&7)==0])
 enc.seed('x0',enc.record);enc.seed('sp',enc.sp-0x10);enc.run('size_output')
 prove('nonoverflow_original_size_output_word_and_leaf_SP_restore',enc,z3.Or(
   cell(enc,enc.record+0x20,8)+NORMALIZER!=z3.If(size>=0,size,z3.BitVecVal(1<<63,64)),enc.read('sp')!=enc.sp),[(size&7)==0])
 composed=Model(e);cn=composed.size_n;product=24*cn
 classified=z3.If(z3.UGT(cn,MASK//24),z3.BitVecVal(1<<63,64),z3.If(product>=0,product,z3.BitVecVal(1<<63,64)))
 prove('all_count64_composed_size_protocol_closed_form',composed,
   classified!=z3.If(z3.ULE(cn,((1<<63)-1)//24),product,z3.BitVecVal(1<<63,64)),(),
   [{'lemmas':['all_decoded_count64_size_overflow_guard_and_dispatch','all_count64_original_24_byte_multiply_and_alignment',
       'all_aligned_size64_original_signed_clamp_and_encoded_output','overflow_original_size_output_word_and_leaf_SP_restore',
       'nonoverflow_original_size_output_word_and_leaf_SP_restore'],'rewrite':'Compose the certified guard, multiply, signed clamp, output-store and normalizer relations by exhaustive unsigned-overflow cases.'}])
 # The exact immediate caller has decoded count128; the two preceding source
 # contracts yield the encoded value for 3072 B. Keep this cut explicit.
 v.returned();mem(v,v.sp+0x30,8,(3072+ENCODE_BIAS)&MASK);v.run('variable_request')
 prove('original_variable_allocator_descriptor_and_3072_byte_ABI',v,z3.Or(v.read('x0')!=0xfffffe000ccc3720,v.read('x1')!=3072,
   v.read('x10')!=0xfffffe000c4ba95c,v.read('x17')!=0x3ff2),valid,
   [{'lemma':'original_size_record_decodes_count128_and_token_ed1','rewrite':'Compose count128, multiply24, overflow dispatch and encoded-size contract at the ordinary size-helper return.'}])
 a=Model(e);a.seed('x0',0xfffffe000ccc3720);a.seed('x1',3072);a.run('variable_adapter')
 prove('original_kernel_variable_allocator_adapter_ABI',a,z3.Or(a.read('x0')!=0xfffffe000ccc3721,a.read('x1')!=3072,a.read('w2')!=0x1f1004,a.read('x3')!=0))
 v.returned();v.seed('x0',v.buffer);v.run('allocation_gate')
 prove('all_buffer64_header_publication_null_gate_and_failure_status',v,z3.Or(cell(v,v.header+8,8)!=v.buffer,v.read('w8')!=0x41d,
   v.read('w10')!=0x7cb49d7a,v.read('x9')!=z3.If(v.buffer==0,z3.BitVecVal(0xfffffe000a627804,64),z3.BitVecVal(0xfffffe000a627744,64))),valid)
 success=copy.copy(v);success.regs=dict(v.regs);success.memory=dict(v.memory);success.address_checks=list(v.address_checks);success.reads=list(v.reads);success.stores=list(v.stores);success.values=dict(v.values)
 success.run('loop_gate')
 prove('nonnull_buffer_original_first_iteration_and_success_status',success,z3.Or(success.read('x9')!=0,success.read('w10')!=0x7cb541a6,success.read('x11')!=0xfffffe000a627788),valid+[v.buffer!=0])
 loop=Model(e);i=z3.BitVec('HI_entry_index64',64)
 for name,value in {'x20':loop.header,'x26':TABLE,'w8':0x41d,'x9':i}.items():loop.seed(name,value)
 mem(loop,loop.header+8,8,loop.buffer);mem(loop,loop.header+4,4,128)
 loop.run('loop_address');address=loop.read('x12');condition=loop.equal
 boundary=[loop.buffer!=0,z3.ULT(i,128),((loop.buffer^(loop.buffer+3071))&TAG_MASK)==0]
 prove('all_valid_array_index_original_address_and_no_retag_guard',loop,z3.Or(address!=loop.buffer+24*i,z3.Not(condition)),boundary)
 tagged=copy.copy(loop);tagged.regs=dict(loop.regs);tagged.values=dict(loop.values);tagged.run('loop_retag')
 prove('original_alternate_pointer_retag_effect',tagged,tagged.read('x12')!=((address&0x0000ffffffffffff)|0xc8a2000000000000),[z3.Not(condition)])
 loop.run('loop_writes').run('loop_continue')
 writes=loop.stores
 assert len(writes)==3 and [w['size_bytes'] for w in writes]==[4,8,8]
 prove('all_index0_to127_original_entry_defaults_and_loop_control',loop,z3.Or(
   *[w['address']!=loop.buffer+24*i+off for w,off in zip(writes,[0,8,16])],
   writes[0]['value']!=0x629f8775,writes[1]['value']!=0x1ee45f68039f9913,writes[2]['value']!=0,
   loop.read('x9')!=i+1,loop.read('w10')!=0x7cb541a6,
   loop.read('x11')!=z3.If(z3.ULT(i+1,128),z3.BitVecVal(0xfffffe000a627788,64),z3.BitVecVal(0xfffffe000a627804,64))),boundary)
 v.run('output');prove('null_buffer_original_failure_word_output',v,cell(v,v.record,4)!=0x7cb49d7a,valid+[v.buffer==0])
 mem(success,success.sp,8,success.record);success.run('output');prove('ordinary_success_original_status_word_output',success,cell(success,success.record,4)!=0x7cb541a6,valid+[success.buffer!=0])
 c=Model(e);c.run('guard_save').run('canary');prove('original_stack_canary_compares_saved_and_fresh_guard',c,c.equal!=(c.guard0==c.guard1))
 f=Model(e);caller_sp=f.read('sp');saved={}
 for j in range(19,31):saved['x'+str(j)]=z3.BitVec('HI_saved_X'+str(j),64);f.seed('x'+str(j),saved['x'+str(j)])
 f.run('frame_enter');f.run('epilogue')
 prove('original_frame_epilogue_restores_SP_and_callee_registers',f,z3.Or(f.read('sp')!=caller_sp,*[f.read(name)!=value for name,value in saved.items()]))
 expected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']}
 assert visited==expected,(len(visited),len(expected),sorted(expected-visited))
 return out,coverage,sorted(visited)

def concrete_array(e):
 v=Model(e);base=0xfffffe000e000000;header=0xfffffe000d000000
 for n,x in {'x20':header,'x26':TABLE,'w8':0x41d,'x9':0}.items():v.seed(n,x)
 mem(v,header+8,8,base);mem(v,header+4,4,128)
 initial=bytes((j*37+11)&255 for j in range(3072));data=bytearray(initial);rows=[];old=0
 for j in range(128):
  v.run('loop_address');assert z3.is_true(z3.simplify(v.equal));v.run('loop_writes').run('loop_continue')
  ww=v.stores[old:];old=len(v.stores);assert len(ww)==3
  for w in ww:
   a=number(w['address'])-base;n=w['size_bytes'];assert 0<=a<a+n<=3072
   data[a:a+n]=number(w['value']).to_bytes(n,'little')
  target=number(v.read('x11'));assert target==(0xfffffe000a627788 if j<127 else 0xfffffe000a627804)
  rows.append({'index':j,'offset_bytes':24*j,'next_target':hex(target),'writes':3})
 for j in range(128):
  off=24*j;assert int.from_bytes(data[off:off+4],'little')==0x629f8775
  assert data[off+4:off+8]==initial[off+4:off+8]
  assert int.from_bytes(data[off+8:off+16],'little')==0x1ee45f68039f9913 and data[off+16:off+24]==bytes(8)
 return {'synthetic_only':True,'source_instruction_instances':v.count,'entries':rows,'written_bytes':2560,
         'untouched_padding_bytes':512,'after_sha256':sha256(data).hexdigest(),'no_native_memory_or_allocator':True}

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));validate_input(e);banks=[]
 for r in e['bank_rules']:
  left=bytes.fromhex(e['banks'][r['pair']+'L']['bytes_hex']);right=bytes.fromhex(e['banks'][r['pair']+'R']['bytes_hex'])
  assert all(x^right[left[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
  banks.append({'name':r['name'],'input_cases_checked':256})
 ps,coverage,visited=proofs(e);array=concrete_array(e);prior=[]
 for p in json.loads(read(ROOT/'userclient_hash_table_bootstrap_audit.json'))['source_proofs']:
  if p['label'] not in ['original_caller_record_to_initializer_header_codec_join','all_initializer_output32_exact_publication_status_gate','matching_status_publishes_allocated_global_and_enters_processing']:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
  prior.append({'label':p['label'],'query_sha256':sha256(p['query'].encode()).hexdigest(),'result':'unsat'})
 assert len(prior)==3
 altered=[]
 for what in ['instruction_byte','bank_byte','entry_size_word','branch_target']:
  bad=copy.deepcopy(e)
  if what=='instruction_byte':row=bad['spans'][2];raw=bytearray.fromhex(row['bytes_hex']);raw[0]^=1;row['bytes_hex']=raw.hex()
  elif what=='bank_byte':row=bad['banks']['TL'];raw=bytearray.fromhex(row['bytes_hex']);raw[0]^=1;row['bytes_hex']=raw.hex()
  elif what=='entry_size_word':bad['variable_descriptor']['element_size_word_u32']=16
  else:bad['branch_pointers'][0]['target']='0xfffffe000a627804'
  try:validate_input(bad)
  except AssertionError:altered.append({'alteration':what,'rejected':True})
  else:raise AssertionError('altered evidence admitted')
 return {'auditor_sha256':sha(__file__),'source_sha256':sha(SOURCE),'scope':R.SCOPE,'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'dependencies':{n:sha(ROOT/n) for n in R.DEPS+['recover_userclient_hash_table_initializer.py']},
  'source_proofs':ps,'source_coverage':coverage,'distinct_source_PCs':[hex(a) for a in visited],'bank_audits':banks,'rechecked_prior_source_proofs':prior,'array_replay':array,'altered_evidence_controls':altered,
  'ownership_protected_image_regions':[{'address':hex(a),'size_bytes':n} for a,n in IMAGE_REGIONS],
  'independent_totals':{'new_source_queries_unsat':len(ps),'prior_source_queries_unsat':3,'bank_input_cases_checked':1792,
    'source_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),'distinct_source_instructions':len(visited),'array_source_instruction_instances':array['source_instruction_instances'],
    'array_entries_checked':128,'array_written_bytes_checked':2560,'array_padding_bytes_preserved':512,'altered_evidence_rejections':4},
  'conditional_hash_table_initializer_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
