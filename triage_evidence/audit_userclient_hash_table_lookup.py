#!/usr/bin/env python3
"""Instruction-derived table-probe contracts and synthetic source replay.
O(I+256R+query DAG) construction space/time before bounded SMT search.
The bounded replay cost is O(cases*capacity); no target or IDB executes.
"""
import copy
import json
from hashlib import sha256
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword
from lskd_values_symbolic import Lift, resize, mem
from audit_userclient_hash_table_initializer import Model as Engine, DEC, IMAGE_REGIONS
from audit_userclient_uidlist_cleanup import lookup
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_userclient_hash_table_lookup as R

MASK=(1<<64)-1
SUCCESS=0x31ae0066
EMPTY=0x629f8775
DELETED=0x629f8776
OCCUPIED=0x629f8777
TAG_MASK=0xffc0000000000000

def number(x):
 x=z3.simplify(x);assert z3.is_bv_value(x),str(x);return x.as_long()

class Model(Engine):
 def __init__(self,e):
  Lift.__init__(self,{'spans':e['spans']});self.e=e;self.reads=[];self.address_checks=[];self.visited=set()
  self.sp,self.record,self.header,self.buffer,self.flag,self.index=z3.BitVecs('HL_SP64 HL_record64 HL_header64 HL_buffer64 HL_flag64 HL_index64',64)
  self.marker,self.capacity=z3.BitVecs('HL_raw_marker32 HL_capacity32',32)
  self.state=z3.BitVec('HL_entry_state32',32);self.entry_key=z3.BitVec('HL_entry_key64',64)
  self.base={n:int(b['address'],16) for n,b in e['banks'].items()};self.banks={n:bytes.fromhex(b['bytes_hex']) for n,b in e['banks'].items()}
  self.bank_pc={0xfffffe000a626ee4:'FL',0xfffffe000a626ef4:'FR',0xfffffe000a627070:'VL',0xfffffe000a627080:'VR',0xfffffe000a5ae454:'BL',0xfffffe000a5ae468:'BR'}
  self.bind={}
  def fixed(pc,a,v):self.bind[pc]=lambda:(resize(a,64),v)
  for pc,a in [(0xfffffe000a626ec8,0xfffffe000ccc3330),(0xfffffe000a626ecc,0xfffffe000ccc32f8),
   (0xfffffe000a627054,0xfffffe000ccc3330),(0xfffffe000a627058,0xfffffe000ccc32f8),
   (0xfffffe000a5ae380,0xfffffe000ccc3158),(0xfffffe000a5ae388,0xfffffe000ccc32f8)]:
   fixed(pc,a,z3.BitVec('HL_controller_'+format(pc,'x'),64 if pc>=0xfffffe000a5ae000 and pc<0xfffffe000a5af000 else 32))
  for pc,a,v in [(0xfffffe000a626df8,self.header+8,self.buffer),(0xfffffe000a626dfc,self.header+4,self.capacity),
   (0xfffffe000a626f5c,self.header+8,self.buffer),(0xfffffe000a626fbc,self.header+4,self.capacity)]:fixed(pc,a,v)
  self.table_pc={0xfffffe000a626f04:[0xf19],0xfffffe000a627094:[0xf19],0xfffffe000a5ae484:[0x33],
   0xfffffe000a5ae48c:[0x541,0x55a],0xfffffe000a5ae50c:[0x30d,0x323],0xfffffe000a5ae528:[0x323],
   0xfffffe000a5ae5f4:[0xeba],0xfffffe000a5ae65c:[0x5ca],0xfffffe000a5ae6a4:[0x5ca,0xe3e],
   0xfffffe000a5ae6f0:[0x79c,0x7b0],0xfffffe000a5ae74c:[0xeba],0xfffffe000a5ae794:[0x234,0x29a],
   0xfffffe000a5ae7c0:[0xeba],0xfffffe000a5ae7e4:[0x6d0],0xfffffe000a5ae824:[0x7db,0x7ff],
   0xfffffe000a5ae838:[0x7db],0xfffffe000a5ae850:[0x7b0],0xfffffe000a626f38:[0x2d4,0x4ff],
   0xfffffe000a626f9c:[0x2d4,0x2fc],0xfffffe000a6270d0:[0xa8f,0xaf7]}
  self.seed('sp',self.sp)

 def load(self,a,n):
  if self.pc in self.table_pc:
   choices=self.table_pc[self.pc];base=POOL if self.pc==0xfffffe000a5ae484 else TABLE
   tests=[a==base+8*j for j in choices];self.address_checks.append(z3.Or(*tests));v=resize(qword(base+8*choices[-1]),n*8)
   for j,t in reversed(list(zip(choices[:-1],tests[:-1]))):v=z3.If(t,resize(qword(base+8*j),n*8),v)
   self.reads.append({'pc':hex(self.pc),'size_bytes':n});return v
  if self.pc in [0xfffffe000a5ae718,0xfffffe000a5ae778]:
   j=resize(self.read('w5'),64);at=self.buffer+24*j
   if self.pc==0xfffffe000a5ae778:
    at=z3.If(((self.buffer^at)&TAG_MASK)==0,at,(at&((1<<48)-1))|(0xc8a2<<48))+8
   self.address_checks.append(a==at);self.reads.append({'pc':hex(self.pc),'size_bytes':n})
   return self.state if n==4 else self.entry_key
  return super().load(a,n)

 def run(self,label):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   m=i.mnemonic;o=i.operands
   if m=='csel' or (m=='cset' and i.op_str.endswith(', hi')):
    self.pc=i.address;self.visited.add(i.address);self.count+=1;cond=i.op_str.rsplit(',',1)[1].strip()
    take={'eq':lambda:self.equal,'ne':lambda:z3.Not(self.equal),'hi':lambda:z3.UGT(self.cmp_left,self.cmp_right)}[cond]()
    self.write(i.reg_name(o[0].reg),z3.If(take,self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))) if m=='csel' else z3.If(take,resize(1,32),resize(0,32)))
   else:
    old=self.e;self.e={**old,'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e=old
  return self

 def owned(self):
  # The array's full decoded capacity is an explicit readable extent. Every
  # output and frame lies outside both this extent and the complete image VMs.
  length=24*z3.ZeroExt(32,self.capacity)
  ranges=[(self.sp-0x70,0x1b0),(self.record,48),(self.header,16),(self.flag,1),(self.index,4),(self.buffer,length)]
  out=[z3.UGE(self.sp,0x70)]
  def sep(a,n,b,m):return z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,MASK-n)])
   for b,m in ranges[j+1:]:out.append(sep(a,n,b,m))
   for b,m in IMAGE_REGIONS:out.append(sep(a,n,resize(b,64),m))
  return out

def validate_input(e):
 assert e['source_sha256']==sha(SOURCE)
 f=e['lookup_function'];raw=bytes.fromhex(f['bytes_hex']);assert IMAGE.read(int(f['start'],16),len(raw))==raw
 r=e['caller_region'];assert IMAGE.read(int(r['start'],16),0x314).hex()==r['bytes_hex']
 for t in e['transfers']:assert IMAGE.read(int(t['ea'],16),4).hex()==t['bytes_hex']
 for s in e['spans']:
  raw=bytes.fromhex(s['bytes_hex']);a=int(s['start'],16);assert IMAGE.read(a,len(raw))==raw
  assert s['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in DEC.disasm(raw,a)]
 for b in e['banks'].values():assert IMAGE.read(int(b['address'],16),256).hex()==b['bytes_hex']
 for r in e['bank_rules']:
  assert (qword(int(r['slot'],16))+int(r['bias'],16))&MASK==int(r['target'],16)
  assert r['inputs_checked']==256
 for p in e['branch_pointers']:assert qword(int(p['slot'],16))==int(p['target'],16)

def cell(v,a,n):return v.memory[(z3.simplify(resize(a,64)).sexpr(),n)]

def caller(e):
 v=Model(e)
 for name,value in {'w22':0x2d4,'w23':v.marker,'x21':v.header,'x2':0xfffffe000ccc32f8,'x3':0xfffffe000ccc3330,
  'x26':0xa41a4d891208c018,'w28':0x4d08a3fb,'x27':TABLE}.items():v.seed(name,value)
 for off,n in [(0x50,'FL'),(0x58,'FR'),(0x30,'VL'),(0x38,'VR')]:mem(v,v.sp+off,8,v.base[n])
 mem(v,v.sp+0x68,8,0xfffffe000ccc32f8);mem(v,v.sp+0x70,8,0xfffffe000ccc3330)
 return v.run('caller_first')

def helper(e,token=0x541,buffer=None,flag=None):
 v=Model(e);r=v.record;v.lookup_key=z3.BitVec('HL_lookup_key32',32)
 v.seed('x0',r);v.run('lookup_key');codec=v.read('x13')
 encoded=resize(0x652019cc00000000,64)|z3.ZeroExt(32,v.lookup_key^0x6a48ac59)
 mem(v,r,8,encoded-codec);mem(v,r+8,8,v.flag if flag is None else flag)
 mem(v,r+0x10,8,v.index);mem(v,r+0x20,8,v.buffer if buffer is None else buffer)
 mem(v,r+0x28,4,resize(codec,32)+token);mem(v,r+0x2c,4,(v.capacity+0x4f950919)^resize(codec,32))
 v.run('lookup_gate');v.entry_target=v.read('x12')
 if buffer!=0:v.run('lookup_decode')
 return v

def phase(e):
 v=Model(e);v.probe,v.visits,v.remember,v.lookup_key=z3.BitVecs('HL_probe32 HL_visits32 HL_remember32 HL_lookup_key32',32)
 constants={'w6':0x430cb901,'w7':0xbf4,'w8':0xce515bbf,'x9':TABLE,'w10':0x541,'x11':v.buffer,
  'w13':v.visits,'w14':0xbcf34134,'w15':0x66127b47,'w16':0x5ca,'w19':0x2c,
  'w20':OCCUPIED,'x21':0x840479346de8456c,'w22':0x4471c88a,'w23':0x4471cdcb,
  'w24':0xbb8e37fe,'w25':DELETED,'w26':EMPTY,'w27':v.probe,'w3':v.remember,
  'w1':v.capacity+0xbcf34134,'w2':v.capacity+0x66127b47,'x0':v.record,
  'x4':resize(0x1ee45f68039f9913,64)+z3.ZeroExt(32,v.lookup_key)-0x840479346de8456c}
 for n,x in constants.items():v.seed(n,x)
 mem(v,v.sp,8,v.flag);mem(v,v.record+8,8,v.flag);mem(v,v.record+0x10,8,v.index)
 return v

def proofs(e):
 out=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=(),owner=None):
  s=z3.Solver();s.set(timeout=30000);s.add(*(owner or v).owned(),*premises);assert s.check()==z3.sat,label
  owner=owner or v;length=24*z3.ZeroExt(32,owner.capacity)
  untouched=[z3.Or(z3.ULE(t['address']+t['size_bytes'],owner.buffer),z3.ULE(owner.buffer+length,t['address'])) for t in v.stores]
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks+untouched],bad)))
  assert s.check()==z3.unsat,(label,s.reason_unknown())
  out.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),'certified_rewrites':list(rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'read_instances':len(v.reads),'write_instances':len(v.stores)})
  visited.update(v.visited)
 v=caller(e);U=v.marker^SUCCESS
 encoded=resize(0x652019cc00000000,64)|z3.ZeroExt(32,U^0x6a48ac59)
 prove('original_first_cleanup_lookup_key_phase_and_call_binding',v,z3.Or(v.read('w24')!=0x980,v.read('x19')!=encoded,
  v.read('x8')!=0xfffffe000a5ae354,v.read('x0')!=v.sp+0x90,v.read('x17')!=0x6a0f,cell(v,v.sp+0x7c,4)!=0))
 def join(v,label,keypc,keyreg,extra=()):
  d=Model(e);d.memory=dict(v.memory);d.seed('x0',v.sp+0x90);d.run('lookup_key')
  ck=v.values[(keypc,keyreg)];dk=d.values[(0xfffffe000a5ae408,'x9')]
  lemma=label+'_pre_multiply_codec_key_equivalence'
  prove(lemma,d,ck!=dk,extra,owner=v)
  # Certified equality is substituted through the exact common multiplication.
  d.seed('x13',v.values[(keypc+12,'x8' if keyreg=='x8' else 'x10')])
  d.run('lookup_gate').run('lookup_decode')
  prove(label+'_decoded_record_fields',d,z3.Or(d.read('w10')!=0x541,d.read('x11')!=v.buffer,
   d.read('x12')!=v.sp+(0x86 if label=='first_cleanup' else 0x87),d.read('x4')!=encoded,
   d.read('w2')!=v.capacity+0x4f950919,d.read('w27')!=(U&(v.capacity-1))),
   premises=extra,rewrites=[{'lemma':lemma,'rewrite':'Congruence through common u64 multiplication, then original record decoder.'}],owner=v)
 join(v,'first_cleanup',0xfffffe000a626e90,'x8')
 # Ordinary helper-return seam: arbitrary status/flag/index; source gates prove
 # their exact interpretation without assuming that every successful lookup hits.
 status=z3.BitVec('HL_call_status32',32);flag=z3.BitVec('HL_call_flag8',8);index=z3.BitVec('HL_call_index32',32)
 v.returned();mem(v,v.sp+0xa8,4,status);v.run('caller_first_gate')
 prove('all_status32_first_cleanup_gate',v,v.read('x8')!=z3.If(status==SUCCESS,resize(0xfffffe000a626f44,64),resize(qword(TABLE+8*0x2d4),64)))
 addr=v.buffer+24*z3.ZeroExt(32,index)
 # The index is supplied at the helper output seam after proving its writer.
 mem(v,v.sp+0x7c,4,index)
 # Re-run this source block with the output cell now bound.
 v.run('caller_entry_address')
 prove('all_index32_first_cleanup_entry_address_and_tag_test',v,z3.Or(v.read('x9')!=addr,v.equal!=(((v.buffer^addr)&TAG_MASK)==0)))
 v.run('caller_entry_retag')
 prove('original_cleanup_entry_alternate_top16_retag',v,v.read('x9')!=((addr&((1<<48)-1))|(0xc8a2<<48)))
 mem(v,v.sp+0x86,1,flag);v.run('caller_found_gate')
 prove('all_found_flag8_first_cleanup_gate',v,v.read('x10')!=z3.If((flag&1)!=0,resize(0xfffffe000a626fa8,64),resize(qword(TABLE+8*0x2d4),64)))
 # The non-retag ordinary address supplies the selected entry payload. This is
 # raw data flow only; its ownership/business meaning is not inferred.
 payload=z3.BitVec('HL_selected_entry_payload64',64);mem(v,addr+16,8,payload);v.seed('x9',addr);v.seed('x8',v.buffer)
 selected=[v.capacity==128,z3.ULT(index,v.capacity),((v.buffer^(v.buffer+3071))&TAG_MASK)==0]
 v.run('caller_second')
 prove('original_second_cleanup_preserves_payload_and_common_lookup_binding',v,z3.Or(cell(v,v.sp+0x18,8)!=payload,
  cell(v,v.sp+0x80,4)!=0,cell(v,v.sp+0x87,1)!=0,v.read('w23')!=0xa8f,v.read('w22')!=0x4fa,
  v.read('x8')!=0xfffffe000a5ae354,v.read('x17')!=0x6a0f),selected)
 join(v,'second_cleanup',0xfffffe000a62701c,'x10',selected)
 v.returned();mem(v,v.sp+0xa8,4,status);mem(v,v.sp+0x87,1,flag);v.run('caller_second_gate')
 # CSET is ANDed with the whole byte, but multiplication depends on bit0 only.
 prove('all_status32_flag8_second_cleanup_gate',v,v.read('x9')!=z3.If(z3.And(status==SUCCESS,(flag&1)!=0),resize(0xfffffe000a6270dc,64),resize(0xfffffe000a627308,64)))
 h=Model(e);h.seed('x0',h.record);h.run('lookup_key')
 prove('original_record_codec_closed_form',h,h.read('x13')!=(h.record^0xec7859d5734a22b2)*0x8c229611)
 for null in [False,True]:
  h=helper(e,buffer=0 if null else None)
  # Gate is captured before decoder overwrites X12.
  prove('token541_'+('null_array_failure_gate' if null else 'nonnull_array_decoder_contract'),h,
   z3.Or(h.entry_target!=(0xfffffe000a5ae864 if null else 0xfffffe000a5ae4a0),h.read('w27')!=0xce515bbf) if null else z3.Or(h.entry_target!=0xfffffe000a5ae4a0,h.read('w10')!=0x541,h.read('w27')!=(h.lookup_key&(h.capacity-1))),
   rewrites=[{'scope':'Token0x541 only; helper() constructs an independently parameterized valid record.'}])
 h=helper(e);h.run('flag_clear').run('probe_setup')
 prove('original_probe_setup_mask_capacity_key_codec_and_sentinels',h,z3.Or(
  h.read('w27')!=(h.lookup_key&(h.capacity-1)),h.read('w13')!=0,h.read('w3')!=0xffffffff,
  h.read('w16')!=0x5ca,h.read('w1')!=h.capacity+0xbcf34134,h.read('w2')!=h.capacity+0x66127b47,
  h.read('x4')+0x840479346de8456c!=resize(0x1ee45f68039f9913,64)+z3.ZeroExt(32,h.lookup_key),
  cell(h,h.flag,1)!=0,h.read('x28')!=0xfffffe000a5ae658))
 prove('positive_capacity_initial_probe_is_in_bounds',h,z3.UGE(h.read('w27'),h.capacity),[h.capacity!=0])
 h=phase(e);h.run('probe_resume').run('probe_wrap')
 prove('all_probe32_capacity32_wrap_to_zero_or_enter_limit',h,z3.Or(h.read('w5')!=h.probe,h.read('w27')!=0,
  h.read('x12')!=z3.If(z3.ULT(h.probe,h.capacity),resize(0xfffffe000a5ae6b4,64),resize(0xfffffe000a5ae66c,64))))
 prove('zero_capacity_wrap_has_no_exit_in_this_phase',h,h.read('x12')!=0xfffffe000a5ae66c,[h.capacity==0])
 h=phase(e);h.seed('w5',h.probe);h.run('probe_limit')
 prove('all_visit32_capacity32_probe_budget_guard',h,z3.Or(h.read('w16')!=0x79c,
  h.read('w27')!=0xce515bd9,h.read('x12')!=z3.If(z3.ULT(h.visits,h.capacity),resize(0xfffffe000a5ae700,64),resize(0xfffffe000a5ae864,64))),[h.visits!=0xffffffff])
 h.run('probe_state')
 prove('bounded_probe_original_state_read_and_visit_increment',h,z3.Or(h.read('w13')!=h.visits+1,h.read('w27')!=h.state,
  h.read('x12')!=24*z3.ZeroExt(32,h.probe)),[z3.ULT(h.probe,h.capacity),h.visits!=0xffffffff])
 h.run('state_empty_test')
 prove('original_empty_state_equality',h,h.equal!=(h.state==EMPTY),[z3.ULT(h.probe,h.capacity),h.visits!=0xffffffff])
 h.run('probe_other')
 prove('all_entry_states_first_tombstone_and_probe_successor',h,z3.Or(h.read('w16')!=0x5ca,h.read('w27')!=h.probe+1,
  h.read('w3')!=z3.If(z3.And(h.remember==0xffffffff,h.state==DELETED),h.probe,h.remember),h.read('x12')!=0xfffffe000a5ae658),
  [z3.ULT(h.probe,h.capacity),h.visits!=0xffffffff])
 h=phase(e);h.seed('w5',h.probe);h.seed('x16',z3.ZeroExt(32,h.probe));h.run('key_address');addr=h.buffer+24*z3.ZeroExt(32,h.probe)
 prove('all_probe32_key_address_and_tag_condition',h,z3.Or(h.read('x17')!=addr,h.equal!=(((h.buffer^addr)&TAG_MASK)==0)))
 h.run('key_retag');prove('original_key_alternate_top16_retag',h,h.read('x17')!=((addr&((1<<48)-1))|(0xc8a2<<48)))
 h.seed('x17',addr);h.run('key_compare')
 stable=[((h.buffer^addr)&TAG_MASK)==0]
 prove('all_key64_occupied_entry_equality_and_branch',h,h.read('x12')!=z3.If(h.entry_key==resize(0x1ee45f68039f9913,64)+z3.ZeroExt(32,h.lookup_key),resize(0xfffffe000a5ae7f0,64),resize(0xfffffe000a5ae7a0,64)),stable)
 h.seed('w27',OCCUPIED);h.run('key_mismatch')
 prove('occupied_key_mismatch_preserves_tombstone_and_advances',h,z3.Or(h.read('w3')!=h.remember,h.read('w27')!=h.probe+1,h.read('x12')!=0xfffffe000a5ae658),stable)
 h=phase(e);h.seed('w5',h.probe);h.run('choose_empty')
 prove('all_remember32_empty_selects_first_tombstone_or_current',h,z3.Or(h.read('w5')!=z3.If(h.remember==0xffffffff,h.probe,h.remember),h.read('x10')!=0xfffffe000a5ae844,h.read('w8')!=0x7b0))
 h.run('index_output').run('status_output')
 prove('empty_selected_index_and_success_status_stores',h,z3.Or(cell(h,h.index,4)!=z3.If(h.remember==0xffffffff,h.probe,h.remember),cell(h,h.record+0x18,4)!=SUCCESS))
 for has_flag in [False,True]:
  h=phase(e);h.seed('w5',h.probe)
  if not has_flag:mem(h,h.sp,8,0)
  h.run('found_gate')
  prove(('nonnull' if has_flag else 'null')+'_matched_optional_flag_gate',h,z3.Or(h.read('x12')!=(0xfffffe000a5ae830 if has_flag else 0xfffffe000a5ae844),h.read('w8')!=0x7b0,h.read('w10')!=0x7db))
  if has_flag:h.run('flag_set');prove('original_matched_optional_flag_store',h,z3.Or(cell(h,h.flag,1)!=1,h.read('x10')!=0xfffffe000a5ae844))
  h.run('index_output').run('status_output')
  prove(('nonnull' if has_flag else 'null')+'_matched_index_and_success_status_stores',h,z3.Or(cell(h,h.index,4)!=h.probe,cell(h,h.record+0x18,4)!=SUCCESS,h.read('x8')!=0xfffffe000a5ae864))
 h=helper(e,flag=0)
 prove('null_optional_flag_skips_clear_and_enters_probe_setup',h,h.read('x13')!=0xfffffe000a5ae534)
 h=phase(e);h.seed('w27',0xce515bd9);h.run('status_output')
 prove('exhausted_probe_status_without_index_write',h,z3.Or(cell(h,h.record+0x18,4)!=0xce515bd9,len(h.stores)!=1))
 h=phase(e);h.seed('w27',0xce515bbf);h.run('status_output')
 prove('null_array_status_without_index_write',h,cell(h,h.record+0x18,4)!=0xce515bbf)
 h=Model(e)
 for j in range(19,31):h.seed('x'+str(j),z3.BitVec('HL_saved_X'+str(j),64))
 before={j:h.read('x'+str(j)) for j in range(19,31)};h.run('frame_enter').run('epilogue')
 prove('ordinary_frame_restore_preserves_SP_and_X19_X30',h,z3.Or(h.read('sp')!=h.sp,*[h.read('x'+str(j))!=before[j] for j in before]))
 return out,coverage,visited

def reference(entries,key,has_flag=True,null_array=False):
 if null_array:return {'status':0xce515bbf,'index':0xdecafbad,'flag':0xa5 if has_flag else None,'visits':[]}
 n=len(entries);assert n>0;i=key&(n-1);remember=None;visits=[]
 for _ in range(n):
  if i>=n:i=0
  visits.append(i);state,stored=entries[i]
  if state==OCCUPIED and stored==(0x1ee45f68039f9913+key)&MASK:
   return {'status':SUCCESS,'index':i,'flag':1 if has_flag else None,'visits':visits}
  if state==EMPTY:return {'status':SUCCESS,'index':i if remember is None else remember,'flag':0 if has_flag else None,'visits':visits}
  if state==DELETED and remember is None:remember=i
  i+=1
 return {'status':0xce515bd9,'index':0xdecafbad,'flag':0 if has_flag else None,'visits':visits}

def replay(e):
 cases=[]
 def add(name,n,key,changes=(),fill=None,has_flag=True,null_array=False):
  entries=[(EMPTY,0x1ee45f68039f9913)]*n if fill is None else [fill]*n
  for j,state,k in changes:entries[j]=(state,k)
  cases.append({'name':name,'capacity':n,'key_u32':key,'has_flag':has_flag,'null_array':null_array,'entries':[list(x) for x in entries]})
 base=0x1ee45f68039f9913
 add('constructor_defaults',128,0x12345678)
 add('key_zero_empty_is_not_occupied',128,0)
 add('occupied_hit',128,5,[(5,OCCUPIED,base+5)])
 add('occupied_hit_without_optional_flag',128,5,[(5,OCCUPIED,base+5)],has_flag=False)
 add('occupied_wrong_key_then_empty',128,5,[(5,OCCUPIED,base+99)])
 add('tombstone_then_hit',128,5,[(5,DELETED,base+77),(6,OCCUPIED,base+5)])
 add('first_tombstone_before_empty',128,5,[(5,DELETED,base+77),(6,DELETED,base+88)])
 add('unknown_state_is_skipped',128,5,[(5,0x10203040,base+5)])
 add('wrap_at_end_then_hit',128,127,[(127,OCCUPIED,base+11),(0,OCCUPIED,base+127)])
 add('wrap_at_end_then_empty',128,127,[(127,OCCUPIED,base+11)])
 add('full_table_miss',128,0xffffffff,fill=(OCCUPIED,base+17))
 add('full_table_tombstones_still_exhausts',128,0xffffffff,fill=(DELETED,base+77))
 add('last_probe_hit',128,127,[(126,OCCUPIED,base+127)],fill=(OCCUPIED,base+17))
 add('single_entry_empty',1,0xffffffff)
 add('single_entry_full_miss',1,0,fill=(OCCUPIED,base+1))
 add('non_power_two_capacity',3,2,[(2,OCCUPIED,base+1),(0,DELETED,base+4)])
 add('maximum_u32_key_hit',128,0xffffffff,[(127,OCCUPIED,base+0xffffffff)])
 add('null_array_does_not_touch_outputs',128,5,null_array=True)
 rows=[];visited=set();instances=0
 for c in cases:
  h=Model(e)
  for n,x in {'sp':0xfffffe000d100000,'record':0xfffffe000d200000,'header':0xfffffe000d400000,
   'buffer':0xfffffe000e000000,'flag':0xfffffe000d300000,'index':0xfffffe000d300008}.items():setattr(h,n,resize(x,64))
  h.capacity=resize(c['capacity'],32);h.seed('sp',h.sp)
  for pc,(a,value) in [(pc,fn()) for pc,fn in h.bind.items() if 'controller' in str(fn()[1])]:
   h.bind[pc]=lambda a=a,value=resize(pc&0xffff,64):(a,value)
  h.seed('x0',h.record)
  for j in range(19,31):h.seed('x'+str(j),0x51000000+j)
  h.run('frame_enter').run('lookup_key');codec=h.read('x13');key=c['key_u32']
  encoded=resize(0x652019cc00000000|((key^0x6a48ac59)&0xffffffff),64)
  mem(h,h.record,8,encoded-codec);mem(h,h.record+8,8,h.flag if c['has_flag'] else 0);mem(h,h.record+0x10,8,h.index)
  mem(h,h.record+0x20,8,0 if c['null_array'] else h.buffer)
  mem(h,h.record+0x28,4,resize(codec,32)+0x541);mem(h,h.record+0x2c,4,(h.capacity+0x4f950919)^resize(codec,32))
  mem(h,h.flag,1,0xa5);mem(h,h.index,4,0xdecafbad)
  labels=['frame_enter','lookup_key']
  def run(label):labels.append(label);h.run(label)
  run('lookup_gate');path=[]
  if number(h.read('x12'))!=0xfffffe000a5ae864:
   run('lookup_decode')
   if number(h.read('x13'))==0xfffffe000a5ae518:run('flag_clear')
   run('probe_setup')
   while True:
    assert len(path)<=c['capacity']
    run('probe_resume');run('probe_wrap')
    if number(h.read('x12'))==0xfffffe000a5ae66c:
     run('probe_wrap');assert number(h.read('x12'))==0xfffffe000a5ae6b4
    run('probe_limit')
    if number(h.read('x12'))==0xfffffe000a5ae864:break
    i=number(h.read('w5'));assert i<c['capacity'];path.append(i)
    h.state=resize(c['entries'][i][0],32);h.entry_key=resize(c['entries'][i][1],64);run('probe_state')
    if z3.is_true(z3.simplify(h.equal)):
     run('key_address')
     if not z3.is_true(z3.simplify(h.equal)):run('key_retag')
     run('key_compare')
     if number(h.read('x12'))==0xfffffe000a5ae7f0:
      run('found_gate')
      if number(h.read('x12'))==0xfffffe000a5ae830:run('flag_set')
      run('index_output');break
     run('key_mismatch')
    else:
     run('state_empty_test')
     if z3.is_true(z3.simplify(h.equal)):run('choose_empty');run('index_output');break
     run('probe_other')
  run('status_output');run('epilogue')
  actual={'status':number(cell(h,h.record+0x18,4)),'index':number(cell(h,h.index,4)),
   'flag':number(cell(h,h.flag,1)) if c['has_flag'] else None,'visits':path}
  expected=reference(c['entries'],key,c['has_flag'],c['null_array']);assert actual==expected,(c['name'],actual,expected)
  assert all(z3.is_true(z3.simplify(x)) for x in h.address_checks)
  assert number(h.read('sp'))==number(h.sp)
  assert all(number(h.read('x'+str(j)))==0x51000000+j for j in range(19,31))
  b=number(h.buffer);assert all(not b<=number(s['address'])<b+24*c['capacity'] for s in h.stores)
  visited.update(h.visited);instances+=h.count
  rows.append({**c,**actual,'source_instruction_instances':h.count,'source_path':labels,
   'source_path_sha256':sha256(json.dumps(labels,separators=(',',':')).encode()).hexdigest(),'array_unchanged':True,'frame_restored':True})
 return rows,instances,visited

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));validate_input(e);banks=[]
 for r in e['bank_rules']:
  l=bytes.fromhex(e['banks'][r['pair']+'L']['bytes_hex']);rr=bytes.fromhex(e['banks'][r['pair']+'R']['bytes_hex'])
  assert all(x^rr[l[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
  banks.append({'name':r['name'],'input_cases_checked':256,'constant8':int(r['constant'],16)})
 ps,coverage,visited=proofs(e);rows,instances,replayed=replay(e)
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected
 rechecked=[]
 for name,labels in [
  ('userclient_hash_table_bootstrap_audit.json',['matching_status_publishes_allocated_global_and_enters_processing']),
  ('userclient_hash_table_initializer_audit.json',['original_initializer_roots_and_valid_token_header',
   'all_valid_array_index_original_address_and_no_retag_guard','all_index0_to127_original_entry_defaults_and_loop_control'])]:
  for p in json.loads(read(ROOT/name))['source_proofs']:
   if p['label'] not in labels:continue
   s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
   rechecked.append({'source':name,'label':p['label'],'query_sha256':sha256(p['query'].encode()).hexdigest(),'result':'unsat'})
 assert len(rechecked)==4
 altered=[]
 for what in ['instruction_byte','bank_byte','branch_target','complete_function_byte']:
  bad=copy.deepcopy(e)
  if what=='instruction_byte':r=bad['spans'][0];r['bytes_hex']=(bytes([bytes.fromhex(r['bytes_hex'])[0]^1])+bytes.fromhex(r['bytes_hex'])[1:]).hex()
  elif what=='bank_byte':r=bad['banks']['BL'];r['bytes_hex']=(bytes([bytes.fromhex(r['bytes_hex'])[0]^1])+bytes.fromhex(r['bytes_hex'])[1:]).hex()
  elif what=='branch_target':bad['branch_pointers'][0]['target']=hex(int(bad['branch_pointers'][0]['target'],16)^4)
  else:r=bad['lookup_function'];r['bytes_hex']=(bytes([bytes.fromhex(r['bytes_hex'])[0]^1])+bytes.fromhex(r['bytes_hex'])[1:]).hex()
  try:validate_input(bad)
  except AssertionError:altered.append({'alteration':what,'rejected':True})
  else:raise AssertionError(('accepted altered evidence',what))
 return {'auditor_sha256':sha(__file__),'source_sha256':sha(SOURCE),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'scope':R.SCOPE,'source_proofs':ps,'source_coverage':coverage,'bank_audit':banks,'source_replay_cases':rows,
  'rechecked_prior_source_proofs':rechecked,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(ps),'prior_source_queries_unsat':len(rechecked),
   'bank_input_cases_checked':768,'distinct_source_instructions':len(visited),
   'source_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),
   'source_replay_cases':len(rows),'source_replay_instruction_instances':instances,
   'source_replay_distinct_instructions':len(replayed),'source_replay_entry_visits':sum(len(x['visits']) for x in rows),
   'altered_evidence_rejections':len(altered)},
  'conditional_hash_table_lookup_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
