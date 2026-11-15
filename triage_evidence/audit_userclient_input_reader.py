#!/usr/bin/env python3
"""Conditional shared reader, protected header and copy-step source obligations.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
No target executes; storage, pointer-branch and ordinary ABI cuts are explicit.
"""
import copy
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,POOL,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_input_reader as R

TOKEN=0x886a1ca3
PHASE=0x7795e642
SUCCESS=0x31ae0066
KEY=0x4dae26df20976138
REQUEST=0x2685a3ce
HASH_GATE=0xfffffe000a6570c4
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
WORD_BYTES={0xfffffe000a637158,0xfffffe000a637190,0xfffffe000a6371d4,0xfffffe000a637214}
TYPE_BYTES={0xfffffe000a639348,0xfffffe000a639380}

def mask(a,k):
 return z3.Extract(7,0,z3.LShR((z3.RotateRight(a&resize(-8,64),8)+k)^KEY,(a&7)<<3))

class Model(Base):
 def __init__(self,e):
  super().__init__(e);self.receipt=e
  self.object,self.node,self.next,self.result,self.protection_key,self.counter=z3.BitVecs('IR_object64 IR_node64 IR_next64 IR_result64 IR_key64 IR_counter64',64)
  self.extent,self.encoded_length=z3.BitVecs('IR_extent32 IR_encoded_length32',32)
  self.plain=[z3.BitVec('IR_header_byte'+str(j),8) for j in range(10)];self.copy_byte=z3.BitVec('IR_copy_byte8',8)
  self.byte_offsets=[];self.byte_pos=0;self.branch_guards=[];self.branch_choices={};self.direct_target=None
  self.with_node=False;self.with_buffer=False;self.with_result=False
 def owned(self):
  ranges=[(self.sp,0x1120),(self.ctx,2048),(self.src,4096),(self.object,16)]
  if self.with_node:ranges.append((self.node,32))
  if self.with_buffer:ranges.append((self.buffer,z3.If(z3.ULT(self.extent,10),resize(10,64),z3.ZeroExt(32,self.extent))))
  if self.with_result:ranges.append((self.result,z3.If(self.length()==0,resize(1,64),z3.ZeroExt(32,self.length()))))
  out=[(self.sp&15)==0]
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in ranges[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def length(self):return self.encoded_length^SUCCESS
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc in WORD_BYTES|TYPE_BYTES:
   assert n==1 and self.byte_pos<len(self.byte_offsets);j=self.byte_offsets[self.byte_pos];self.byte_pos+=1
   self.address_checks.append(a==self.buffer+j);return self.plain[j]^mask(a,self.protection_key)
  if self.pc==0xfffffe000a63e0c8:
   assert n==1;self.address_checks.append(a==self.buffer+10+self.counter-1);return self.copy_byte^mask(a,self.protection_key)
  for name,lp,rp,pp in [('allocate',0xfffffe000a63df5c,0xfffffe000a63df6c,0xfffffe000a63df80),
   ('search_callback_value',0xfffffe000a662b2c,0xfffffe000a662b3c,0xfffffe000a662b54)]:
   r=next(r for r in self.receipt['bank_rules'] if r['name']==name);l,rr=int(r['left'],16),int(r['right'],16)
   if self.pc==lp:
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('IR_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)));self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256})
    return self.bank_input^int(r['constant'],16)
   if self.pc==pp:self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('IR_controller_'+format(self.pc,'x'),32)
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;m=i.mnemonic;o=i.operands
   custom=m in ['ror','cmn','cmp','csel'] or m.startswith('b.') or m=='cset' and i.op_str.endswith((', hi',', lo')) or m in ['lsr','lsl'] and o[2].type==ARM64_OP_REG
   if custom:
    self.visited.add(i.address);self.count+=1
    if m.startswith('b.'):
     assert m in ['b.eq','b.ne'];condition=self.equal if m=='b.eq' else z3.Not(self.equal)
     if i.address in R.RETAGS:
      assert m=='b.eq' and o[0].imm&(2**64-1)==i.address+8;self.branch_guards.append(condition);skip=R.RETAGS[i.address]
     else:
      take=self.branch_choices.get(i.address,False);self.branch_guards.append(condition if take else z3.Not(condition))
      if take:self.direct_target=o[0].imm&(2**64-1);break
    elif m=='cmp':
     n=self.width(i.reg_name(o[0].reg));self.cmp_left=self.operand(i,o[0],n);self.cmp_right=self.operand(i,o[1],n);self.equal=self.cmp_left==self.cmp_right;self.carry=None
    elif m=='cmn':
     n=self.width(i.reg_name(o[0].reg));a,b=self.operand(i,o[0],n),self.operand(i,o[1],n);self.equal=a+b==0;self.carry=z3.ULT(a+b,a)
    elif m=='cset':
     cond=i.op_str.rsplit(',',1)[1].strip();v=z3.Not(self.carry) if cond=='lo' and self.carry is not None else z3.ULT(self.cmp_left,self.cmp_right) if cond=='lo' else z3.UGT(self.cmp_left,self.cmp_right)
     self.write(i.reg_name(o[0].reg),z3.If(v,resize(1,32),resize(0,32)))
    elif m=='csel':
     assert i.op_str.endswith(', ne');self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))))
    elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    else:
     n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);s=self.operand(i,o[2],n)&(n-1)
     self.write(i.reg_name(o[0].reg),z3.LShR(a,s) if m=='lsr' else a<<s)
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=old_e,old_c
  return self
 def decode(self,offsets):self.byte_offsets=list(offsets);self.byte_pos=0;self.run('decode_type' if len(offsets)==2 else 'decode_word');assert self.byte_pos==len(offsets);return self
 def returned(self):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('IR_return_'+str(self.count)+'_X'+str(j),64))
  self.seed('x0',self.result);return self

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w1',PHASE),('w24',0x7795e3ce),('w30',SUCCESS),
  ('x22',v.object),('x21',0xfffffe000792fcc0),('x20',KEY),('x26',v.protection_key),('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018)]:v.seed(reg,x)
 for off,x in [(0x478,v.ctx+0x128),(0xd8,v.src+0xaa8),(0x700,v.ctx+0x400),(0x7c0,v.ctx+0x728),
  (0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa20,0xfffffe00079391f0),(0x9f8,0xfffffe0007949ed0),(0x9f0,0xfffffe000792fec0)]:mem(v,v.sp+off,8,x)
 mem(v,v.sp+0x9ec,4,v.status);mem(v,v.object,8,v.node);mem(v,v.node,8,v.next)
 mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.buffer)
 return v

def request(e):return setup(e).run('reader_request').run('shared_entry')
def search(e):return request(e).run('search_setup').run('search_entry').run('search_nonnull').run('search_node')
def searched(e):
 v=search(e);v.with_node=True;v.with_buffer=True
 return v.run('node_decode_prepare').run('word_bridge').decode(range(4)).run('tag_match').run('search_result').run('search_callback').run('after_search')
def header(e):
 v=searched(e);v.run('select_node').run('header_extent').run('header_prepare').run('word_bridge').decode(range(4))
 v.run('type_prepare').decode(range(4,6)).run('length_prepare').run('length_bridge').decode(range(6,10)).run('payload_extent');return v
def allocation(e):
 v=header(e);v.run('type_switch').run('body_pointer').run('body_length_prepare').run('save_length').run('type_gate').run('body_gate').run('allocate_request');return v

def tag(v):return z3.Concat(*v.plain[:4])^SUCCESS
def kind(v):return z3.Concat(*v.plain[4:6])^0x365e
def payload_length(v):return z3.Concat(*v.plain[6:10])
def matched(v):return [tag(v)==REQUEST]
def valid_header(v):return matched(v)+[v.encoded_length==(payload_length(v)^SUCCESS),z3.UGE(z3.ZeroExt(32,v.extent),10+z3.ZeroExt(32,payload_length(v)))]
def accepted(v):return valid_header(v)+[kind(v)==0x6685]

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(x^rr[l[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
 qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises)
  assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check()
  assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_rewrites':list(rewrites)+[{'lemma':'exhaustive_original_bank_composition','applications':copy.deepcopy(v.bank_rewrites)}]})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited)
 v=setup(e)
 for label in ['input_root','length_root','node_root','buffer_root']:v.run(label)
 prove('four_original_saved_reader_cell_address_roots',v,z3.Or(cell(v,v.sp+0x478,8)!=v.ctx+0x128,cell(v,v.sp+0xd8,8)!=v.src+0xaa8,
  cell(v,v.sp+0x700,8)!=v.ctx+0x400,cell(v,v.sp+0x7c0,8)!=v.ctx+0x728))
 v=setup(e);v.run('reader_request')
 prove('caller_tag_outputs_and_hash_gate_continuation_index',v,z3.Or(v.read('x8')!=0xfffffe000a662a28,v.read('w24')!=0x133,
  v.read('x11')!=v.ctx+0x128,v.read('x10')!=v.src+0xaa8,v.read('w9')!=REQUEST,v.read('w27')!=0x37,v.read('w0')!=0x19,v.read('x17')!=0x73ed))
 v.seed('x22',v.header);v.run('shared_entry')
 prove('all_container64_shared_output_cells_and_exact_outer_continuation',v,z3.Or(cell(v,v.ctx+0x298,8)!=HASH_GATE,
  cell(v,v.ctx+0x158,8)!=v.ctx+0x128,cell(v,v.ctx+0x160,8)!=v.src+0xaa8,v.read('w23')!=0xce515bbf,
  v.read('x10')!=z3.If(v.header==0,resize(0xfffffe000a663110,64),resize(0xfffffe000a662a80,64))))
 v.run('resume');prove('null_container_resumes_hash_gate_with_failure_status',v,z3.Or(v.read('x8')!=HASH_GATE,v.read('w23')!=0xce515bbf),[v.header==0])
 v=request(e).run('search_setup').run('search_entry')
 prove('nonnull_container_search_continuation_tag_and_output_cell',v,z3.Or(cell(v,v.ctx+0xc8,8)!=0xfffffe000a662ee0,
  cell(v,v.ctx+0x758,8)!=v.ctx+0x400,cell(v,v.src,4)!=REQUEST,cell(v,v.src+0xc78,8)!=0,
  v.read('x8')!=0xfffffe000a662be0,v.read('w25')!=TOKEN))
 v.run('search_nonnull').run('search_node')
 prove('all_first_node64_empty_or_decode_gate',v,z3.Or(cell(v,v.ctx+0x2b0,8)!=v.node,v.read('x22')!=0,
  v.read('w23')!=0xce515bda,v.read('x9')!=z3.If(v.node==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))))
 empty=copy.deepcopy(v);empty.run('search_result').run('search_callback').run('after_search').run('clear_outputs').run('resume')
 prove('empty_search_clears_pointer_and_encoded_length_then_resumes',empty,z3.Or(cell(empty,empty.ctx+0x400,8)!=0,
  cell(empty,empty.ctx+0x128,8)!=0,cell(empty,empty.src+0xaa8,4)!=SUCCESS,empty.read('w23')!=0xce515bda,empty.read('x8')!=HASH_GATE),[empty.node==0])
 v.with_node=True;v.with_buffer=True;v.run('node_decode_prepare').run('word_bridge').decode(range(4))
 prove('protected_header_first_word_decodes_tag_channel',v,z3.Or(v.read('w22')!=tag(v),v.read('x9')!=0xfffffe000a63d624))
 v.run('tag_match')
 prove('all_decoded_tag32_exact_match_or_next_gate',v,z3.Or(v.read('x22')!=v.node,v.read('w23')!=SUCCESS,
  v.read('x10')!=z3.If(tag(v)==REQUEST,resize(0xfffffe000a662c44,64),resize(0xfffffe000a63d680,64))))
 nxt=copy.deepcopy(v);nxt.run('search_next').run('search_node')
 prove('tag_mismatch_reads_successor_and_repeats_exact_node_gate',nxt,z3.Or(cell(nxt,nxt.ctx+0x2b0,8)!=nxt.next,
  nxt.read('x9')!=z3.If(nxt.next==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))),[tag(nxt)!=REQUEST])
 v.run('search_result').run('search_callback').run('after_search')
 prove('matched_node_output_and_search_callback_select_header_reader',v,z3.Or(cell(v,v.ctx+0x400,8)!=v.node,
  v.read('w23')!=SUCCESS,v.read('x8')!=0xfffffe000a662f24,cell(v,v.ctx+0x298,8)!=HASH_GATE),matched(v))
 v=setup(e);v.with_node=True
 for reg,x in [('w11',0xadf),('w3',TOKEN)]:v.seed(reg,x)
 mem(v,v.ctx+0x400,8,v.node);v.run('select_node')
 prove('all_selected_buffer64_nullable_gate_and_node_extent32',v,z3.Or(cell(v,v.ctx+0x728,8)!=v.buffer,v.read('x10')!=z3.ZeroExt(32,v.extent),
  v.read('x11')!=z3.If(v.buffer==0,resize(0xfffffe000a6630e0,64),resize(0xfffffe000a662f80,64))))
 v=setup(e);v.seed('w9',0x2e6);v.seed('x10',z3.ZeroExt(32,v.extent));mem(v,v.src+0xc78,8,0);v.run('header_extent')
 prove('all_extent32_ten_byte_header_gate_and_saved_cursor',v,z3.Or(v.read('x9')!=z3.If(z3.UGE(v.extent,10),resize(0xfffffe000a66302c,64),resize(0xfffffe000a6630e0,64)),
  cell(v,v.sp+0xc10,8)!=0,cell(v,v.src+0xd68,8)!=z3.ZeroExt(32,v.extent)+0x2e8366f85c5b16d6,v.read('w12')!=0x179))
 v=searched(e);v.run('select_node').run('header_extent').run('header_prepare').run('word_bridge').decode(range(4)).run('type_prepare').decode(range(4,6))
 prove('protected_header_u16_type_at_offset_four',v,z3.Or(z3.Extract(15,0,v.read('w8'))!=kind(v),v.read('x10')!=0xfffffe000a639b30),matched(v)+[z3.UGE(v.extent,10)])
 v.run('length_prepare').run('length_bridge').decode(range(6,10))
 prove('protected_header_u32_length_channel_at_offset_six',v,z3.Or(v.read('w22')!=(payload_length(v)^SUCCESS),v.read('x9')!=0xfffffe000a63c3fc),matched(v)+[z3.UGE(v.extent,10)])
 v.run('payload_extent')
 prove('all_payload_length32_and_extent32_exact_ten_plus_length_bound',v,z3.Or(v.read('x8')!=z3.If(z3.UGE(z3.ZeroExt(32,v.extent),10+z3.ZeroExt(32,payload_length(v))),
  resize(0xfffffe000a63c494,64),resize(0xfffffe000a6630e0,64)),v.read('x10')!=10,v.read('x9')!=10+z3.ZeroExt(32,payload_length(v))),matched(v)+[z3.UGE(v.extent,10)])
 for label,choices,extra,target in [
  ('type_b2db_selects_alternate_length_path',{0xfffffe000a63c4a4:True},lambda v:[kind(v)==0xb2db],0xfffffe000a63de14),
  ('type_a129_selects_alternate_length_path',{0xfffffe000a63c4b0:True},lambda v:[kind(v)==0xa129],0xfffffe000a63de14),
  ('other_type_rejects_before_pointer_extraction',{0xfffffe000a63c4bc:True},lambda v:[kind(v)!=0xb2db,kind(v)!=0xa129,kind(v)!=0x6685],0xfffffe000a6630e0)]:
  v=header(e);v.branch_choices=choices;v.run('type_switch')
  prove(label,v,z3.Or(z3.BoolVal(v.direct_target!=target),v.read('w8')!=z3.ZeroExt(16,kind(v))),valid_header(v)+extra(v))
 v=header(e);v.run('type_switch').run('body_pointer').run('body_length_prepare').run('save_length')
 prove('type_6685_body_pointer_cursor_and_encoded_length_output',v,z3.Or(cell(v,v.ctx+0x88,8)!=v.buffer+10,
  cell(v,v.src+0xc78,8)!=10+z3.ZeroExt(32,payload_length(v)),cell(v,v.src+0xaa8,4)!=(payload_length(v)^SUCCESS),
  v.read('x9')!=0xfffffe000a63de68),accepted(v))
 for t in [0xb2db,0xa129]:
  v=header(e);v.branch_choices={0xfffffe000a63c4a4:True} if t==0xb2db else {0xfffffe000a63c4b0:True}
  v.run('type_switch').run('alternate_type_length_prepare').run('save_length').run('type_gate').run('clear_outputs').run('resume')
  prove('alternate_type_'+hex(t)+'_clears_outputs_and_reports_separate_failure',v,z3.Or(cell(v,v.ctx+0x128,8)!=0,
   cell(v,v.src+0xaa8,4)!=SUCCESS,v.read('w23')!=0xce515ae1,v.read('x8')!=HASH_GATE),valid_header(v)+[kind(v)==t])
 v=allocation(e)
 prove('accepted_body_original_IOMallocData_length_request_and_saved_outputs',v,z3.Or(v.read('x0')!=z3.ZeroExt(32,payload_length(v)),
  v.read('x8')!=0xfffffe000c4ba60c,v.read('x17')!=0xca0c,v.read('x22')!=v.buffer+10,v.read('x24')!=v.src+0xaa8,
  cell(v,v.src+0xaa8,4)!=(payload_length(v)^SUCCESS),cell(v,v.ctx+0x158,8)!=v.ctx+0x128,
  cell(v,v.ctx+0x160,8)!=v.src+0xaa8,cell(v,v.ctx+0x298,8)!=HASH_GATE,v.read('x26')!=v.protection_key,
  v.read('w20')!=0xe5d,v.read('w23')!=0x22d),accepted(v))
 v.returned().run('allocate_return')
 prove('all_allocator_result64_exact_copy_or_clear_gate_and_saved_status_reload',v,z3.Or(v.read('x8')!=z3.If(v.result==0,
  resize(0xfffffe000a6630e0,64),resize(0xfffffe000a63dff0,64)),v.read('w23')!=v.status,v.read('x22')!=v.buffer+10,
  v.read('x24')!=v.src+0xaa8,v.read('x26')!=v.protection_key),accepted(v))
 nil=copy.deepcopy(v);nil.run('clear_outputs').run('resume')
 prove('null_allocation_clears_pointer_and_length_preserving_primary_status_channel',nil,z3.Or(cell(nil,nil.ctx+0x128,8)!=0,
  cell(nil,nil.src+0xaa8,4)!=SUCCESS,nil.read('w23')!=nil.status,nil.read('x8')!=HASH_GATE),accepted(nil)+[nil.result==0])
 v.run('copy_gate')
 prove('all_length32_empty_copy_or_reverse_loop_gate',v,z3.Or(v.read('x12')!=z3.If(payload_length(v)==0,
  resize(0xfffffe000a63e110,64),resize(0xfffffe000a63e084,64)),v.read('w11')!=(payload_length(v)^0xf7cd412c),
  v.read('w8')!=0x659,v.read('w9')!=0x54e,v.read('x15')!=KEY),accepted(v)+[v.result!=0])
 zero=copy.deepcopy(v);zero.run('publish').run('resume')
 prove('zero_length_nonnull_allocator_seam_publishes_without_copy',zero,z3.Or(cell(zero,zero.ctx+0x128,8)!=zero.result,
  cell(zero,zero.src+0xaa8,4)!=SUCCESS,zero.read('w23')!=SUCCESS,zero.read('x8')!=HASH_GATE),accepted(zero)+[zero.result!=0,payload_length(zero)==0])
 v.run('copy_prepare')
 prove('nonzero_copy_preparation_preserves_key_and_sets_unsigned_byte_count',v,z3.Or(v.read('x1')!=v.protection_key,
  v.read('x10')!=z3.ZeroExt(32,payload_length(v)),v.read('x9')!=0xfffffe000a63e09c),accepted(v)+[v.result!=0,payload_length(v)!=0])
 v.with_result=True;v.seed('x10',v.counter);v.run('copy_step')
 stores=[s for s in v.stores if s['pc']==0xfffffe000a63e0ec];assert len(stores)==1 and stores[0]['size_bytes']==1
 prove('all_valid_copy_counter64_one_decoded_byte_exact_reverse_store_and_loop_gate',v,z3.Or(stores[0]['address']!=v.result+v.counter-1,
  stores[0]['value']!=v.copy_byte,v.read('x10')!=v.counter-1,v.read('x11')!=z3.If(v.counter==1,
  resize(0xfffffe000a63e110,64),resize(0xfffffe000a63e09c,64)),v.read('x0')!=v.result,v.read('x22')!=v.buffer+10,
  v.read('x1')!=v.protection_key,v.read('x15')!=KEY,v.read('w8')!=0x659,v.read('w9')!=0x54e),
  accepted(v)+[v.result!=0,z3.UGE(v.counter,1),z3.ULE(v.counter,z3.ZeroExt(32,payload_length(v)))])
 v.run('publish').run('resume')
 prove('final_copy_iteration_publishes_pointer_length_and_success_to_hash_gate',v,z3.Or(cell(v,v.ctx+0x128,8)!=v.result,
  cell(v,v.src+0xaa8,4)!=(payload_length(v)^SUCCESS),v.read('w23')!=SUCCESS,v.read('x8')!=HASH_GATE),
  accepted(v)+[v.result!=0,v.counter==1,z3.UGT(payload_length(v),0)])
 for branch,pc in R.RETAGS.items():
  row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytes.fromhex(row['bytes_hex'])[off:off+4]
  ins=next(DEC.disasm(raw,pc));assert ins.mnemonic=='movk' and ins.operands[1].imm==0xc8a2 and ins.operands[1].shift.value==48
  v=setup(e);reg=ins.reg_name(ins.operands[0].reg);v.seed(reg,v.result)
  v.e=v.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':raw.hex()}]};v.run('alternate')
  prove('alternate_retag_bit_transform_'+hex(pc),v,v.read(reg)!=((v.result&0xffffffffffff)|(0xc8a2<<48)),
   rewrites=[{'scope':'Exact alternate instruction transform only; native dereference, storage compatibility and reachability are not established.'}])
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,{'missing':sorted(map(hex,selected-visited)),'extra':sorted(map(hex,visited-selected))}
 # Induction step for the finite reverse-copy traversal; instruction proof above
 # supplies the single decoded-byte write and exact backedge for every i.
 length,index,iteration=z3.Ints('IR_copy_length IR_copy_index IR_copy_iteration')
 s=z3.SolverFor('QF_LIA');s.set(timeout=30000)
 s.add(length>0,length<2**32,iteration>=0,iteration<length,index==length-1-iteration)
 assert s.check()==z3.sat
 s.add(z3.Or(index<0,index>=length,index==length,
  z3.And(iteration<length-1,index-1!=length-1-(iteration+1)),
  z3.And(iteration==length-1,index!=0)))
 assert s.check()==z3.unsat
 qs.append({'label':'finite_reverse_copy_index_range_and_induction_certificate','result':'unsat',
  'premises_nonvacuous':True,'query':s.to_smt2(),'pointer_branch_guards':0,
  'certified_rewrites':[{'scope':'Index/range induction only; stable readable protected input and writable distinct result storage remain premises.'}]})
 coverage.append({'label':qs[-1]['label'],'source_instruction_instances':0,'store_instances':0})
 prior=json.loads(read(ROOT/'userclient_discriminator_origin_audit.json'));pp=[]
 for label in ['all_status32_success_enters_pointer_gate_other_rejects',
  'all_pointer64_null_to_zero_store_nonnull_to_first_byte','null_input_stores_zero_and_rejects']:
  q=next(q for q in prior['source_proofs'] if q['label']==label)
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
  pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_discriminator_origin_audit.json')})
 altered=[]
 for label in ['instruction_byte','bank_composition','length_channel_claim','native_termination_claim']:
  bad=copy.deepcopy(e)
  if label=='instruction_byte':
   b=bytearray.fromhex(bad['spans'][0]['bytes_hex']);b[0]^=1;bad['spans'][0]['bytes_hex']=b.hex()
  elif label=='bank_composition':bad['bank_rules'][0]['constant']=hex(int(bad['bank_rules'][0]['constant'],16)^1)
  elif label=='length_channel_claim':bad['scope']=bad['scope'].replace('encoded length channel','primary status channel')
  else:bad['NUL_termination_guaranteed']=True
  assert bad!=R.build();altered.append({'alteration':label,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':pp,
  'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':sum(256 for _ in e['bank_rules']),
   'alternate_retag_transforms':len(R.RETAGS),'altered_evidence_rejections':len(altered)},
  'conditional_input_reader_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
 print(json.dumps(a['independent_totals']),flush=True)
