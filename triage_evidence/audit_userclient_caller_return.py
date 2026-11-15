#!/usr/bin/env python3
"""Conditional caller destructor, copy-back, storage and return audit.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_MEM,ARM64_OP_REG
from kext_port_tools import ROOT,TABLE,POOL,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import Model as ReaderModel,DEC,TOKEN,PHASE,SUCCESS,mask
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_caller_return as R

KEY0=0x02e859d27e491464
KEY1=0x4dae26df20976138
MULT=0x4d08a3fb
MAGIC=0xa41a4d891208c018
SIZE_CODEC=0x621745fcc03f95d4

class Model(ReaderModel):
 def __init__(self,e):
  super().__init__(e)
  self.argument,self.input,self.staged,self.auxiliary,self.guard_saved,self.guard_current=z3.BitVecs('CR_argument64 CR_input64 CR_staged64 CR_auxiliary64 CR_saved_guard64 CR_current_guard64',64)
  self.aux_extent=z3.BitVec('CR_auxiliary_extent32',32)
  self.byte=z3.BitVec('CR_plain_byte8',8)
  self.with_container=True;self.with_staged=False;self.with_input=False
  self.table_pcs=set()
  for row in e['spans']:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if i.mnemonic=='ldr' and i.operands[1].type==ARM64_OP_MEM and i.operands[1].mem.index and i.reg_name(i.operands[0].reg).startswith('x'):
     if i.reg_name(i.operands[1].mem.base) in ['x7','x21']:self.table_pcs.add(i.address)
 def n(self):return z3.Extract(31,0,self.argument)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,4096),(self.src,16384)]
  if self.with_container:spans.append((self.object,16))
  if self.with_node:spans.append((self.node,32))
  if self.with_staged:spans.append((self.staged,z3.ZeroExt(32,self.n())))
  if self.with_input:spans.append((self.input,z3.ZeroExt(32,self.n())))
  out=[(self.sp&15)==0]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  for name,(lp,rp,pp) in R.BANK_PCS.items():
   r=next(r for r in self.receipt['bank_rules'] if r['name']==name);l,rr=int(r['left'],16),int(r['right'],16)
   if self.pc==lp:
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('CR_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in self.table_pcs:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc==0xfffffe000a6660d4:
   assert n==1;self.address_checks.append(a==self.staged+self.counter-1);return self.byte^mask(a,resize(KEY0,64))
  if self.pc in [0xfffffe000a63525c,0xfffffe000a6662bc,0xfffffe000a69f29c]:
   r=self.receipt['guard_pointers'][1 if self.pc==0xfffffe000a69f29c else 0]
   assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['target'],16),64)
  if self.pc in [0xfffffe000a635260,0xfffffe000a6662c0]:
   self.address_checks.append(a==int(self.receipt['guard_pointers'][0]['target'],16));assert n==8
   return self.guard_saved if self.pc==0xfffffe000a635260 else self.guard_current
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('CR_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None;self.direct_target=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;m=i.mnemonic;o=i.operands
   custom=m=='ror' or m.startswith('b.') or m in ['lsl','lsr'] and o[2].type==ARM64_OP_REG or m=='str' and i.writeback
   if custom:
    self.visited.add(i.address);self.count+=1
    if m.startswith('b.'):
     assert m in ['b.eq','b.ne'];condition=self.equal if m=='b.eq' else z3.Not(self.equal)
     if i.address in R.RETAGS:
      assert m=='b.eq' and o[0].imm&(2**64-1)==i.address+8;self.branch_guards.append(condition);skip=R.RETAGS[i.address]
     else:
      take=self.branch_choices.get(i.address,False);self.branch_guards.append(condition if take else z3.Not(condition))
      if take:self.direct_target=o[0].imm&(2**64-1);break
    elif m=='str':
     a=self.address(i,o[1]);reg=i.reg_name(o[0].reg);self.store(a,self.width(reg)//8,self.read(reg),i.address)
     self.write(i.reg_name(o[1].mem.base),a)
    elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    else:
     n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);s=self.operand(i,o[2],n)&(n-1)
     self.write(i.reg_name(o[0].reg),z3.LShR(a,s) if m=='lsr' else a<<s)
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    Base.run(self,'one');self.e,self.c=old_e,old_c
  return self
 def returned(self,value=None):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('CR_call_'+str(self.count)+'_X'+str(j),64))
  if value is not None:self.seed('x0',value)
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('x21',0xfffffe000792fcc0),('x28',0xfffffe0007949dd0),
  ('w3',TOKEN),('w10',TOKEN),('w1',PHASE),('w30',SUCCESS),('w23',v.status),
  ('x6',0xfffffe000ccc30d0),('x5',MAGIC),('x29',v.sp+0x10e0)]:v.seed(r,x)
 for o,x in [(0x988,v.ctx+0x600),(0x670,v.ctx+0x90),(0x728,v.ctx+0x3c0),(0x888,v.src+0xbe4),
  (0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0x9f8,0xfffffe0007949ed0),(0x9f0,0xfffffe000792fec0),(0xa10,0xfffffe0007949fd0),(0xa18,0xfffffe000792ffc0),
  (0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),(0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0),
  (0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0),(0x930,0xfffffe000792fdc0),(0x928,0xfffffe00079392f0),
  (0x878,v.argument),(0x8f8,v.input),(0x1060,v.guard_saved)]:mem(v,v.sp+o,8,x)
 mem(v,v.sp+0x9ec,4,v.status)
 for o,x in [(0x600,v.object),(0x90,v.staged),(0x3c0,v.auxiliary)]:mem(v,v.ctx+o,8,x)
 mem(v,v.src+0xbe4,4,v.aux_extent^SUCCESS);mem(v,v.src+0xe10,8,z3.ZeroExt(32,v.n())+SIZE_CODEC)
 mem(v,v.object,8,v.node);mem(v,v.node,8,v.next);mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.buffer)
 return v

def cleanup(e):return setup(e).run('cleanup_gate').run('cleanup_request').run('failure_bridge').run('destroy_entry').run('destroy_object').run('destroy_head')
def aux_entry(e):
 v=setup(e);v.with_container=False;mem(v,v.ctx+0x600,8,0)
 return v.run('cleanup_gate').run('auxiliary_gate')
def primary(e):return aux_entry(e).run('primary_load').run('copyback_gate')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 v=setup(e)
 for r,x in [('x23',v.ctx),('x28',POOL)]:v.seed(r,x)
 for n in ['primary_alias','primary_alias_save','auxiliary_alias','auxiliary_extent_alias','retirement_bank_left','retirement_bank_right']:v.run(n)
 prove('original_distinct_primary_auxiliary_extent_and_retirement_bank_roots',v,z3.Or(
  cell(v,v.sp+0x670,8)!=v.ctx+0x90,cell(v,v.sp+0x728,8)!=v.ctx+0x3c0,cell(v,v.sp+0x888,8)!=v.src+0xbe4,
  cell(v,v.sp+0x930,8)!=0xfffffe000792fdc0,cell(v,v.sp+0x928,8)!=0xfffffe00079392f0))
 v=setup(e);v.seed('w30',SUCCESS);v.run('auxiliary_initial_zero')
 prove('original_staging_completion_initializes_auxiliary_pointer_and_extent_to_zero',v,z3.Or(
  cell(v,v.ctx+0x600,8)!=0,cell(v,v.ctx+0x3c0,8)!=0,cell(v,v.src+0xbe4,4)!=SUCCESS))
 v=setup(e).run('size_channel').run('size_codec').run('retained_size_store')
 prove('original_argument64_low32_size_codec_saved_for_final_retirement',v,z3.Or(cell(v,v.src+0xe10,8)!=z3.ZeroExt(32,v.n())+SIZE_CODEC,
  cell(v,v.src+0xe10,8)+0x9de8ba02b7564d89+TOKEN!=z3.ZeroExt(32,v.n())))
 v=setup(e)
 for r,x in [('x19',MAGIC),('x20',0xfffffe000ccc30d0),('x25',0xfffffe000ccc32f8),('w26',MULT),('x28',POOL),
  ('x8',0xfffffe000ccc3000),('x9',0xfffffe000ccc3000)]:v.seed(r,x)
 v.run('outer_workspace_request')
 prove('original_outer_workspace_requests_aligned_sixteen_kibibytes',v,z3.Or(v.read('x8')!=0xfffffe000c4b9a08,
  v.read('x21')!=TABLE,v.read('x0')!=16384,v.read('x1')!=64))
 v.returned(v.src).run('outer_context_request')
 prove('workspace_result_retained_and_original_context_typed_allocation_requested',v,z3.Or(v.read('x24')!=v.src,
  v.read('x0')!=0xfffffe000847bea0,v.read('x10')!=0xfffffe000c4ba154))
 v.returned(v.ctx).run('outer_context_result')
 prove('original_outer_allocation_results_retained_as_separate_context_workspace_roots',v,z3.Or(v.read('x23')!=v.ctx,v.read('x24')!=v.src))
 v=setup(e).run('cleanup_gate')
 prove('caller_cleanup_saves_arbitrary_raw_status_and_selects_container_request',v,z3.Or(cell(v,v.src+0xde4,4)!=v.status,
  v.read('w24')!=0x1a,v.read('x8')!=0xfffffe000a656f4c))
 v.run('cleanup_request').run('failure_bridge').run('destroy_entry').run('destroy_object')
 prove('caller_specific_destructor_callback_and_original_container_cell',v,z3.Or(cell(v,v.ctx+0x368,8)!=0xfffffe000a665e90,
  v.read('x19')!=v.ctx+0x600,v.read('x22')!=v.object,v.read('x10')!=0xfffffe000a6604fc,
  cell(v,v.src+0xde4,4)!=v.status))
 v.run('destroy_head')
 prove('caller_container_empty_or_node_destructor_gate_retains_saved_status',v,z3.Or(v.read('x23')!=v.node,
  v.read('x8')!=z3.If(v.node==0,resize(0xfffffe000a660534,64),resize(0xfffffe000a660750,64)),cell(v,v.src+0xde4,4)!=v.status))
 empty=copy.deepcopy(v);empty.run('container_request')
 prove('caller_empty_container_requests_original_typed_retirement',empty,z3.Or(empty.read('x0')!=0xfffffe000847bde0,
  empty.read('x1')!=empty.object,empty.read('x10')!=0xfffffe000c4ba368),[empty.node==0])
 empty.returned().run('container_return').run('destroy_resume')
 prove('caller_container_return_clears_original_output_and_resumes_callback_one_a',empty,z3.Or(
  cell(empty,empty.ctx+0x600,8)!=0,empty.read('x8')!=0xfffffe000a665e90,empty.read('w10')!=TOKEN,
  empty.read('w3')!=TOKEN,empty.read('w1')!=PHASE,cell(empty,empty.src+0xde4,4)!=empty.status),[empty.node==0])
 for buffer in [False,True]:
  d=copy.deepcopy(v);d.with_node=True;d.run('node_gate');prem=[d.buffer!=0 if buffer else d.buffer==0]
  prove('caller_list_node_'+str(buffer)+'_saves_successor_and_selects_data_or_type_retirement',d,z3.Or(d.read('x25')!=d.next,
   d.read('x8')!=(0xfffffe000a660790 if buffer else 0xfffffe000a66066c),cell(d,d.src+0xde4,4)!=d.status),prem)
  if buffer:
   d.run('node_data_request');prove('caller_list_node_requests_original_data_retirement',d,z3.Or(
    d.read('x0')!=d.buffer,d.read('x1')!=z3.ZeroExt(32,d.extent),d.read('x8')!=0xfffffe000c4ba84c),prem)
   d.returned().run('node_data_return');prove('caller_list_data_return_clears_buffer_and_keeps_successor',d,z3.Or(
    cell(d,d.node+0x18,8)!=0,d.read('x25')!=d.next,d.read('x8')!=0xfffffe000a66066c),prem)
  d.run('node_type_request');prove('caller_list_node_'+str(buffer)+'_requests_original_typed_retirement',d,z3.Or(
   d.read('x0')!=0xfffffe000847be20,d.read('x1')!=d.node,d.read('x10')!=0xfffffe000c4ba368),prem)
  d.returned().run('node_type_return');prove('caller_list_node_'+str(buffer)+'_selects_successor_or_container_retirement',d,z3.Or(
   d.read('x23')!=d.next,d.read('x8')!=z3.If(d.next==0,resize(0xfffffe000a660534,64),resize(0xfffffe000a660750,64))),prem)
  d.run('container_request').returned().run('container_return').run('destroy_resume').run('auxiliary_gate')
  prove('caller_last_list_node_'+str(buffer)+'_joins_auxiliary_gate_with_raw_status_saved',d,z3.Or(cell(d,d.ctx+0x600,8)!=0,
   cell(d,d.src+0xde4,4)!=d.status,d.read('x0')!=d.auxiliary,d.read('x8')!=z3.If(d.auxiliary==0,
    resize(0xfffffe000a665f8c,64),resize(0xfffffe000a665ee4,64))),prem+[d.next==0])
 v=aux_entry(e)
 prove('null_container_cleanup_skips_destructor_and_selects_exact_auxiliary_gate',v,z3.Or(cell(v,v.src+0xde4,4)!=v.status,
  v.read('x0')!=v.auxiliary,v.read('w19')!=0xd61,v.read('w20')!=0x5aa,v.read('x8')!=z3.If(v.auxiliary==0,
   resize(0xfffffe000a665f8c,64),resize(0xfffffe000a665ee4,64))))
 v.run('auxiliary_request')
 prove('nonnull_auxiliary_requests_original_data_free_with_its_own_extent32',v,z3.Or(v.read('x0')!=v.auxiliary,
  v.read('x1')!=z3.ZeroExt(32,v.aux_extent),v.read('x8')!=0xfffffe000c4ba84c,v.read('w20')!=0x5aa),[v.auxiliary!=0])
 v.returned().run('auxiliary_return').run('primary_load')
 prove('auxiliary_free_return_reloads_raw_status_and_separate_original_staged_pointer',v,z3.Or(v.read('w19')!=v.status,
  v.read('x8')!=v.staged,v.read('x9')!=0xfffffe000a665fc8,v.read('w10')!=0xb1d,
  cell(v,v.ctx+0x3c0,8)!=v.auxiliary),[v.auxiliary!=0])
 v.run('copyback_gate')
 prove('nonnull_auxiliary_free_return_reaches_same_size_controlled_primary_copyback_contract',v,z3.Or(
  v.read('x8')!=v.staged,v.read('x0')!=v.input,v.read('w19')!=v.status,v.read('x1')!=KEY1,
  v.read('x12')!=z3.ZeroExt(32,v.n()^0xc03f95d4),v.read('w22')!=0x204,
  v.read('x9')!=z3.ZeroExt(32,v.n())+SIZE_CODEC,v.read('x10')!=z3.If(v.n()==0,
   resize(0xfffffe000a666118,64),resize(0xfffffe000a66609c,64))),[v.auxiliary!=0])
 v=primary(e)
 prove('null_auxiliary_skips_free_and_primary_copyback_gate_is_exact_nonzero_size32',v,z3.Or(v.read('x8')!=v.staged,
  v.read('x0')!=v.input,v.read('x12')!=z3.ZeroExt(32,v.n()^0xc03f95d4),v.read('w22')!=0x204,
  v.read('x10')!=z3.If(v.n()==0,resize(0xfffffe000a666118,64),resize(0xfffffe000a66609c,64))),[v.auxiliary==0])
 zero=copy.deepcopy(v);zero.run('primary_request')
 prove('zero_size_staged_retirement_request_uses_retained_pointer_and_zero_extent',zero,z3.Or(zero.read('x0')!=zero.staged,
  zero.read('x1')!=0,zero.read('x11')!=0xfffffe000c4ba84c),[zero.auxiliary==0,zero.n()==0])
 zero.returned().run('primary_return').run('context_request').returned().run('workspace_request').returned().run('guard_gate').run('status_return')
 prove('zero_size_staged_cleanup_with_equal_canary_returns_decoded_saved_status',zero,zero.read('w0')!=(zero.status^SUCCESS),
  [zero.auxiliary==0,zero.n()==0,zero.guard_current==zero.guard_saved])
 v.run('copyback_prepare')
 prove('nonzero_copyback_preparation_uses_full_low32_count_and_same_protection_keys',v,z3.Or(v.read('x10')!=z3.ZeroExt(32,v.n()),
  v.read('x8')!=v.staged,v.read('x0')!=v.input,v.read('x1')!=KEY1,v.read('x2')!=KEY0),[v.auxiliary==0,v.n()!=0])
 v.with_staged=v.with_input=True;v.seed('x10',v.counter)
 kept={r:v.read(r) for r in ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x11','x12','x19','x20','x25','x26']}
 v.run('copyback_step')
 st=[s for s in v.stores if s['pc']==0xfffffe000a6660f4];assert len(st)==1 and st[0]['size_bytes']==1
 prem=[v.auxiliary==0,v.n()!=0,z3.UGE(v.counter,1),z3.ULE(v.counter,z3.ZeroExt(32,v.n()))]
 prove('every_valid_reverse_copyback_counter_decodes_one_byte_into_original_caller_buffer',v,z3.Or(
  st[0]['address']!=v.input+v.counter-1,st[0]['value']!=v.byte,v.read('x10')!=v.counter-1,
  v.read('x13')!=z3.If(v.counter==1,resize(0xfffffe000a666118,64),resize(0xfffffe000a6660b4,64))),prem)
 prove('reverse_copyback_read_and_write_offsets_fit_original_low32_extent',v,z3.Or(
  z3.ULT(v.staged+v.counter-1,v.staged),z3.UGE(v.staged+v.counter-1,v.staged+z3.ZeroExt(32,v.n())),
  z3.ULT(st[0]['address'],v.input),z3.UGE(st[0]['address'],v.input+z3.ZeroExt(32,v.n()))),prem)
 prove('reverse_copyback_step_preserves_every_live_loop_and_retirement_input',v,z3.Or(
  *[v.read(r)!=x for r,x in kept.items()],v.read('w22')!=0x204,
  cell(v,v.src+0xde4,4)!=v.status,cell(v,v.src+0xe10,8)!=z3.ZeroExt(32,v.n())+SIZE_CODEC),prem)
 prove('finite_reverse_copyback_unsigned_rank_and_exact_last_iteration_certificate',v,z3.Or(
  z3.UGE(v.counter-1,v.counter),z3.UGE(v.counter-1,z3.ZeroExt(32,v.n())),
  (v.counter-1==0)!=(v.counter==1),z3.UGT(v.counter,0xffffffff)),prem)
 v.run('primary_request')
 prove('final_copyback_iteration_requests_staged_retirement_with_original_extent32',v,z3.Or(v.read('x0')!=v.staged,
  v.read('x1')!=z3.ZeroExt(32,v.n()),v.read('x11')!=0xfffffe000c4ba84c,v.read('w19')!=v.status),prem+[v.counter==1])
 v.returned().run('primary_return')
 prove('staged_free_return_moves_saved_raw_status_to_callee_saved_return_channel',v,z3.Or(v.read('w26')!=v.status,
  v.read('x8')!=0xfffffe000a6661bc,v.read('x2')!=v.ctx,v.read('x4')!=v.src),prem+[v.counter==1])
 v.run('context_request')
 prove('outer_context_retirement_requests_distinct_original_alloc_type_descriptor',v,z3.Or(v.read('x0')!=0xfffffe000847ba60,
  v.read('x1')!=v.ctx,v.read('x10')!=0xfffffe000c4ba368,v.read('w23')!=SUCCESS,v.read('x22')!=v.src),prem+[v.counter==1])
 v.returned().run('workspace_request')
 prove('context_return_requests_original_aligned_workspace_retirement_sixteen_kibibytes',v,z3.Or(v.read('x0')!=v.src,
  v.read('x1')!=16384,v.read('x8')!=0xfffffe000c4b9a24,v.read('w26')!=v.status),prem+[v.counter==1])
 v.returned().run('guard_gate').run('status_return')
 prove('ordinary_cleanup_return_with_equal_canary_decodes_arbitrary_raw_status32',v,v.read('w0')!=(v.status^SUCCESS),prem+[v.counter==1,v.guard_current==v.guard_saved])
 fail=setup(e);fail.seed('w26',fail.status);fail.seed('w23',SUCCESS);fail.branch_choices[0xfffffe000a6662c8]=True;fail.run('guard_gate')
 prove('unequal_canary_selects_original_guard_failure_call_frontier',fail,z3.BoolVal(fail.direct_target!=0xfffffe000a66692c),[fail.guard_current!=fail.guard_saved])
 fail.run('guard_failure_veneer');prove('guard_failure_veneer_loads_original_stack_chk_fail_pointer',fail,z3.Or(
  fail.read('x16')!=0xfffffe000c629694,fail.read('x17')!=0xfffffe000847c478))
 save=setup(e).run('guard_save');prove('original_saved_canary_occupies_exact_frame_slot',save,
  cell(save,save.sp+0x1060,8)!=save.guard_saved)
 n=setup(e)
 for r,x in [('w19',0x2e5),('w20',TOKEN),('w25',MULT),('x24',0xfffffe000ccc32f8),('x0',0)]:n.seed(r,x)
 n.run('staging_result')
 prove('null_staging_allocation_result_skips_copyback_and_enters_outer_context_retirement',n,z3.Or(
  cell(n,n.ctx+0x90,8)!=0,n.read('w26')!=n.status,n.read('x8')!=0xfffffe000a6661bc))
 n.run('context_request').returned().run('workspace_request').returned().run('guard_gate').run('status_return')
 prove('null_staging_result_ordinary_outer_cleanup_returns_decoded_original_status',n,n.read('w0')!=(n.status^SUCCESS),[n.guard_current==n.guard_saved])
 pc=next(iter(R.RETAGS.values()));row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16)
 raw=bytes.fromhex(row['bytes_hex'])[off:off+4];d=setup(e);old=z3.BitVec('CR_alternate_pointer64',64);d.seed('x13',old)
 d.e=d.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':raw.hex()}]};d.run('alternate')
 prove('alternate_copyback_retag_bit_transform_only',d,d.read('x13')!=((old&0xffffffffffff)|(0xc8a2<<48)))
 pcs={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==pcs,{'missing':sorted(map(hex,pcs-visited)),'extra':sorted(map(hex,visited-pcs))}
 rechecked=[]
 for f,label in [
  ('userclient_container_staging_audit.json','post_stack_probe_saved_three_entry_arguments'),
  ('userclient_container_staging_audit.json','scratch_source_aliases_and_writeback_staging_output_roots'),
  ('userclient_container_staging_audit.json','exact_saved_input_size_original_IOMallocData_request'),
  ('userclient_container_staging_audit.json','every_valid_reverse_counter_one_protected_byte_exact_destination_and_backedge'),
  ('userclient_parser_cleanup_audit.json','list_node_buffer_returns_exact_successor_or_container_gate'),
  ('userclient_command_dispatch_audit.json','unsupported_command_cleanup_saves_exact_status_and_requests_container_path')]:
  p=next(p for p in json.loads(read(ROOT/f))['source_proofs'] if p['label']==label)
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert p['premises_nonvacuous'] and s.check()==z3.unsat
  rechecked.append({'artifact':f,'artifact_sha256':sha(ROOT/f),'label':label,'result':'unsat'})
 controls=[]
 for name,mutate in [('instruction_byte',lambda x:x['spans'][0].update(bytes_hex='00'+x['spans'][0]['bytes_hex'][2:])),
  ('bank_constant',lambda x:x['bank_rules'][0].update(constant='0x0')),('outer_descriptor_size',lambda x:x['typed_descriptors'][0].update(size_bytes=16)),
  ('native_ownership_claim',lambda x:x.update(native_ownership_established=True))]:
  altered=copy.deepcopy(e);mutate(altered);assert altered!=e;controls.append({'alteration':name,'equality_check_rejects':True})
 return {'generator_sha256':sha(__file__),'source_sha256':e['source_sha256'],'scope':R.SCOPE,'source_proofs':qs,
  'proof_coverage':coverage,'proved_pcs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':rechecked,'altered_evidence_controls':controls,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(rechecked),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':256*len(e['bank_rules']),'altered_evidence_rejections':len(controls),'list_buffer_cases':2,
   'copyback_counter_cases':'all unsigned64 J with 1<=J<=zero_extend32(N)'},
  'conditional_caller_return_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
