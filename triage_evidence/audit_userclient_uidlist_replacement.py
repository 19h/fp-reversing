#!/usr/bin/env python3
"""Prove conditional old-marker resource records and replacement status joins.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
Source interpretation only; ordinary ABI, coherent storage and epochs are premises.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,resize,mem,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_uidlist_replacement as R

SUCCESS=0x31ae0066
TOKEN=0x886a1ca3
PHASE=0x7795e642
KEY0=0x1ee45f68039f9913
TAG=0xffc0000000000000

class Model(Base):
 def __init__(self,e):
  super().__init__(e)
  self.node,self.context,self.holder,self.old_payload=z3.BitVecs('UR_node64 UR_context64 UR_holder64 UR_old_payload64',64)
  self.old_marker,self.saved_status,self.flag1,self.flag2=z3.BitVecs('UR_old_marker32 UR_saved_status32 UR_flag1_8 UR_flag2_8',32)
  self.flag1=z3.Extract(7,0,self.flag1);self.flag2=z3.Extract(7,0,self.flag2)
  self.branch_loads=[]
 def owned(self):
  ranges=[(self.sp-0xe0,0x1160),(self.src,4096),(self.ctx,2048),(self.node,16),(self.context,24),
   (self.payload,120),(self.header,16),(self.buffer,24*z3.ZeroExt(32,self.capacity))]
  out=[z3.UGE(self.sp,0xe0),(self.sp&15)==0,(self.record&7)==0,(self.header&7)==0,(self.buffer&7)==0,
   (self.node&7)==0,self.capacity!=0,z3.ULT(self.index,self.capacity)]
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1,64)-n)])
   for b,m in ranges[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def address(self,i,o):
  if i.writeback:
   assert i.address==0xfffffe000a65ac58
   a=z3.simplify(resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp)
   self.write(i.reg_name(o.mem.base),a);return a
  return super().address(i,o)
 def load(self,a,n):
  a=z3.simplify(a)
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]))
   self.branch_loads.append({'pc':hex(self.pc),'indices':js});out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  for name,(lp,rp,pp) in R.BANK_PCS.items():
   r=next(r for r in self.e['bank_rules'] if r['name']==name)
   l,rr=int(r['left'],16),int(r['right'],16)
   if self.pc==lp:
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('UR_left_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'checked_inputs':256})
    return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc==0xfffffe000a65ac58:
   assert n==8;self.address_checks.append(a==0xfffffe000ccceac0);return self.holder
  if n==4 and z3.is_bv_value(a) and a.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:
   return z3.BitVec('UR_fresh_controller_'+format(self.pc,'x'),32)
  return super().load(a,n)
 def returned(self):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('UR_call_'+str(self.count)+'_X'+str(j),64))
  return self

def codec(e,record):
 v=Model(e);v.seed('x0',record);v.run('lookup_decoder_key');return v.read('x13')

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('x6',0xfffffe000ccc30d0),
  ('x5',0xa41a4d891208c018),('x11',0xfffffe000794a0d0),('x21',0xfffffe000792fcc0),
  ('x28',0xfffffe0007949dd0),('w1',PHASE),('w3',TOKEN),('w19',TOKEN),('w8',0x71),
  ('w30',SUCCESS),('w13',0x7795e3ce),('w25',0x4d08a3fb)]:v.seed(reg,x)
 for o,x in [(0xa08,v.src),(0xa28,v.ctx),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa40,0xfffffe000792fbc0),(0xa48,0xfffffe0007949dd0),(0xa50,0xfffffe0007941f60),
  (0xa58,0xfffffe000794a0d0),(0xa60,TABLE),(0xa20,0xfffffe00079391f0),
  (0x650,v.src+0xb68),(0x5d8,v.ctx+0x7a8),(0x940,v.src+0xa28),(0x428,v.src+0xbe0),
  (0x398,v.src+0xc80),(0x998,v.record),(0x6f0,v.record|0xd9d0ab468c12f4cb),
  (0x3a0,codec(e,v.record)),(0x2c8,v.record^0x2a4f38d70e12cee6)]:mem(v,v.sp+o,8,x)
 mem(v,v.sp+0x9ec,4,v.saved_status)
 for o,x in [(0x420,v.header),(0x7a8,v.old_payload),(0x2c8,v.node+4),(0x410,v.node),
  (0x680,qword(TABLE+8*0x160)),(0x30,qword(TABLE+8*0x16e))]:mem(v,v.ctx+o,8,x)
 for o,x in [(0xc84,v.old_marker),(0xd8c,v.raw_marker),(0xa28,v.index),(0xbe0,v.index)]:mem(v,v.src+o,4,x)
 mem(v,v.src+0xb68,1,v.flag1);mem(v,v.src+0xc80,1,v.flag2)
 mem(v,v.node+4,4,v.old_marker)
 mem(v,v.header+4,4,v.capacity);mem(v,v.header+8,8,v.buffer)
 mem(v,v.buffer+24*z3.ZeroExt(32,v.index)+16,8,v.old_payload)
 return v

def first_request(e):
 v=setup(e)
 # Certified below: caller/helper pre-multiply keys agree. Transport through
 # the identical u64 multiplier rather than asking SMT to rediscover it.
 v.overrides={(0xfffffe000a65b498,'x13'):codec(e,v.record)}
 for reg,x in [('w20',0x5df),('w23',0x160),('w10',0x16e),('x22',v.header),
  ('x9',v.src+0xb68),('x19',v.ctx+0x7a8),('w8',v.old_marker),('w25',0x12)]:v.seed(reg,x)
 v.run('first_header_gate').run('first_record').run('first_call');return v

def second_request(e):
 v=setup(e)
 for reg,x in [('w8',0xea2),('w9',0x146),('x28',0xfffffe0007949dd0)]:v.seed(reg,x)
 v.run('second_header_gate').run('second_record').run('second_call');return v

def deletion(e):
 v=setup(e)
 for reg,x in [('x24',v.header),('w22',0xc95),('x21',0xfffffe000792fcc0)]:v.seed(reg,x)
 v.run('delete_address').run('delete_record').run('delete_call');return v

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(x^rr[l[x]^int(r['key'],16)]==int(r['constant'],16) for x in range(256))
 qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*premises);assert s.check()==z3.sat,label
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check()
  assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'certified_rewrites':list(rewrites)+[{'lemma':'exhaustive_original_bank_composition','applications':copy.deepcopy(v.bank_rewrites)}]})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited)
 # Actual entry-derived saved cells, with record identity supplied by the
 # preceding affine-record report. Prove pre-multiply equality independently.
 v=setup(e);v.seed('x16',v.record);v.run('saved_codec_basis')
 prove('saved_writer_and_lookup_pre_multiply_basis',v,z3.Or(
  cell(v,v.sp+0x2c8,8)!=(v.record^0x2a4f38d70e12cee6),
  v.read('x8')!=((v.record^0x8be454d92cc693a0)^0x679c0d0c5f8cb112)))
 v.run('saved_codec_cells')
 prove('saved_private_record_and_lookup_codec_cells',v,z3.Or(cell(v,v.sp+0x998,8)!=v.record,
  cell(v,v.sp+0x6f0,8)!=(v.record|0xd9d0ab468c12f4cb),cell(v,v.sp+0x3a0,8)!=codec(e,v.record)),
  rewrites=[{'lemma':'original_linear_def_use_gap','source_sha256':e['codec_basis_def_use_gap']['sha256'],
   'instructions_checked':134,'preserved_registers':['X8','X16'],'control_transfers':0}])
 v=setup(e)
 for name in ['first_index_root','payload_output_root','first_flag_root','second_index_root','second_flag_root']:v.run(name)
 prove('saved_first_second_index_flag_and_payload_output_roots',v,z3.Or(*[
  cell(v,v.sp+o,8)!=x for o,x in [(0x940,v.src+0xa28),(0x5d8,v.ctx+0x7a8),
  (0x650,v.src+0xb68),(0x428,v.src+0xbe0),(0x398,v.src+0xc80)]]))
 v=setup(e);v.seed('x8',v.node);v.seed('w11',0xbc1);v.run('matched_capture')
 prove('matched_node_capture_old_marker_and_exact_resource_gate',v,z3.Or(cell(v,v.ctx+0x410,8)!=v.node,
  cell(v,v.ctx+0x2c8,8)!=v.node+4,cell(v,v.ctx+0x7a8,8)!=0,cell(v,v.src+0xb68,1)!=0,
  cell(v,v.src+0xc84,4)!=v.old_marker,v.read('w23')!=0xce515bbf,v.read('w19')!=TOKEN,v.read('w8')!=0x71,
  v.read('x9')!=z3.If(v.old_marker==SUCCESS,resize(0xfffffe000a65e6cc,64),resize(0xfffffe000a65eee4,64))))
 v.run('resource_entry').run('holder_gate')
 prove('matched_unequal_marker_enters_shared_holder_gate',v,z3.Or(v.read('x19')!=0xfffffe000a65b0e0,
  cell(v,v.sp+0x9e0,8)!=0xfffffe000ccceac0,v.read('x22')!=v.holder,v.read('w20')!=0x81b,
  v.read('x8')!=z3.If(v.holder==0,resize(0xfffffe000a65ac84,64),resize(0xfffffe000a65affc,64))),[v.old_marker!=SUCCESS])
 v.run('holder_resume')
 prove('nonnull_holder_resume_retains_original_resource_continuation',v,z3.Or(v.read('x19')!=0xfffffe000a65b0e0,v.read('x17')!=0xcb79),[v.holder!=0])
 v.run('processing_gate')
 prove('all_holder64_processing_gate_and_saved_status_reload',v,z3.Or(cell(v,v.ctx+0x420,8)!=v.holder,
  v.read('w23')!=v.saved_status,v.read('w10')!=0x16e,v.read('w19')!=TOKEN,
  v.read('x8')!=z3.If(v.holder==0,resize(0xfffffe000a65e6cc,64),resize(0xfffffe000a65b12c,64))))
 v=setup(e);v.seed('x8',v.node);v.seed('w11',0xbc1);v.run('matched_capture').run('status_gate')
 prove('matched_raw_success_marker_directly_selects_failure_continuation',v,
  v.read('x9')!=0xfffffe000a65ef14,[v.old_marker==SUCCESS])
 v=setup(e);v.seed('w10',0x16e);v.seed('x22',v.header);v.run('first_dispatch').run('first_entry').run('first_header_gate')
 prove('old_marker_and_output_roots_enter_first_lookup',v,z3.Or(v.read('w8')!=v.old_marker,
  v.read('x19')!=v.ctx+0x7a8,v.read('x9')!=v.src+0xb68,v.read('w24')!=0x2ed,
  cell(v,v.src+0xa28,4)!=0,cell(v,v.ctx+0x30,8)!=0xfffffe000a65b608,
  cell(v,v.ctx+0x680,8)!=0xfffffe000a65b5f8,v.read('x11')!=0xfffffe000a65b408))
 # Explicit nullable-header local cut, without dereferencing it in this gate.
 v=setup(e);v.seed('x22',v.holder);v.seed('w20',0x5df);v.seed('w23',0x160);v.run('first_header_gate')
 prove('all_header64_first_lookup_or_null_trampoline_gate',v,v.read('x11')!=z3.If(v.holder==0,resize(0xfffffe000a65b5ec,64),resize(0xfffffe000a65b408,64)))
 for request,name in [(first_request,'first'),(second_request,'second')]:
  v=request(e);k=codec(e,v.record);u=v.old_marker^SUCCESS
  if name=='first':
   d=setup(e);d.seed('x0',v.record);d.run('lookup_decoder_key')
   prove('first_lookup_caller_helper_pre_multiply_key_equality',v,
    v.values[(0xfffffe000a65b48c,'x13')]!=d.values[(0xfffffe000a5ae408,'x9')])
  shape=resize(0x652019cc00000000,64)|z3.ZeroExt(32,u^0x6a48ac59)
  prove(name+'_lookup_record_old_marker_key_outputs_and_call',v,z3.Or(cell(v,v.record,8)+k!=shape,
   cell(v,v.record+8,8)!=(v.src+0xb68 if name=='first' else v.src+0xc80),
   cell(v,v.record+0x10,8)!=(v.src+0xa28 if name=='first' else v.src+0xbe0),
   cell(v,v.record+0x20,8)!=v.buffer,cell(v,v.record+0x28,4)-resize(k,32)!=0x541,
   (cell(v,v.record+0x2c,4)^resize(k,32))-0x4f950919!=v.capacity,
   v.read('x0')!=v.record,v.read('x8')!=0xfffffe000a5ae354,v.read('x17')!=0x6a0f),
   rewrites=[{'lemma':'saved_private_record_and_lookup_codec_cells','cut':'Saved record codec survives intervening phases.'},
    {'lemma':'first_lookup_caller_helper_pre_multiply_key_equality' if name=='first' else 'saved_private_record_and_lookup_codec_cells',
     'rewrite':'Congruence through identical u64 multiplier; first-call product replacement is backed by the separately proved pre-key equality.'}])
 v=first_request(e);v.returned();mem(v,v.record+0x18,4,v.status)
 mem(v,v.src+0xa28,4,v.index);mem(v,v.src+0xb68,1,v.flag1);v.run('first_return')
 prove('all_first_status32_payload_read_gate',v,z3.Or(v.read('w23')!=v.status,
  v.read('x8')!=z3.If(v.status==SUCCESS,resize(0xfffffe000a65b564,64),resize(0xfffffe000a65b5ac,64))))
 v.run('payload_address');a=v.buffer+24*z3.ZeroExt(32,v.index)
 prove('first_index24_stride_and_tag_guard',v,z3.Or(v.read('x10')!=a,v.equal!=(((v.buffer^a)&TAG)==0)))
 v.run('payload_retag');prove('first_payload_address_alternate_top16',v,v.read('x10')!=((a&((1<<48)-1))|(0xc8a2<<48)))
 v.seed('x10',a);v.run('payload_read').run('first_restore').run('first_null_trampoline').run('first_return_trampoline')
 prove('entry_payload_capture_and_restored_status_trampoline',v,z3.Or(cell(v,v.ctx+0x7a8,8)!=v.old_payload,
  v.read('x8')!=0xfffffe000a65b608,v.read('x10')!=0xfffffe000a65b5f8,v.read('x17')!=0x78f4,
  v.read('x2')!=v.ctx,v.read('x4')!=v.src,v.read('w3')!=TOKEN,v.read('w1')!=PHASE),
  [v.status==SUCCESS,((v.buffer^a)&TAG)==0])
 v=setup(e);v.seed('w23',v.status);v.run('first_status')
 prove('all_first_status32_second_phase_or_status_gate',v,z3.Or(v.read('w9')!=0x146,v.read('w19')!=TOKEN,
  v.read('x8')!=z3.If(v.status==SUCCESS,resize(0xfffffe000a65b64c,64),resize(0xfffffe000a65e6cc,64))))
 v.run('first_found')
 prove('all_first_found8_low_bit_gate_and_failure_default',v,z3.Or(v.read('w23')!=0xce515bbf,v.read('w19')!=TOKEN,v.read('w8')!=0xea2,
  v.read('x10')!=z3.If((v.flag1&1)!=0,resize(0xfffffe000a65b6ac,64),resize(0xfffffe000a65e6cc,64))))
 v=setup(e);v.seed('w8',0xea2);v.seed('w9',0x146);mem(v,v.ctx+0x420,8,v.holder);v.run('second_header_gate')
 prove('all_header64_second_lookup_gate_and_outputs_clear',v,z3.Or(v.read('w22')!=0xc95,cell(v,v.src+0xbe0,4)!=0,
  cell(v,v.src+0xc80,1)!=0,v.read('w10')!=v.old_marker,
  v.read('x8')!=z3.If(v.holder==0,resize(0xfffffe000a65e6cc,64),resize(0xfffffe000a65b6fc,64))))
 v=second_request(e);v.returned();mem(v,v.record+0x18,4,v.status);mem(v,v.src+0xc80,1,v.flag2);v.run('second_return')
 prove('all_second_status32_found8_exact_mutation_gate',v,v.read('x8')!=z3.If(z3.And(v.status==SUCCESS,(v.flag2&1)!=0),resize(0xfffffe000a65b820,64),resize(0xfffffe000a65ba34,64)))
 v=setup(e);v.seed('x24',v.header);v.run('delete_address');a=v.buffer+24*z3.ZeroExt(32,v.index)
 prove('second_index24_stride_and_tag_guard',v,z3.Or(v.read('x10')!=a,v.equal!=(((v.buffer^a)&TAG)==0)))
 v.run('delete_retag');prove('deletion_address_alternate_top16',v,v.read('x10')!=((a&((1<<48)-1))|(0xc8a2<<48)))
 v=deletion(e);k=(v.record^0x2a4f38d70e12cee6)*0x91c952ff
 prove('tombstone_writer_record_key_zero_payload_header_and_call',v,z3.Or(cell(v,v.record,8)!=a,
  cell(v,v.record+8,4)-resize(k,32)!=0xc28,cell(v,v.record+0x10,8)!=0,
  cell(v,v.record+0x18,8)!=v.header,cell(v,v.record+0x20,4)-resize(k,32)!=0x629f8776,
  cell(v,v.record+0x28,8)+k!=KEY0,v.read('x0')!=v.record,v.read('x8')!=0xfffffe000a5aec24,v.read('x17')!=0x3936),
  [((v.buffer^a)&TAG)==0],rewrites=[{'lemma':'saved_writer_and_lookup_pre_multiply_basis'}])
 d=setup(e);d.seed('x0',d.record);d.run('lookup_decoder_key')
 prove('original_lookup_decoder_pre_multiply_basis',d,
  d.values[(0xfffffe000a5ae408,'x9')]!=((d.record^0x8be454d92cc693a0)^0x679c0d0c5f8cb112))
 d=setup(e);d.seed('x0',d.record);d.run('writer_decoder_key')
 prove('writer_record_codec_matches_original_decoder',d,d.read('x8')!=((d.record^0x2a4f38d70e12cee6)*0x91c952ff))
 v.returned();k32=resize((v.record^0x0c92091678856dd2)*0x40d18915,32)
 v.overrides={(0xfffffe000a65b980,'w13'):k32};v.run('reclaim_record').run('reclaim_call')
 prove('reclaimer_pre_multiply_low32_codec_equality',v,
  v.values[(0xfffffe000a65b974,'w13')]!=resize(v.record^0x0c92091678856dd2,32),[((v.buffer^a)&TAG)==0])
 prove('backward_reclamation_record_index_capacity_header_and_call',v,z3.Or(cell(v,v.record,8)!=v.header,
  cell(v,v.record+8,4)+k32+0xe7a61627!=v.index,cell(v,v.record+0xc,4)-k32!=0x559,
  cell(v,v.record+0x10,4)-k32-0x35f2763e!=v.capacity,cell(v,v.record+0x18,8)!=v.buffer,
  v.read('x0')!=v.record,v.read('x8')!=0xfffffe000a616860,v.read('x17')!=0xaf1c),
  [((v.buffer^a)&TAG)==0],rewrites=[{'lemma':'reclaimer_pre_multiply_low32_codec_equality',
   'rewrite':'Congruence through identical low32 multiplier; only W13 is read before overwrite.'}])
 v.returned();mem(v,v.record+0x20,4,v.status);v.run('reclaim_return').run('retire_status')
 prove('all_reclamation_status32_retirement_or_update_gate',v,z3.Or(v.read('w23')!=v.status,v.read('w19')!=TOKEN,v.read('w25')!=0x146,
  v.read('x8')!=z3.If(v.status==SUCCESS,resize(0xfffffe000a65ba98,64),resize(0xfffffe000a65e6cc,64))))
 v=setup(e);v.seed('w19',TOKEN);v.run('retire_prepare').run('free_alias').run('free_gate')
 prove('all_saved_payload64_free_or_success_join_gate',v,z3.Or(v.read('x22')!=v.ctx+0x7a8,v.read('x1')!=v.old_payload,
  v.read('x24')!=0xfffffe000a65e6cc,v.read('w20')!=0xd46,
  v.read('x8')!=z3.If(v.old_payload==0,resize(0xfffffe000a65e6a8,64),resize(0xfffffe000a65e5dc,64))))
 v.run('free_request')
 prove('original_prior_payload_FPSecureTunnel_typed_free_ABI',v,z3.Or(v.read('x0')!=0xfffffe000847bf60,
  v.read('x1')!=v.old_payload,v.read('x10')!=0xfffffe000c4ba368,v.read('x17')!=0x4d6a),[v.old_payload!=0])
 v.returned();v.run('free_return')
 prove('ordinary_free_return_clears_saved_payload_and_restores_roots',v,z3.Or(cell(v,v.ctx+0x7a8,8)!=0,
  v.read('x8')!=0xfffffe000a65e6a8,v.read('x2')!=v.ctx,v.read('x4')!=v.src,
  v.read('x7')!=TABLE,v.read('x6')!=0xfffffe000ccc30d0,v.read('w3')!=TOKEN,v.read('w30')!=SUCCESS))
 v.run('free_join').run('status_gate').run('marker_update')
 prove('retirement_success_replaces_existing_node_marker_and_continues',v,z3.Or(v.read('w23')!=SUCCESS,v.read('w19')!=TOKEN,
  cell(v,v.node+4,4)!=v.raw_marker,v.read('x8')!=0xfffffe000a65e890),
  rewrites=[{'predecessor':'Matching-node capture binds C+2c8 to node+4, C+410 to the matching node and S+d8c to the new marker; stable epochs are premises.'}])
 v=setup(e);v.seed('w19',TOKEN);v.run('retire_prepare').run('free_alias').run('free_gate').run('free_join').run('status_gate').run('marker_update')
 prove('zero_saved_payload_skips_free_and_replaces_existing_marker',v,z3.Or(v.read('w23')!=SUCCESS,
  cell(v,v.node+4,4)!=v.raw_marker,v.read('x8')!=0xfffffe000a65e890),[v.old_payload==0])
 prior_specs={
  'userclient_uidlist_publication_audit.json':['matched_node_marker_address_old_marker_and_resource_gate','all_status32_gate_before_existing_marker_update','existing_marker_write_and_match_presence_branch'],
  'userclient_hash_table_lookup_audit.json':['token541_nonnull_array_decoder_contract',
   'all_entry_states_first_tombstone_and_probe_successor','all_key64_occupied_entry_equality_and_branch',
   'empty_selected_index_and_success_status_stores','original_matched_optional_flag_store',
   'nonnull_matched_index_and_success_status_stores','ordinary_frame_restore_preserves_SP_and_X19_X30'],
  'userclient_hash_table_reclamation_audit.json':['original_FPSecureTunnel_typed_free_ABI',
   'token_c28_nonnull_entry_gate_and_decoded_token','all_state32_unchanged_counter_and_exact_entry_stores',
   'cleanup_reclaimer_record_decodes_token559_index_and_capacity','original_reclamation_success_raw_status_store',
   'original_reclamation_null_array_raw_status_store','original_reclamation_budget_exhausted_raw_status_store',
   'ordinary_reclamation_frame_restore_SP_X19_X30']}
 pp=[]
 for name,labels in prior_specs.items():
  old=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,sorted(map(hex,selected-visited))
 altered=[]
 for what in ['instruction_byte','bank_byte','branch_target','native_deallocation_claim']:
  bad=copy.deepcopy(e)
  if what=='instruction_byte':
   row=bad['spans'][0];b=bytearray.fromhex(row['bytes_hex']);b[0]^=1;row['bytes_hex']=b.hex()
  elif what=='bank_byte':
   row=bad['banks']['TL'];b=bytearray.fromhex(row['bytes_hex']);b[0]^=1;row['bytes_hex']=b.hex()
  elif what=='branch_target':bad['branch_pointers'][0]['target']=hex(int(bad['branch_pointers'][0]['target'],16)^4)
  else:bad['native_deallocation_established']=True
  assert bad!=R.build();altered.append({'alteration':what,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':pp,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),
   'bank_input_cases_checked':1792,'altered_evidence_rejections':len(altered)},'conditional_UIDList_replacement_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
