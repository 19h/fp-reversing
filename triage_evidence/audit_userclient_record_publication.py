#!/usr/bin/env python3
"""Conditional lookup/list stores and retirement-call source obligations.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import Model as ReaderModel,DEC,WORD_BYTES,TOKEN,PHASE,SUCCESS,mask
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_record_publication as R

KEY0=0x02e859d27e491464
KEY1=0x4dae26df20976138
MISS=0xce515bda

class Model(ReaderModel):
 def __init__(self,e):
  super().__init__(e)
  self.new_node,self.previous,self.tail,self.head,self.cursor=z3.BitVecs('RP_new_node64 RP_previous64 RP_tail64 RP_head64 RP_cursor64',64)
  self.request_tag,self.node_tag,self.outer_length=z3.BitVecs('RP_request_tag32 RP_node_tag32 RP_outer_length32',32)
  self.with_new=True;self.with_previous=False;self.with_next=False;self.with_tail=False
  self.table_pcs=set()
  for row in e['spans']:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if i.mnemonic=='ldr' and i.reg_name(i.operands[0].reg).startswith('x') and i.operands[1].type==ARM64_OP_MEM and i.operands[1].mem.index:
     if i.reg_name(i.operands[1].mem.base) in ['x7','x21']:self.table_pcs.add(i.address)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000),(self.object,16)]
  for yes,a,n in [(self.with_new,self.new_node,32),(self.with_node,self.node,32),(self.with_previous,self.previous,32),
   (self.with_next,self.next,32),(self.with_tail,self.tail,32),(self.with_buffer,self.buffer,4)]:
   if yes:spans.append((a,n))
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
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('RP_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in self.table_pcs:
   assert n==8;js=R.BRANCHES[self.pc]
   self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc in WORD_BYTES:
   assert n==1 and self.byte_pos<len(self.byte_offsets);j=self.byte_offsets[self.byte_pos];self.byte_pos+=1
   self.address_checks.append(a==self.buffer+j)
   return z3.Extract(31-8*j,24-8*j,self.node_tag^SUCCESS)^mask(a,resize(KEY0,64))
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('RP_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)
 def returned(self):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('RP_call_'+str(self.count)+'_X'+str(j),64))
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w25',TOKEN),('w1',PHASE),('w30',SUCCESS),
  ('x0',KEY1),('x26',KEY0),('x21',TABLE),('x28',0xfffffe0007949dd0),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018)]:v.seed(r,x)
 for o,x in [(0x350,v.ctx+0x628),(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),
  (0xa38,0xfffffe000ccc32f8),(0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),
  (0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0),(0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0),
  (0xa80,v.cursor)]:mem(v,v.sp+o,8,x)
 for o,x in [(0x780,v.object),(0x6b8,v.new_node),(0x628,0)]:mem(v,v.ctx+o,8,x)
 mem(v,v.src+0x128,4,v.request_tag);mem(v,v.src+0xc8c,4,v.outer_length^SUCCESS)
 mem(v,v.object,8,v.node);mem(v,v.object+8,8,v.tail)
 mem(v,v.node,8,v.next);mem(v,v.node+8,8,v.previous);mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.buffer)
 mem(v,v.new_node,8,0);mem(v,v.new_node+8,8,0)
 return v

def requested(e):return setup(e).run('publication_request').run('search_entry')
def search(e):return requested(e).run('search_nonnull').run('search_node')
def matched(e):
 v=search(e);v.with_node=v.with_buffer=True
 return v.run('node_decode_prepare').run('word_bridge').decode(range(4)).run('tag_match').run('search_result').run('search_callback')

def result(e,success=True):
 v=setup(e);v.with_node=success
 v.seed('x21',0xfffffe000792fcc0);v.seed('x22',0xfffffe000847bce0);v.seed('w25',0x4d08a3fb)
 if success:mem(v,v.object,8,v.head)
 mem(v,v.ctx+0x628,8,v.node if success else 0);v.seed('w23',SUCCESS if success else MISS)
 v.branch_choices={0xfffffe000a66249c:success};v.run('status_success_gate')
 return v if success else v.run('status_miss_gate')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check()
  assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited)
  print(label,flush=True)
 def cursor_bad(v):return z3.Or(cell(v,v.sp+0xa80,8)!=v.cursor,v.read('x12')!=z3.If(
  z3.ULT(v.cursor,z3.ZeroExt(32,v.outer_length)),resize(0xfffffe000a6421dc,64),resize(0xfffffe000a642180,64)))
 v=setup(e);v.seed('x21',0xfffffe000792fcc0);v.seed('x10',0xfffffe00079391f0)
 v.run('output_root').run('saved_lookup_roots').run('saved_typed_root')
 prove('original_output_alias_and_retained_lookup_typed_bank_roots',v,z3.Or(cell(v,v.sp+0x350,8)!=v.ctx+0x628,
  cell(v,v.sp+0xa00,8)!=0xfffffe000792fcc0,cell(v,v.sp+0xa20,8)!=0xfffffe00079391f0,
  cell(v,v.sp+0xa48,8)!=0xfffffe0007949dd0))
 v=setup(e).run('publication_request')
 prove('post_copy_requests_tag_lookup_with_caller_specific_output_and_continuation',v,z3.Or(cell(v,v.ctx+0x628,8)!=0,
  v.read('x22')!=v.object,v.read('w9')!=v.request_tag,v.read('x10')!=v.ctx+0x628,v.read('w8')!=0x7b,
  v.read('x11')!=0xfffffe000a662ab4,v.read('w1')!=PHASE,v.read('w3')!=TOKEN,v.read('w30')!=SUCCESS,
  v.read('x20')!=KEY1,v.read('x21')!=0xfffffe000792fcc0,v.read('x28')!=0xfffffe0007949dd0))
 v.run('search_entry')
 prove('shared_lookup_retains_new_return_tag_and_output_and_selects_nonnull_container',v,z3.Or(
  cell(v,v.ctx+0xc8,8)!=0xfffffe000a66248c,cell(v,v.ctx+0x758,8)!=v.ctx+0x628,
  cell(v,v.src,4)!=v.request_tag,v.read('x8')!=0xfffffe000a662be0))
 v.run('search_nonnull').run('search_node')
 prove('all_first_node64_empty_or_protected_tag_decode_gate',v,z3.Or(cell(v,v.ctx+0x2b0,8)!=v.node,
  v.read('w23')!=MISS,v.read('x9')!=z3.If(v.node==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))))
 empty=copy.deepcopy(v);empty.run('search_result').run('search_callback')
 prove('empty_container_lookup_returns_miss_zero_result_and_original_retirement_descriptor',empty,z3.Or(
  cell(empty,empty.ctx+0x628,8)!=0,empty.read('w23')!=MISS,empty.read('x8')!=0xfffffe000a66248c,
  empty.read('x22')!=0xfffffe000847bce0,empty.read('w25')!=0x4d08a3fb),[empty.node==0])
 v.with_node=v.with_buffer=True;v.run('node_decode_prepare').run('word_bridge').decode(range(4)).run('tag_match')
 prove('all_stored_tag32_and_requested_tag32_exact_match_or_successor_gate',v,z3.Or(v.read('x22')!=v.node,
  v.read('x10')!=z3.If(v.node_tag==v.request_tag,resize(0xfffffe000a662c44,64),resize(0xfffffe000a63d680,64))))
 nxt=copy.deepcopy(v);nxt.run('search_next').run('search_node')
 prove('nonmatching_node_follows_next_and_repeats_empty_or_decode_gate',nxt,z3.Or(cell(nxt,nxt.ctx+0x2b0,8)!=nxt.next,
  nxt.read('x9')!=z3.If(nxt.next==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))),[nxt.node_tag!=nxt.request_tag])
 v.run('search_result').run('search_callback')
 prove('matching_node_publishes_old_result_success_and_retirement_descriptor_to_caller',v,z3.Or(cell(v,v.ctx+0x628,8)!=v.node,
  v.read('w23')!=SUCCESS,v.read('x8')!=0xfffffe000a66248c,v.read('x22')!=0xfffffe000847bce0,
  v.read('w25')!=0x4d08a3fb),[v.node_tag==v.request_tag])
 for success in [False,True]:
  v=result(e,success)
  prove('raw_lookup_'+('success_selects_replacement' if success else 'miss_selects_append'),v,
   z3.BoolVal(v.direct_target!=(0xfffffe000a662538 if success else None)))
 v=setup(e);v.seed('w23',v.status);v.branch_choices={0xfffffe000a6624ac:True}
 v.run('status_success_gate').run('status_miss_gate').run('unexpected_lookup_status')
 prove('all_other_lookup_status32_selects_new_node_cleanup_frontier',v,z3.Or(cell(v,v.sp+0x50,8)!=v.new_node,
  v.read('x8')!=0xfffffe000a6622bc,v.read('w23')!=v.status),[v.status!=SUCCESS,v.status!=MISS])
 for tail_present in [False,True]:
  v=result(e,False);v.with_tail=tail_present
  v.run('append_prepare');prem=[v.tail!=0,v.node!=0,v.node!=v.new_node] if tail_present else [v.tail==0,v.node==0]
  prove('append_'+('tail' if tail_present else 'empty')+'_exact_selected_branch',v,v.read('x13')!=(0xfffffe000a6624f4 if tail_present else 0xfffffe000a66286c),prem)
  v.run('append_tail' if tail_present else 'append_empty')
  bad=[cell(v,v.object+8,8)!=v.new_node,cell(v,v.new_node,8)!=0,
   cell(v,v.new_node+8,8)!=(v.tail if tail_present else 0),v.read('x8')!=0xfffffe000a642138]
  if tail_present:bad.extend([cell(v,v.tail,8)!=v.new_node,cell(v,v.object,8)!=v.node])
  else:bad.append(cell(v,v.object,8)!=v.new_node)
  prove('append_'+('tail' if tail_present else 'empty')+'_publishes_new_node_exact_list_fields',v,z3.Or(*bad),prem)
  v.run('parser_cursor_gate');prove('append_'+('tail' if tail_present else 'empty')+'_returns_unchanged_cursor_to_exact_parser_gate',v,cursor_bad(v),prem)
 for previous_present in [False,True]:
  for next_present in [False,True]:
   name=('interior' if next_present else 'tail') if previous_present else ('head' if next_present else 'sole')
   v=result(e);v.with_previous=previous_present;v.with_next=next_present
   prem=[v.previous!=0 if previous_present else v.previous==0,v.next!=0 if next_present else v.next==0,
    z3.And(v.head!=0,v.head!=v.node) if previous_present else v.head==v.node,
    z3.And(v.tail!=0,v.tail!=v.node) if next_present else v.tail==v.node]
   v.run('replace_prepare')
   prove('replace_'+name+'_copies_old_neighbors_and_selects_previous_update',v,z3.Or(
    cell(v,v.new_node,8)!=v.next,cell(v,v.new_node+8,8)!=v.previous,
    v.read('x13')!=(0xfffffe000a662584 if previous_present else 0xfffffe000a6625a0)),prem)
   if previous_present:v.run('replace_previous')
   v.run('replace_next_gate')
   prove('replace_'+name+'_selects_next_update_and_retains_old_result_alias',v,z3.Or(v.read('x23')!=v.ctx+0x628,
    v.read('x9')!=(0xfffffe000a6625d0 if next_present else 0xfffffe000a6625f4)),prem)
   if next_present:v.run('replace_next')
   v.run('replace_head_gate')
   prove('replace_'+name+'_selects_head_update',v,v.read('x11')!=(0xfffffe000a662654 if previous_present else 0xfffffe000a662634),prem)
   if not previous_present:v.run('replace_head')
   v.run('replace_tail_gate')
   prove('replace_'+name+'_selects_tail_update',v,v.read('x11')!=(0xfffffe000a6626a8 if next_present else 0xfffffe000a662684),prem)
   if not next_present:v.run('replace_tail')
   fields=[cell(v,v.new_node,8)!=v.next,cell(v,v.new_node+8,8)!=v.previous,
    cell(v,v.object,8)!=(v.head if previous_present else v.new_node),
    cell(v,v.object+8,8)!=(v.tail if next_present else v.new_node)]
   if previous_present:fields.append(cell(v,v.previous,8)!=v.new_node)
   if next_present:fields.append(cell(v,v.next+8,8)!=v.new_node)
   prove('replace_'+name+'_rewires_exact_surviving_list_fields_before_retirement',v,z3.Or(*fields),prem)
   v.run('retire_gate')
   prove('replace_'+name+'_all_old_buffer64_exact_nullable_retirement_gate',v,z3.Or(v.read('x1')!=v.node,
    v.read('x0')!=v.buffer,v.read('x8')!=z3.If(v.buffer==0,resize(0xfffffe000a66278c,64),resize(0xfffffe000a662700,64))),prem)
   nil=copy.deepcopy(v)
   for has_buffer,u in [(False,nil),(True,v)]:
    pp=[*prem,u.buffer!=0 if has_buffer else u.buffer==0];suffix='_buffer' if has_buffer else '_null_buffer'
    if has_buffer:
     u.run('retire_data_request')
     prove('replace_'+name+'_requests_original_IOFreeData_with_old_extent',u,z3.Or(u.read('x0')!=u.buffer,
      u.read('x1')!=z3.ZeroExt(32,u.extent),u.read('x8')!=0xfffffe000c4ba84c,u.read('x17')!=0x85d),pp)
     u.returned().run('retire_data_return')
     prove('replace_'+name+'_data_return_clears_old_buffer_field_and_selects_typed_retirement',u,z3.Or(
      cell(u,u.node+0x18,8)!=0,u.read('x1')!=u.node,u.read('x8')!=0xfffffe000a66278c),pp)
    u.run('retire_node_request')
    prove('replace_'+name+suffix+'_requests_original_IOFreeTypeImpl_descriptor_and_old_node',u,z3.Or(u.read('x0')!=0xfffffe000847bce0,
     u.read('x1')!=u.node,u.read('x8')!=0xfffffe000c4ba368,u.read('x17')!=0x4d6a),pp)
    u.returned().run('retire_node_return').run('parser_cursor_gate')
    prove('replace_'+name+suffix+'_clears_old_result_and_returns_unchanged_cursor',u,z3.Or(cell(u,u.ctx+0x628,8)!=0,
     cell(u,u.new_node,8)!=u.next,cell(u,u.new_node+8,8)!=u.previous,
     cell(u,u.object,8)!=(u.head if previous_present else u.new_node),cell(u,u.object+8,8)!=(u.tail if next_present else u.new_node),
     cursor_bad(u)),pp)
 for pc in R.RETAGS.values():
  row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16)
  b=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(b,pc));reg=i.reg_name(i.operands[0].reg)
  v=setup(e);v.seed(reg,v.result);v.e=v.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':b.hex()}]};v.run('alternate')
  prove('alternate_lookup_retag_'+format(pc,'x')+'_bit_transform_only',v,v.read(reg)!=((v.result&0xffffffffffff)|(0xc8a2<<48)))
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,{'missing':sorted(map(hex,selected-visited))}
 pp=[]
 for name,labels in [('userclient_record_writer_audit.json',['complete_ten_byte_header_preserves_node_extent_buffer_and_metadata',
  'every_valid_payload_counter64_source_byte8_exact_protected_rebase_and_exit_backedge','finite_payload_reverse_indices_cover_exactly_L_bytes']),
  ('userclient_input_reader_audit.json',['all_decoded_tag32_exact_match_or_next_gate','matched_node_output_and_search_callback_select_header_reader'])]:
  prior=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in prior['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']))
   assert s.check()==z3.unsat;pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 altered=[]
 for label in ['instruction_byte','retirement_descriptor_size','bank_constant','native_ownership_claim']:
  bad=copy.deepcopy(e)
  if label=='instruction_byte':
   b=bytearray.fromhex(bad['spans'][0]['bytes_hex']);b[0]^=1;bad['spans'][0]['bytes_hex']=b.hex()
  elif label=='retirement_descriptor_size':bad['retirement_descriptor']['size_bytes']=16
  elif label=='bank_constant':bad['bank_rules'][0]['constant']=hex(int(bad['bank_rules'][0]['constant'],16)^1)
  else:bad['native_ownership_established']=True
  assert bad!=R.build();altered.append({'alteration':label,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':pp,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),'distinct_proved_instructions':len(visited),
   'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),'bank_composition_input_cases':768,
   'replacement_positions':4,'retirement_buffer_cases':8,'append_cases':2,'altered_evidence_rejections':len(altered)},
  'conditional_record_publication_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
