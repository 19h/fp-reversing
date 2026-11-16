#!/usr/bin/env python3
"""Prove query-specific lookup, list mutation, retirement and return cuts.
O(I+256R+query DAG) construction/space; SMT search separate, 30 s/query.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import DEC,WORD_BYTES,TOKEN,PHASE,SUCCESS,mask
from audit_userclient_record_publication import Model as PriorModel,KEY0,KEY1,MISS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_query_publication as R

class Model(PriorModel):
 def __init__(self,e):
  super().__init__(e);self.query_buffer,self.request_callback=z3.BitVecs('QP_query_buffer64 QP_request_callback64',64)
  self.peer_extents=z3.BitVecs('QP_previous_extent32 QP_next_extent32 QP_tail_extent32',32)
  self.peer_buffers=z3.BitVecs('QP_previous_buffer64 QP_next_buffer64 QP_tail_buffer64',64)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,4096),(self.src,16384),(self.object,16),(self.new_node,32),(self.query_buffer,14)]
  for yes,a,n in [(self.with_node,self.node,32),(self.with_previous,self.previous,32),
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
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('QP_bank_'+name,8)
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
  if self.pc in WORD_BYTES:
   assert n==1 and self.byte_pos<len(self.byte_offsets);j=self.byte_offsets[self.byte_pos];self.byte_pos+=1
   self.address_checks.append(a==self.buffer+j)
   return z3.Extract(31-8*j,24-8*j,self.node_tag^SUCCESS)^mask(a,resize(KEY0,64))
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('QP_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w25',TOKEN),('w1',PHASE),('w30',SUCCESS),
  ('x0',0x19),('x20',KEY1),('x26',KEY0),('x21',0xfffffe000792fcc0),('x28',0xfffffe0007949dd0),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018)]:v.seed(r,x)
 for o,x in [(0x348,v.ctx+0x50),(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),
  (0xa38,0xfffffe000ccc32f8),(0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),
  (0xa10,0xfffffe0007949fd0),(0xa18,0xfffffe000792ffc0),(0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0)]:mem(v,v.sp+o,8,x)
 for o,x in [(0x20,v.object),(0x58,v.new_node),(0x50,0),(0x260,0xfffffe000a664230),
  (0x5a8,v.request_callback)]:mem(v,v.ctx+o,8,x)
 mem(v,v.object,8,v.node);mem(v,v.object+8,8,v.tail)
 mem(v,v.node,8,v.next);mem(v,v.node+8,8,v.previous);mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.buffer)
 for peer,extent,buffer in zip([v.previous,v.next,v.tail],v.peer_extents,v.peer_buffers):
  mem(v,peer+0x10,4,extent);mem(v,peer+0x18,8,buffer)
 mem(v,v.new_node,8,0);mem(v,v.new_node+8,8,0);mem(v,v.new_node+0x10,4,14);mem(v,v.new_node+0x18,8,v.query_buffer)
 return v

def requested(e):
 v=setup(e);v.seed('x22',v.object);v.seed('w9',v.request_tag);v.seed('x10',v.ctx+0x50);v.seed('w8',0x6c)
 return v.run('search_entry')
def search(e):return requested(e).run('search_nonnull').run('search_node')
def result(e,success=True):
 v=setup(e);v.with_node=success;v.seed('w23',SUCCESS if success else MISS)
 mem(v,v.ctx+0x50,8,v.node if success else 0)
 if success:mem(v,v.object,8,v.head)
 v.seed('x21',0xfffffe000792fcc0);v.seed('x22',0xfffffe000847bce0);v.seed('w25',0x4d08a3fb)
 v.branch_choices={0xfffffe000a662b74:success};v.run('query_status_success')
 return v if success else v.run('query_status_miss')

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
 def pending(v):return z3.Or(cell(v,v.new_node+0x10,4)!=14,cell(v,v.new_node+0x18,8)!=v.query_buffer,
  cell(v,v.ctx+0x58,8)!=v.new_node,cell(v,v.ctx+0x260,8)!=0xfffffe000a664230,
  cell(v,v.ctx+0x5a8,8)!=v.request_callback)
 def returned(v):
  v.run('query_constructor_return').run('query_request_return');return v
 v=setup(e).run('query_output_root')
 prove('original_query_output_slot_producer_at_selected_context_frame_epoch',v,cell(v,v.sp+0x348,8)!=v.ctx+0x50)
 v=requested(e)
 prove('query_lookup_retains_callback6c_tag_and_exact_context_output_alias',v,z3.Or(
  cell(v,v.ctx+0xc8,8)!=0xfffffe000a662b64,cell(v,v.ctx+0x758,8)!=v.ctx+0x50,
  cell(v,v.src,4)!=v.request_tag,v.read('x8')!=0xfffffe000a662be0,pending(v)))
 v.run('search_nonnull').run('search_node')
 prove('query_search_first_node_exact_empty_or_header_decode_split',v,z3.Or(cell(v,v.ctx+0x2b0,8)!=v.node,
  v.read('w23')!=MISS,v.read('x9')!=z3.If(v.node==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))))
 d=copy.deepcopy(v);d.run('search_result').run('search_callback')
 prove('empty_query_search_publishes_null_miss_and_query_callback',d,z3.Or(cell(d,d.ctx+0x50,8)!=0,
  d.read('w23')!=MISS,d.read('x8')!=0xfffffe000a662b64,d.read('x22')!=0xfffffe000847bce0,d.read('w25')!=0x4d08a3fb),[d.node==0])
 v.with_node=v.with_buffer=True;v.run('node_decode_prepare').run('word_bridge').decode(range(4)).run('tag_match')
 prove('query_all_encoded_tags_exact_match_or_next_node_gate',v,v.read('x10')!=z3.If(v.node_tag==v.request_tag,
  resize(0xfffffe000a662c44,64),resize(0xfffffe000a63d680,64)))
 d=copy.deepcopy(v);d.run('search_next').run('search_node')
 prove('query_nonmatching_tag_follows_next_without_losing_query_callback',d,z3.Or(cell(d,d.ctx+0x2b0,8)!=d.next,
  d.read('x9')!=z3.If(d.next==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64)),
  cell(d,d.ctx+0xc8,8)!=0xfffffe000a662b64),[d.node_tag!=d.request_tag])
 v.run('search_result').run('search_callback')
 prove('query_matched_tag_publishes_old_node_success_and_query_callback',v,z3.Or(cell(v,v.ctx+0x50,8)!=v.node,
  v.read('w23')!=SUCCESS,v.read('x8')!=0xfffffe000a662b64,v.read('x22')!=0xfffffe000847bce0,
  v.read('w25')!=0x4d08a3fb,pending(v)),[v.node_tag==v.request_tag])
 for success in [False,True]:
  v=result(e,success)
  prove('query_status_'+('match' if success else 'miss')+'_exact_publication_branch',v,z3.BoolVal(v.direct_target!=(0xfffffe000a663d28 if success else None)))
 v=setup(e);v.seed('w23',v.status);v.branch_choices={0xfffffe000a662b84:True}
 v.run('query_status_success').run('query_status_miss').run('query_unexpected_status')
 prove('query_other_status_preserved_to_new_node_retirement_frontier',v,z3.Or(v.read('w23')!=v.status,
  v.read('x22')!=v.new_node,v.read('x8')!=0xfffffe000a664074),[v.status!=SUCCESS,v.status!=MISS])
 for tail_present in [False,True]:
  v=result(e,False);v.with_tail=tail_present
  prem=[v.tail!=0,v.node!=0,v.node!=v.new_node] if tail_present else [v.tail==0,v.node==0]
  v.run('query_append_prepare')
  prove('query_append_'+('tail' if tail_present else 'empty')+'_selects_exact_store_block',v,
   v.read('x12')!=(0xfffffe000a6654e0 if tail_present else 0xfffffe000a662bc4),prem)
  v.run('query_append_tail' if tail_present else 'query_append_empty')
  bad=[cell(v,v.object+8,8)!=v.new_node,cell(v,v.new_node,8)!=0,cell(v,v.new_node+8,8)!=(v.tail if tail_present else 0),
   v.read('w23')!=SUCCESS,v.read('x8')!=0xfffffe000a664218,pending(v)]
  if tail_present:bad.extend([cell(v,v.tail,8)!=v.new_node,cell(v,v.object,8)!=v.node,
   cell(v,v.tail+0x10,4)!=v.peer_extents[2],cell(v,v.tail+0x18,8)!=v.peer_buffers[2]])
  else:bad.append(cell(v,v.object,8)!=v.new_node)
  prove('query_append_'+('tail' if tail_present else 'empty')+'_publishes_new_record_with_success',v,z3.Or(*bad),prem)
  returned(v)
  prove('query_append_'+('tail' if tail_present else 'empty')+'_reaches_saved_request_callback',v,z3.Or(v.read('x8')!=v.request_callback,
   v.read('w23')!=SUCCESS,v.read('w21')!=PHASE,pending(v)),prem)
 for pp in [False,True]:
  for nn in [False,True]:
   name=('interior' if nn else 'tail') if pp else ('head' if nn else 'sole')
   v=result(e);v.with_previous=pp;v.with_next=nn
   prem=[v.previous!=0 if pp else v.previous==0,v.next!=0 if nn else v.next==0,
    z3.And(v.head!=0,v.head!=v.node) if pp else v.head==v.node,z3.And(v.tail!=0,v.tail!=v.node) if nn else v.tail==v.node]
   v.run('query_replace_prepare')
   prove('query_replace_'+name+'_copies_neighbors_and_selects_previous_update',v,z3.Or(
    cell(v,v.new_node,8)!=v.next,cell(v,v.new_node+8,8)!=v.previous,
    v.read('x12')!=(0xfffffe000a663d80 if pp else 0xfffffe000a663da4)),prem)
   if pp:v.run('query_replace_previous')
   v.run('query_replace_next_gate')
   prove('query_replace_'+name+'_selects_next_update_and_old_result_alias',v,z3.Or(v.read('x22')!=v.ctx+0x50,
    v.read('x12')!=(0xfffffe000a663dd8 if nn else 0xfffffe000a663dfc)),prem)
   if nn:v.run('query_replace_next')
   v.run('query_replace_head_gate')
   prove('query_replace_'+name+'_selects_head_update',v,v.read('x9')!=(0xfffffe000a663e50 if pp else 0xfffffe000a663e2c),prem)
   if not pp:v.run('query_replace_head')
   v.run('query_replace_tail_gate')
   prove('query_replace_'+name+'_selects_tail_update',v,v.read('x10')!=(0xfffffe000a663eb0 if nn else 0xfffffe000a663e94),prem)
   if not nn:v.run('query_replace_tail')
   def fields(u):
    out=[cell(u,u.new_node,8)!=u.next,cell(u,u.new_node+8,8)!=u.previous,
     cell(u,u.object,8)!=(u.head if pp else u.new_node),cell(u,u.object+8,8)!=(u.tail if nn else u.new_node),pending(u)]
    if pp:out.extend([cell(u,u.previous,8)!=u.new_node,cell(u,u.previous+0x10,4)!=u.peer_extents[0],cell(u,u.previous+0x18,8)!=u.peer_buffers[0]])
    if nn:out.extend([cell(u,u.next+8,8)!=u.new_node,cell(u,u.next+0x10,4)!=u.peer_extents[1],cell(u,u.next+0x18,8)!=u.peer_buffers[1]])
    return out
   prove('query_replace_'+name+'_exact_surviving_list_fields_before_retirement',v,z3.Or(*fields(v)),prem)
   v.run('query_retire_gate')
   prove('query_replace_'+name+'_nullable_old_data_retirement_split',v,z3.Or(v.read('x1')!=v.node,v.read('x0')!=v.buffer,
    v.read('x8')!=z3.If(v.buffer==0,resize(0xfffffe000a663f78,64),resize(0xfffffe000a663ef0,64))),prem)
   nil=copy.deepcopy(v)
   for has_buffer,u in [(False,nil),(True,v)]:
    p=[*prem,u.buffer!=0 if has_buffer else u.buffer==0];suffix='_data' if has_buffer else '_null_data'
    if has_buffer:
     u.run('query_retire_data_request')
     prove('query_replace_'+name+'_requests_original_IOFreeData_old_extent',u,z3.Or(u.read('x0')!=u.buffer,u.read('x1')!=z3.ZeroExt(32,u.extent),
      u.read('x8')!=0xfffffe000c4ba84c,u.read('x17')!=0x85d),p)
     u.returned().run('query_retire_data_return')
     prove('query_replace_'+name+'_data_return_clears_old_buffer_and_selects_typed_retirement',u,z3.Or(cell(u,u.node+0x18,8)!=0,
      u.read('x1')!=u.node,u.read('x8')!=0xfffffe000a663f78),p)
    u.run('query_retire_node_request')
    prove('query_replace_'+name+suffix+'_requests_original_IOFreeTypeImpl_old_node',u,z3.Or(u.read('x0')!=0xfffffe000847c2a0,
     u.read('x1')!=u.node,u.read('x10')!=0xfffffe000c4ba368,u.read('x17')!=0x4d6a),p)
    u.returned().run('query_retire_node_return')
    prove('query_replace_'+name+suffix+'_clears_old_result_and_selects_constructor_return',u,z3.Or(cell(u,u.ctx+0x50,8)!=0,
     u.read('w23')!=SUCCESS,u.read('x8')!=0xfffffe000a664218,*fields(u)),p)
    returned(u)
    prove('query_replace_'+name+suffix+'_reaches_saved_request_callback_with_success',u,z3.Or(u.read('x8')!=u.request_callback,
     u.read('w23')!=SUCCESS,*fields(u)),p)
 # The saved request callback is not universally the first callback.
 for callback in [0xfffffe000a656f8c,0xfffffe000a657018,0xfffffe000a65f358]:
  v=setup(e);mem(v,v.ctx+0x5a8,8,callback);v.seed('w23',v.status);returned(v)
  prove('query_saved_callback_'+format(callback,'x')+'_retains_arbitrary_raw_status',v,z3.Or(v.read('x8')!=callback,
   v.read('w23')!=v.status,v.read('w3')!=TOKEN,v.read('w10')!=TOKEN))
 selected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']};excluded=set(R.RETAGS.values())
 assert selected-excluded<=visited and not excluded&visited,sorted(map(hex,selected-excluded-visited))
 prior=[]
 for name,labels in [('userclient_query_writer_audit.json',[
  'first_complete_fourteen_protected_record_bytes_and_publication_continuation',
  'second_complete_fourteen_protected_record_bytes_and_publication_continuation',
  'third_complete_fourteen_protected_record_bytes_and_publication_continuation',
  'first_lookup_entry_uses_w8_callback6c_and_retains_output_tag_pending_node']),
  ('userclient_record_publication_audit.json',['all_stored_tag32_and_requested_tag32_exact_match_or_successor_gate']),
  ('userclient_serializer_extent_audit.json',['size_phase_exact_positive_padding_and_wide_overhead',
   'exact_largest_accepted_sum_and_allocation_extent_bounds','source_composed_success_consumer_admits_only_exact_allocated_extent']),
  ('userclient_query_records_audit.json',['first_callback_uses_same_success_constant_and_exact_status_split',
   'second_callback_uses_same_success_constant_and_exact_status_split','third_callback_uses_same_success_constant_and_exact_status_split',
   'third_success_passes_container_and_auxiliary_output_aliases_to_next_facility'])]:
  old=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   prior.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 # Finite-list congruence lemmas are separate from instruction-source queries.
 composition=[]
 def compose(label,premises,bad):
  s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(bad);assert s.check()==z3.unsat,(label,s.reason_unknown())
  composition.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2()})
 tag=z3.Function('QP_tag_of_node',z3.BitVecSort(64),z3.BitVecSort(32));o,j,k=z3.BitVecs('QP_seq_old64 QP_seq_new64 QP_seq_prior64',64)
 target,prior_tag=z3.BitVecs('QP_seq_target32 QP_seq_prior_tag32',32)
 compose('different_tag_match_cannot_retire_previous_new_node',[tag(o)==target,tag(k)==prior_tag,target!=prior_tag],o==k)
 seq=z3.SeqSort(z3.BitVecSort(64));prefix,suffix=z3.Consts('QP_seq_prefix QP_seq_suffix',seq)
 before=z3.Concat(prefix,z3.Unit(o),suffix);after=z3.Concat(prefix,z3.Unit(j),suffix)
 compose('finite_replacement_retains_every_other_node_and_contains_new_node',[o!=k,z3.Contains(before,z3.Unit(k))],
  z3.Or(z3.Not(z3.Contains(after,z3.Unit(k))),z3.Not(z3.Contains(after,z3.Unit(j))),z3.Length(after)!=z3.Length(before)))
 after=z3.Concat(prefix,z3.Unit(j))
 compose('finite_append_retains_all_nodes_and_contains_new_node',[z3.Contains(prefix,z3.Unit(k))],
  z3.Or(z3.Not(z3.Contains(after,z3.Unit(k))),z3.Not(z3.Contains(after,z3.Unit(j))),z3.Length(after)!=z3.Length(prefix)+1))
 remaining,original_length=z3.Ints('QP_other_node_byte_sum QP_original_low32_length');length=42+remaining;padding=16-((length+10)%16);extent=length+10+padding
 compose('three_retained_fourteen_byte_records_imply_padded_extent_at_least_sixty_four',
  [remaining>=0,length<=0xffffffe5,original_length==extent],
  z3.Or(extent<64,original_length<64,z3.And(remaining==0,z3.Or(padding!=12,extent!=64))))
 # Change the empty-append head operand: the same source model must refute head=J.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='query_append_empty');b=bytearray.fromhex(row['bytes_hex'])
 word=int.from_bytes(b[:4],'little');b[:4]=(word^1).to_bytes(4,'little');row['bytes_hex']=b.hex()
 v=result(changed,False);v.run('query_append_prepare').run('query_append_empty');s=z3.Solver();s.set(timeout=30000)
 s.add(*v.owned(),*v.branch_guards,v.tail==0,v.node==0,cell(v,v.object,8)!=v.new_node);assert s.check()==z3.sat
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':prior,'composition_proofs':composition,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_proved_instructions':len(selected-excluded),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'excluded_retag_instructions':len(excluded),'bank_composition_input_cases':1024,'new_composition_queries_unsat':len(composition),'append_cases':2,
   'replacement_positions':4,'replacement_data_cases':8,'saved_request_callback_cases':3,'altered_append_store_counterexample':True},
  'conditional_query_publication_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
