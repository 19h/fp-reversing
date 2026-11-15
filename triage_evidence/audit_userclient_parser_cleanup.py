#!/usr/bin/env python3
"""Conditional failure output, container/list and pending-node retirement audit.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,TABLE,POOL,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import Model as ReaderModel,DEC,TOKEN,PHASE,SUCCESS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_parser_cleanup as R

class Model(ReaderModel):
 def __init__(self,e):
  super().__init__(e)
  self.pending,self.pending_buffer,self.cursor=z3.BitVecs('PC_pending64 PC_pending_buffer64 PC_cursor64',64)
  self.pending_extent=z3.BitVec('PC_pending_extent32',32)
  self.with_container=True;self.with_pending=False
  self.table_pcs=set()
  for s in e['spans']:
   for i in DEC.disasm(bytes.fromhex(s['bytes_hex']),int(s['start'],16)):
    if i.mnemonic=='ldr' and i.reg_name(i.operands[0].reg).startswith('x') and i.operands[1].type==ARM64_OP_MEM and i.operands[1].mem.index:
     if i.reg_name(i.operands[1].mem.base) in ['x7','x21']:self.table_pcs.add(i.address)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000)]
  if self.with_container:spans.append((self.object,16))
  if self.with_node:spans.append((self.node,32))
  if self.with_pending:spans.append((self.pending,32))
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
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('PC_bank_'+name,8)
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
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('PC_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)
 def returned(self):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('PC_call_'+str(self.count)+'_X'+str(j),64))
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('x21',0xfffffe000792fcc0),('w3',TOKEN),('w25',TOKEN),
  ('w1',PHASE),('w30',SUCCESS),('w14',PHASE),('w24',0x50),('w27',0x37),('w23',v.status),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018),('x28',0xfffffe0007949dd0)]:v.seed(r,x)
 for o,x in [(0x5f8,v.ctx+0x4e8),(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),
  (0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0x9f8,0xfffffe0007949ed0),(0x9f0,0xfffffe000792fec0),
  (0xa10,0xfffffe0007949fd0),(0xa18,0xfffffe000792ffc0),
  (0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),
  (0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0),
  (0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0),
  (0x860,0xfffffe000847b6a0),(0x50,v.pending),(0xa80,v.cursor)]:mem(v,v.sp+o,8,x)
 mem(v,v.ctx+0x228,8,v.object);mem(v,v.ctx+0x188,8,v.ctx+0x600)
 mem(v,v.ctx+0x5c8,8,0xfffffe000a656c08);mem(v,v.ctx+0x600,8,z3.BitVec('PC_initial_output64',64))
 mem(v,v.sp+0x9ec,4,v.status)
 mem(v,v.object,8,v.node);mem(v,v.object+8,8,z3.BitVec('PC_initial_tail64',64))
 mem(v,v.node,8,v.next);mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.buffer)
 mem(v,v.pending+0x10,4,v.pending_extent);mem(v,v.pending+0x18,8,v.pending_buffer)
 return v

def destroy(e):return setup(e).run('failure_prepare').run('failure_bridge').run('destroy_entry').run('destroy_object').run('destroy_head')
def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('cleanup_cell_root').run('retained_node_key')
 prove('original_cleanup_cell_alias_and_retained_node_bank_key',v,z3.Or(cell(v,v.sp+0x5f8,8)!=v.ctx+0x4e8,v.read('w27')!=0x37))
 v=setup(e);u=z3.BitVec('PC_pending_descriptor_input32',32)
 for r,x in [('x21',0xfffffe0007949dd0),('x22',0xfffffe000792fbc0),('x28',POOL),('w10',u)]:v.seed(r,x)
 v.run('pending_descriptor_index').run('pending_descriptor_producer')
 prove('original_pending_descriptor_bank_producer_and_saved_cell',v,cell(v,v.sp+0x860,8)!=0xfffffe000847b6a0)
 v=setup(e).run('failure_prepare').run('failure_bridge')
 prove('arbitrary_failure_status_and_retained_container_request_shared_destructor',v,z3.Or(
  cell(v,v.src+0xc10,4)!=v.status,cell(v,v.ctx+0x4e8,8)!=v.object,v.read('x19')!=v.ctx+0x4e8,
  v.read('x8')!=0xfffffe000a660468,v.read('w9')!=0xafb,v.read('w25')!=TOKEN))
 v.run('destroy_entry').run('destroy_object').run('destroy_head')
 prove('nonnull_container_exact_empty_or_first_node_destructor_gate',v,z3.Or(v.read('x22')!=v.object,v.read('x23')!=v.node,
  v.read('x8')!=z3.If(v.node==0,resize(0xfffffe000a660534,64),resize(0xfffffe000a660750,64)),
  cell(v,v.ctx+0x368,8)!=0xfffffe000a660a98))
 empty=copy.deepcopy(v);empty.run('container_request')
 prove('empty_container_requests_original_typed_retirement_with_distinct_descriptor',empty,z3.Or(
  empty.read('x0')!=0xfffffe000847bde0,empty.read('x1')!=empty.object,empty.read('x10')!=0xfffffe000c4ba368),[empty.node==0])
 empty.returned().run('container_return').run('destroy_resume').run('failure_return').run('parser_output').run('parser_resume')
 prove('empty_container_failure_clears_cell_and_output_retains_status_and_resumes',empty,z3.Or(
  cell(empty,empty.ctx+0x4e8,8)!=0,cell(empty,empty.ctx+0x228,8)!=0,cell(empty,empty.ctx+0x600,8)!=0,
  empty.read('w23')!=empty.status,empty.read('x8')!=0xfffffe000a656c08,cell(empty,empty.sp+0xa80,8)!=empty.cursor),[empty.node==0])
 nil=setup(e);nil.with_container=False
 nil.run('failure_prepare').run('failure_bridge').run('destroy_entry').run('destroy_object')
 prove('null_container_selects_destructor_resume_without_typed_retirement_request',nil,z3.Or(
  nil.read('x22')!=0,nil.read('x10')!=0xfffffe000a660614,nil.read('x8')!=0xfffffe000a660a98),[nil.object==0])
 nil.run('destroy_resume').run('failure_return').run('parser_output').run('parser_resume')
 prove('null_container_failure_publishes_null_and_preserves_arbitrary_saved_status',nil,z3.Or(
  cell(nil,nil.ctx+0x228,8)!=0,cell(nil,nil.ctx+0x600,8)!=0,nil.read('w23')!=nil.status,
  nil.read('x8')!=0xfffffe000a656c08,cell(nil,nil.sp+0xa80,8)!=nil.cursor),[nil.object==0])
 for has_buffer in [False,True]:
  v=destroy(e);v.with_node=True;v.run('node_gate');prem=[v.buffer!=0 if has_buffer else v.buffer==0]
  prove('list_node_'+('buffer' if has_buffer else 'null_buffer')+'_saves_successor_and_selects_retirement',v,z3.Or(
   v.read('x25')!=v.next,v.read('x0')!=v.buffer,v.read('x8')!=(0xfffffe000a660790 if has_buffer else 0xfffffe000a66066c)),prem)
  if has_buffer:
   v.run('node_data_request');prove('list_node_requests_original_data_retirement_with_extent32',v,z3.Or(
    v.read('x0')!=v.buffer,v.read('x1')!=z3.ZeroExt(32,v.extent),v.read('x8')!=0xfffffe000c4ba84c),prem)
   v.returned().run('node_data_return');prove('list_node_data_return_clears_buffer_and_preserves_successor',v,z3.Or(
    cell(v,v.node+0x18,8)!=0,v.read('x25')!=v.next,v.read('x8')!=0xfffffe000a66066c),prem)
  v.run('node_type_request');prove('list_node_'+('buffer' if has_buffer else 'null_buffer')+'_requests_original_typed_retirement',v,z3.Or(
   v.read('x0')!=0xfffffe000847be20,v.read('x1')!=v.node,v.read('x10')!=0xfffffe000c4ba368,v.read('x25')!=v.next),prem)
  v.returned().run('node_type_return');prove('list_node_'+('buffer' if has_buffer else 'null_buffer')+'_returns_exact_successor_or_container_gate',v,z3.Or(
   v.read('x23')!=v.next,v.read('x8')!=z3.If(v.next==0,resize(0xfffffe000a660534,64),resize(0xfffffe000a660750,64))),prem)
  tail=copy.deepcopy(v);tail.run('container_request')
  prove('last_list_node_'+('buffer' if has_buffer else 'null_buffer')+'_requests_retained_container_retirement',tail,z3.Or(
   tail.read('x0')!=0xfffffe000847bde0,tail.read('x1')!=tail.object,tail.read('x10')!=0xfffffe000c4ba368),prem+[tail.next==0])
  tail.returned().run('container_return').run('destroy_resume').run('failure_return').run('parser_output').run('parser_resume')
  prove('last_list_node_'+('buffer' if has_buffer else 'null_buffer')+'_failure_clears_output_and_restores_saved_status',tail,z3.Or(
   cell(tail,tail.ctx+0x4e8,8)!=0,cell(tail,tail.ctx+0x228,8)!=0,cell(tail,tail.ctx+0x600,8)!=0,
   tail.read('w23')!=tail.status,tail.read('x8')!=0xfffffe000a656c08,cell(tail,tail.sp+0xa80,8)!=tail.cursor),prem+[tail.next==0])
 for has_buffer in [False,True]:
  v=setup(e);v.with_pending=True;v.seed('x21',TABLE);v.run('pending_gate')
  prem=[v.pending_buffer!=0 if has_buffer else v.pending_buffer==0]
  prove('valid_pending_node_'+('buffer' if has_buffer else 'null_buffer')+'_retirement_gate',v,z3.Or(
   v.read('x25')!=v.pending,v.read('x0')!=v.pending_buffer,
   v.read('x8')!=(0xfffffe000a662310 if has_buffer else 0xfffffe000a662394)),prem)
  if has_buffer:
   v.run('pending_data_request');prove('pending_node_requests_original_data_free_extent32',v,z3.Or(
    v.read('x0')!=v.pending_buffer,v.read('x1')!=z3.ZeroExt(32,v.pending_extent),v.read('x8')!=0xfffffe000c4ba84c),prem)
   v.returned().run('pending_data_return');prove('pending_data_return_clears_buffer_before_typed_retirement',v,z3.Or(
    cell(v,v.pending+0x18,8)!=0,v.read('x8')!=0xfffffe000a662394),prem)
  v.run('pending_type_request');prove('pending_node_'+('buffer' if has_buffer else 'null_buffer')+'_requests_saved_original_typed_descriptor',v,z3.Or(
   v.read('x0')!=0xfffffe000847b6a0,v.read('x1')!=v.pending,v.read('x8')!=0xfffffe000c4ba368),prem)
  v.returned().run('pending_type_return');prove('pending_node_'+('buffer' if has_buffer else 'null_buffer')+'_return_selects_container_failure_and_preserves_status',v,z3.Or(
   v.read('x8')!=0xfffffe000a662440,v.read('w24')!=0x50,v.read('w23')!=v.status,
   v.read('x21')!=0xfffffe000792fcc0),prem)
  v.run('failure_prepare').run('failure_bridge');prove('pending_node_'+('buffer' if has_buffer else 'null_buffer')+'_chains_saved_status_to_container_destructor',v,z3.Or(
   cell(v,v.src+0xc10,4)!=v.status,cell(v,v.ctx+0x4e8,8)!=v.object,v.read('x8')!=0xfffffe000a660468),prem)
 v=setup(e);v.with_pending=True
 for r,x in [('x27',v.pending),('x0',0),('x21',TABLE),('w20',0x766)]:v.seed(r,x)
 v.run('pending_buffer_result').run('pending_gate')
 prove('nonnull_new_node_with_null_data_result_enters_valid_null_buffer_cleanup',v,z3.Or(
  cell(v,v.sp+0x50,8)!=v.pending,cell(v,v.pending+0x18,8)!=0,v.read('w23')!=v.status,
  v.read('x25')!=v.pending,v.read('x8')!=0xfffffe000a662394,v.read('w27')!=0x37))
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']}
 assert visited==selected,{'missing':sorted(map(hex,selected-visited)),'extra':sorted(map(hex,visited-selected))}
 rechecked=[]
 for f,label in [
  ('userclient_container_staging_audit.json','shared_parser_entry_retains_output_continuation_input_and_encoded_extent'),
  ('userclient_record_metadata_audit.json','short_header_reaches_failure_frontier_without_cursor_advance'),
  ('userclient_record_metadata_audit.json','oversized_body_retains_candidate_but_rejects_without_committing_cursor'),
  ('userclient_record_nodes_audit.json','all_buffer_result64_retained_field_and_exact_nullable_gate'),
  ('userclient_record_nodes_audit.json','null_node_result_joins_common_allocation_failure_target'),
  ('userclient_record_publication_audit.json','all_other_lookup_status32_selects_new_node_cleanup_frontier')]:
  p=next(p for p in json.loads(read(ROOT/f))['source_proofs'] if p['label']==label)
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert p['premises_nonvacuous'] and s.check()==z3.unsat
  rechecked.append({'artifact':f,'artifact_sha256':sha(ROOT/f),'label':label,'result':'unsat'})
 controls=[]
 for name,mutate in [
  ('instruction_byte',lambda x:x['spans'][0].update(bytes_hex='00'+x['spans'][0]['bytes_hex'][2:])),
  ('bank_constant',lambda x:x['bank_rules'][0].update(constant='0x0')),
  ('descriptor_size',lambda x:x['typed_descriptors'][0].update(size_bytes=32)),
  ('native_ownership_claim',lambda x:x.update(native_ownership_established=True))]:
  altered=copy.deepcopy(e);mutate(altered);assert altered!=e;controls.append({'alteration':name,'equality_check_rejects':True})
 return {'generator_sha256':sha(__file__),'source_sha256':e['source_sha256'],'scope':R.SCOPE,
  'source_proofs':qs,'proof_coverage':coverage,'proved_pcs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':rechecked,'altered_evidence_controls':controls,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(rechecked),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':256*len(e['bank_rules']),'altered_evidence_rejections':len(controls),
   'pending_buffer_cases':2,'list_node_buffer_cases':2},
  'conditional_parser_cleanup_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
