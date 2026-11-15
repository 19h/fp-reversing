#!/usr/bin/env python3
"""Prove selected context-list source, field widths and caller/callee cuts.
O(I+256R+query DAG) construction and space; SMT cost separate, 30 s/query.
No target executes. Valid storage, stable roots and ordinary ABI are premises.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,resize,mem,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_uidlist_publication as R
SUCCESS=0x31ae0066
TOKEN=0x886a1ca3
PHASE=0x7795e642
KEY0=0x1ee45f68039f9913

class Model(Base):
 def __init__(self,e):
  super().__init__(e)
  self.context,self.node,self.new,self.head,self.next=z3.BitVecs('UP_context64 UP_node64 UP_new64 UP_head64 UP_next64',64)
  self.discriminator,self.node_key,self.old_marker=z3.BitVecs('UP_discriminator32 UP_node_discriminator32 UP_old_marker32',32)
  self.with_payload=True;self.with_new=False;self.branch_loads=[];self.node_bytes={}
 def owned(self):
  ranges=[(self.sp,0x1080),(self.ctx,0x800),(self.src,0x1000),(self.context,24),(self.node,16)]
  if self.with_payload:ranges.append((self.payload,120))
  if self.with_new:ranges.append((self.new,16))
  out=[(self.sp&15)==0,(self.context&7)==0,(self.node&7)==0]
  if self.with_new:out.append((self.new&7)==0)
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1-n,64))])
   for b,m in ranges[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  a=z3.simplify(a)
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]))
   self.branch_loads.append({'pc':hex(self.pc),'indices':js})
   out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  bank_pcs={0xfffffe000a65e798:('L','allocate_adapter'),0xfffffe000a65e7a4:('R','allocate_adapter'),
   0xfffffe000a65e7cc:('L','allocate_descriptor'),0xfffffe000a65e7dc:('R','allocate_descriptor')}
  if self.pc in bank_pcs:
   side,name=bank_pcs[self.pc];r=next(r for r in self.e['bank_rules'] if r['name']==name)
   l,rr=int(r['left'],16),int(r['right'],16);assert n==1
   if side=='L':
    self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('UP_left_byte_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
   self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs_checked':256})
   return self.bank_input^int(r['constant'],16)
  if self.pc in [0xfffffe000a65e7b4,0xfffffe000a65e7f4]:
   r=next(r for r in self.e['bank_rules'] if r['name']==('allocate_adapter' if self.pc==0xfffffe000a65e7b4 else 'allocate_descriptor'))
   self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  return super().load(a,n)
 def store(self,a,n,x,pc):
  super().store(a,n,x,pc);off=z3.simplify(a-self.new)
  if z3.is_bv_value(off) and off.as_long()<16:
   off=off.as_long();assert off+n<=16
   for j in range(n):self.node_bytes[off+j]=z3.Extract(8*j+7,8*j,resize(x,n*8))

def setup(e,head=None):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x8',v.payload),('x7',TABLE),('x6',0xfffffe000ccc30d0),
  ('x5',0xa41a4d891208c018),('x28',0xfffffe0007949dd0),('w3',TOKEN),('w1',PHASE),('w30',SUCCESS)]:v.seed(r,x)
 for o,x in [(0x738,v.context),(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),
  (0xa38,0xfffffe000ccc32f8),(0xa40,0xfffffe000792fbc0),(0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0)]:mem(v,v.sp+o,8,x)
 mem(v,v.sp+0x9ec,4,z3.BitVec('UP_saved_status32',32))
 for o,x in [(0x218,v.payload),(0x4c8,v.payload),(0x118,v.context),(0x410,v.node),(0x2c8,v.node+4)]:mem(v,v.ctx+o,8,x)
 for o,x in [(0xc90,v.discriminator),(0xd8c,v.raw_marker)]:mem(v,v.src+o,4,x)
 mem(v,v.context,8,v.head if head is None else head);mem(v,v.payload+0x6c,4,v.raw_marker)
 mem(v,v.node,4,v.node_key);mem(v,v.node+4,4,v.old_marker);mem(v,v.node+8,8,v.next)
 for a in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:mem(v,a,4,z3.BitVec('UP_controller_'+format(a,'x'),32))
 return v

def search(v):
 v.seed('w10',0x90d);v.run('marker_head');v.seed('x8',v.node)
 v.run('walk_key').run('walk_compare');return v

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
 v=setup(e);v.seed('x2',v.context);v.run('entry_context_save')
 prove('original_third_argument_context_frame_cell',v,cell(v,v.sp+0x738,8)!=v.context)
 v=setup(e);v.run('candidate_alias')
 prove('tunnel_alias_from_scratch218_to_scratch4c8',v,cell(v,v.ctx+0x4c8,8)!=v.payload)
 v=setup(e);v.with_payload=False;v.seed('w9',0xb33);v.run('candidate_gate')
 prove('all_pointer64_candidate_gate_and_next_phase',v,z3.Or(v.read('x9')!=z3.If(v.payload==0,resize(0xfffffe000a65ef14,64),resize(0xfffffe000a65ed24,64)),v.read('w10')!=0x90d,v.read('w19')!=TOKEN))
 v=setup(e);v.seed('w10',0x90d);v.run('marker_head')
 prove('tunnel_marker_context_head_and_empty_list_branch',v,z3.Or(v.read('w24')!=v.raw_marker,
  cell(v,v.src+0xd8c,4)!=v.raw_marker,cell(v,v.ctx+0x118,8)!=v.context,cell(v,v.ctx+0x410,8)!=v.head,
  v.read('x10')!=z3.If(v.head==0,resize(0xfffffe000a65e760,64),resize(0xfffffe000a65ed88,64)),v.read('w9')!=TOKEN,v.read('w19')!=TOKEN))
 v=search(setup(e))
 prove('all_discriminator32_exact_node0_search_gate',v,v.read('x9')!=z3.If(v.node_key==v.discriminator,resize(0xfffffe000a65ee64,64),resize(0xfffffe000a65edf0,64)))
 v.run('walk_next')
 prove('all_successor64_loop_or_exhaustion_branch',v,z3.Or(v.read('x8')!=v.next,
  v.read('x11')!=z3.If(v.next==0,resize(0xfffffe000a65ee30,64),resize(0xfffffe000a65edac,64)),v.read('w9')!=TOKEN),premises=[v.node_key!=v.discriminator])
 v=search(setup(e));v.run('walk_next').run('walk_exhaust')
 prove('exhaustion_clears_match_cell_and_selects_allocation',v,z3.Or(cell(v,v.ctx+0x410,8)!=0,v.read('x8')!=0xfffffe000a65e760,v.read('w19')!=TOKEN),premises=[v.node_key!=v.discriminator,v.next==0])
 v=search(setup(e));v.seed('x8',v.node);v.run('matched_capture')
 prove('matched_node_marker_address_old_marker_and_resource_gate',v,z3.Or(cell(v,v.ctx+0x410,8)!=v.node,
  cell(v,v.ctx+0x2c8,8)!=v.node+4,cell(v,v.src+0xc84,4)!=v.old_marker,
  cell(v,v.ctx+0x7a8,8)!=0,cell(v,v.src+0xb68,1)!=0,v.read('w19')!=TOKEN,v.read('w23')!=0xce515bbf,
  v.read('x9')!=z3.If(v.old_marker==SUCCESS,resize(0xfffffe000a65e6cc,64),resize(0xfffffe000a65eee4,64))),premises=[v.node_key==v.discriminator])
 v=setup(e);v.seed('w19',TOKEN);v.seed('w23',v.status);v.run('status_gate')
 prove('all_status32_gate_before_existing_marker_update',v,z3.Or(v.read('w8')!=0x746,
  v.read('x9')!=z3.If(v.status==SUCCESS,resize(0xfffffe000a65e710,64),resize(0xfffffe000a65ef14,64))))
 v=setup(e);v.seed('w19',TOKEN);v.seed('w8',0x746);mem(v,v.ctx+0x410,8,v.head);v.run('marker_update')
 prove('existing_marker_write_and_match_presence_branch',v,z3.Or(cell(v,v.node+4,4)!=v.raw_marker,
  v.read('x8')!=z3.If(v.head==0,resize(0xfffffe000a65e760,64),resize(0xfffffe000a65e890,64)),v.read('w19')!=TOKEN))
 v=setup(e);v.seed('w19',TOKEN);v.seed('w24',v.raw_marker);v.run('allocate_prepare')
 prove('all_controller_words_original_UIDList_allocation_ABI',v,z3.Or(v.read('x0')!=0xfffffe000847b8a0,
  v.read('x10')!=0xfffffe000c4ba154,v.read('x17')!=0xd0c8,v.read('w20')!=0x746,v.read('w22')!=0x51f,v.read('w24')!=v.raw_marker),rewrites=[{'lemma':'tunnel_marker_context_head_and_empty_list_branch','cut':'Retained W24 marker at entry to allocation preparation.'}])
 # Ordinary ABI cut: caller-save GP registers arbitrary; saved root cells and
 # X19-X29/SP are retained. Allocator result remains arbitrary, including zero.
 for j in range(19):v.seed('x'+str(j),z3.BitVec('UP_return_clobber_X'+str(j),64))
 v.seed('x0',v.new);v.run('allocate_return')
 prove('all_allocator_result64_null_branch_and_root_restoration',v,z3.Or(v.read('x8')!=z3.If(v.new==0,resize(0xfffffe000a65ef14,64),resize(0xfffffe000a65e85c,64)),v.read('x2')!=v.ctx,v.read('x4')!=v.src,v.read('x7')!=TABLE,v.read('x0')!=v.new,v.read('w24')!=v.raw_marker))
 v.with_new=True;v.run('node_prepend')
 expected=z3.Concat(v.head,v.raw_marker,v.discriminator);actual=z3.Concat(*[v.node_bytes[j] for j in reversed(range(16))])
 assert set(v.node_bytes)==set(range(16))
 stores=v.stores[-4:];assert [(x['pc'],x['size_bytes']) for x in stores]==[(0xfffffe000a65e870,4),(0xfffffe000a65e870,4),(0xfffffe000a65e87c,8),(0xfffffe000a65e880,8)]
 prove('complete_16_byte_node_then_context_head_publication',v,z3.Or(actual!=expected,cell(v,v.context,8)!=v.new,v.read('x8')!=0xfffffe000a65e890),rewrites=[{'ABI_cut':'New storage is valid/nonzero/disjoint, X24 and saved roots persist; current context head is read at a65e878 before publication at a65e880.'}])
 prove('published_marker_reconstructs_insertion_cleanup_key',v,
  KEY0+z3.ZeroExt(32,cell(v,v.new+4,4)^SUCCESS)!=KEY0+z3.ZeroExt(32,v.raw_marker^SUCCESS),rewrites=[{'predecessor':'Post-writer marker and original cleanup key-phase queries are independently re-solved; epoch identity remains a premise.'}])
 v=setup(e);v.run('marker_default')
 prove('source_marker_default_is_raw_success',v,cell(v,v.src+0xd8c,4)!=SUCCESS)
 v=setup(e);v.run('discriminator_default')
 prove('discriminator_default_is_0x1505',v,cell(v,v.src+0xc90,4)!=0x1505)
 v=setup(e);v.seed('x10',z3.BitVec('UP_derived_discriminator64',64));before=v.read('w10');v.run('discriminator_store')
 prove('derived_discriminator_is_stored_with_u32_width',v,cell(v,v.src+0xc90,4)!=before)
 prior_specs={
 'secure_tunnel_table_insertion_audit.json':['tunnel_alias_and_source_marker_load','post_writer_raw_marker_into_source_and_tunnel','all_source_marker32_key_basis'],
 'userclient_uidlist_cleanup_audit.json':['all_marker32_successor64_original_node_gate_and_successor_save','all_controller_words_original_typed_UIDList_free_ABI'],
 'userclient_hash_table_lookup_audit.json':['original_first_cleanup_lookup_key_phase_and_call_binding']}
 pp=[]
 for name,labels in prior_specs.items():
  old=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in old['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':e['scope'],'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':pp,'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),
   'bank_input_cases_checked':512,'published_node_bytes_checked':16,'publication_stores_checked':4},
  'conditional_UIDList_publication_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
