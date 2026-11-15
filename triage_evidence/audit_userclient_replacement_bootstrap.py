#!/usr/bin/env python3
"""Prove this caller's constructor, private record and saved continuation joins.
O(I+256R+query DAG) construction/space; SMT cost separate, 30 s/query.
No native target executes; ordinary ABI, valid storage and epochs are premises.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,resize,mem,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_replacement_bootstrap as R

HOLDER=0xfffffe000ccceac0
TOKEN=0x886a1ca3
PHASE=0x7795e642
SUCCESS=0x31ae0066
INITIALIZED=0x7cb541a6
CONTINUATION=0xfffffe000a65b0e0

class Model(Base):
 def __init__(self,e):
  super().__init__(e)
  self.h0,self.h1,self.allocation,self.node,self.context=z3.BitVecs('RB_initial_holder64 RB_reloaded_holder64 RB_allocation64 RB_node64 RB_context64',64)
  self.output,self.saved_status=z3.BitVecs('RB_initializer_output32 RB_saved_status32',32)
  self.with_allocation=False;self.branch_loads=[]
 def owned(self):
  ranges=[(self.sp-0xa0,0x1120),(self.src,4096),(self.ctx,2048),(self.node,16),(self.context,24),(self.payload,120)]
  out=[z3.UGE(self.sp,0xa0),(self.sp&15)==0,(self.record&7)==0,(self.node&7)==0]
  for j,(a,n) in enumerate(ranges):
   out.extend([a!=0,z3.ULE(a,resize((1<<64)-1-n,64))])
   for b,m in ranges[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  if self.with_allocation:
   a=self.allocation;out.extend([a!=0,z3.ULE(a,resize((1<<64)-17,64)),(a&7)==0])
   for b,m in ranges:out.append(z3.Or(z3.ULE(a+16,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+16,resize(b,64)),z3.ULE(resize(b+m,64),a)))
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
   r=next(r for r in self.e['bank_rules'] if r['name']==name);l,rr=int(r['left'],16),int(r['right'],16)
   if self.pc==lp:
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('RB_left_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'checked_inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in [0xfffffe000a65ac58,0xfffffe000a65afb0]:
   assert n==8;self.address_checks.append(a==HOLDER);return self.h0 if self.pc==0xfffffe000a65ac58 else self.h1
  if n==4 and z3.is_bv_value(a) and a.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:
   return z3.BitVec('RB_controller_'+format(self.pc,'x'),32)
  return super().load(a,n)
 def returned(self):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('RB_call_'+str(self.count)+'_X'+str(j),64))
  return self

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('x6',0xfffffe000ccc30d0),
  ('x5',0xa41a4d891208c018),('x11',0xfffffe000794a0d0),('w1',PHASE),('w3',TOKEN),
  ('w19',TOKEN),('w8',0x71),('w30',SUCCESS),('w13',0x7795e3ce),('w25',0x4d08a3fb)]:v.seed(reg,x)
 for o,x in [(0xa08,v.src),(0xa28,v.ctx),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa40,0xfffffe000792fbc0),(0xa48,0xfffffe0007949dd0),(0xa50,0xfffffe0007941f60),
  (0xa58,0xfffffe000794a0d0),(0xa60,TABLE),(0x9f8,0xfffffe0007949ed0),(0x9f0,0xfffffe000792fec0),
  (0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),(0x998,v.record),
  (0x9e0,HOLDER),(0x9d0,CONTINUATION)]:mem(v,v.sp+o,8,x)
 mem(v,v.sp+0x9ec,4,v.saved_status);mem(v,v.src+0xd8c,4,v.raw_marker)
 mem(v,v.ctx+0x2c8,8,v.node+4);mem(v,v.ctx+0x410,8,v.node)
 return v

def request(e):return setup(e).run('resource_entry').run('holder_gate').run('allocate_request')

def initialized_request(e):
 v=request(e);v.returned();v.seed('x0',v.allocation);v.run('allocate_return').run('initialize_request');return v

def initializer_return(v):
 v.returned();mem(v,v.record,4,v.output);v.run('initialize_return');return v

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
 v=setup(e);v.seed('x28',0xfffffe0007949dd0)
 v.run('root_call_phase').run('root_call_select').run('allocate_left_root').run('root_call_descriptor_left')
 v.run('allocate_right_root').run('root_call_prepare')
 prove('root_envelope_original_FPTTLV_typed_allocation_ABI',v,z3.Or(v.read('x0')!=0xfffffe000847bb60,
  v.read('x11')!=0xfffffe000c4ba154,v.read('x17')!=0xd0c8,v.read('x24')!=0xfffffe0007949ed0,
  v.read('x26')!=0xfffffe000792fec0,v.read('x28')!=POOL))
 v.returned()
 v.run('allocate_left_save').run('allocate_right_save')
 prove('original_allocator_bank_roots_survive_ordinary_call_and_save',v,z3.Or(cell(v,v.sp+0x9f8,8)!=0xfffffe0007949ed0,
  cell(v,v.sp+0x9f0,8)!=0xfffffe000792fec0,v.read('x28')!=POOL),
  rewrites=[{'lemma':'original_bank_root_def_use_envelope','sha256':e['bank_root_def_use_envelope']['sha256'],
   'ordinary_call':'0xfffffe000a636404','callee_save_premise':['X24','X26','X28']}])
 v.run('rollback_roots_and_status_default')
 prove('original_rollback_bank_roots_and_raw_saved_status_default',v,z3.Or(cell(v,v.sp+0xa00,8)!=0xfffffe000792fcc0,
  cell(v,v.sp+0xa20,8)!=0xfffffe00079391f0,cell(v,v.sp+0x9ec,4)!=0xce515bb2))
 v=setup(e);v.run('resource_entry').run('holder_gate')
 prove('all_holder64_constructor_gate_and_saved_continuation',v,z3.Or(v.read('x19')!=CONTINUATION,
  cell(v,v.sp+0x9e0,8)!=HOLDER,v.read('w20')!=0x81b,v.read('x22')!=v.h0,
  v.read('x8')!=z3.If(v.h0==0,resize(0xfffffe000a65ac84,64),resize(0xfffffe000a65affc,64))))
 v=request(e)
 prove('null_holder_original_typed_FPHashTable_allocation_request',v,z3.Or(v.read('x0')!=0xfffffe000847b960,
  v.read('x10')!=0xfffffe000c4ba154,v.read('x17')!=0xd0c8,v.read('w24')!=0x57a,v.read('w25')!=0x539,
  v.read('x19')!=CONTINUATION,v.read('x26')!=0xa41a4d891208c018,v.read('x28')!=0xfffffe000ccc30d0),[v.h0==0])
 v.returned();v.seed('x0',v.allocation);v.run('allocate_return')
 prove('all_allocation_pointer64_initializer_or_reload_gate',v,z3.Or(v.read('x19')!=CONTINUATION,
  v.read('x8')!=z3.If(v.allocation==0,resize(0xfffffe000a65afa8,64),resize(0xfffffe000a65ad7c,64))),[v.h0==0])
 v=initialized_request(e);k=(resize(v.record,32)^0x7abbf985)*0xded29631
 prove('nonnull_allocation_initializer_record_and_saved_continuation',v,z3.Or(v.read('x22')!=v.allocation,
  cell(v,v.sp+0x9d0,8)!=CONTINUATION,cell(v,v.record+4,4)!=(k^0xabd),cell(v,v.record+8,8)!=v.allocation,
  v.read('x0')!=v.record,v.read('x8')!=0xfffffe000a627400,v.read('x17')!=0x2bbe,v.read('w25')!=0x539,v.read('w20')!=0x4e3),[v.h0==0,v.allocation!=0])
 d=setup(e);d.with_allocation=True;d.memory=dict(v.memory);d.seed('sp',v.sp-0xa0);d.seed('x0',v.record)
 d.overrides={(0xfffffe000a627544,'w12'):k};d.run('initializer_header')
 prove('initializer_caller_decoder_pre_multiply_codec_equality',d,
  d.values[(0xfffffe000a627538,'w12')]!=v.values[(0xfffffe000a65adb0,'w10')])
 prove('new_caller_token_abd_decodes_allocated_header_and_0_128_stores',d,z3.Or(d.read('w24')!=0xabd,
  d.read('x20')!=d.allocation,cell(d,d.allocation,4)!=0,cell(d,d.allocation+4,4)!=128),
  rewrites=[{'lemma':'initializer_caller_decoder_pre_multiply_codec_equality',
   'rewrite':'Congruence through the same low32 multiplier and XOR decoder; record bytes are supplied by the verified new caller.'}])
 initializer_return(v)
 prove('all_initializer_output32_publication_or_rollback_gate',v,v.read('x8')!=z3.If(v.output==INITIALIZED,
  resize(0xfffffe000a65ae58,64),resize(0xfffffe000a65af10,64)),[v.h0==0,v.allocation!=0])
 good=copy.deepcopy(v);good.run('publish').run('resume')
 prove('publication_restores_saved_continuation_and_authenticated_resume_register',good,z3.Or(
  good.read('x19')!=CONTINUATION,good.read('x8')!=0xfffffe000a65affc,good.read('x17')!=0xcb79,
  good.read('x22')!=good.allocation),[good.h0==0,good.allocation!=0,good.output==INITIALIZED])
 good.run('processing_gate')
 prove('initializer_success_publishes_allocated_header_and_resumes_processing',good,z3.Or(cell(good,resize(HOLDER,64),8)!=good.allocation,
  good.read('x19')!=TOKEN,cell(good,good.ctx+0x420,8)!=good.allocation,good.read('w23')!=good.saved_status,
  good.read('x8')!=0xfffffe000a65b12c,good.read('x2')!=good.ctx,good.read('x4')!=good.src,
  good.read('x6')!=0xfffffe000ccc30d0,good.read('w1')!=PHASE,good.read('w3')!=TOKEN),
  [good.h0==0,good.allocation!=0,good.output==INITIALIZED])
 v.run('rollback_request')
 prove('initializer_nonmatching_output_typed_FPHashTable_rollback_request',v,z3.Or(v.read('x0')!=0xfffffe000847b9a0,
  v.read('x1')!=v.allocation,v.read('x10')!=0xfffffe000c4ba368,v.read('x17')!=0x4d6a,v.read('w25')!=0x539),
  [v.h0==0,v.allocation!=0,v.output!=INITIALIZED])
 v.returned();v.run('rollback_return')
 prove('ordinary_rollback_return_restores_saved_continuation_and_selects_reload',v,z3.Or(v.read('x19')!=CONTINUATION,
  v.read('x8')!=0xfffffe000a65afa8),[v.h0==0,v.allocation!=0,v.output!=INITIALIZED])
 # These two routes preserve different original continuation channels: X19
 # directly for null allocation, SP+9d0 after initializer/rollback.
 fallback=[]
 for name,w in [('rollback',v),('null_allocation',request(e))]:
  if name=='null_allocation':w.returned();w.seed('x0',w.allocation);w.run('allocate_return')
  w.run('reload').run('resume')
  guards=[w.h0==0,w.allocation!=0,w.output!=INITIALIZED] if name=='rollback' else [w.h0==0,w.allocation==0]
  prove(name+'_reload_preserves_original_continuation_before_resume',w,z3.Or(w.read('x19')!=CONTINUATION,
   w.read('x8')!=0xfffffe000a65affc,w.read('x17')!=0xcb79,w.read('x22')!=w.h1),guards)
  w.run('processing_gate')
  prove(name+'_all_reloaded_holder64_restored_roots_and_processing_gate',w,z3.Or(cell(w,w.ctx+0x420,8)!=w.h1,
   w.read('w23')!=w.saved_status,w.read('w19')!=TOKEN,w.read('w30')!=SUCCESS,w.read('w3')!=TOKEN,w.read('w1')!=PHASE,
   w.read('x2')!=w.ctx,w.read('x4')!=w.src,w.read('x6')!=0xfffffe000ccc30d0,
   w.read('x8')!=z3.If(w.h1==0,resize(0xfffffe000a65e6cc,64),resize(0xfffffe000a65b12c,64))),guards)
  w.run('status_gate')
  prove(name+'_null_reloaded_holder_all_saved_status32_update_or_failure_gate',w,w.read('x9')!=z3.If(w.saved_status==SUCCESS,
   resize(0xfffffe000a65e710,64),resize(0xfffffe000a65ef14,64)),guards+[w.h1==0])
  w.run('marker_update')
  prove(name+'_null_holder_saved_success_updates_existing_marker',w,z3.Or(cell(w,w.node+4,4)!=w.raw_marker,
   w.read('x8')!=0xfffffe000a65e890),guards+[w.h1==0,w.saved_status==SUCCESS])
  fallback.append(name)
 prior_specs={'userclient_hash_table_initializer_audit.json':None,
  'userclient_uidlist_replacement_audit.json':['matched_node_capture_old_marker_and_exact_resource_gate',
   'all_holder64_processing_gate_and_saved_status_reload','all_first_status32_second_phase_or_status_gate',
   'retirement_success_replaces_existing_node_marker_and_continues','zero_saved_payload_skips_free_and_replaces_existing_marker']}
 pp=[]
 for name,labels in prior_specs.items():
  old=json.loads(read(ROOT/name));qq=old['source_proofs'] if labels is None else [next(q for q in old['source_proofs'] if q['label']==label) for label in labels]
  for q in qq:
   s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   pp.append({'label':q['label'],'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,sorted(map(hex,selected-visited))
 altered=[]
 for what in ['instruction_byte','bank_byte','descriptor_size','native_holder_coherence_claim']:
  bad=copy.deepcopy(e)
  if what in ['instruction_byte','bank_byte']:
   row=bad['spans'][0] if what=='instruction_byte' else bad['banks']['EL'];b=bytearray.fromhex(row['bytes_hex']);b[0]^=1;row['bytes_hex']=b.hex()
  elif what=='descriptor_size':bad['hash_table_descriptors'][0]['size_bytes']=17
  else:bad['native_global_holder_coherence_established']=True
  assert bad!=R.build();altered.append({'alteration':what,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':pp,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(x['source_instruction_instances'] for x in coverage),
   'bank_input_cases_checked':2048,'fallback_routes_checked':len(fallback),'altered_evidence_rejections':len(altered)},
  'conditional_replacement_bootstrap_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
