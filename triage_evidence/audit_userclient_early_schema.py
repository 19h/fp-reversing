#!/usr/bin/env python3
"""Original-word exhaustion/action/lookup composition and packet-byte cross-check.
O(I+query DAG+C*I+packet bytes) construction/space; SMT search 60 s/query.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_early_publication as Parent
import recover_userclient_early_schema as R
H=Parent.H;DEC=Parent.DEC;SUCCESS=Parent.SUCCESS
class Model(Parent.Model):
 def __init__(self,e):
  combined=copy.deepcopy(e);combined['source']['spans']=e['publication_source']['spans']+e['source']['spans'];super().__init__(combined);c=self.common
  mem(self,c['C']+0xb0,8,c['H']);mem(self,c['C']+0x718,8,c['C']+0x418);self.seed('x2',c['C']);self.seed('x4',c['S']);self.seed('x17',c['C']+0x418)
  for label in ['container_zero','result_zero','container_root_save','container_alias','mode_literal','result_root','lookup_root']:self.run(label)
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  return super().load(a,n)
 def run(self,label,take=None):
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.visited.add(i.address)
   if i.address in R.DIRECT:
    m,t=R.DIRECT[i.address];assert i.mnemonic==m and i.operands[0].imm&((1<<64)-1)==t;cond=self.condition(m[2:]);self.direct.append({'pc':i.address,'condition':cond,'next_PC':z3.If(cond,resize(t,64),resize(i.address+4,64))});self.count+=1
    if take is not None:self.guards.append(cond if take else z3.Not(cond))
   elif i.address in R.Parent.P0.RETAGS:
    assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.Parent.P0.RETAGS[i.address];self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one');self.e=original
  self.e=original;return self
def prepared(e,kind):
 v=Model(e)
 for label in H.PATH:v.run(label)
 if kind=='u32':v.run('primary_gate',False).run('u32_gate');v.extra.append(v.common['L']==4);v.run('u32_request').run('length_bridge').run('word_writer')
 elif kind=='u64':v.run('primary_gate',True).run('secondary_gate',True).run('u64_gate');v.extra.append(v.common['L']==8);v.run('u64_request').run('u64_writer')
 else:
  v.run('primary_gate',True).run('secondary_gate',False).run('span_gate',False).run('span_length')
  if kind=='span_zero':v.extra.append(v.common['L']==0)
  else:
   assert kind=='span_nonzero';v.extra.extend([v.common['L']!=0,v.counter==1]);v.with_span=True;v.run('span_request');v.seed('x10',v.counter);v.run('span_copy')
 v.publication_store_start=len(v.stores);Parent.finish(v);v.extra.append(z3.ZeroExt(32,v.common['N'])==z3.ZeroExt(32,v.common['L'])+10);v.schema_store_start=len(v.stores);return v
STAGES=['exhaustion','container_publish','action_first','action_second','action_third','action_status','schema_request','schema_entry','schema_lookup','search_entry']
def finish(v,through='search_entry'):
 for label in STAGES:
  v.run(label,False if label in ['action_first','action_second','action_third']else None)
  if label==through:return v
 raise AssertionError(through)
def state_bad(v):
 c=v.common;return z3.Or(H.cell(v,c['C']+0x418,8)!=c['H'],H.cell(v,c['H'],8)!=c['J'],H.cell(v,c['H']+8,8)!=c['J'],H.cell(v,c['S']+0xc94,4)!=SUCCESS,H.cell(v,c['S']+0xa10,8)!=z3.ZeroExt(32,c['L'])+10)
def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra
  p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);assert p.check()==z3.sat,name
  # A fresh solver preserves full bit-vector preprocessing after the SAT check.
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*[z3.Not(q)for q in v.address_checks],bad));query=s.to_smt2();result=s.check();assert result==z3.unsat,(name,str(result),s.reason_unknown());out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count});visited.update(v.visited)
 v=Model(e);c=v.common;prove('source_produces_fixed_action_aliases_and_zero_result_word',v,z3.Or(H.cell(v,c['S']+0x1e0,4)!=0x1830b7ce,H.cell(v,c['F']+0x648,8)!=c['S']+0xbc4,H.cell(v,c['F']+0x708,8)!=c['C']+0x710,H.cell(v,c['F']+0x908,8)!=c['C']+0x418,H.cell(v,c['C']+0x170,8)!=c['C']+0x418,H.cell(v,c['S']+0xbc4,4)!=0))
 v=prepared(e,'u32').run('exhaustion');c=v.common;prove('exhausted_first_record_saves_raw_success_and_requests_container_publication',v,z3.Or(H.cell(v,c['S']+0xc94,4)!=SUCCESS,Parent.edge(v,0xfffffe000a660b64,0x8ef5)))
 v.run('container_publish');prove('successful_parse_publishes_same_container_through_original_output_alias',v,z3.Or(state_bad(v),Parent.edge(v,0xfffffe000a660b88,0x1fcb)))
 v.run('action_first',False).run('action_second',False).run('action_third',False);prove('source_fixed_action_selects_third_fallthrough_without_external_mode_binding',v,z3.Or(*[q['condition']for q in v.direct[-3:]],v.read('w8')!=0x1830b7ce))
 cut=copy.deepcopy(v);cut.seed('w23',cut.status);cut.run('action_status');prove('fixed_action_all_status32_exact_schema_request_or_failure_edge',cut,Parent.edge(cut,z3.If(cut.status==SUCCESS,resize(0xfffffe000a6366e0,64),resize(0xfffffe000a641c1c,64)),0x64d8))
 v.run('action_status').run('schema_request');prove('first_schema_request_exact_key_result_alias_and_return_channel',v,z3.Or(state_bad(v),v.read('x22')!=c['H'],v.read('w9')!=0xcb2d4174,(v.read('w9')^SUCCESS)!=0xfa834112,v.read('x11')!=c['S']+0xbc4,v.read('w8')!=0xf6,Parent.edge(v,0xfffffe000a654278,0x2d2b)))
 v.run('schema_entry');prove('schema_entry_retains_caller_result_and_initializes_lookup_state',v,z3.Or(H.cell(v,c['C']+0x4d0,8)!=0xfffffe000a636728,H.cell(v,c['C']+0x5f0,8)!=c['S']+0xbc4,H.cell(v,c['C']+0x710,8)!=0,H.cell(v,c['S']+0xb64,4)!=SUCCESS,H.cell(v,c['F']+0xaa8,8)!=0,Parent.edge(v,0xfffffe000a6542d4,0x3751)))
 v.run('schema_lookup');prove('schema_helper_emits_caller_specific_shared_lookup_ABI',v,z3.Or(state_bad(v),v.read('x22')!=c['H'],v.read('w9')!=0xcb2d4174,v.read('x10')!=c['C']+0x710,v.read('w8')!=0x7f,H.cell(v,c['C']+0x5f0,8)!=c['S']+0xbc4,Parent.edge(v,0xfffffe000a662ab4,0xee9)))
 v.run('search_entry');prove('shared_lookup_saves_schema_return_and_result_alias_for_same_container',v,z3.Or(H.cell(v,c['C']+0xc8,8)!=0xfffffe000a661c34,H.cell(v,c['C']+0x758,8)!=c['C']+0x710,H.cell(v,c['S'],4)!=0xcb2d4174,Parent.edge(v,0xfffffe000a662be0,0x7250)))
 models={}
 for kind in ['u32','u64','span_zero','span_nonzero']:
  v=finish(prepared(e,kind));c=v.common;end=c['Z']+z3.ZeroExt(32,c['L'])+10;outside=[z3.Or(z3.ULE(q['address']+q['size_bytes'],c['Z']),z3.ULE(end,q['address']))for q in v.stores[v.schema_store_start:]];prove(kind+'_composed_exhaustion_to_raw_fa834112_lookup_preserves_record_and_container',v,z3.Or(state_bad(v),*[z3.Not(q)for q in outside],H.cell(v,c['C']+0x5f0,8)!=c['S']+0xbc4,H.cell(v,c['C']+0x710,8)!=0,H.cell(v,c['C']+0xc8,8)!=0xfffffe000a661c34,H.cell(v,c['S'],4)!=0xcb2d4174,Parent.edge(v,0xfffffe000a662be0,0x7250)));models[kind]=v
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(visited&captured)
def evaluations(e,models):
 rows=[]
 for r in e['predecessor_states']:
  p=r['input'];profile=p['profile'];kind='u32'if profile.startswith('u32')else'u64'if profile.startswith('u64')else'span_nonzero'if p['wire_length32']else'span_zero';v=models[kind];c=v.common;g=[int(x,16)for x in r['handoff_state']['registers31']];raw=bytes.fromhex(p['input_fixture_hex']);values={'F':int(r['frame_base_SP'],16),'C':g[11],'S':g[3],'J':p['node_result_fixture'],'Z':p['data_result_fixture'],'D':p['wire_tag32'],'U':p['wire_type16'],'L':p['wire_length32'],'V':int.from_bytes(raw[10:14],'big')if kind=='u32'else 0,'Q':int.from_bytes(raw[10:18],'big')if kind=='u64'else 0,'P':p['inputs8'][0]+10 if kind.startswith('span')else 0,'H':int(r['original_container'],16),'N':r['outer_size32']};bindings=[(c[k],resize(x,c[k].size()))for k,x in values.items()]+[(v.counter,resize(1,64))];controller_queries=0
  for premise in v.owned()+v.guards+v.extra+v.address_checks:
   q=z3.simplify(z3.substitute(premise,*bindings))
   if not z3.is_true(q):
    s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(z3.Not(q));assert s.check()==z3.unsat;controller_queries+=1
  fields=[('C',0x418,8,values['H']),('S',0xc94,4,SUCCESS),('C',0x4d0,8,0xfffffe000a636728),('C',0x5f0,8,values['S']+0xbc4),('C',0x710,8,0),('S',0xb64,4,SUCCESS),('F',0xaa8,8,0),('C',0xc8,8,0xfffffe000a661c34),('C',0x758,8,values['C']+0x710),('S',0,4,0xcb2d4174),('H',0,8,values['J']),('H',8,8,values['J']),('S',0xa10,8,r['cursor64'])]
  for root,off,n,want in fields:assert H.numeric(H.cell(v,c[root]+off,n),bindings)==want
  assert H.numeric(v.edges[-1]['target'],bindings)==0xfffffe000a662be0
  rows.append({'predecessor_case_index':r['predecessor_case_index'],'domain':kind,'post_schema_fields_checked':len(fields),'unbound_controller_premise_queries_unsat':controller_queries,'requested_raw_key32':'0xfa834112','all_storage_branch_and_lookup_premises_checked':True,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'all_checks_pass':True})
 return rows
def negative_controls(e):
 rows=[]
 for pc in [0xfffffe000a660b70,0xfffffe000a635960,0xfffffe000a63670c]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);replacement=(((int.from_bytes(old,'little')&~(0xffff<<5))|(0xb7cf<<5)).to_bytes(4,'little'))if pc==0xfffffe000a635960 else bytes.fromhex('1f2003d5');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex();v=prepared(changed,'u32')
  if pc==0xfffffe000a635960:
   v.run('exhaustion').run('container_publish').run('action_first',False).run('action_second',False).run('action_third');bad=v.direct[-1]['condition'];stop='before_following_changed_action_branch'
  else:
   finish(v,'schema_request');bad=z3.Or(v.read('x22')!=v.common['H'],v.read('w9')!=0xcb2d4174);stop='before_entering_schema_helper'
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat;rows.append({'mutated_PC':hex(pc),'original_word_hex':old.hex(),'replacement_word_hex':replacement.hex(),'satisfiable_violation_query':s.to_smt2(),'stop_boundary':stop,'normal_oracle_rejected':True,'native_target_executed':False})
 return rows
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases=evaluations(e,models);controls=negative_controls(e);old=json.loads(read(ROOT/'userclient_early_publication_audit.json'));rechecked=[]
 for kind in ['u32','u64','span_zero','span_nonzero']:
  name=kind+'_composed_first_publication_preserves_serialized_buffer_and_returns_exact_cursor_gate';p=next(q for q in old['source_proofs']if q['name']==name);s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;rechecked.append({'name':name,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_early_publication_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'prior_publication_queries_unsat':len(rechecked),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'predecessor_bound_partial_state_evaluations':len(cases),'additional_prefix_cells_reconstructed':sum(len(q['additional_source_defined_cells'])for q in e['predecessor_states']),'post_schema_fields_checked':sum(q['post_schema_fields_checked']for q in cases),'unbound_controller_premise_queries_unsat':sum(q['unbound_controller_premise_queries_unsat']for q in cases),'negative_source_controls':len(controls),'missing_cells_assigned_concrete_values':0,'schema_source_stores_per_case':len(models['u32'].stores)-models['u32'].schema_store_start,'ADID_packets_independently_parsed':len(e['adid_evidence']['packets']),'ADID_field_record_bytes_per_packet':14,'ADID_containment_levels':4}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_publication_proofs':rechecked,'partial_state_evaluations':cases,'negative_source_controls':controls,'independent_totals':totals,'conditional_exhaustion_to_schema_lookup_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
