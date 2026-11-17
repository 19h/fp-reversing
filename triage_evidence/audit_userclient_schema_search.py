#!/usr/bin/env python3
"""Compose original search/decoder words with the early writer's actual bytes.
O(I+query DAG+C*I) construction/space; SMT search: 60 s/new query, 120 s/retained formula recheck.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_early_schema as Parent
import recover_userclient_schema_search as R
H=Parent.H;DEC=Parent.DEC;SUCCESS=Parent.SUCCESS;MISS=0xce515bda
class Model(Parent.Model):
 def __init__(self,e):
  self.bank_calls=0;self.controller_reads=0
  combined=copy.deepcopy(e);combined['source']['spans']=e['schema_source']['spans']+e['source']['spans'];super().__init__(combined);self.seed('x2',self.common['C']);self.run('buffer_output_root')
 def load(self,a,n):
  if self.pc in [0xfffffe000a662b08,0xfffffe000a662b10]:
   assert n==4;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==(0xfffffe000ccc30d0 if self.pc==0xfffffe000a662b08 else 0xfffffe000ccc32f8));self.controller_reads+=1;return z3.BitVec('SS_controller_read_'+str(self.controller_reads),32)
  if self.pc==0xfffffe000a662b2c:
   assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});bank=self.publication_receipt['source']['bank_rule'];l=int(bank['left'],16);self.bank_input=z3.Extract(7,0,a-l);self.bank_calls+=1;self.bank_byte=z3.BitVec('SS_bank_byte_'+str(self.bank_calls),8);self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
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
   if i.address in R.RETAGS:
    assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.RETAGS[i.address];self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one',take);self.e=original
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
 v.publication_store_start=len(v.stores);Parent.Parent.finish(v);v.extra.append(z3.ZeroExt(32,v.common['N'])==z3.ZeroExt(32,v.common['L'])+10);v.schema_store_start=len(v.stores);Parent.finish(v);v.search_store_start=len(v.stores);return v
def searched(e,kind,match=True):
 v=prepared(e,kind);v.run('search_nonnull').run('search_node').run('node_decode_prepare').run('word_bridge_read').run('decode_word').run('tag_match');v.extra.append(v.common['D']==0xfa834112 if match else v.common['D']!=0xfa834112)
 if not match:v.run('search_next').run('search_node')
 return v.run('search_result').run('search_callback').run('schema_search_return')
KEY=0xfa834112;LENGTH_BIAS=0x7834dd25aad3a2b1
DOMAINS=['u32','u64','span_zero','span_nonzero']
def matched(v):return v.run('schema_node_fields').run('schema_extent').run('schema_decode_request')
def missed(v):return v.run('schema_caller_return')
def invariant(v):
 c=v.common;return z3.Or(H.cell(v,c['C']+0x418,8)!=c['H'],H.cell(v,c['H'],8)!=c['J'],H.cell(v,c['H']+8,8)!=c['J'],H.cell(v,c['J'],8)!=0,H.cell(v,c['J']+8,8)!=0,H.cell(v,c['J']+0x10,4)!=c['L']+10,H.cell(v,c['J']+0x18,8)!=c['Z'],H.cell(v,c['S']+0xa10,8)!=z3.ZeroExt(32,c['L'])+10,H.cell(v,c['S']+0xbc4,4)!=0)
def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra;p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);r=p.check();assert r==z3.sat,(name,'premises',str(r),p.reason_unknown())
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.Or(*[z3.Not(q)for q in v.address_checks],bad)));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,str(r),s.reason_unknown());out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count,'independent_controller_reads':v.controller_reads,'independent_bank_bytes':v.bank_calls});visited.update(v.visited)
 v=Model(e);c=v.common;prove('original_source_produces_schema_buffer_output_alias',v,H.cell(v,c['F']+0x898,8)!=c['C']+0x560)
 v=prepared(e,'u32').run('search_nonnull').run('search_node');c=v.common;prove('schema_lookup_selects_original_first_published_node',v,z3.Or(H.cell(v,c['C']+0x2b0,8)!=c['J'],Parent.Parent.edge(v,0xfffffe000a662c60,0xb5a8)))
 v.run('node_decode_prepare').run('word_bridge_read').run('decode_word');loads=[q for q in v.loads if q['pc']in R.Reader.RETAGS or q['pc']in [0xfffffe000a637158,0xfffffe000a637190,0xfffffe000a6371d4,0xfffffe000a637214]];assert len(loads)==4
 prove('actual_early_protected_bytes_decode_to_same_encoded_tag32',v,z3.Or(v.read('w22')!=(c['D']^SUCCESS),*[q['address']!=c['Z']+j for j,q in enumerate(loads)],v.read('x26')!=H.KEY0,v.read('x20')!=H.KEY1,Parent.Parent.edge(v,0xfffffe000a63d624,0xb745)))
 v.run('tag_match');prove('all_raw_tag32_exact_requested_key_match_or_successor_edge',v,z3.Or(v.read('x22')!=c['J'],Parent.Parent.edge(v,z3.If(c['D']==KEY,resize(0xfffffe000a662c44,64),resize(0xfffffe000a63d680,64)),0xde40)))
 w=copy.deepcopy(v);w.extra.append(c['D']!=KEY);w.run('search_next').run('search_node');prove('sole_nonmatching_node_follows_source_zero_next_and_returns_raw_miss',w,z3.Or(H.cell(w,c['C']+0x2b0,8)!=0,w.read('x22')!=0,w.read('w23')!=MISS,Parent.Parent.edge(w,0xfffffe000a662c44,0xb5a8)))
 w.run('search_result').run('search_callback');prove('schema_miss_publishes_zero_and_returns_exact_caller_callback',w,z3.Or(H.cell(w,c['C']+0x710,8)!=0,w.read('w23')!=MISS,Parent.Parent.edge(w,0xfffffe000a661c34,0x8d28)))
 v.extra.append(c['D']==KEY);v.run('search_result').run('search_callback');prove('schema_match_publishes_original_node_and_returns_exact_caller_callback',v,z3.Or(H.cell(v,c['C']+0x710,8)!=c['J'],v.read('w23')!=SUCCESS,Parent.Parent.edge(v,0xfffffe000a661c34,0x8d28)))
 cut=Model(e);status=z3.BitVec('SS_callback_status32',32)
 for reg,x in [('w24',0x7795e3ce),('w3',0x886a1ca3),('w23',status),('x7',TABLE)]:cut.seed(reg,x)
 cut.run('schema_search_return');prove('schema_callback_all_status32_only_raw_success_selects_node_fields',cut,Parent.Parent.edge(cut,z3.If(status==SUCCESS,resize(0xfffffe000a661c88,64),resize(0xfffffe000a661e40,64)),0x3751))
 cut=Model(e);c=cut.common;buffer=z3.BitVec('SS_nullable_buffer64',64);extent=z3.BitVec('SS_node_extent32',32)
 for reg,x in [('x2',c['C']),('x7',TABLE),('w9',0xf04)]:cut.seed(reg,x)
 mem(cut,c['C']+0x710,8,c['J']);mem(cut,c['J']+0x18,8,buffer);mem(cut,c['J']+0x10,4,extent);cut.run('schema_node_fields')
 prove('all_buffer64_and_extent32_publish_through_original_alias_and_select_null_gate',cut,z3.Or(H.cell(cut,c['C']+0x560,8)!=buffer,cut.read('w11')!=extent,cut.read('w23')!=0xce515bbf,cut.read('w10')!=0x3d8,Parent.Parent.edge(cut,z3.If(buffer==0,resize(0xfffffe000a661e40,64),resize(0xfffffe000a661cec,64)),0xd784)))
 cut=Model(e);c=cut.common;cursor=z3.BitVec('SS_header_cursor64',64);cut.extra.append(z3.ULE(cursor,z3.ZeroExt(32,extent)))
 for reg,x in [('x2',c['C']),('x4',c['S']),('x7',TABLE),('w3',0x886a1ca3),('w10',0x3d8),('w11',extent)]:cut.seed(reg,x)
 mem(cut,c['F']+0xaa8,8,cursor);cut.run('schema_extent');target=z3.If(z3.ULE(cursor+10,z3.ZeroExt(32,extent)),resize(0xfffffe000a661da0,64),resize(0xfffffe000a661e40,64))
 prove('all_extent32_and_bounded_cursor64_exact_ten_byte_header_fit_gate',cut,z3.Or(H.cell(cut,c['S']+0x260,8)!=(z3.ZeroExt(32,extent)+LENGTH_BIAS),H.cell(cut,c['F']+0xbd0,8)!=cursor,cut.read('w23')!=0xce515bb8,Parent.Parent.edge(cut,target,0x3751)))
 models={}
 for kind in DOMAINS:
  for found in [False,True]:
   v=searched(e,kind,found);v.schema_effect_start=len(v.stores);v=matched(v)if found else missed(v);c=v.common;bad=[invariant(v),H.cell(v,c['C']+0x710,8)!=(c['J']if found else 0),H.cell(v,c['C']+0x5f0,8)!=c['S']+0xbc4]
   if found:
    bad.extend([H.cell(v,c['C']+0x560,8)!=c['Z'],H.cell(v,c['S']+0x260,8)!=(z3.ZeroExt(32,c['L'])+10+LENGTH_BIAS),H.cell(v,c['F']+0xbd0,8)!=0,v.read('x8')!=c['Z'],v.read('x10')!=0x59ea252df044bd94,v.read('x1')!=0xa615dad20fbb426c,(v.read('x10')+v.read('x1'))!=0,v.read('w9')!=0x1a2,v.read('w11')!=0xe07,v.read('x26')!=H.KEY0,v.read('x20')!=H.KEY1,Parent.Parent.edge(v,0xfffffe000a656ef0,0x5e04)])
   else:bad.extend([v.read('w23')!=MISS,Parent.Parent.edge(v,0xfffffe000a636728,0x415f),z3.BoolVal(any(q['pc']==0xfffffe000a661cb8 for q in v.stores))])
   end=c['Z']+z3.ZeroExt(32,c['L'])+10;bad.extend(z3.Not(z3.Or(z3.ULE(q['address']+q['size_bytes'],c['Z']),z3.ULE(end,q['address'])))for q in v.stores[v.search_store_start:])
   prove(kind+'_complete_'+('found_buffer_extent_and_next_header_request'if found else'sole_miss_to_original_caller'),v,z3.Or(*bad));models[(kind,found)]=v
 for pc in [0xfffffe000a637154,0xfffffe000a63718c,0xfffffe000a6371d0,0xfffffe000a637210]:
  v=Model(e);row=next(s for s in e['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);b=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(b,pc));reg=i.reg_name(i.operands[0].reg);p=z3.BitVec('SS_alternate_pointer64',64);v.seed(reg,p);v.e={'source':{'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':b.hex()}]}};v.run('alternate');prove('alternate_retag_'+format(pc,'x')+'_bit_transform_only',v,v.read(reg)!=((p&0xffffffffffff)|(0xc8a2<<48)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(visited&captured)
def values_for(r):
 p=r['input'];profile=p['profile'];kind='u32'if profile.startswith('u32')else'u64'if profile.startswith('u64')else'span_nonzero'if p['wire_length32']else'span_zero';g=[int(x,16)for x in r['handoff_state']['registers31']];raw=bytes.fromhex(p['input_fixture_hex'])
 return kind,{'F':int(r['frame_base_SP'],16),'C':g[11],'S':g[3],'J':p['node_result_fixture'],'Z':p['data_result_fixture'],'D':p['wire_tag32'],'U':p['wire_type16'],'L':p['wire_length32'],'V':int.from_bytes(raw[10:14],'big')if kind=='u32'else 0,'Q':int.from_bytes(raw[10:18],'big')if kind=='u64'else 0,'P':p['inputs8'][0]+10 if kind.startswith('span')else 0,'H':int(r['original_container'],16),'N':r['outer_size32']}
def bindings(v,values):return[(v.common[k],resize(x,v.common[k].size()))for k,x in values.items()]+[(v.counter,resize(1,64))]
def checked_premises(v,b):
 queries=0
 for premise in v.owned()+v.guards+v.extra+v.address_checks:
  q=z3.simplify(z3.substitute(premise,*b))
  if not z3.is_true(q):
   s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(z3.Not(q));assert s.check()==z3.unsat;queries+=1
 return queries
def evaluations(e,models):
 rows=[]
 for r in e['predecessor_states']:
  kind,base=values_for(r)
  for derived in [False,True]:
   values=dict(base)
   if derived:values['D']=KEY
   found=values['D']==KEY;v=models[kind,found];c=v.common;b=bindings(v,values);queries=checked_premises(v,b)
   fields=[('C',0x418,8,values['H']),('C',0x4d0,8,0xfffffe000a636728),('C',0x5f0,8,values['S']+0xbc4),('C',0x710,8,values['J']if found else 0),('C',0x758,8,values['C']+0x710),('C',0xc8,8,0xfffffe000a661c34),('S',0,4,0xcb2d4174),('S',0xbc4,4,0),('H',0,8,values['J']),('H',8,8,values['J']),('S',0xa10,8,values['L']+10),('J',0x10,4,values['L']+10),('J',0x18,8,values['Z'])]
   if found:fields.extend([('C',0x560,8,values['Z']),('S',0x260,8,values['L']+10+LENGTH_BIAS),('F',0xbd0,8,0)])
   else:fields.append(('F',0xaa8,8,0))
   for root,off,n,want in fields:assert H.numeric(H.cell(v,c[root]+off,n),b)==want
   target=0xfffffe000a656ef0 if found else 0xfffffe000a636728;modifier=0x5e04 if found else 0x415f;assert H.numeric(v.edges[-1]['target'],b)==target and H.numeric(v.edges[-1]['modifier'],b)==modifier
   rows.append({'predecessor_case_index':r['predecessor_case_index'],'domain':kind,'evaluation_kind':'derived_key_substitution'if derived else'retained_predecessor_projection','raw_tag32':hex(values['D']),'original_raw_tag32':hex(base['D']),'found':found,'post_search_fields_checked':len(fields),'unbound_controller_premise_queries_unsat':queries,'independent_controller_reads':v.controller_reads,'independent_bank_bytes':v.bank_calls,'final_target':hex(target),'all_storage_branch_and_lookup_premises_checked':True,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'native_target_executed':False,'all_checks_pass':True})
 return rows
def adid_field_certificate(e,models):
 r=next(r for r in e['predecessor_states']if values_for(r)[0]=='u32');_,values=values_for(r);values.update(D=KEY,U=0x9777,L=4,V=0,N=14);v=models['u32',True];b=bindings(v,values);queries=checked_premises(v,b);field=e['adid_evidence']['packets'][0]['field_record_hex'];assert field=='fa83411297770000000400000000';raw=bytes.fromhex(field);actual=bytes(H.numeric(H.cell(v,v.common['Z']+j,1),b)for j in range(14));want=bytes(x^H.py_mask(values['Z']+j)for j,x in enumerate(raw));assert actual==want
 assert H.numeric(H.cell(v,v.common['C']+0x710,8),b)==values['J']and H.numeric(v.edges[-1]['target'],b)==0xfffffe000a656ef0
 return {'source_predecessor_case_index':r['predecessor_case_index'],'synthetic_tag_and_scalar_substitution':True,'raw_record_hex':field,'protected_record_hex':actual.hex(),'protected_record_bytes_checked':14,'matches_all_twelve_frozen_ADID_field_records':all(p['field_record_hex']==field for p in e['adid_evidence']['packets']),'lookup_found_original_synthetic_node':True,'next_header_request_target':'0xfffffe000a656ef0','all_storage_branch_and_lookup_premises_checked':True,'unbound_controller_premise_queries_unsat':queries,'native_target_executed':False,'whole_ADID_packet_parsed_by_kext':False,'transport_identity_established':False}
def negative_controls(e):
 rows=[]
 for pc in [0xfffffe000a637158,0xfffffe000a662c4c,0xfffffe000a636104]:
  changed=copy.deepcopy(e);all_spans=changed['publication_source']['spans']+changed['source']['spans'];row=next(s for s in all_spans if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);replacement=(((int.from_bytes(old,'little')&~(0xfff<<10))|(0x568<<10)).to_bytes(4,'little'))if pc==0xfffffe000a636104 else bytes.fromhex('1f2003d5');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex()
  if pc==0xfffffe000a637158:
   v=prepared(changed,'u32');v.extra.append(v.common['D']==KEY);v.run('search_nonnull').run('search_node').run('node_decode_prepare').run('word_bridge_read').run('decode_word');bad=v.read('w22')!=(v.common['D']^SUCCESS);stop='before_following_wrong_tag_comparison'
  elif pc==0xfffffe000a662c4c:
   v=searched(changed,'u32',True);bad=H.cell(v,v.common['C']+0x710,8)!=v.common['J'];stop='before_loading_unpublished_found_node'
  else:
   v=searched(changed,'u32',True).run('schema_node_fields');store=next(q for q in reversed(v.stores)if q['pc']==0xfffffe000a661cb8);bad=store['address']!=v.common['C']+0x560;stop='before_entering_extent_check'
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat;rows.append({'mutated_PC':hex(pc),'original_word_hex':old.hex(),'replacement_word_hex':replacement.hex(),'satisfiable_violation_query':s.to_smt2(),'stop_boundary':stop,'normal_oracle_rejected':True,'native_target_executed':False})
 return rows
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases=evaluations(e,models);certificate=adid_field_certificate(e,models);controls=negative_controls(e);old=json.loads(read(ROOT/'userclient_early_schema_audit.json'));prior=[]
 for kind in DOMAINS:
  p=next(q for q in old['source_proofs']if q['name']==kind+'_composed_exhaustion_to_raw_fa834112_lookup_preserves_record_and_container');ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));result=s.check();assert result==z3.unsat,(p['name'],str(result),s.reason_unknown());prior.append({'name':p['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_early_schema_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'prior_schema_queries_unsat':len(prior),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'retained_predecessor_projections':sum(q['evaluation_kind']=='retained_predecessor_projection'for q in cases),'derived_key_substitution_projections':sum(q['evaluation_kind']=='derived_key_substitution'for q in cases),'post_search_fields_checked':sum(q['post_search_fields_checked']for q in cases),'unbound_controller_premise_queries_unsat':sum(q['unbound_controller_premise_queries_unsat']for q in cases)+certificate['unbound_controller_premise_queries_unsat'],'additional_prefix_cells_reconstructed':sum(len(r['schema_search_additional_source_cells'])for r in e['predecessor_states']),'negative_source_controls':len(controls),'missing_cells_assigned_concrete_values':0,'independent_controller_reads_per_composition':4,'independent_bank_bytes_per_composition':2,'ADID_compatible_record_bytes_checked':14,'ADID_record_type16':0x9777,'ADID_record_length32':4,'composed_domains':4}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_schema_proofs':prior,'partial_state_evaluations':cases,'ADID_field_certificate':certificate,'negative_source_controls':controls,'independent_totals':totals,'conditional_schema_search_step_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
