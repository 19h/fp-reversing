#!/usr/bin/env python3
"""Compose source words through actual protected schema fields and output.
O(I+query DAG+C*I) construction/space; SMT search is separately bounded.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_schema_search as Parent
import audit_userclient_early_publication as Publication
import audit_userclient_early_schema as Schema
import recover_userclient_schema_scalar as R
H=Parent.H;DEC=Parent.DEC;SUCCESS=Parent.SUCCESS
class Model(Parent.Model):
 def __init__(self,e):
  self.codec_rewrites=[]
  combined=copy.deepcopy(e);combined['source']['spans']=e['lookup_source']['spans']+e['source']['spans'];super().__init__(combined)
 def write(self,name,v):
  if self.pc==0xfffffe000a637244 and name=='w22':
   b=resize(self.values[(0xfffffe000a637238,'w8')],32);assert z3.simplify(self.read('w30')).as_long()==SUCCESS and z3.simplify(self.read('w15')).as_long()==0x635c00cc
   expected=z3.simplify(b+SUCCESS-((b<<1)&0x635c00cc));assert z3.simplify(v).eq(expected),'word-codec source shape'
   self.codec_rewrites.append({'source_PC':hex(self.pc),'rule':'word32_add_and_sub_is_xor','source_shape_checked':True});v=z3.simplify(b^SUCCESS)
  if self.pc==0xfffffe000a6393bc and name=='w8':
   b=resize(self.values[(0xfffffe000a6393a4,'w9')],32);expected=z3.simplify(b-(((b&0x365f)^(b&1))<<1)+0x365e);assert z3.simplify(v).eq(expected),'type-codec source shape'
   self.codec_rewrites.append({'source_PC':hex(self.pc),'rule':'type32_add_mask_xor_sub_is_xor','source_shape_checked':True});v=z3.simplify(b^0x365e)
  super().write(name,v)
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
   if i.address in R.RETAGS:
    assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.RETAGS[i.address];self.count+=1
   elif i.address in R.DIRECT:
    m,t=R.DIRECT[i.address];assert i.mnemonic==m and i.operands[0].imm&((1<<64)-1)==t;cond=self.condition(m[2:]);self.direct.append({'pc':i.address,'condition':cond,'next_PC':z3.If(cond,resize(t,64),resize(i.address+4,64))});self.count+=1
    if take is not None:self.guards.append(cond if take else z3.Not(cond))
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one',take);self.e=original
  self.e=original;return self
def prepared(e,kind='u32'):
 v=Model(e)
 for label in H.PATH:v.run(label)
 if kind=='u32':v.run('primary_gate',False).run('u32_gate');v.extra.append(v.common['L']==4);v.run('u32_request').run('length_bridge').run('word_writer')
 elif kind=='u64':v.run('primary_gate',True).run('secondary_gate',True).run('u64_gate');v.extra.append(v.common['L']==8);v.run('u64_request').run('u64_writer')
 else:
  v.run('primary_gate',True).run('secondary_gate',False).run('span_gate',False).run('span_length')
  if kind=='span_zero':v.extra.append(v.common['L']==0)
  else:v.extra.extend([v.common['L']!=0,v.counter==1]);v.with_span=True;v.run('span_request');v.seed('x10',v.counter);v.run('span_copy')
 v.publication_store_start=len(v.stores);Publication.finish(v);v.extra.extend([z3.ZeroExt(32,v.common['N'])==z3.ZeroExt(32,v.common['L'])+10,v.common['D']==Parent.KEY]);v.schema_store_start=len(v.stores);Schema.finish(v);v.search_store_start=len(v.stores)
 v.run('search_nonnull').run('search_node').run('node_decode_prepare').run('word_bridge_read').run('decode_word').run('tag_match').run('search_result').run('search_callback').run('schema_search_return');Parent.matched(v);v.scalar_store_start=len(v.stores);return v
def header(v):
 v.scalar_load_start=len(v.loads)
 v.run('word_bridge_read').run('decode_word');v.header_tag=v.read('w22')
 v.run('schema_tag_return').run('schema_type_decode');v.header_type=v.read('w8')
 v.run('schema_type_return').run('schema_length_bridge').run('decode_word');v.header_length=v.read('w22')
 return v.run('schema_body_extent')
TOKEN=0x886a1ca3;PHASE=0x7795e642;TYPE_ERROR=0xce515ae1;SHORT=0xce515bb8
U32_TARGET=0xfffffe000a63677c;ERROR_TARGET=0xfffffe000a641c1c

def finished(e,kind='u32'):
 v=header(prepared(e,kind)).run('schema_type_gate',kind!='u32')
 if kind=='u32':v.run('schema_scalar_request').run('schema_length_bridge').run('decode_word').run('schema_scalar_return').run('schema_commit_entry')
 else:v.run('schema_other_type')
 v.run('schema_commit_cursor')
 if kind=='u32':v.run('schema_scalar_output')
 return v.run('schema_caller_return').run('schema_caller_status')

def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  premises=[]if v is None else v.owned()+v.guards+v.extra
  p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);r=p.check();assert r==z3.sat,(name,'premises',str(r),p.reason_unknown())
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.Or(bad,*([]if v is None else[z3.Not(q)for q in v.address_checks]))));query=s.to_smt2();r=s.check();assert r==z3.unsat,(name,str(r),s.reason_unknown())
  out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':0 if v is None else v.count,'codec_shape_checks':[]if v is None else copy.deepcopy(v.codec_rewrites)})
  if v is not None:visited.update(v.visited)
  print('proved '+name,flush=True)
 b=z3.BitVec('SC_codec_operand32',32)
 prove('universal_word32_add_mask_sub_equals_xor',None,(b+SUCCESS-((b<<1)&0x635c00cc))!=(b^SUCCESS))
 prove('universal_type32_mask_xor_sub_add_equals_xor',None,(b-(((b&0x365f)^(b&1))<<1)+0x365e)!=(b^0x365e))
 v=header(prepared(e));c=v.common
 loads=v.loads[v.scalar_load_start:]
 pcs=[0xfffffe000a637158,0xfffffe000a637190,0xfffffe000a6371d4,0xfffffe000a637214,0xfffffe000a639348,0xfffffe000a639380]
 byte_loads=[q for q in loads if q['pc']in pcs];assert len(byte_loads)==10,len(byte_loads)
 prove('actual_protected_header_bytes_decode_tag_type_length_and_exact_fit',v,z3.Or(v.header_tag!=(c['D']^SUCCESS),H.cell(v,c['S']+0xc70,2)!=(c['U']^0x365e),v.read('w22')!=(c['L']^SUCCESS),H.cell(v,c['S']+0xad8,8)!=z3.ZeroExt(32,c['L'])+10,*[q['address']!=c['Z']+j for j,q in enumerate(byte_loads)],Publication.edge(v,0xfffffe000a638c04,0x9247)))
 cut=Model(e);c=cut.common;cursor=z3.BitVec('SC_cursor64',64);extent=z3.BitVec('SC_extent32',32);length=z3.BitVec('SC_length32',32)
 cut.extra.append(z3.ULE(cursor,z3.ZeroExt(32,extent)))
 for reg,x in [('x4',c['S']),('x7',TABLE),('w19',PHASE),('w3',TOKEN),('w30',SUCCESS),('w22',length^SUCCESS)]:cut.seed(reg,x)
 mem(cut,c['F']+0xbd0,8,cursor);mem(cut,c['S']+0x260,8,z3.ZeroExt(32,extent)+Parent.LENGTH_BIAS);cut.run('schema_body_extent')
 fits=z3.ULE(cursor+10+z3.ZeroExt(32,length),z3.ZeroExt(32,extent))
 prove('all_length32_extent32_bounded_cursor64_exact_body_fit_gate',cut,z3.Or(H.cell(cut,c['S']+0xad8,8)!=cursor+10+z3.ZeroExt(32,length),Publication.edge(cut,z3.If(fits,resize(0xfffffe000a638c04,64),resize(0xfffffe000a63abf4,64)),0x9247)))
 mem(cut,c['C']+0x4d0,8,0xfffffe000a636728);cut.run('schema_short_body').run('schema_caller_return');prove('short_body_returns_raw_error_without_committing_cursor_or_scalar',cut,z3.Or(cut.read('w23')!=SHORT,Publication.edge(cut,0xfffffe000a636728,0x415f),z3.BoolVal(any(q['pc']in [0xfffffe000a63ac58,0xfffffe000a63acb8]for q in cut.stores))))
 cut=Model(e);c=cut.common;rawtype=z3.BitVec('SC_raw_type16',16)
 for reg,x in [('x4',c['S']),('x7',TABLE),('w24',0x7795e3ce),('w19',PHASE),('w3',TOKEN),('w30',SUCCESS),('w22',length^SUCCESS)]:cut.seed(reg,x)
 mem(cut,c['S']+0xc70,2,rawtype^0x365e);cut.run('schema_type_gate')
 d=cut.direct[-1];prove('all_type16_exact_u32_direct_gate',cut,d['next_PC']!=z3.If(rawtype==0x9777,resize(0xfffffe000a638c18,64),resize(0xfffffe000a63abdc,64)))
 cut.extra.append(rawtype==0x9777);prove('u32_all_length32_exact_four_byte_body_gate',cut,Publication.edge(cut,z3.If(length==4,resize(0xfffffe000a638c50,64),resize(0xfffffe000a63abf4,64)),0x9247))
 cut=Model(e);cut.seed('w9',z3.ZeroExt(16,rawtype^0x365e));cut.run('schema_other_type')
 prove('other_type16_direct_span_u64_or_error_routes',cut,z3.Or(cut.direct[-2]['next_PC']!=z3.If(rawtype==0x50db,resize(0xfffffe000a63ac3c,64),resize(0xfffffe000a63abe8,64)),cut.direct[-1]['next_PC']!=z3.If(rawtype==0x8485,resize(0xfffffe000a63ac3c,64),resize(0xfffffe000a63abf4,64))))
 models={}
 for kind in Parent.DOMAINS:
  v=finished(e,kind);c=v.common;ok=kind=='u32';target=U32_TARGET if ok else ERROR_TARGET
  bad=[H.cell(v,c['S']+0xc70,2)!=(c['U']^0x365e),H.cell(v,c['S']+0xad8,8)!=z3.ZeroExt(32,c['L'])+10,H.cell(v,c['F']+0xaa8,8)!=z3.ZeroExt(32,c['L'])+10,H.cell(v,c['S']+0xbc4,4)!=(c['V']if ok else 0),H.cell(v,c['C']+0x5f0,8)!=c['S']+0xbc4,v.read('w23')!=(SUCCESS if ok else TYPE_ERROR),Publication.edge(v,target,0xd4c)]
  bad.extend([H.cell(v,c['H'],8)!=c['J'],H.cell(v,c['H']+8,8)!=c['J'],H.cell(v,c['J'],8)!=0,H.cell(v,c['J']+8,8)!=0,H.cell(v,c['J']+0x10,4)!=c['L']+10,H.cell(v,c['J']+0x18,8)!=c['Z'],H.cell(v,c['C']+0x560,8)!=c['Z']])
  end=c['Z']+z3.ZeroExt(32,c['L'])+10;bad.extend(z3.Not(z3.Or(z3.ULE(q['address']+q['size_bytes'],c['Z']),z3.ULE(end,q['address'])))for q in v.stores[v.scalar_store_start:])
  if ok:
   body=[q for q in v.loads[v.scalar_load_start:]if q['size_bytes']==1][-4:];assert len(body)==4;bad.extend(q['address']!=c['Z']+10+j for j,q in enumerate(body))
  prove(kind+'_complete_same_node_header_body_output_cursor_and_caller',v,z3.Or(*bad));models[kind]=v
 cut=Model(e);c=cut.common;status=z3.BitVec('SC_status32',32)
 for reg,x in [('x7',TABLE),('w3',TOKEN),('w30',SUCCESS),('w28',PHASE),('w23',status)]:cut.seed(reg,x)
 cut.run('schema_caller_status');prove('all_status32_exact_saved_caller_success_or_error_edge',cut,Publication.edge(cut,z3.If(status==SUCCESS,resize(U32_TARGET,64),resize(ERROR_TARGET,64)),0xd4c))
 for pc in [0xfffffe000a639344,0xfffffe000a639378]:
  cut=Model(e);row=next(s for s in e['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);word=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(word,pc));reg=i.reg_name(i.operands[0].reg);p=z3.BitVec('SC_alternate_pointer64',64);cut.seed(reg,p);cut.e={'source':{'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':word.hex()}]}};cut.run('alternate');prove('alternate_type_retag_'+format(pc,'x')+'_bit_transform_only',cut,cut.read(reg)!=((p&0xffffffffffff)|(0xc8a2<<48)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']}
 assert captured<=visited,captured-visited
 return out,models,len(visited&captured)

def projected_fields(v,values):
 return [('C',0x418,8,values['H']),('C',0x4d0,8,0xfffffe000a636728),('C',0x5f0,8,values['S']+0xbc4),('C',0x560,8,values['Z']),('C',0x710,8,values['J']),('H',0,8,values['J']),('H',8,8,values['J']),('J',0x10,4,values['L']+10),('J',0x18,8,values['Z']),('S',0xc70,2,values['U']^0x365e),('S',0xad8,8,values['L']+10),('F',0xaa8,8,values['L']+10),('S',0xbc4,4,values['V']if values['U']==0x9777 else 0)]

def evaluations(e,models):
 rows=[]
 for r in e['predecessor_states']:
  kind,values=Parent.values_for(r);original=values['D'];values['D']=Parent.KEY;v=models[kind];b=Parent.bindings(v,values);queries=Parent.checked_premises(v,b);fields=projected_fields(v,values)
  for root,off,n,want in fields:assert H.numeric(H.cell(v,v.common[root]+off,n),b)==want
  success=kind=='u32';target=U32_TARGET if success else ERROR_TARGET;status=SUCCESS if success else TYPE_ERROR
  assert H.numeric(v.edges[-1]['target'],b)==target and H.numeric(v.edges[-1]['modifier'],b)==0xd4c and H.numeric(v.read('w23'),b)==status
  rows.append({'predecessor_case_index':r['predecessor_case_index'],'domain':kind,'evaluation_kind':'derived_key_substitution','original_raw_tag32':hex(original),'raw_tag32':hex(values['D']),'raw_type16':hex(values['U']),'length32':values['L'],'output32':values['V']if success else 0,'raw_status32':hex(status),'final_target':hex(target),'fields_checked':len(fields),'unbound_controller_premise_queries_unsat':queries,'codec_shape_checks':copy.deepcopy(v.codec_rewrites),'all_storage_branch_and_lookup_premises_checked':True,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'native_target_executed':False,'all_checks_pass':True})
 return rows

def adid_field_certificate(e,models):
 r=next(r for r in e['predecessor_states']if Parent.values_for(r)[0]=='u32');_,values=Parent.values_for(r);values.update(D=Parent.KEY,U=0x9777,L=4,V=0,N=14);v=models['u32'];b=Parent.bindings(v,values);queries=Parent.checked_premises(v,b);field=e['adid_evidence']['packets'][0]['field_record_hex'];assert field=='fa83411297770000000400000000';raw=bytes.fromhex(field);actual=bytes(H.numeric(H.cell(v,v.common['Z']+j,1),b)for j in range(14));assert actual==bytes(x^H.py_mask(values['Z']+j)for j,x in enumerate(raw))
 for root,off,n,want in projected_fields(v,values):assert H.numeric(H.cell(v,v.common[root]+off,n),b)==want
 assert H.numeric(v.read('w23'),b)==SUCCESS and H.numeric(v.edges[-1]['target'],b)==U32_TARGET
 return {'source_predecessor_case_index':r['predecessor_case_index'],'synthetic_tag_and_scalar_substitution':True,'raw_record_hex':field,'protected_record_hex':actual.hex(),'protected_record_bytes_checked':14,'matches_all_twelve_frozen_ADID_field_records':all(p['field_record_hex']==field for p in e['adid_evidence']['packets']),'decoded_output32':0,'committed_cursor64':14,'raw_status32':hex(SUCCESS),'saved_caller_success_target':hex(U32_TARGET),'unbound_controller_premise_queries_unsat':queries,'all_storage_branch_and_lookup_premises_checked':True,'native_target_executed':False,'whole_ADID_packet_parsed_by_kext':False,'transport_identity_established':False}

def negative_controls(e):
 rows=[]
 for pc in [0xfffffe000a638c0c,0xfffffe000a63ac58,0xfffffe000a63acb8]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);old=bytes(raw[off:off+4]);replacement=((int.from_bytes(old,'little')^(1<<5)).to_bytes(4,'little'))if pc==0xfffffe000a638c0c else bytes.fromhex('1f2003d5');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex()
  if pc==0xfffffe000a638c0c:
   v=header(prepared(changed)).run('schema_type_gate');bad=v.direct[-1]['next_PC']!=0xfffffe000a638c18;stop='before_following_mutated_type_branch'
  else:
   v=finished(changed);c=v.common;bad=H.cell(v,c['F']+0xaa8,8)!=14 if pc==0xfffffe000a63ac58 else H.cell(v,c['S']+0xbc4,4)!=c['V'];stop='after_saved_caller_dispatch'
  premises=v.owned()+v.guards+v.extra+v.address_checks;p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);assert p.check()==z3.sat
  s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,bad);assert s.check()==z3.sat
  rows.append({'mutated_PC':hex(pc),'original_word_hex':old.hex(),'replacement_word_hex':replacement.hex(),'satisfiable_violation_query':s.to_smt2(),'stop_boundary':stop,'normal_oracle_rejected':True,'native_target_executed':False})
 return rows

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases=evaluations(e,models);certificate=adid_field_certificate(e,models);controls=negative_controls(e);old=json.loads(read(ROOT/'userclient_schema_search_audit.json'));prior=[]
 for kind in Parent.DOMAINS:
  p=next(q for q in old['source_proofs']if q['name']==kind+'_complete_found_buffer_extent_and_next_header_request');ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));result=s.check();assert result==z3.unsat,(p['name'],str(result),s.reason_unknown());prior.append({'name':p['name'],'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_schema_search_audit.json')});print('rechecked '+kind,flush=True)
 totals={'new_source_queries_unsat':len(proofs),'prior_search_queries_unsat':len(prior),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'derived_key_substitution_projections':len(cases),'fields_checked':sum(q['fields_checked']for q in cases),'unbound_controller_premise_queries_unsat':sum(q['unbound_controller_premise_queries_unsat']for q in cases)+certificate['unbound_controller_premise_queries_unsat'],'negative_source_controls':len(controls),'missing_cells_assigned_concrete_values':0,'independent_controller_reads_per_composition':4,'independent_bank_bytes_per_composition':2,'ADID_compatible_record_bytes_checked':14,'ADID_decoded_output32':0,'ADID_committed_cursor64':14,'composed_domains':4}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_search_proofs':prior,'partial_state_evaluations':cases,'ADID_field_certificate':certificate,'negative_source_controls':controls,'independent_totals':totals,'conditional_schema_u32_decoding_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
