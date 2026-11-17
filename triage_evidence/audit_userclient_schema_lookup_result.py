#!/usr/bin/env python3
"""Execute actual schema packet through helper and caller result consumers.
O(I+C*I+256+query DAG) construction/space; SMT search bounded separately.
Authenticated return is an explicit opaque ABI boundary, not PAC emulation.
"""
import copy,json
import z3
from kext_port_tools import ROOT,TABLE,qword,IMAGE
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_schema_registry as Parent
import recover_userclient_schema_lookup_result as R
H=Parent.H;DEC=Parent.DEC;Publication=Parent.Publication;Schema=Parent.Schema
SUCCESS=Parent.SUCCESS;TOKEN=Parent.TOKEN;PHASE=Parent.PHASE;KEY_BIAS=Parent.KEY_BIAS
EMPTY=0x629f8775;OCCUPIED=0x629f8777;TAG=0xffc0000000000000;MASK=(1<<64)-1
pc=R.pc
PROFILES=['hit_nonnull','hit_null','empty_candidate','null_array']
class Model(Parent.Model):
 def __init__(self,e):
  self.result_receipt=e;self.result_controller_reads=[];self.result_table_reads=[];self.result_bank_rewrites=[];self.PAC_boundaries=[];self.PAC_checks=[];self.result_array_owned=False;self.result_frame_owned=False;self.profile=None
  combined=copy.deepcopy(e);combined['source']['spans']=e['registry_source']['spans']+e['source']['spans'];super().__init__(combined)
  self.payload=z3.BitVec('LR_selected_raw_payload64',64);self.seed('x6',pc(0xccc30d0));self.seed('x7',TABLE);self.run('result_frame_roots')
 def owned(self):
  out=super().owned();c=self.common
  def sep(a,n,b,m):return z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))
  ranges=[(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['H'],resize(16,64)),(c['J'],resize(32,64)),(c['Z'],z3.ZeroExt(32,c['L'])+10)]
  if self.header_owned:ranges.append((self.holder,resize(16,64)))
  if self.result_frame_owned:
   out.append(z3.UGE(c['F'],0x70))
   for a,n in ranges:out.append(sep(c['F']-0x70,resize(0x70,64),a,n))
   for a,off,n in IMAGE.segments:out.append(sep(c['F']-0x70,resize(0x70,64),resize(a,64),resize(n,64)))
  if self.result_array_owned:
   length=24*z3.ZeroExt(32,self.capacity);out.extend([self.capacity!=0,self.entries!=0,z3.ULE(self.entries,resize(MASK,64)-length)])
   for a,n in ranges+[(c['F']-0x70,resize(0x1160,64))]:out.append(sep(self.entries,length,a,n))
   for a,off,n in IMAGE.segments:out.append(sep(self.entries,length,resize(a,64),resize(n,64)))
  return out
 def load(self,a,n):
  if self.pc in [pc(0xa5ae380),pc(0xa5ae388)]:
   assert n==8;expected=pc(0xccc3158)if self.pc==pc(0xa5ae380)else pc(0xccc32f8);value=z3.BitVec('LR_controller64_'+str(len(self.result_controller_reads)),64);self.address_checks.append(a==expected);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.result_controller_reads.append({'pc':self.pc,'address':a,'value':value});return value
  rule=self.result_receipt['result_bank_rule'];left,right=int(rule['left'],16),int(rule['right'],16)
  if self.pc==pc(0xa5ae454):
   assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.result_bank_input=z3.Extract(7,0,a-left);self.result_bank_byte=z3.BitVec('LR_helper_bank_byte8',8);self.address_checks.append(a==left+z3.ZeroExt(56,self.result_bank_input));return self.result_bank_byte
  if self.pc==pc(0xa5ae468):
   assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==right+z3.ZeroExt(56,self.result_bank_byte^int(rule['key'],16)));self.result_bank_rewrites.append({'source_PC':hex(self.pc),'rule':'helper_table','certified_inputs':256});return self.result_bank_input^int(rule['constant'],16)
  if self.pc==pc(0xa5ae484):
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==int(rule['slot'],16));return resize(int(rule['original_pointer']['target'],16),64)
  if self.pc in [pc(0xa5ae718),pc(0xa5ae778),pc(0xa65b598)]:
   assert self.profile in PROFILES and self.profile!='null_array';probe=self.common['V']&(self.capacity-1);entry=self.entries+24*z3.ZeroExt(32,probe);expected=entry+(0 if n==4 else 8 if self.pc==pc(0xa5ae778)else 16);self.address_checks.append(a==expected);self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.result_table_reads.append({'pc':self.pc,'address':a,'size_bytes':n})
   if n==4:return resize(EMPTY if self.profile=='empty_candidate'else OCCUPIED,32)
   assert n==8
   if self.pc==pc(0xa5ae778):return resize(KEY_BIAS,64)+z3.ZeroExt(32,self.common['V'])
   return resize(0,64)if self.profile in ['empty_candidate','hit_null']else self.payload
  if self.pc in R.BRANCHES:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
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
   elif i.mnemonic=='pacibsp':
    assert i.address==pc(0xa5ae354);self.raw_return_link=self.read('x30');self.entry_SP=self.read('sp');self.entry_saved={j:self.read('x'+str(j))for j in range(19,30)};self.signed_return_token=z3.BitVec('LR_opaque_signed_return64',64);self.write('x30',self.signed_return_token);self.PAC_boundaries.append({'source_PC':hex(i.address),'kind':'opaque_B_key_SP_signing_boundary','native_PAC_implemented':False});self.count+=1
   elif i.mnemonic=='retab':
    assert i.address==pc(0xa5ae888);self.PAC_checks.extend([self.read('sp')==self.entry_SP,self.read('x30')==self.signed_return_token,*[self.read('x'+str(j))==value for j,value in self.entry_saved.items()]]);self.edges.append({'pc':i.address,'target':self.raw_return_link,'modifier':self.read('sp'),'conditional_authenticated_return':True});self.PAC_boundaries.append({'source_PC':hex(i.address),'kind':'normal_authenticated_return_ABI_premise','native_PAC_implemented':False});self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one',take);self.e=original
  self.e=original;return self

def requested(e):
 # Construct with this Model; every business output comes from source words.
 v=Model(e)
 for label in H.PATH:v.run(label)
 v.run('primary_gate',False).run('u32_gate');v.extra.append(v.common['L']==4);v.run('u32_request').run('length_bridge').run('word_writer');v.publication_store_start=len(v.stores);Publication.finish(v);v.extra.extend([z3.ZeroExt(32,v.common['N'])==z3.ZeroExt(32,v.common['L'])+10,v.common['D']==Parent.Parent.Parent.KEY]);v.schema_store_start=len(v.stores);Schema.finish(v);v.search_store_start=len(v.stores)
 v.run('search_nonnull').run('search_node').run('node_decode_prepare').run('word_bridge_read').run('decode_word').run('tag_match').run('search_result').run('search_callback').run('schema_search_return');Parent.Parent.Parent.matched(v);v.scalar_store_start=len(v.stores)
 Parent.Parent.header(v).run('schema_type_gate',False).run('schema_scalar_request').run('schema_length_bridge').run('decode_word').run('schema_scalar_return').run('schema_commit_entry').run('schema_commit_cursor').run('schema_scalar_output').run('schema_caller_return').run('schema_caller_status')
 v.registry_store_start=len(v.stores);v.run('registry_request').run('registry_holder');v.extra.append(v.holder!=0);v.run('registry_resume').run('registry_return').run('registry_scalar');v.header_owned=True;mem(v,v.holder+4,4,v.capacity);mem(v,v.holder+8,8,v.entries);return v.run('registry_lookup_entry').run('registry_lookup_header').run('registry_lookup_record').run('registry_lookup_call')
def follow(v,label,modifier):
 v.address_checks.append(z3.Not(Publication.edge(v,R.SPANS[label][0],modifier)));return v.run(label)
def helper(e,profile):
 assert profile in PROFILES;v=requested(e);v.profile=profile;v.result_store_start=len(v.stores);v.result_frame_owned=True;c=v.common
 v.preserved_ranges=[(c['S']+0xbc4,4),(c['F']+0xaa8,8),(c['H'],16),(c['J'],32),(c['Z'],14)]
 v.preserved_cells=[(a,n,H.cell(v,a,n))for a,n in [(c['S']+0xbc4,4),(c['F']+0xaa8,8),(c['H'],8),(c['H']+8,8),(c['J']+0x18,8)]]
 if profile=='null_array':v.extra.append(v.entries==0)
 else:v.result_array_owned=True
 if profile=='hit_nonnull':v.extra.append(v.payload!=0)
 follow(v,'result_helper_entry',0x6a0f);v.run('result_helper_gate')
 if profile=='null_array':return follow(v,'result_status_return',0x24d2)
 follow(v,'result_helper_decode',0x24d2);follow(v,'result_flag_clear',0xe9d3);follow(v,'result_probe_setup',0xe9d3);follow(v,'result_probe_resume',0x5ae2);follow(v,'result_probe_wrap',0x9e2);follow(v,'result_probe_budget',0x9e2);follow(v,'result_probe_state',0xe32f)
 if profile=='empty_candidate':
  v.run('result_empty_test',True);v.address_checks.append(v.direct[-2]['next_PC']==R.SPANS['result_empty_test'][0]);v.address_checks.append(v.direct[-1]['next_PC']==R.SPANS['result_choose_empty'][0]);v.run('result_choose_empty');follow(v,'result_index',0x4db)
 else:
  v.address_checks.append(v.direct[-1]['next_PC']==R.SPANS['result_key_address'][0]);v.run('result_key_address').run('result_key_compare');follow(v,'result_found',0x8821);follow(v,'result_found_store',0x89ee);follow(v,'result_index',0x89ee)
 return follow(v,'result_status_return',0xe32f)
def consumed(e,profile):
 v=helper(e,profile);follow(v,'result_caller_return',v.common['F'])
 if profile!='null_array':follow(v,'result_payload_address',0x73ed);v.run('result_payload_copy')
 follow(v,'result_restore',0x73ed);follow(v,'result_inner_trampoline',0x9599);follow(v,'result_outer_trampoline',0x78f4);follow(v,'result_outer_status',0x78f4)
 if profile=='null_array':v.address_checks.append(z3.Not(Publication.edge(v,pc(0xa641c1c),0x64d8)))
 else:
  follow(v,'result_outer_found',0x64d8)
  if profile=='empty_candidate':v.address_checks.append(z3.Not(Publication.edge(v,pc(0xa641c1c),0x9fa)))
  else:
   follow(v,'result_outer_payload',0x9fa);v.address_checks.append(z3.Not(Publication.edge(v,pc(0xa636958)if profile=='hit_nonnull'else pc(0xa641c1c),0x9fa)))
 if profile!='hit_nonnull':v.run('registry_error_status')
 return v
def result_bad(v,final=True):
 c=v.common;profile=v.profile;record=c['S']+0x968;status=0xce515bbf if profile=='null_array'else SUCCESS;bad=[H.cell(v,record+0x18,4)!=status,*[z3.Not(q)for q in v.PAC_checks],*[H.cell(v,a,n)!=value for a,n,value in v.preserved_cells]]
 bad.extend(z3.Not(z3.Or(z3.ULE(q['address']+q['size_bytes'],a),z3.ULE(a+n,q['address'])))for q in v.stores[v.result_store_start:]for a,n in v.preserved_ranges)
 if profile!='null_array':
  bad.extend([H.cell(v,c['S']+0xa28,4)!=(c['V']&(v.capacity-1)),H.cell(v,c['S']+0x10,1)!=(0 if profile=='empty_candidate'else 1)])
  if final:bad.append(H.cell(v,c['C']+0x440,8)!=(v.payload if profile=='hit_nonnull'else 0))
 else:
  bad.append(H.cell(v,c['S']+0xa28,4)!=0);assert not v.result_table_reads;assert not any(q['pc']in [pc(0xa5ae524),pc(0xa5ae834),pc(0xa5ae84c),pc(0xa65b59c)]for q in v.stores[v.result_store_start:])
 if v.result_array_owned:
  bad.extend(z3.Not(z3.Or(z3.ULE(q['address']+q['size_bytes'],v.entries),z3.ULE(v.entries+24*z3.ZeroExt(32,v.capacity),q['address'])))for q in v.stores[v.result_store_start:])
 if final:
  if profile=='hit_nonnull':bad.append(Publication.edge(v,pc(0xa636958),0x9fa))
  else:
   want={'hit_null':0xce515bda,'empty_candidate':0xce515bc4,'null_array':0xce515bbf}[profile];bad.extend([H.cell(v,c['S']+0x1c,4)!=want,Publication.edge(v,pc(0xa66229c),0xb23e)])
 return z3.Or(*bad)

def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  premises=v.owned()+v.guards+v.extra;p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);r=p.check();assert r==z3.sat,(name,'premises',str(r),p.reason_unknown())
  obligation=z3.simplify(z3.Or(bad,*[z3.Not(q)for q in v.address_checks]));terms=list(obligation.children())if z3.is_or(obligation)else[obligation];chunks=[terms[j:j+2]for j in range(0,len(terms),2)]
  for j,terms in enumerate(chunks):
   label=name if len(chunks)==1 else name+'_part_'+str(j+1);s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.Or(*terms));query=s.to_smt2();r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown(),s.model()if r==z3.sat else'')
   out.append({'name':label,'semantic_contract':name,'counterexample_partition':j+1,'counterexample_partitions':len(chunks),'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count,'authenticated_return_boundaries':copy.deepcopy(v.PAC_boundaries),'helper_controller_read_widths_bits':[64 for q in v.result_controller_reads],'table_read_PCs':[hex(q['pc'])for q in v.result_table_reads],'helper_bank_rewrites':copy.deepcopy(v.result_bank_rewrites),'source_business_outputs_replaced':0});print('proved '+label,flush=True)
  visited.update(v.visited)
 v=Model(e);c=v.common;prove('original_prefix_frame_roots_from_source_stores',v,z3.Or(H.cell(v,c['F']+0xa60,8)!=TABLE,H.cell(v,c['F']+0xa30,8)!=pc(0xccc30d0)))
 v=helper(e,'hit_nonnull');c=v.common;g0,g1=(q['value']for q in v.result_controller_reads);t=c['F']-0x68+g0+g1
 prove('actual_helper_u64_controller_effects_and_saved_register_return',v,z3.Or(H.cell(v,pc(0xccc3158),8)!=((t*0x4d08a3fb)^0xa41a4d891208c018),H.cell(v,pc(0xccc32f8),8)!=((t^0xa41a4d891208c018)*0x4d08a3fb),*[z3.Not(q)for q in v.PAC_checks],Publication.edge(v,pc(0xa65b530),c['F'])))
 models={}
 for profile in PROFILES:
  v=consumed(e,profile);prove('actual_packet_helper_and_caller_'+profile,v,result_bad(v));models[profile]=v
 status=z3.BitVec('LR_cut_status32',32);flag=z3.BitVec('LR_cut_flag8',8);payload=z3.BitVec('LR_cut_payload64',64)
 def outer_cut():
  v=Model(e)
  for reg,value in [('x7',TABLE),('w1',PHASE),('w3',TOKEN),('w30',SUCCESS),('w23',status)]:v.seed(reg,value)
  return v.run('result_outer_status')
 v=outer_cut();prove('all_status32_outer_caller_gate',v,Publication.edge(v,z3.If(status==SUCCESS,resize(pc(0xa6368b0),64),resize(pc(0xa641c1c),64)),0x64d8))
 v=outer_cut();mem(v,v.common['S']+0x10,1,flag);v.run('result_outer_found');prove('all_flag8_outer_caller_uses_only_bit_zero',v,z3.Or(v.read('w23')!=0xce515bc4,Publication.edge(v,z3.If((flag&1)==0,resize(pc(0xa641c1c),64),resize(pc(0xa636904),64)),0x9fa)))
 v=outer_cut();mem(v,v.common['S']+0x10,1,1);v.run('result_outer_found');mem(v,v.common['C']+0x440,8,payload);v.run('result_outer_payload');prove('all_payload64_outer_caller_NULL_gate',v,z3.Or(v.read('w23')!=0xce515bda,Publication.edge(v,z3.If(payload==0,resize(pc(0xa641c1c),64),resize(pc(0xa636958),64)),0x9fa)))
 for label,reg in [('result_key_retag','x17'),('result_payload_retag','x10')]:
  v=Model(e);value=z3.BitVec('LR_alternate_pointer64',64);v.seed(reg,value);v.run(label);prove(label+'_top16_bit_transform_only',v,v.read(reg)!=((value&0xffffffffffff)|(0xc8a2<<48)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(captured&visited)

def evaluations(e,models):
 rows=[];certificates=[]
 predecessors=[r for r in e['predecessor_states']if Parent.Parent.Parent.values_for(r)[0]=='u32']
 for source,adid in [(r,False)for r in predecessors]+[(predecessors[0],True)]:
  _,values=Parent.Parent.Parent.values_for(source);original=values['D'];values['D']=Parent.Parent.Parent.KEY
  if adid:values.update(U=0x9777,L=4,V=0,N=14)
  for profile,v in models.items():
   b=Parent.Parent.Parent.bindings(v,values)+[(v.capacity,resize(128,32))];premises=[z3.simplify(z3.substitute(q,*b))for q in v.owned()+v.guards+v.extra+v.address_checks];p=z3.SolverFor('QF_BV');p.set(timeout=60000);p.add(*premises);assert p.check()==z3.sat,(profile,adid,p.reason_unknown());s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises,z3.simplify(z3.substitute(result_bad(v),*b)));assert s.check()==z3.unsat,(profile,adid,s.reason_unknown());c=v.common;fields=[('S',0xbc4,4,values['V']),('F',0xaa8,8,14),('F',0xa60,8,TABLE),('F',0xa30,8,pc(0xccc30d0)),('S',0x980,4,0xce515bbf if profile=='null_array'else SUCCESS),('S',0xa28,4,0 if profile=='null_array'else values['V']&127)]
   if profile!='null_array':fields.append(('S',0x10,1,0 if profile=='empty_candidate'else 1))
   if profile in ['empty_candidate','hit_null']:fields.append(('C',0x440,8,0))
   if profile!='hit_nonnull':fields.append(('S',0x1c,4,{'hit_null':0xce515bda,'empty_candidate':0xce515bc4,'null_array':0xce515bbf}[profile]))
   for root,off,n,want in fields:assert H.numeric(H.cell(v,c[root]+off,n),b)==want
   target=pc(0xa636958)if profile=='hit_nonnull'else pc(0xa66229c)
   # Target remains symbolic when payload is nonzero but otherwise arbitrary.
   # The complete result counterexample above proves its exact conditional value.
   if profile!='hit_nonnull':assert H.numeric(v.edges[-1]['target'],b)==target
   row={'source_predecessor_case_index':source['predecessor_case_index'],'profile':profile,'evaluation_kind':'derived_tag_and_declared_table_profile','original_raw_tag32':hex(original),'raw_tag32':hex(values['D']),'raw_scalar32':hex(values['V']),'capacity_profile32':128,'capacity_observed_natively':False,'numeric_fields_checked':len(fields),'premises_sat':True,'conditional_result_query_unsat':True,'final_target':hex(target),'helper_source_executed':True,'native_target_executed':False,'native_PAC_verified':False,'native_holder_values_supplied':0,'native_array_values_supplied':0,'native_payload_values_supplied':0,'continuous_guest_extended':False,'missing_cells_bound_to_concrete_values':0,'all_checks_pass':True}
   if adid:
    field=e['adid_evidence']['packets'][0]['field_record_hex'];actual=bytes(H.numeric(H.cell(v,c['Z']+j,1),b)for j in range(14));assert field=='fa83411297770000000400000000'and actual==bytes(x^H.py_mask(values['Z']+j)for j,x in enumerate(bytes.fromhex(field)));certificates.append({**row,'raw_record_hex':field,'protected_record_hex':actual.hex(),'protected_bytes_checked':14,'matches_all_twelve_frozen_field_records':all(p['field_record_hex']==field for p in e['adid_evidence']['packets']),'derived_entry_key64':hex(KEY_BIAS),'whole_ADID_packet_parsed_by_kext':False,'transport_identity_established':False})
   else:rows.append(row)
 return rows,certificates

def negative_controls(e):
 rows=[]
 for addr,profile,label in [(pc(0xa5ae834),'hit_nonnull','found-byte store'),(pc(0xa65b59c),'hit_nonnull','payload output store'),(pc(0xa6368f8),'empty_candidate','found-failure status')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=addr<int(s['end_exclusive'],16));off=addr-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);original=bytes(raw[off:off+4]);word=int.from_bytes(original,'little')
  if addr==pc(0xa5ae834):word=(word&~31)|31
  elif addr==pc(0xa65b59c):word|=1<<10
  else:word^=1<<10
  replacement=word.to_bytes(4,'little');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex()
  if addr==pc(0xa5ae834):
   v=helper(changed,profile);bad=H.cell(v,v.common['S']+0x10,1)!=1;stop='before_caller_found_byte_consumer'
  elif addr==pc(0xa65b59c):
   v=helper(changed,profile);follow(v,'result_caller_return',v.common['F']);follow(v,'result_payload_address',0x73ed);v.run('result_payload_copy');q=next(q for q in reversed(v.stores)if q['pc']==addr);bad=q['address']!=v.common['C']+0x440;stop='after_mutated_store_before_output_read'
  else:
   v=consumed(changed,profile);bad=H.cell(v,v.common['S']+0x1c,4)!=0xce515bc4;stop='at_cleanup_request_without_executing_cleanup'
  premises=v.owned()+v.guards+v.extra+v.address_checks;s=z3.SolverFor('QF_BV');s.set(timeout=60000);s.add(*premises);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat
  rows.append({'mutated_PC':hex(addr),'label':label,'original_word_hex':original.hex(),'replacement_word_hex':replacement.hex(),'satisfiable_violation_query':s.to_smt2(),'normal_oracle_rejected':True,'stop_boundary':stop,'native_target_executed':False})
 return rows

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases,certs=evaluations(e,models);controls=negative_controls(e);prior=[]
 selected={'userclient_schema_scalar_audit.json':['universal_word32_add_mask_sub_equals_xor','universal_type32_mask_xor_sub_add_equals_xor'],'userclient_schema_registry_audit.json':['universal_caller_decoder_pre_multiply_equality','complete_actual_u32_to_token541_packet_and_pending_lookup_call'],'userclient_hash_table_lookup_audit.json':['positive_capacity_initial_probe_is_in_bounds','empty_selected_index_and_success_status_stores'],'userclient_hash_table_initializer_audit.json':['all_index0_to127_original_entry_defaults_and_loop_control']}
 for filename,names in selected.items():
  old=json.loads(read(ROOT/filename))
  for name in names:
   p=next(q for q in old['source_proofs']if q.get('name',q.get('label'))==name);ctx=z3.Context();s=z3.SolverFor('QF_BV',ctx=ctx);s.set(timeout=120000);s.add(*z3.parse_smt2_string(p['query'],ctx=ctx));result=s.check();assert result==z3.unsat,(name,str(result),s.reason_unknown());prior.append({'name':name,'result':'unsat','source_audit':filename,'source_audit_sha256':sha(ROOT/filename)});print('rechecked '+name,flush=True)
 totals={'new_source_queries_unsat':len(proofs),'prior_source_queries_unsat':len(prior),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'derived_predecessor_profile_projections':len(cases),'ADID_profile_projections':len(certs),'numeric_fields_checked':sum(q['numeric_fields_checked']for q in cases+certs),'environment_premises_sat':len(cases)+len(certs),'conditional_environment_queries_unsat':len(cases)+len(certs),'additional_prefix_cells_reconstructed':sum(len(p['result_additional_source_cells'])for p in e['predecessor_states']),'additional_prefix_bytes_reconstructed':sum(sum(q['size_bytes']for q in p['result_additional_source_cells'])for p in e['predecessor_states']),'negative_source_controls':len(controls),'missing_cells_assigned_concrete_values':0,'native_target_calls':0,'source_business_outputs_replaced':0,'native_PAC_checks':0,'profiles':len(PROFILES),'helper_new_controller_reads64_per_profile':2,'helper_bank_cases':256,'ADID_protected_bytes_checked':sum(q['protected_bytes_checked']for q in certs)}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_source_proofs':prior,'partial_state_evaluations':cases,'ADID_field_certificates':certs,'negative_source_controls':controls,'independent_totals':totals,'conditional_source_lookup_result_established':True,'schema_registry_lookup_result_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
