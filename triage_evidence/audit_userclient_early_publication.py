#!/usr/bin/env python3
"""Original-word first-record publication and caller-specific lookup ABI.
O(I+256+query DAG+C*I) construction/space; SMT search 30 s/query.
"""
import copy,json
import z3
from capstone.arm64 import ARM64_EXT_UXTB
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_early_payload as P0
import recover_userclient_early_publication as R
H=P0.H;DEC=P0.DEC;SUCCESS=0x31ae0066;MISS=0xce515bda
class Model(P0.Model):
 def __init__(self,e):
  self.publication_receipt=e;joined=copy.deepcopy(e);joined['source']['spans']=e['payload_source']['spans']+e['source']['spans'];super().__init__(joined);self.common['H']=z3.BitVec('EU_container64',64);self.common['N']=z3.BitVec('EU_outer_size32',32);self.status=z3.BitVec('EU_callback_status32',32);self.bank_rewrites=[];c=self.common
  for off,value in [(0x348,c['C']+0x50),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),(0xa48,0xfffffe0007949dd0),(0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0)]:mem(self,c['F']+off,8,value)
  mem(self,c['C']+0x20,8,c['H']);mem(self,c['C']+0x260,8,0xfffffe000a661ba0);mem(self,c['S']+0x1d0,4,c['D']^SUCCESS);mem(self,c['S']+0xa10,8,z3.ZeroExt(32,c['L'])+10);mem(self,c['S']+0xb5c,4,c['N']^SUCCESS)
  self.seed('x0',c['H']);self.run('H_zero');self.seed('x0',c['Z']);self.seed('x2',c['C']);self.run('early_output_root')
 def owned(self):
  c=self.common;h=c['H'];n=z3.ZeroExt(32,c['L']);out=super().owned()+[h!=0,z3.ULE(h,resize(2**64-17,64)),z3.ULE(n+10,z3.ZeroExt(32,c['N'])),z3.Or(c['U']!=0x50db,c['D']!=0)]
  extents=[(c['F'],resize(0x10f0,64)),(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['J'],resize(32,64)),(c['Z'],n+10)]
  if self.with_span:extents.append((c['P'],n))
  for a,b in extents:out.append(z3.Or(z3.ULE(h+16,a),z3.ULE(a+b,h)))
  for a,off,b in IMAGE.segments:out.append(z3.Or(z3.ULE(h+16,resize(a,64)),z3.ULE(resize(a+b,64),h)))
  return out
 def load(self,a,n):
  bank=self.publication_receipt['source']['bank_rule'];l,r=int(bank['left'],16),int(bank['right'],16)
  if self.pc==0xfffffe000a662b2c:
   assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('EU_lookup_bank_byte8',8);self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
  if self.pc==0xfffffe000a662b3c:
   assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==r+z3.ZeroExt(56,self.bank_byte^int(bank['key'],16)));self.bank_rewrites.append({'pc':hex(self.pc),'certified_inputs':256});return self.bank_input^int(bank['constant'],16)
  if self.pc==0xfffffe000a662b54:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==int(bank['slot'],16));return resize(int(bank['original_pointer']['target'],16),64)
  if self.pc in R.BRANCHES:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa)and aa.as_long()in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});return z3.BitVec('EU_controller_'+format(self.pc,'x'),32)
  return super().load(a,n)
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTB:return resize(self.read(i.reg_name(o.reg))&255,n)<<o.shift.value
  return super().operand(i,o,n)
 def run(self,label,take=None):
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.visited.add(i.address)
   if i.address in R.DIRECT:
    m,t=R.DIRECT[i.address];assert i.mnemonic==m and i.operands[0].imm&((1<<64)-1)==t;cond=self.condition(m[2:]);self.direct.append({'pc':i.address,'condition':cond,'next_PC':z3.If(cond,resize(t,64),resize(i.address+4,64))});self.count+=1
    if take is not None:self.guards.append(cond if take else z3.Not(cond))
   elif i.address in R.P0.RETAGS:
    assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.P0.RETAGS[i.address];self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one');self.e=original
  self.e=original;return self
def prepared(e,kind):
 v=Model(e)
 for label in H.PATH:v.run(label)
 if kind=='u32':
  v.run('primary_gate',False).run('u32_gate');v.extra.append(v.common['L']==4);v.run('u32_request').run('length_bridge').run('word_writer')
 elif kind=='u64':
  v.run('primary_gate',True).run('secondary_gate',True).run('u64_gate');v.extra.append(v.common['L']==8);v.run('u64_request').run('u64_writer')
 else:
  v.run('primary_gate',True).run('secondary_gate',False).run('span_gate',False).run('span_length')
  if kind=='span_zero':v.extra.append(v.common['L']==0)
  else:
   assert kind=='span_nonzero';v.extra.extend([v.common['L']!=0,v.counter==1]);v.with_span=True;v.run('span_request');v.seed('x10',v.counter);v.run('span_copy')
 v.publication_store_start=len(v.stores);return v
STAGES=['early_publication_request','search_entry','search_nonnull','search_node','search_result','search_callback','early_status_success','early_status_miss','early_append_prepare','early_append_empty','early_saved_callback','early_parser_callback','early_cursor_gate']
def finish(v,through='early_cursor_gate'):
 for label in STAGES:
  v.run(label,False if label in ['early_status_success','early_status_miss']else None)
  if label==through:return v
 raise AssertionError(through)
def edge(v,target,modifier):return z3.Or(v.edges[-1]['target']!=target,v.edges[-1]['modifier']!=modifier)
def publication_bad(v):
 c=v.common;bad=[H.cell(v,c['H'],8)!=c['J'],H.cell(v,c['H']+8,8)!=c['J'],H.cell(v,c['J'],8)!=0,H.cell(v,c['J']+8,8)!=0,H.cell(v,c['J']+0x10,4)!=c['L']+10,H.cell(v,c['J']+0x18,8)!=c['Z'],H.cell(v,c['C']+0x58,8)!=c['J'],H.cell(v,c['C']+0x50,8)!=0,H.cell(v,c['S']+0xa10,8)!=z3.ZeroExt(32,c['L'])+10,v.read('w23')!=SUCCESS]
 return z3.Or(*bad)
def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.guards,*v.extra);assert s.check()==z3.sat,name;s.add(z3.Or(*[z3.Not(q)for q in v.address_checks],bad));query=s.to_smt2();assert s.check()==z3.unsat,(name,s.reason_unknown());out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count,'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)});visited.update(v.visited)
 v=Model(e);c=v.common;prove('source_produces_early_lookup_output_alias_and_empty_container',v,z3.Or(H.cell(v,c['F']+0x348,8)!=c['C']+0x50,H.cell(v,c['H'],8)!=0,H.cell(v,c['H']+8,8)!=0))
 for kind in ['u32','u64','span_zero','span_nonzero']:
  v=prepared(e,kind).run('early_publication_request');c=v.common;prove(kind+'_exact_early_lookup_request_ABI',v,z3.Or(H.cell(v,c['C']+0x50,8)!=0,v.read('x22')!=c['H'],v.read('w9')!=(c['D']^SUCCESS),v.read('x10')!=c['C']+0x50,v.read('w8')!=0x6c,v.read('x20')!=H.KEY1,v.read('x21')!=0xfffffe000792fcc0,v.read('x28')!=0xfffffe0007949dd0,v.read('w3')!=0x886a1ca3,v.read('w30')!=SUCCESS,edge(v,0xfffffe000a662ab4,0xee9)))
 v=prepared(e,'u32').run('early_publication_request').run('search_entry');c=v.common;prove('shared_lookup_saves_early_return_tag_and_output_alias',v,z3.Or(H.cell(v,c['C']+0xc8,8)!=0xfffffe000a662b64,H.cell(v,c['C']+0x758,8)!=c['C']+0x50,H.cell(v,c['S'],4)!=(c['D']^SUCCESS),edge(v,0xfffffe000a662be0,0x7250)))
 v.run('search_nonnull').run('search_node').run('search_result');prove('fresh_empty_container_lookup_returns_miss_and_zero_old_result',v,z3.Or(H.cell(v,c['C']+0x2b0,8)!=0,H.cell(v,c['C']+0x50,8)!=0,v.read('w23')!=MISS,edge(v,0xfffffe000a662b00,0x7250)))
 v.run('search_callback');prove('arbitrary_controller_pair_certified_bank_preserves_early_lookup_return',v,z3.Or(v.read('x22')!=int(e['source']['bank_rule']['target'],16),v.read('w23')!=MISS,edge(v,0xfffffe000a662b64,0x8d28)))
 v.run('early_status_success',False).run('early_status_miss',False).run('early_append_prepare');prove('raw_miss_selects_empty_append_with_current_early_node',v,z3.Or(v.read('x9')!=c['H'],v.read('x10')!=c['J'],v.read('x11')!=0,edge(v,0xfffffe000a662bc4,0xd5cf)))
 v.run('early_append_empty');prove('first_append_publishes_exact_head_tail_and_preserves_node_fields',v,z3.Or(publication_bad(v),edge(v,0xfffffe000a664218,0x7250)))
 v.run('early_saved_callback');prove('first_append_requests_source_retained_parser_callback',v,z3.Or(publication_bad(v),edge(v,0xfffffe000a661ba0,0xf596)))
 v.run('early_parser_callback');prove('success_callback_returns_to_early_parser_cursor_gate',v,z3.Or(publication_bad(v),edge(v,0xfffffe000a660af4,0xc9dc)))
 v.run('early_cursor_gate');c=v.common;target=z3.If(z3.ULT(z3.ZeroExt(32,c['L'])+10,z3.ZeroExt(32,c['N'])),resize(0xfffffe000a660c28,64),resize(0xfffffe000a660b2c,64));prove('published_first_record_keeps_cursor_and_selects_exact_exhaustion_or_next_header',v,z3.Or(publication_bad(v),edge(v,target,0x2f10)))
 models={}
 for kind in ['u32','u64','span_zero','span_nonzero']:
  v=finish(prepared(e,kind));c=v.common;end=c['Z']+z3.ZeroExt(32,c['L'])+10;outside=[z3.Or(z3.ULE(q['address']+q['size_bytes'],c['Z']),z3.ULE(end,q['address']))for q in v.stores[v.publication_store_start:]];target=z3.If(z3.ULT(z3.ZeroExt(32,c['L'])+10,z3.ZeroExt(32,c['N'])),resize(0xfffffe000a660c28,64),resize(0xfffffe000a660b2c,64));prove(kind+'_composed_first_publication_preserves_serialized_buffer_and_returns_exact_cursor_gate',v,z3.Or(publication_bad(v),*[z3.Not(q)for q in outside],edge(v,target,0x2f10)));models[kind]=v
 v=Model(e);v.seed('w3',0x886a1ca3);v.seed('w30',SUCCESS);v.seed('x7',TABLE);v.seed('w23',v.status);v.run('early_parser_callback');prove('all_callback_status32_exact_success_or_error_continuation',v,edge(v,z3.If(v.status==SUCCESS,resize(0xfffffe000a660af4,64),resize(0xfffffe000a661bfc,64)),0xc9dc))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,captured-visited
 return out,models,len(visited&captured)
def evaluations(e,models):
 rows=[]
 for r in e['predecessor_states']:
  p=r['input'];profile=p['profile'];kind='u32'if profile.startswith('u32')else'u64'if profile.startswith('u64')else'span_nonzero'if p['wire_length32']else'span_zero';v=models[kind];c=v.common;g=[int(x,16)for x in r['handoff_state']['registers31']];raw=bytes.fromhex(p['input_fixture_hex']);values={'F':int(r['frame_base_SP'],16),'C':g[11],'S':g[3],'J':p['node_result_fixture'],'Z':p['data_result_fixture'],'D':p['wire_tag32'],'U':p['wire_type16'],'L':p['wire_length32'],'V':int.from_bytes(raw[10:14],'big')if kind=='u32'else 0,'Q':int.from_bytes(raw[10:18],'big')if kind=='u64'else 0,'P':p['inputs8'][0]+10 if kind.startswith('span')else 0,'H':int(r['original_container'],16),'N':r['outer_size32']};bindings=[(c[k],resize(x,c[k].size()))for k,x in values.items()]+[(v.counter,resize(1,64))]
  controller_queries=0
  for premise in v.owned()+v.guards+v.extra+v.address_checks:
   q=z3.simplify(z3.substitute(premise,*bindings))
   if not z3.is_true(q):
    solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.Not(q));assert solver.check()==z3.unsat;controller_queries+=1
  f,c0,s,j,z,h=(values[n]for n in ['F','C','S','J','Z','H']);fields=[(h,8,j),(h+8,8,j),(j,8,0),(j+8,8,0),(j+0x10,4,values['L']+10),(j+0x18,8,z),(c0+0x58,8,j),(c0+0x50,8,0),(s+0xa10,8,r['cursor64'])]
  for addr,n,want in fields:
   base,off=next((c[name],addr-values[name])for name in ['H','J','C','S']if values[name]<=addr<values[name]+({'H':16,'J':32,'C':4096,'S':16384}[name]));assert H.numeric(H.cell(v,base+off,n),bindings)==want
  assert H.numeric(v.edges[-1]['target'],bindings)==0xfffffe000a660b2c and H.numeric(v.edges[-1]['modifier'],bindings)==0x2f10 and H.numeric(v.read('w23'),bindings)==SUCCESS
  rows.append({'predecessor_case_index':r['predecessor_case_index'],'domain':kind,'published_head':hex(j),'published_tail':hex(j),'cursor64':r['cursor64'],'outer_size32':r['outer_size32'],'post_publication_fields_checked':len(fields),'unbound_controller_premise_queries_unsat':controller_queries,'final_target':'0xfffffe000a660b2c','all_storage_branch_and_lookup_premises_checked':True,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'all_checks_pass':True})
 return rows
def negative_controls(e):
 out=[]
 for pc in [0xfffffe000a662bc8,0xfffffe000a662ba8,0xfffffe000a664224]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);original=bytes(raw[off:off+4]);raw[off:off+4]=bytes.fromhex('1f2003d5');row['bytes_hex']=raw.hex();v=finish(prepared(changed,'u32'),'early_saved_callback');bad=z3.Or(publication_bad(v),edge(v,0xfffffe000a661ba0,0xf596));s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat
  out.append({'mutated_PC':hex(pc),'original_word_hex':original.hex(),'replacement_word_hex':'1f2003d5','satisfiable_violation_query':s.to_smt2(),'normal_oracle_rejected':True,'stopped_before_following_mutated_callback_target':True,'native_target_executed':False})
 return out
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases=evaluations(e,models);controls=negative_controls(e);prior=json.loads(read(ROOT/'userclient_early_payload_audit.json'));rechecked=[]
 for name in ['complete_u32_record_has_fourteen_exact_protected_bytes','complete_u64_record_has_eighteen_exact_protected_bytes','every_span_counter_reads_plaintext_and_writes_destination_protected_byte','finite_reverse_span_indices_cover_exactly_L_payload_bytes']:
  p=next(q for q in prior['source_proofs']if q['name']==name);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;rechecked.append({'name':name,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_early_payload_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'prior_payload_queries_unsat':len(rechecked),'lifted_instruction_instances':sum(q['lifted_instruction_instances']for q in proofs),'new_source_words_covered':covered,'certified_bank_inputs':256,'predecessor_bound_partial_state_evaluations':len(cases),'prefix_cells_reconstructed':sum(len(q['source_defined_cells'])for q in e['predecessor_states']),'post_publication_fields_checked':sum(q['post_publication_fields_checked']for q in cases),'unbound_controller_premise_queries_unsat':sum(q['unbound_controller_premise_queries_unsat']for q in cases),'missing_cells_assigned_concrete_values':0,'negative_source_controls':len(controls),'publication_source_stores_per_case':len(models['u32'].stores)-models['u32'].publication_store_start,'composed_domains':len(models)}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_payload_proofs':rechecked,'partial_state_evaluations':cases,'negative_source_controls':controls,'independent_totals':totals,'conditional_first_record_publication_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
