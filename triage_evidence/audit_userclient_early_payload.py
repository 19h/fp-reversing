#!/usr/bin/env python3
"""Independent fixed-width original-word payload composition and induction.
O(I+query DAG+C*I+fixture bytes) construction/space; SMT search 30 s/query.
No native execution or extension of the stopped continuous private guest.
"""
import copy,json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from lskd_values_symbolic import mem,resize
from verify_daemon_reader_record_payloads_publication import read,sha
import audit_userclient_early_writer as H
import recover_userclient_early_payload as R
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
FRONTIER=0xfffffe000a655cb4
U64_STORES=[0xfffffe000a655b50,0xfffffe000a655b80,0xfffffe000a655bb0,0xfffffe000a655be0,0xfffffe000a655c0c,0xfffffe000a655c34,0xfffffe000a655c60,0xfffffe000a655c98]
class Model(H.Model):
 def __init__(self,e):
  combined=copy.deepcopy(e);combined['source']['spans']=e['header_source']['spans']+e['source']['spans'];super().__init__(combined);self.extra=[];self.direct=[];self.with_span=False;self.counter=z3.BitVec('EP_counter64',64);self.byte=z3.BitVec('EP_source_byte8',8);self.common['Q']=z3.BitVec('EP_scalar64',64);self.common['P']=z3.BitVec('EP_span64',64);c=self.common
  mem(self,c['S']+0xad0,8,c['Q']^0x8f98c6acce5848ca);mem(self,c['S']+0xca8,8,z3.ZeroExt(32,c['L'])+0x622f763938943e93);mem(self,c['C']+0x168,8,c['P'])
  self.run('fixed_controls');self.seed('x4',c['S']);self.run('u64_cell');self.seed('x7',TABLE);self.run('table_cell')
 def load(self,a,n):
  if self.pc==0xfffffe000a6553d0:
   assert n==1;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});self.address_checks.append(a==self.common['P']+self.counter-1);return self.byte
  if self.pc in R.BRANCHES:
   assert n==8;self.loads.append({'pc':self.pc,'address':a,'size_bytes':n});js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  return super().load(a,n)
 def owned(self):
  c=self.common;n=z3.ZeroExt(32,c['L']);extents=[(c['F'],resize(0x10f0,64)),(c['C'],resize(0x1000,64)),(c['S'],resize(0x4000,64)),(c['J'],resize(32,64)),(c['Z'],n+10)]
  if self.with_span:extents.append((c['P'],n))
  out=[(c['F']&15)==0,z3.ULE(c['L'],0xfffffff5)]
  for j,(a,b)in enumerate(extents):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-b)])
   for d,m in extents[j+1:]:out.append(z3.Or(z3.ULE(a+b,d),z3.ULE(d+m,a)))
   for d,off,m in IMAGE.segments:out.append(z3.Or(z3.ULE(a+b,resize(d,64)),z3.ULE(resize(d+m,64),a)))
  return out
 def run(self,label,take=None):
  original=self.e;row=next(s for s in original['source']['spans']if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.visited.add(i.address)
   if i.address in R.DIRECT:
    m,t=R.DIRECT[i.address];assert i.mnemonic==m and i.operands[0].imm&((1<<64)-1)==t;c=self.condition(m[2:]);self.direct.append({'pc':i.address,'condition':c,'next_PC':z3.If(c,resize(t,64),resize(i.address+4,64))});self.count+=1
    if take is not None:self.guards.append(c if take else z3.Not(c))
   elif i.address in R.RETAGS:
    assert i.mnemonic=='b.eq'and i.operands[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.RETAGS[i.address];self.count+=1
   else:
    self.e={'source':{'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}};super().run('one');self.e=original
  self.e=original;return self
def whole(e):
 v=Model(e)
 for label in H.PATH:v.run(label)
 return v
def scalar32(e):
 v=whole(e).run('primary_gate',False).run('u32_gate');v.extra.append(v.common['L']==4);return v.run('u32_request').run('length_bridge').run('word_writer')
def scalar64(e):
 v=whole(e).run('primary_gate',True).run('secondary_gate',True).run('u64_gate');v.extra.append(v.common['L']==8);return v.run('u64_request').run('u64_writer')
def span(e):return whole(e).run('primary_gate',True).run('secondary_gate',False).run('span_gate',False).run('span_length')
def span_step(e):
 v=span(e);v.extra.extend([v.common['L']!=0,z3.UGE(v.counter,1),z3.ULE(v.counter,z3.ZeroExt(32,v.common['L']))]);v.with_span=True;v.run('span_request');v.seed('x10',v.counter);return v.run('span_copy')
def bytes_written(v):return[q for q in v.stores if q['size_bytes']==1]
def expected(v,kind):
 c=v.common;out=H.expected_bytes(v)
 if kind=='u32':value,n=c['V'],4
 else:value,n=c['Q'],8
 return out+[z3.Extract(8*(n-j)-1,8*(n-j-1),value)^H.mask(c['Z']+10+j)for j in range(n)]
def payload_bad(v,kind):
 stores=bytes_written(v);want=expected(v,kind)
 if len(stores)!=len(want):return z3.BoolVal(True)
 return z3.Or(*[z3.Or(q['address']!=v.common['Z']+j,q['value']!=want[j])for j,q in enumerate(stores)])
def source_obligations(e):
 out=[];visited=set()
 def prove(name,v,bad):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.guards,*v.extra);assert s.check()==z3.sat,name;s.add(z3.Or(*[z3.Not(q)for q in v.address_checks],bad));query=s.to_smt2();assert s.check()==z3.unsat,(name,s.reason_unknown());out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':v.count});visited.update(v.visited)
 def edge(v,target,modifier):return z3.Or(v.edges[-1]['target']!=target,v.edges[-1]['modifier']!=modifier)
 v=Model(e);c=v.common;prove('source_produces_fixed_controls_and_workspace_scalar_pointer',v,z3.Or(H.cell(v,c['F']+0x104,4)!=0x802218a3,H.cell(v,c['F']+0x560,8)!=0x886a1ca0,H.cell(v,c['F']+0xf8,8)!=c['S']+0xad0,H.cell(v,c['F']+0xa60,8)!=TABLE))
 v=whole(e).run('primary_gate');c=v.common;prove('early_primary_type_branch_is_exact_u32_domain',v,v.direct[-1]['condition']!=(c['U']!=0x9777))
 v=whole(e).run('primary_gate',True).run('secondary_gate');c=v.common;prove('early_secondary_type_branch_is_exact_u64_domain',v,v.direct[-1]['condition']!=(c['U']==0x8485))
 v=whole(e).run('primary_gate',True).run('secondary_gate',False).run('span_gate');c=v.common;prove('remaining_early_type_branch_accepts_exact_span_domain',v,v.direct[-1]['condition']!=(c['U']!=0x50db))
 v=whole(e).run('primary_gate',False).run('u32_gate');c=v.common;prove('u32_payload_gate_requires_exact_four_bytes',v,edge(v,z3.If(c['L']==4,resize(0xfffffe000a654e34,64),resize(0xfffffe000a664074,64)),0x3769))
 v.extra.append(c['L']==4);v.run('u32_request');prove('u32_request_selects_current_buffer_encoded_scalar_and_offset_ten',v,z3.Or(v.read('x16')!=c['J']+0x18,v.read('w23')!=((c['V']^H.SUCCESS)^0x14ac30f9),v.read('w24')!=0x129,edge(v,0xfffffe000a654c44,0x8165)))
 v.run('length_bridge').run('word_writer');prove('complete_u32_record_has_fourteen_exact_protected_bytes',v,z3.Or(payload_bad(v,'u32'),edge(v,FRONTIER,0x3aa3)));u32=v
 v=whole(e).run('primary_gate',True).run('secondary_gate',True).run('u64_gate');c=v.common;prove('u64_payload_gate_requires_exact_eight_bytes',v,edge(v,z3.If(c['L']==8,resize(0xfffffe000a655acc,64),resize(0xfffffe000a664074,64)),0x3769))
 v.extra.append(c['L']==8);v.run('u64_request');prove('u64_request_selects_source_produced_workspace_cell_and_writer',v,z3.Or(v.read('x8')!=c['S']+0xad0,v.read('x9')!=0x30c4cd3710c7dd6a,v.read('w10')!=0xc5,edge(v,0xfffffe000a655b14,0x9c6d)))
 v.run('u64_writer');prove('complete_u64_record_has_eighteen_exact_protected_bytes',v,z3.Or(payload_bad(v,'u64'),edge(v,FRONTIER,0xc4bd)));u64=v
 v=span(e);c=v.common;prove('span_length_gate_recovers_exact_u32_length_and_zero_bypass',v,z3.Or(v.read('w10')!=(c['L']^0xc76bc16d),v.read('w13')!=0xc76bc16d,edge(v,z3.If(c['L']==0,resize(FRONTIER,64),resize(0xfffffe000a65538c,64)),0x4bb5)))
 v.extra.append(c['L']!=0);v.with_span=True;v.run('span_request');prove('span_request_loads_plaintext_source_and_exact_widened_count',v,z3.Or(v.read('x8')!=c['Z'],v.read('x9')!=c['P'],v.read('x10')!=z3.ZeroExt(32,c['L']),edge(v,0xfffffe000a6553b0,0xd76c)));span_request=v
 v=span_step(e);c=v.common;ss=[q for q in v.stores if q['pc']==0xfffffe000a655410];assert len(ss)==1;q=ss[0];prove('every_span_counter_reads_plaintext_and_writes_destination_protected_byte',v,z3.Or(q['address']!=c['Z']+v.counter+9,q['value']!=(v.byte^H.mask(c['Z']+v.counter+9)),v.read('x10')!=v.counter-1,v.read('x8')!=c['Z'],v.read('x9')!=c['P'],v.read('x0')!=H.KEY1,v.read('x26')!=H.KEY0,edge(v,z3.If(v.counter==1,resize(FRONTIER,64),resize(0xfffffe000a6553b0,64)),0xd76c)));step=v
 j=z3.BitVec('EP_completed_steps64',64);n=z3.ZeroExt(32,c['L']);i=n-1-j;v.extra.append(z3.ULT(j,n));prove('finite_reverse_span_indices_cover_exactly_L_payload_bytes',v,z3.Or(z3.Not(z3.ULT(i,n)),(i==0)!=(j==n-1),z3.Not(z3.UGE(i+10,10)),z3.Not(z3.ULT(i+10,n+10)),z3.And(j+1<n,i-1!=n-1-(j+1))));v.extra.pop()
 pc=0xfffffe000a6553e4;row=next(s for s in e['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);v=Model(e);p=z3.BitVec('EP_alternate_pointer64',64);v.seed('x13',p);v.e['source']['spans'].append({'label':'alternate','start':hex(pc),'bytes_hex':row['bytes_hex'][2*off:2*off+8]});v.run('alternate');prove('span_alternate_MOVK_bit_transform_only',v,v.read('x13')!=((p&0xffffffffffff)|(0xc8a2<<48)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured<=visited,(captured-visited)
 zero=span(e);zero.extra.append(zero.common['L']==0)
 return out,{'u32':u32,'u64':u64,'span_zero':zero,'span_request':span_request,'span_step':step},len(visited&captured)
def evaluations(e,models):
 out=[]
 for r in e['predecessor_states']:
  p=r['input'];g=[int(x,16)for x in r['handoff_state']['registers31']];profile=p['profile'];kind='u32'if profile.startswith('u32')else'u64'if profile.startswith('u64')else'span';v=models[('span_request'if p['wire_length32']else'span_zero')if kind=='span'else kind];c=v.common;values={'F':int(r['frame_base_SP'],16),'C':g[11],'S':g[3],'J':p['node_result_fixture'],'Z':p['data_result_fixture'],'D':p['wire_tag32'],'U':p['wire_type16'],'L':p['wire_length32'],'V':r['raw_scalar32'],'Q':r['raw_scalar64'],'P':r['span_source']};bindings=[(c[k],resize(value,c[k].size()))for k,value in values.items()];raw=bytes.fromhex(p['input_fixture_hex']);L=values['L'];actual=bytearray(H.numeric(q['value'],bindings)for q in bytes_written(v));assert[H.numeric(q['address'],bindings)for q in bytes_written(v)]==[values['Z']+j for j in range(len(actual))]
  for premise in v.owned()+v.guards+v.extra+v.address_checks:assert z3.is_true(z3.simplify(z3.substitute(premise,*bindings)))
  if kind=='span'and L:
   step=models['span_step'];store=next(q for q in step.stores if q['pc']==0xfffffe000a655410);payload=bytearray(L)
   for count in range(L,0,-1):
    b=bindings+[(step.counter,resize(count,64)),(step.byte,resize(raw[10+count-1],8))]
    for premise in step.owned()+step.guards+step.extra+step.address_checks:assert z3.is_true(z3.simplify(z3.substitute(premise,*b)))
    assert H.numeric(store['address'],b)==values['Z']+count+9;payload[count-1]=H.numeric(store['value'],b)
   actual.extend(payload)
  want=bytes(raw[j]^H.py_mask(values['Z']+j)for j in range(L+10));assert bytes(actual)==want
  for row in r['source_defined_cells'][:4]:assert H.numeric(H.cell(v,c['F']+int(row['offset'],16),row['size_bytes']),bindings)==int.from_bytes(bytes.fromhex(row['last_exact_store']['after_hex']),'little')
  out.append({'predecessor_case_index':r['predecessor_case_index'],'profile':profile,'domain':kind,'protected_record_hex':actual.hex(),'serialized_bytes_checked':len(actual),'saved_control_values_checked':4,'all_storage_branch_and_lookup_premises_checked':True,'zero_span_bypass_used':kind=='span'and L==0,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'all_checks_pass':True})
 return out
def negative_controls(e):
 out=[]
 for pc,kind in [(0xfffffe000a654e64,'u32'),(0xfffffe000a655b50,'u64'),(0xfffffe000a655410,'span')]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);original=bytes(raw[off:off+4]);raw[off:off+4]=bytes.fromhex('1f2003d5');row['bytes_hex']=raw.hex();v=scalar32(changed)if kind=='u32'else scalar64(changed)if kind=='u64'else span_step(changed);bad=payload_bad(v,kind)if kind!='span'else z3.BoolVal(not any(q['pc']==pc for q in v.stores));s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.guards,*v.extra,*v.address_checks);assert s.check()==z3.sat;s.add(bad);assert s.check()==z3.sat
  out.append({'domain':kind,'mutated_PC':hex(pc),'original_word_hex':original.hex(),'replacement_word_hex':'1f2003d5','satisfiable_violation_query':s.to_smt2(),'normal_oracle_rejected':True,'native_target_executed':False})
 return out
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,models,covered=source_obligations(e);cases=evaluations(e,models);controls=negative_controls(e);prior=json.loads(read(ROOT/'userclient_early_writer_audit.json'));rechecked=[]
 for name in ['complete_early_ten_byte_header_and_retained_node_fields','two_world_early_header_memory_addresses_and_control_independent_of_eight_missing_cells']:
  p=next(q for q in prior['source_proofs']if q['name']==name);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;rechecked.append({'name':name,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_early_writer_audit.json')})
 totals={'new_source_queries_unsat':len(proofs),'prior_header_queries_unsat':len(rechecked),'lifted_instruction_instances':sum(p['lifted_instruction_instances']for p in proofs),'new_source_words_covered':covered,'predecessor_bound_partial_state_evaluations':len(cases),'serialized_bytes_checked':sum(q['serialized_bytes_checked']for q in cases),'saved_control_values_checked':sum(q['saved_control_values_checked']for q in cases),'missing_cells_assigned_concrete_values':0,'negative_source_controls':len(controls),'u32_case_evaluations':sum(q['domain']=='u32'for q in cases),'u64_case_evaluations':sum(q['domain']=='u64'for q in cases),'span_case_evaluations':sum(q['domain']=='span'for q in cases),'u32_record_bytes':len(bytes_written(models['u32'])),'u64_record_bytes':len(bytes_written(models['u64'])),'span_copy_byte_loads_per_step':1,'span_copy_byte_stores_per_step':1}
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_header_proofs':rechecked,'partial_state_evaluations':cases,'negative_source_controls':controls,'independent_totals':totals,'conditional_three_domain_payload_serialization_established':True,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
