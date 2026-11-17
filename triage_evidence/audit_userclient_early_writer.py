#!/usr/bin/env python3
"""Original-word early header composition with arbitrary unused setup cells.
O(I+query DAG+C*I) construction/space; SMT search separate, 30 s/query.
No continuous guest repair, native target operation or IDB mutation.
"""
import copy,json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_SXTW
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_userclient_early_node import Lift
from lskd_values_symbolic import resize,mem
import recover_userclient_early_writer as R
KEY0=0x02e859d27e491464;KEY1=0x4dae26df20976138;SUCCESS=0x31ae0066
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True
WORD_PCS=[0xfffffe000a654ccc,0xfffffe000a654d18,0xfffffe000a654d74,0xfffffe000a654db0]
TYPE_PCS=[0xfffffe000a655014,0xfffffe000a655038]
PATH=['data_return','early_prepare','shared_setup','word_writer','early_type','length_bridge','word_writer']
def cell(v,a,n):return v.memory[(z3.simplify(resize(a,64)).sexpr(),n)]
def mask(a):return z3.Extract(7,0,z3.LShR((z3.RotateRight(a&resize(-8,64),8)+KEY0)^KEY1,(a&7)<<3))
class Model(Lift):
 def __init__(self,e,world='a',common=None):
  super().__init__({'spans':e['source']['spans']});self.e=e;self.visited=set();self.guards=[];self.address_checks=[];self.edges=[];self.loads=[]
  self.common=common if common is not None else {n:z3.BitVec('EW_'+n,b)for n,b in [('F',64),('C',64),('S',64),('J',64),('Z',64),('D',32),('U',16),('L',32),('V',32),('status',32)]};v=self.common
  self.dead=[z3.BitVec('EW_'+world+'_'+n,b)for n,b in [('root768',64),('root458',64),('root140',64),('root6b8',64),('meta_d30',32),('meta_e28',32),('meta_df8',32),('type_b90',16)]]
  for j in range(31):self.seed('x'+str(j),z3.BitVec('EW_'+world+'_entry_X'+str(j),64))
  for reg,value in [('sp',v['F']),('x0',v['Z']),('x21',TABLE),('x22',v['J']),('w26',0x871),('w19',v['D']^SUCCESS)]:self.seed(reg,value)
  for off,n,value in [(0xa08,8,v['S']),(0xa28,8,v['C']),(0x9ec,4,v['status'])]:mem(self,v['F']+off,n,value)
  for off,value in zip([0x768,0x458,0x140,0x6b8],self.dead[:4]):mem(self,v['C']+off,8,value)
  mem(self,v['C']+0x58,8,v['J'])
  for off,value in zip([0xd30,0xe28,0xdf8],self.dead[4:7]):mem(self,v['S']+off,4,value)
  mem(self,v['S']+0xb90,2,self.dead[7]);mem(self,v['S']+0x94,4,v['L']^SUCCESS);mem(self,v['S']+0x110,4,v['V']^SUCCESS);mem(self,v['S']+0x1b2,2,v['U']^0xa2e3)
  mem(self,v['J'],8,0);mem(self,v['J']+8,8,0);mem(self,v['J']+0x10,4,v['L']+10)
 def address(self,i,o):
  if o.ext==ARM64_EXT_SXTW:return z3.simplify(resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp+(z3.SignExt(32,resize(self.read(i.reg_name(o.mem.index)),32))<<o.shift.value))
  return super().address(i,o)
 def load(self,a,n):
  self.loads.append({'pc':self.pc,'address':a,'size_bytes':n})
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));value=resize(0,64)
   for j in js:value=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),value)
   return value
  return super().load(a,n)
 def owned(self):
  v=self.common;extents=[(v['F'],0x10f0),(v['C'],0x1000),(v['S'],0x4000),(v['J'],32),(v['Z'],10)];p=[(v['F']&15)==0,z3.ULE(v['L'],0xfffffff5)]
  for j,(a,n)in enumerate(extents):
   p.extend([a!=0,z3.ULE(a,resize(2**64-1-n,64))])
   for b,m in extents[j+1:]:p.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,off,m in IMAGE.segments:p.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return p
 def run(self,label):
  row=next(s for s in self.e['source']['spans']if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.address==skip:continue
   self.pc=i.address;self.visited.add(i.address);o=i.operands;m=i.mnemonic
   if m in ['bti','nop']:self.count+=1
   elif m=='braa':self.edges.append({'pc':i.address,'target':self.read(i.reg_name(o[0].reg)),'modifier':self.read(i.reg_name(o[1].reg))});self.count+=1
   elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm));self.count+=1
   elif m=='b.eq':
    assert i.address in R.RETAGS and o[0].imm&((1<<64)-1)==i.address+8;self.guards.append(self.condition('eq'));skip=R.RETAGS[i.address];self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one')
  return self
def header_stores(v):return[s for s in v.stores if s['pc']in WORD_PCS+TYPE_PCS]
def expected_bytes(v):
 c=v.common;raw=[*[z3.Extract(31-8*j,24-8*j,c['D'])for j in range(4)],*[z3.Extract(15-8*j,8-8*j,c['U'])for j in range(2)],*[z3.Extract(31-8*j,24-8*j,c['L'])for j in range(4)]]
 return[raw[j]^mask(c['Z']+j)for j in range(10)]
def whole(e,world='a',common=None):
 v=Model(e,world,common)
 for label in PATH:v.run(label)
 return v
def source_obligations(e):
 out=[];visited=set()
 def prove(name,models,bad):
  models=models if isinstance(models,list)else[models];s=z3.Solver();s.set(timeout=30000)
  for v in models:s.add(*v.owned(),*v.guards)
  assert s.check()==z3.sat,name;s.add(z3.Or(*[z3.Not(c)for v in models for c in v.address_checks],bad));query=s.to_smt2();assert s.check()==z3.unsat,(name,s.reason_unknown())
  out.append({'name':name,'result':'unsat','premises_nonvacuous':True,'query':query,'lifted_instruction_instances':sum(v.count for v in models),'normal_pointer_branch_instances':sum(len(v.guards)for v in models)})
  for v in models:visited.update(v.visited)
 def edge(v,n,target,modifier):return z3.Or(v.edges[n]['target']!=target,v.edges[n]['modifier']!=modifier)
 v=Model(e).run('data_return');c=v.common;prove('nonnull_data_result_source_retention_and_dispatch',v,z3.Or(cell(v,c['J']+0x18,8)!=c['Z'],edge(v,0,0xfffffe000a661880,0x3769)))
 v.run('early_prepare');prove('early_handoff_preserves_current_node_phase_and_raw_tag',v,z3.Or(v.read('x16')!=c['J']+0x18,v.read('w23')!=(c['D']^0x2502309f),v.read('w24')!=0x13c,v.read('x3')!=c['S'],v.read('x11')!=c['C'],v.read('x0')!=KEY0,edge(v,1,0xfffffe000a654ad4,0xdfc5)))
 v.run('shared_setup');prove('shared_setup_keeps_early_root_and_selects_word_writer_with_arbitrary_other_cells',v,z3.Or(v.read('x16')!=c['J']+0x18,v.read('x8')!=c['J']+0x18,v.read('w24')!=0x13c,v.read('w23')!=(c['D']^0x2502309f),edge(v,2,0xfffffe000a654c64,0x682a)))
 v.run('word_writer');ss=header_stores(v);assert len(ss)==4;want=expected_bytes(v);prove('early_raw_tag32_exact_four_protected_bytes_and_early_type_continuation',v,z3.Or(*[z3.Or(q['address']!=c['Z']+j,q['value']!=want[j])for j,q in enumerate(ss)],v.read('x0')!=KEY1,v.read('x26')!=KEY0,edge(v,3,0xfffffe000a654fc8,0x3aa3)))
 v.run('early_type');ss=header_stores(v)[4:];assert len(ss)==2;prove('early_raw_type16_exact_two_protected_bytes_and_current_length_channel',v,z3.Or(*[z3.Or(q['address']!=c['Z']+4+j,q['value']!=want[4+j])for j,q in enumerate(ss)],v.read('x16')!=c['J']+0x18,v.read('w23')!=((c['L']^SUCCESS)^0x14ac30f9),v.read('w24')!=0x165,edge(v,4,0xfffffe000a654c44,0x8165)))
 v.run('length_bridge');prove('early_length_bridge_restores_key_and_same_buffer_cell',v,z3.Or(v.read('x0')!=KEY0,v.read('x16')!=c['J']+0x18,edge(v,5,0xfffffe000a654c64,0x682a)))
 v.run('word_writer');ss=header_stores(v)[6:];assert len(ss)==4;prove('early_raw_length32_exact_four_protected_bytes_and_early_type_gate',v,z3.Or(*[z3.Or(q['address']!=c['Z']+6+j,q['value']!=want[6+j])for j,q in enumerate(ss)],edge(v,6,0xfffffe000a654dcc,0x3aa3)))
 ss=header_stores(v);assert len(ss)==10 and all(q['size_bytes']==1 for q in ss)
 prove('complete_early_ten_byte_header_and_retained_node_fields',v,z3.Or(*[z3.Or(q['address']!=c['Z']+j,q['value']!=want[j])for j,q in enumerate(ss)],cell(v,c['J'],8)!=0,cell(v,c['J']+8,8)!=0,cell(v,c['J']+0x10,4)!=c['L']+10,cell(v,c['J']+0x18,8)!=c['Z'],cell(v,c['C']+0x58,8)!=c['J'],v.read('w4')!=z3.ZeroExt(16,c['U']^0xa2e3),v.read('w2')!=(c['L']^SUCCESS)))
 other=whole(e,'b',c);tt=header_stores(other);assert len(tt)==10 and len(v.edges)==len(other.edges)==7
 assert len(v.loads)==len(other.loads)==25 and len(v.stores)==len(other.stores)==15
 prove('two_world_early_header_memory_addresses_and_control_independent_of_eight_missing_cells',[v,other],z3.Or(*[z3.Or(a['address']!=b['address'],a['value']!=b['value'])for a,b in zip(ss,tt)],*[a['address']!=b['address']for a,b in zip(v.loads,other.loads)],*[a['address']!=b['address']for a,b in zip(v.stores,other.stores)],*[z3.Or(a['target']!=b['target'],a['modifier']!=b['modifier'])for a,b in zip(v.edges,other.edges)]))
 raw=[q['value']^mask(q['address'])for q in ss];prove('protected_early_header_recovers_raw_fields_and_staged_type_domain',v,z3.Or(z3.Concat(*raw[:4])!=c['D'],z3.Concat(*raw[4:6])!=c['U'],z3.Concat(*raw[6:])!=c['L'],(z3.Concat(*raw[4:6])^0x365e)!=((c['U']^0xa2e3)^0x94bd)))
 for pc in R.RETAGS.values():
  row=next(s for s in e['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);b=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(b,pc));p=z3.BitVec('EW_alternate_pointer64',64);q=Model(e);q.seed(i.reg_name(i.operands[0].reg),p);q.e={'source':{'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':b.hex()}]}};q.run('alternate');prove('alternate_MOVK_'+format(pc,'x')+'_bit_transform_only',q,q.read(i.reg_name(i.operands[0].reg))!=((p&0xffffffffffff)|(0xc8a2<<48)))
 captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};assert captured==visited
 return out,v
def numeric(v,bindings):
 v=z3.simplify(z3.substitute(v,*bindings));assert z3.is_bv_value(v),('unresolved partial-state expression',v);return v.as_long()
def py_mask(a):
 m=(1<<64)-1;a&=m;q=a&~7;rot=((q>>8)|(q<<56))&m;return((((rot+KEY0)&m)^KEY1)>>((a&7)*8))&255
def evaluations(e,v):
 rows=[];handoff=Model(e).run('data_return').run('early_prepare');ss=header_stores(v)
 for r in e['predecessor_handoffs']:
  p=r['input'];g=[int(x,16)for x in r['handoff_state']['registers31']];field=next(q for q in r['writer_input_cells']if q['root']=='S'and q['offset']=='0x110');values={'F':int(r['frame_base_SP'],16),'S':g[3],'C':g[11],'J':p['node_result_fixture'],'Z':p['data_result_fixture'],'D':p['wire_tag32'],'U':p['wire_type16'],'L':p['wire_length32'],'V':int.from_bytes(bytes.fromhex(field['bytes_hex']),'little')^SUCCESS};bindings=[(v.common[n],resize(value,v.common[n].size()))for n,value in values.items()]
  for reg in [0,1,3,11,14,16,17,22,23,24,25]:assert numeric(handoff.read('x'+str(reg)),bindings)==g[reg]
  raw=values['D'].to_bytes(4,'big')+values['U'].to_bytes(2,'big')+values['L'].to_bytes(4,'big');assert raw.hex()==p['input_fixture_hex'][:20];encoded=bytes(raw[j]^py_mask(values['Z']+j)for j in range(10));actual=bytes(numeric(q['value'],bindings)for q in ss)
  assert actual==encoded and[numeric(q['address'],bindings)for q in ss]==[values['Z']+j for j in range(10)]
  rows.append({'predecessor_case_index':r['predecessor_case_index'],'profile':p['profile'],'controller_fixture':p['global_fixture'],'placement':p['placement'],'plaintext_header_hex':raw.hex(),'protected_header_hex':actual.hex(),'projected_handoff_registers_checked':11,'header_bytes_checked':10,'missing_cells_bound_to_concrete_values':0,'continuous_guest_extended':False,'all_checks_pass':True})
 return rows
def negative_controls(e):
 rows=[]
 for pc in [0xfffffe000a655014,0xfffffe000a654dc4]:
  changed=copy.deepcopy(e);row=next(s for s in changed['source']['spans']if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16);raw=bytearray.fromhex(row['bytes_hex']);original=bytes(raw[off:off+4]);replacement=bytes.fromhex('1f2003d5');raw[off:off+4]=replacement;row['bytes_hex']=raw.hex();v=whole(changed);ss=header_stores(v);s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.guards,*v.address_checks);assert s.check()==z3.sat
  if len(ss)!=10:assert len(ss)==9;why='missing_type_byte_store';correct=False;assert pc==0xfffffe000a655014
  else:
   want=expected_bytes(v);s.push();s.add(z3.Or(*[z3.Or(q['address']!=v.common['Z']+j,q['value']!=want[j])for j,q in enumerate(ss)]));assert s.check()==z3.unsat;s.pop();correct=True;s.add(v.edges[-1]['modifier']!=0x3aa3);assert s.check()==z3.sat;why='wrong_authenticated_transfer_modifier';assert pc==0xfffffe000a654dc4
  rows.append({'mutated_PC':hex(pc),'original_word_hex':original.hex(),'replacement_word_hex':replacement.hex(),'header_store_instances':len(ss),'header_bytes_still_correct':correct,'rejection_reason':why,'satisfiable_mutated_path_query':s.to_smt2(),'normal_oracle_rejected':True,'native_target_executed':False})
 return rows
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,v=source_obligations(e);cases=evaluations(e,v);controls=negative_controls(e);prior=json.loads(read(ROOT/'userclient_input_reader_audit.json'));rechecked=[]
 for name in ['protected_header_first_word_decodes_tag_channel','protected_header_u16_type_at_offset_four','protected_header_u32_length_channel_at_offset_six']:
  p=next(p for p in prior['source_proofs']if p['label']==name);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat;rechecked.append({'name':name,'result':'unsat','source_audit_sha256':sha(ROOT/'userclient_input_reader_audit.json')})
 counts={'new_source_queries_unsat':len(proofs),'prior_reader_queries_unsat':len(rechecked),'lifted_instruction_instances':sum(p['lifted_instruction_instances']for p in proofs),'captured_source_words':227,'normal_path_unique_PCs':len(v.visited),'composed_path_instruction_instances':v.count,'normal_pointer_branch_instances':len(v.guards),'header_store_instances':len(header_stores(v)),'all_source_store_instances':len(v.stores),'source_load_instances':len(v.loads),'logical_transfer_instances':len(v.edges),'predecessor_bound_partial_state_evaluations':len(cases),'projected_handoff_register_values_checked':sum(q['projected_handoff_registers_checked']for q in cases),'protected_header_bytes_checked':sum(q['header_bytes_checked']for q in cases),'arbitrary_missing_cells_per_world':8,'missing_cells_assigned_concrete_values':0,'negative_source_controls':len(controls)}
 assert counts['normal_path_unique_PCs']==223 and counts['composed_path_instruction_instances']==309 and counts['normal_pointer_branch_instances']==8
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'kernel_collection_sha256':e['kernel_collection_sha256'],'scope':e['scope'],'dependencies':e['dependencies'],'verified_counts':e['verified_counts'],'source_proofs':proofs,'rechecked_prior_reader_proofs':rechecked,'partial_state_evaluations':cases,'negative_source_controls':controls,'independent_totals':counts,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
