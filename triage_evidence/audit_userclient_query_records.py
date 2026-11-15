#!/usr/bin/env python3
"""Prove conditional query record custody and selected constructor ABI.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
No target calls; ordinary helper returns and selected storage/phase cuts explicit.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_record_metadata import Model as MetadataModel
from audit_userclient_input_reader import TOKEN,PHASE,SUCCESS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_query_records as R

MAGIC=0xa41a4d891208c018
FIRST=0xfffffe000a656f8c
SECOND=0xfffffe000a657018
THIRD=0xfffffe000a65f358
REQUESTS=[('first',0x45,0x33b7bc52,0x7da50066,FIRST),
 ('second',0x42,0xb0ac8a39,0x31ae019e,SECOND),('third',0x68,0xa024e3ab,0x31ae99cd,THIRD)]

class Model(MetadataModel):
 def __init__(self,e):
  super().__init__(e);self.new_node,self.new_buffer=z3.BitVecs('QR_new_node64 QR_new_buffer64',64)
  self.with_node=False;self.with_buffer=False
 def operand(self,i,o,n):
  v=super().operand(i,o,n)
  if i.mnemonic=='cmn' and o.type==ARM64_OP_REG:self.cmn_left=v
  return v
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,4096),(self.src,16384),(self.object,16)]
  if self.with_node:spans.append((self.new_node,32))
  if self.with_buffer:spans.append((self.new_buffer,14))
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
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('QR_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('QR_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)
 def returned(self,value=None):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('QR_call_'+str(self.count)+'_X'+str(j),64))
  if value is not None:self.seed('x0',value)
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w30',SUCCESS),('w19',PHASE),('w24',PHASE-0x274),
  ('x5',MAGIC),('x6',0xfffffe000ccc30d0),('x27',0xfffffe0007949dd0)]:v.seed(r,x)
 # W24 on the accepted caller path is PHASE-0x274 =0x7795e3ce.
 for o,x in [(0x998,v.src+0x968),(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),
  (0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),(0xa10,0xfffffe0007949fd0),(0xa18,0xfffffe000792ffc0),
  (0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0),(0x930,0xfffffe000792fdc0),(0x928,0xfffffe00079392f0),
  (0x9f8,0xfffffe0007949ed0),(0x9f0,0xfffffe000792fec0),(0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),
  (0x988,v.ctx+0x600),(0x728,v.ctx+0x3c0),(0x888,v.src+0xbe4)]:mem(v,v.sp+o,8,x)
 mem(v,v.sp+0x53c,4,0x5cd5096e);mem(v,v.sp+0x9ec,4,v.status)
 mem(v,v.ctx+0x600,8,v.object);mem(v,v.ctx+0x3a8,8,v.object)
 return v

def requests(e,case):
 v=setup(e)
 if case=='first':
  v.run('query_version').returned();mem(v,v.src+0x96c,4,0x4c0b0000)
  v.run('query_capabilities').returned();mem(v,v.src+0x96c,4,0x1f8);v.run('request_first')
 else:
  v.seed('w22',0x42 if case=='second' else 0x68)
  v.run('request_second' if case=='second' else 'request_third')
 return v
def prepared(e,case='first'):
 return requests(e,case).run('shared_entry').run('shared_prepare').run('node_request_record')
def allocation(e):return prepared(e).run('extent_gate').run('node_allocate')

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
 v=setup(e).run('record_root').run('record_root_save').run('callback_basis').run('callback_basis_save')
 prove('original_workspace_record_root_and_second_callback_basis',v,z3.Or(cell(v,v.sp+0x998,8)!=v.src+0x968,cell(v,v.sp+0x53c,4)!=0x5cd5096e))
 v=setup(e).run('query_version');q=v.src+0x968
 prove('version_query_exact_private_header_target_record_and_discriminator',v,z3.Or(
  cell(v,q,4)!=0x440e0fe1*(resize(q,32)^0x841cb645)-0x7f03ff,v.read('x8')!=0xfffffe000a66a5a8,
  v.read('x0')!=q,v.read('x17')!=0x5c97,v.read('w22')!=0x45,cell(v,v.ctx+0x3a8,8)!=v.object))
 v.returned();mem(v,q+4,4,0x4c0b0000);v.run('query_capabilities')
 prove('capability_query_reuses_same_record_without_consuming_version_result',v,z3.Or(
  cell(v,q,4)!=0x3d7a7ab1-0x84d77373*(resize(q,32)^0x6133a0c8),cell(v,q+4,4)!=0x4c0b0000,
  v.read('x8')!=0xfffffe000a5c22a8,v.read('x0')!=q,v.read('x17')!=0x7787))
 v.returned();mem(v,q+4,4,0x1f8);v.run('request_first')
 prove('capability_effect_overwrites_version_word_and_first_request_is_literal_metadata',v,z3.Or(
  cell(v,q+4,4)!=0x1f8,v.read('w26')!=0x7da50066,v.read('w19')!=0x33b7bc52,
  v.read('w22')!=0x45,v.read('w23')!=0x9dc,v.read('x8')!=0xfffffe000a6613fc))
 records=[]
 for case,idx,tag,scalar,callback in REQUESTS:
  d=requests(e,case)
  prove(case+'_request_selects_shared_entry_and_exact_callback_channel',d,z3.Or(d.read('w22')!=idx,d.read('w23')!=0x9dc,
   d.read('w19')!=tag,d.read('w26')!=scalar,d.read('w24')!=PHASE-0x274,d.read('x25')!=d.object,d.read('x8')!=0xfffffe000a6613fc))
  d.run('shared_entry')
  prove(case+'_shared_entry_installs_callback_and_selects_nonnull_container',d,z3.Or(cell(d,d.ctx+0x5a8,8)!=callback,
   d.read('x8')!=0xfffffe000a661458,d.read('w23')!=0xce515bbf))
  d.run('shared_prepare').run('node_request_record')
  prove(case+'_constructor_packet_preserves_exact_metadata_control_words',d,z3.Or(
   cell(d,d.ctx+0x260,8)!=0xfffffe000a664230,cell(d,d.ctx+0x20,8)!=d.object,cell(d,d.ctx+0x168,8)!=0,
   cell(d,d.src+0x1d0,4)!=tag,cell(d,d.src+0x1b2,2)!=0x3594,cell(d,d.src+0x94,4)!=SUCCESS-4,
   cell(d,d.src+0x110,4)!=scalar,cell(d,d.src+0xad0,8)!=0x8f98c6acce5848ca,d.read('x8')!=0xfffffe000a661510))
  records.append({'case':case,'callback_index':hex(idx),'callback':hex(callback),'tag_control_u32':hex(tag),
   'scalar_control_u32':hex(scalar),'xor_success_u32':hex(scalar^SUCCESS),'type_control_u16':'0x3594','payload_extent_bytes':4})
  d.run('extent_gate')
  prove(case+'_four_byte_payload_selects_constructor_extent_gate',d,z3.Or(d.read('w20')!=0xaaa,d.cmn_left!=4,d.read('x8')!=0xfffffe000a66159c))
 v=allocation(e)
 prove('shared_node_requests_original_typed_thirty_two_byte_descriptor',v,z3.Or(v.read('x10')!=0xfffffe000c4ba154,v.read('x0')!=0xfffffe000847b4a0,v.read('x17')!=0xd0c8))
 v.returned(v.new_node).run('node_result')
 prove('node_result_saved_and_null_or_nonnull_frontiers_exact',v,z3.Or(cell(v,v.ctx+0x58,8)!=v.new_node,
  v.read('x8')!=z3.If(v.new_node==0,resize(0xfffffe000a66169c,64),resize(0xfffffe000a6616d4,64))))
 d=copy.deepcopy(v);d.run('node_failure')
 prove('null_node_result_reaches_existing_failure_retirement_frontier',d,z3.Or(d.read('x22')!=0,d.read('w23')!=d.status,d.read('x8')!=0xfffffe000a664074),[d.new_node==0])
 v.with_node=True;v.run('node_initialize')
 prove('nonnull_node_initializes_links_extent_and_requests_fourteen_data_bytes',v,z3.Or(
  cell(v,v.new_node,8)!=0,cell(v,v.new_node+8,8)!=0,cell(v,v.new_node+0x10,4)!=14,
  v.read('x0')!=14,v.read('x8')!=0xfffffe000c4ba60c,v.read('x17')!=0xca0c))
 v.returned(v.new_buffer).run('data_result')
 prove('data_result_saved_with_exact_failure_or_writer_frontier',v,z3.Or(cell(v,v.new_node+0x18,8)!=v.new_buffer,
  v.read('w23')!=v.status,v.read('x8')!=z3.If(v.new_buffer==0,resize(0xfffffe000a664074,64),resize(0xfffffe000a661880,64))))
 v.with_buffer=True;v.run('writer_entry')
 prove('nonnull_data_result_selects_original_protected_writer_input_contract',v,z3.Or(
  v.read('x16')!=v.new_node+0x18,v.read('x3')!=v.src,v.read('x11')!=v.ctx,v.read('w1')!=SUCCESS,
  v.read('x0')!=0x02e859d27e491464,v.read('w14')!=PHASE,v.read('x8')!=0xfffffe000a654ad4))
 for which,callback,idx in [('first',FIRST,0x45),('second',SECOND,0x42),('third',THIRD,0x68)]:
  v=setup(e);v.seed('w23',v.status);v.seed('x28',0xfffffe0007949dd0);mem(v,v.ctx+0x5a8,8,callback)
  v.run('shared_return')
  prove(which+'_shared_return_preserves_arbitrary_raw_status_and_restores_callback_tokens',v,z3.Or(
   v.read('x8')!=callback,v.read('w23')!=v.status,v.read('w3')!=TOKEN,v.read('w10')!=TOKEN,v.read('x27')!=0xfffffe0007949dd0))
  v.run('callback_'+which)
  target=0xfffffe000a656fd4 if which=='first' else 0xfffffe000a65706c if which=='second' else 0xfffffe000a65f3b4
  failure=0xfffffe000a65f358 if which!='third' else 0xfffffe000a656f00
  prove(which+'_callback_uses_same_success_constant_and_exact_status_split',v,z3.Or(v.cmp_right!=SUCCESS,
   v.read('w22')!=(0x42 if which=='first' else 0x68) if which!='third' else z3.BoolVal(False),
   v.read('x8')!=z3.If(v.status==SUCCESS,resize(target,64),resize(failure,64))))
  if which=='third':
   v.run('post_requests');prove('third_success_passes_container_and_auxiliary_output_aliases_to_next_facility',v,z3.Or(
    v.read('x11')!=v.ctx+0x600,v.read('x12')!=v.ctx+0x3c0,v.read('x21')!=v.src+0xbe4,v.read('x8')!=0xfffffe000a65f3ec),[v.status==SUCCESS])
 # The null-container edge is structurally distinct from the admitted parsed-container route.
 v=requests(e,'first');mem(v,v.ctx+0x600,8,0);mem(v,v.ctx+0x3a8,8,0);v.seed('x25',0)
 v.run('shared_entry').run('shared_return')
 prove('conditional_null_container_returns_default_raw_status_to_first_callback',v,z3.Or(v.read('w23')!=0xce515bbf,v.read('x8')!=FIRST))
 v=prepared(e);v.run('shared_empty')
 prove('isolated_shared_empty_block_selects_saved_constructor_return',v,z3.Or(v.read('x8')!=0xfffffe000a664230,v.read('w21')!=PHASE))
 # Retain source-backed predecessor formulas as explicit congruence cuts.
 old=json.loads(read(ROOT/'kext_query_getter_values_checks.json'));rechecked=[]
 names=['version_adapter_all_original_bank_pointer_and_data_addresses_and_call_ABI','status_leaf_exact_u32_store_and_pointer_return',
  'version_adapter_postcall_overwrites_caller_result_with4c0b0000','capability_leaf_exact_u32_store_and_pointer_return']
 for q in old['proofs']:
  if q['name'] not in names:continue
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat;rechecked.append({'label':q['name'],'result':'unsat'})
 assert len(rechecked)==4
 cd=json.loads(read(ROOT/'userclient_command_dispatch_audit.json'));q=next(q for q in cd['source_proofs'] if q['label']=='second_command_entry_saves_container_at_distinct_context_cell')
 s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat;rechecked.append({'label':q['label'],'result':'unsat'})
 from audit_userclient_command_dispatch import scalar as prior_scalar
 d=prior_scalar(json.loads(read(ROOT/'userclient_command_dispatch_checks.json')))
 d.branch_choices={0xfffffe000a63ad50:False,0xfffffe000a63ad60:False};d.run('command_gate').run('second_command_entry')
 assert z3.simplify(d.read('w19')).as_long()==PHASE and z3.simplify(d.read('w24')).as_long()==PHASE-0x274
 # Independent operand-level evidence sensitivity: alter only the literal first scalar.
 changed=copy.deepcopy(e);row=next(s for s in changed['spans'] if s['label']=='request_first');b=bytearray.fromhex(row['bytes_hex'])
 off=0xfffffe000a63af24-int(row['start'],16);original=bytes(b[off:off+4]);word=int.from_bytes(original,'little')
 b[off:off+4]=(word^(1<<5)).to_bytes(4,'little');row['bytes_hex']=b.hex();v=requests(changed,'first')
 s=z3.Solver();s.add(*v.owned(),v.read('w26')!=0x7da50066);assert s.check()==z3.sat
 selected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']}
 assert visited==selected,selected-visited
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],'scope':R.SCOPE,
  'source_proofs':qs,'proof_coverage':coverage,'request_records':records,'rechecked_prior_source_proofs':rechecked,
  'predecessor_command_phase_reconstructed':True,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(rechecked),'distinct_proved_instructions':len(visited),
   'proof_instruction_instances':sum(q['source_instruction_instances'] for q in coverage),'bank_composition_input_cases':1280,'construction_request_cases':3,
   'altered_literal_scalar_counterexample':True},
  'conditional_query_record_request_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
