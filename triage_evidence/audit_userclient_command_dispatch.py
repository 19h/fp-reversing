#!/usr/bin/env python3
"""Conditional parser caller, tagged scalar reader and command obligations.
O(I+256R+query DAG) construction/space; separate SMT cost, 30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import DEC,WORD_BYTES,TYPE_BYTES,TOKEN,PHASE,SUCCESS,mask
from audit_userclient_record_metadata import Model as MetadataModel
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_command_dispatch as R

KEY0=0x02e859d27e491464
KEY1=0x4dae26df20976138
REQUEST=0x45e5918e
MISS=0xce515bda
CLEANUP=0xfffffe000a656f00

class Model(MetadataModel):
 def __init__(self,e):
  super().__init__(e)
  self.plain=[z3.BitVec('CD_plain_byte'+str(j),8) for j in range(14)]
  self.with_container=True
  self.first_input=z3.BitVec('CD_first_input64',64)
  self.table_pcs=set()
  for row in e['spans']:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if i.mnemonic=='ldr' and i.reg_name(i.operands[0].reg).startswith('x') and i.operands[1].type==ARM64_OP_MEM and i.operands[1].mem.index:
     if i.reg_name(i.operands[1].mem.base) in ['x7','x21']:self.table_pcs.add(i.address)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000)]
  if self.with_container:spans.append((self.object,16))
  if self.with_node:spans.append((self.node,32))
  if self.with_buffer:spans.append((self.buffer,z3.If(z3.ULT(self.extent,4),resize(4,64),z3.ZeroExt(32,self.extent))))
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
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('CD_bank_'+name,8)
    self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
   if self.pc==rp:
    assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^int(r['key'],16)))
    self.bank_rewrites.append({'pc':hex(self.pc),'rule':name,'inputs':256});return self.bank_input^int(r['constant'],16)
   if self.pc==pp:
    assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in self.table_pcs:
   assert n==8;js=R.BRANCHES[self.pc]
   self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc in WORD_BYTES|TYPE_BYTES:
   assert n==1 and self.byte_pos<len(self.byte_offsets);j=self.byte_offsets[self.byte_pos];self.byte_pos+=1
   self.address_checks.append(a==self.buffer+j);return self.plain[j]^mask(a,resize(KEY0,64))
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('CD_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)
 def run(self,label,end=None):
  self.direct_target=None
  row=next(s for s in self.e['spans'] if s['label']==label)
  ii=list(DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)))
  if ii[-1].mnemonic!='b':return super().run(label,end)
  i=ii[-1];super().run(label,min(end,i.address) if end is not None else i.address)
  if self.direct_target is None and (end is None or end>i.address):
   self.pc=i.address;self.visited.add(i.address);self.count+=1;self.direct_target=i.operands[0].imm&(2**64-1)
  return self

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w1',PHASE),('w30',SUCCESS),
  ('w23',v.status),('x27',0xfffffe0007949dd0),('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018)]:v.seed(r,x)
 for o,x in [(0x988,v.ctx+0x600),(0x5a8,v.ctx+0x1f8),(0x8e8,v.ctx+0x770),(0x738,v.first_input),
  (0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa00,0xfffffe000792fcc0),(0xa20,0xfffffe00079391f0),
  (0xa48,0xfffffe0007949dd0),(0xa40,0xfffffe000792fbc0)]:mem(v,v.sp+o,8,x)
 mem(v,v.ctx+0x600,8,v.object);mem(v,v.object,8,v.node)
 mem(v,v.node,8,v.next);mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.buffer)
 return v

def requested(e):return setup(e).run('caller_status').run('field_gate').run('field_request')
def search(e):return requested(e).run('search_entry').run('search_nonnull').run('search_node')
def searched(e):
 v=search(e);v.with_node=v.with_buffer=True
 return v.run('node_decode_prepare').run('word_bridge').decode(range(4)).run('tag_match').run('search_result').run('search_callback')
def selected(e):return searched(e).run('field_result').run('node_fields').run('header_extent')
def header(e):
 v=selected(e).run('header_prepare').run('word_bridge').decode(range(4)).run('tag_return').decode(range(4,6))
 return v.run('type_return').run('length_bridge').decode(range(6,10)).run('length_extent')
def scalar(e):return header(e).run('type_gate').run('payload_prepare').run('length_bridge').decode(range(10,14)).run('payload_return').run('scalar_return')
def tag(v):return z3.Concat(*v.plain[:4])^SUCCESS
def kind(v):return z3.Concat(*v.plain[4:6])^0x365e
def length(v):return z3.Concat(*v.plain[6:10])
def value(v):return z3.Concat(*v.plain[10:14])
def matched(v):return [v.status==SUCCESS,tag(v)==REQUEST]
def header_ok(v):return z3.UGE(v.extent,10)
def body_ok(v):return z3.ULE(10+z3.ZeroExt(32,length(v)),z3.ZeroExt(32,v.extent))
def accepted(v):return matched(v)+[header_ok(v),body_ok(v),kind(v)==0xa129,length(v)==4]

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));r=s.check();assert r==z3.unsat,(label,str(r),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('node_output_root').run('node_buffer_root').run('container_root')
 prove('three_original_caller_cell_roots',v,z3.Or(cell(v,v.sp+0x5a8,8)!=v.ctx+0x1f8,
  cell(v,v.sp+0x8e8,8)!=v.ctx+0x770,cell(v,v.sp+0x988,8)!=v.ctx+0x600))
 v=setup(e).run('caller_status')
 prove('all_parser_status32_exact_success_or_failure_continuation',v,z3.Or(v.read('w10')!=TOKEN,
  v.read('x8')!=z3.If(v.status==SUCCESS,resize(0xfffffe000a656c44,64),resize(0xfffffe000a65f358,64))))
 v.run('failure_second')
 prove('parser_failure_second_comparison_is_same_success_constant_and_cannot_take_success_edge',v,z3.Or(
  v.cmp_right!=SUCCESS,v.read('x8')!=CLEANUP),[v.status!=SUCCESS])
 v.with_container=False;v.run('cleanup_gate')
 prove('parser_failure_reaches_null_output_cleanup_and_saves_raw_status',v,z3.Or(cell(v,v.src+0xde4,4)!=v.status,
  v.read('w24')!=0x1a,v.read('x8')!=0xfffffe000a665e90),[v.status!=SUCCESS,v.object==0])
 v=setup(e);v.with_container=False;v.run('caller_status').run('field_gate')
 prove('successful_status_with_null_container_selects_explicit_null_container_frontier',v,z3.Or(
  cell(v,v.ctx+0x1f8,8)!=0,cell(v,v.src+0xcf0,4)!=SUCCESS,cell(v,v.sp+0xa78,8)!=0,
  v.read('w25')!=TOKEN,v.read('x8')!=0xfffffe000a665e50),[v.status==SUCCESS,v.object==0])
 v.run('null_container')
 prove('null_container_frontier_saves_buffer_absent_status_and_skips_container_cleanup',v,z3.Or(
  cell(v,v.src+0xde4,4)!=0xce515bbf,v.read('w10')!=TOKEN,v.read('x8')!=0xfffffe000a665e90),[v.status==SUCCESS,v.object==0])
 v=requested(e)
 prove('nonnull_container_requests_command_tag_with_exact_result_cell_keys_and_continuation',v,z3.Or(
  v.read('w9')!=REQUEST,v.read('x22')!=v.object,v.read('x10')!=v.ctx+0x1f8,v.read('w8')!=0x6b,
  v.read('x11')!=0xfffffe000a662ab4,v.read('x20')!=KEY1,v.read('x26')!=KEY0,
  v.read('w25')!=TOKEN,v.read('w24')!=0x7795e3ce,v.read('w27')!=0x37),[v.status==SUCCESS])
 v.run('search_entry')
 prove('command_search_saves_its_own_callback_output_and_encoded_requested_tag',v,z3.Or(
  cell(v,v.ctx+0xc8,8)!=0xfffffe000a656cfc,cell(v,v.ctx+0x758,8)!=v.ctx+0x1f8,
  cell(v,v.src,4)!=REQUEST,v.read('x8')!=0xfffffe000a662be0),[v.status==SUCCESS])
 v.run('search_nonnull').run('search_node')
 prove('command_search_empty_or_node_decode_gate',v,z3.Or(cell(v,v.ctx+0x2b0,8)!=v.node,v.read('w23')!=MISS,
  v.read('x9')!=z3.If(v.node==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))),[v.status==SUCCESS])
 empty=copy.deepcopy(v);empty.run('search_result').run('search_callback').run('field_result')
 prove('empty_command_search_returns_miss_zero_output_and_cleanup_edge',empty,z3.Or(
  cell(empty,empty.ctx+0x1f8,8)!=0,empty.read('w23')!=MISS,empty.read('x8')!=CLEANUP,
  empty.read('w10')!=TOKEN),[empty.status==SUCCESS,empty.node==0])
 cut=setup(e).run('field_result')
 prove('isolated_search_return_phase_all_status32_selects_success_node_reader_or_cleanup',cut,z3.Or(
  cut.read('x8')!=z3.If(cut.status==SUCCESS,resize(0xfffffe000a656d48,64),resize(CLEANUP,64)),cut.read('w10')!=TOKEN))
 cut.seed('w23',SUCCESS);cut.with_node=True;mem(cut,cut.ctx+0x1f8,8,cut.node)
 cut.run('node_fields')
 prove('isolated_successful_search_return_all_buffer64_and_extent32_exact_nullable_gate',cut,z3.Or(
  cut.read('x11')!=z3.ZeroExt(32,cut.extent),cell(cut,cut.ctx+0x770,8)!=cut.buffer,
  cut.read('x12')!=z3.If(cut.buffer==0,resize(CLEANUP,64),resize(0xfffffe000a656d9c,64)),cut.read('w23')!=0xce515bbf))
 v.with_node=v.with_buffer=True;v.run('node_decode_prepare').run('word_bridge').decode(range(4)).run('tag_match')
 prove('all_protected_node_tags_match_command_tag_or_follow_successor',v,z3.Or(v.read('x22')!=v.node,
  v.read('x10')!=z3.If(tag(v)==REQUEST,resize(0xfffffe000a662c44,64),resize(0xfffffe000a63d680,64))),[v.status==SUCCESS])
 nxt=copy.deepcopy(v);nxt.run('search_next').run('search_node')
 prove('command_tag_mismatch_repeats_lookup_with_saved_successor',nxt,z3.Or(cell(nxt,nxt.ctx+0x2b0,8)!=nxt.next,
  nxt.read('x9')!=z3.If(nxt.next==0,resize(0xfffffe000a662c44,64),resize(0xfffffe000a662c60,64))),[nxt.status==SUCCESS,tag(nxt)!=REQUEST])
 v.run('search_result').run('search_callback').run('field_result')
 prove('matching_command_node_returns_success_to_caller_node_reader',v,z3.Or(cell(v,v.ctx+0x1f8,8)!=v.node,
  v.read('w23')!=SUCCESS,v.read('x8')!=0xfffffe000a656d48,v.read('w19')!=PHASE,v.read('w9')!=0x840),matched(v))
 v.run('node_fields')
 prove('command_node_publishes_buffer_and_zero_extended_extent_then_checks_buffer',v,z3.Or(
  cell(v,v.ctx+0x770,8)!=v.buffer,v.read('x11')!=z3.ZeroExt(32,v.extent),v.read('w23')!=0xce515bbf,
  v.read('x12')!=z3.If(v.buffer==0,resize(CLEANUP,64),resize(0xfffffe000a656d9c,64))),matched(v))
 v.run('header_extent')
 prove('command_reader_header_gate_is_exact_extent_at_least_ten',v,z3.Or(cell(v,v.sp+0xba8,8)!=0,v.read('w12')!=0x1c5,
  v.read('x9')!=z3.If(header_ok(v),resize(0xfffffe000a656e48,64),resize(CLEANUP,64)),
  v.read('w23')!=0xce515bb8),matched(v))
 v.run('header_prepare').run('word_bridge').decode(range(4)).run('tag_return').decode(range(4,6))
 prove('command_reader_reuses_protected_header_type_at_offset_four',v,z3.Or(z3.Extract(15,0,v.read('w8'))!=kind(v),
  v.read('x10')!=0xfffffe000a6370ac),matched(v)+[header_ok(v)])
 v.run('type_return').run('length_bridge').decode(range(6,10)).run('length_extent')
 prove('command_record_body_gate_is_exact_ten_plus_length_with_candidate_saved',v,z3.Or(
  cell(v,v.src+0xd88,2)!=kind(v),cell(v,v.src+0x1c0,8)!=10+z3.ZeroExt(32,length(v)),
  v.read('w22')!=(length(v)^SUCCESS),v.read('x11')!=10,
  v.read('x8')!=z3.If(body_ok(v),resize(0xfffffe000a637514,64),resize(CLEANUP,64))),matched(v)+[header_ok(v)])
 v.run('type_gate')
 prove('command_scalar_type_a129_requires_exact_four_byte_length',v,z3.Or(
  v.read('x8')!=z3.If(length(v)==4,resize(0xfffffe000a637568,64),resize(CLEANUP,64)),
  v.read('w9')!=0x1b7,v.read('w23')!=0xce515bb8),matched(v)+[header_ok(v),body_ok(v),kind(v)==0xa129])
 v.run('payload_prepare').run('length_bridge').decode(range(10,14)).run('payload_return').run('scalar_return')
 prove('command_scalar_four_payload_bytes_publish_encoded_value_and_cursor_fourteen',v,z3.Or(
  cell(v,v.src+0xcf0,4)!=(value(v)^SUCCESS),cell(v,v.sp+0xa78,8)!=14,
  v.read('x8')!=0xfffffe000a63ad3c,v.read('w23')!=0xce515ae1,v.read('w10')!=TOKEN),accepted(v))
 offset=z3.BitVec('CD_read_offset64',64)
 prove('accepted_command_reader_fourteen_offsets_fit_retained_node_extent',v,z3.Or(
  z3.ULT(v.buffer+offset,v.buffer),z3.UGE(v.buffer+offset,v.buffer+z3.ZeroExt(32,v.extent))),accepted(v)+[z3.ULT(offset,14)])
 prove('accepted_command_reader_allows_retained_node_extent_larger_than_fourteen',v,z3.Or(
  cell(v,v.sp+0xa78,8)!=14,v.read('x8')!=0xfffffe000a63ad3c),accepted(v)+[z3.UGT(v.extent,14)])
 for case,n,tgt in [('first',0x88594abe,0xfffffe000a63dd14),('second',0x73eba01e,None),('other',None,0xfffffe000a63ddd0)]:
  d=copy.deepcopy(v);d.branch_choices={0xfffffe000a63ad50:case=='first',0xfffffe000a63ad60:case=='other'};d.run('command_gate')
  prem=accepted(d)+([value(d)==n] if n is not None else [value(d)!=0x88594abe,value(d)!=0x73eba01e])
  prove('decoded_command_'+case+'_selects_exact_direct_edge',d,z3.BoolVal(d.direct_target!=tgt),prem)
  if case=='first':
   d.run('first_command')
   prove('first_command_retains_container_clears_hash_outputs_and_selects_previous_reader',d,z3.Or(
    cell(d,d.ctx+0x4b0,8)!=d.object,cell(d,d.ctx+0x128,8)!=0,cell(d,d.src+0xaa8,4)!=SUCCESS,
    d.read('x8')!=z3.If(d.first_input==0,resize(CLEANUP,64),resize(0xfffffe000a63dd80,64)),d.read('w23')!=0xce515bbf),prem)
  elif case=='second':
   d.run('second_command_entry')
   prove('second_command_entry_saves_container_at_distinct_context_cell',d,z3.Or(cell(d,d.ctx+0x3a8,8)!=d.object,
    d.read('w21')!=PHASE,d.read('w23')!=0x9dc),prem)
  else:
   d.run('unsupported');prove('unsupported_command_assigns_raw_status_and_enters_cleanup',d,z3.Or(
    d.read('w23')!=0xce515bb7,d.read('w10')!=TOKEN,z3.BoolVal(d.direct_target!=CLEANUP)),prem)
   d.run('cleanup_gate');prove('unsupported_command_cleanup_saves_exact_status_and_requests_container_path',d,z3.Or(
    cell(d,d.src+0xde4,4)!=0xce515bb7,d.read('w24')!=0x1a,d.read('x8')!=0xfffffe000a656f4c),prem)
 for u in [0x6685,0xb2db,0]:
  d=header(e);d.branch_choices[0xfffffe000a637524]=True;d.run('type_gate')
  prove('non_scalar_type_'+format(u,'x')+'_takes_other_type_dispatch',d,z3.BoolVal(d.direct_target!=0xfffffe000a63a614),matched(d)+[header_ok(d),body_ok(d),kind(d)==u])
  d.branch_choices={0xfffffe000a63a61c:u==0x6685,0xfffffe000a63a630:u==0xb2db};d.run('other_type_gate')
  if u:
   prove('recognized_other_type_'+format(u,'x')+'_selects_final_type_check',d,z3.BoolVal(d.direct_target!=0xfffffe000a63acf4),matched(d)+[header_ok(d),body_ok(d),kind(d)==u])
   d.run('scalar_return');prove('recognized_other_type_'+format(u,'x')+'_fails_final_scalar_type_check',d,z3.Or(
    d.read('x8')!=CLEANUP,d.read('w23')!=0xce515ae1),matched(d)+[header_ok(d),body_ok(d),kind(d)==u])
  else:
   prove('all_unrecognized_non_scalar_types_take_direct_cleanup',d,z3.BoolVal(d.direct_target!=CLEANUP),matched(d)+[header_ok(d),body_ok(d),kind(d)!=0xa129,kind(d)!=0x6685,kind(d)!=0xb2db])
 for pc in R.RETAGS.values():
  row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16)
  raw=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(raw,pc));reg=i.reg_name(i.operands[0].reg)
  d=setup(e);old=z3.BitVec('CD_retag_input_'+format(pc,'x'),64);d.seed(reg,old)
  d.e=d.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':raw.hex()}]};d.run('alternate')
  prove('alternate_retag_'+format(pc,'x')+'_bit_transform_only',d,d.read(reg)!=((old&0xffffffffffff)|(0xc8a2<<48)))
 selected_pcs={int(i['ea'],16) for s in e['spans'] for i in s['instructions']}
 assert visited==selected_pcs,{'missing':sorted(map(hex,selected_pcs-visited)),'extra':sorted(map(hex,visited-selected_pcs))}
 rechecked=[]
 for f,label in [
  ('userclient_parser_cleanup_audit.json','empty_container_failure_clears_cell_and_output_retains_status_and_resumes'),
  ('userclient_record_publication_audit.json','all_stored_tag32_and_requested_tag32_exact_match_or_successor_gate'),
  ('userclient_input_reader_audit.json','caller_tag_outputs_and_hash_gate_continuation_index'),
  ('userclient_input_reader_audit.json','final_copy_iteration_publishes_pointer_length_and_success_to_hash_gate')]:
  p=next(p for p in json.loads(read(ROOT/f))['source_proofs'] if p['label']==label)
  s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert p['premises_nonvacuous'] and s.check()==z3.unsat
  rechecked.append({'artifact':f,'artifact_sha256':sha(ROOT/f),'label':label,'result':'unsat'})
 controls=[]
 for name,mutate in [
  ('instruction_byte',lambda x:x['spans'][0].update(bytes_hex='00'+x['spans'][0]['bytes_hex'][2:])),
  ('command_value',lambda x:x['command_field']['command_cases'][0].update(decoded_u32='0x0')),
  ('scalar_width',lambda x:x['verified_counts'].update(scalar_bytes=8)),
  ('native_transaction_claim',lambda x:x.update(daemon_kext_transaction_correlated=True))]:
  altered=copy.deepcopy(e);mutate(altered);assert altered!=e;controls.append({'alteration':name,'equality_check_rejects':True})
 return {'generator_sha256':sha(__file__),'source_sha256':e['source_sha256'],'scope':R.SCOPE,
  'source_proofs':qs,'proof_coverage':coverage,'proved_pcs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':rechecked,'altered_evidence_controls':controls,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(rechecked),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':256,'altered_evidence_rejections':len(controls),'command_cases':3},
  'conditional_command_dispatch_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
