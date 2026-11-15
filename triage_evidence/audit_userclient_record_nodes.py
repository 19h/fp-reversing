#!/usr/bin/env python3
"""Conditional post-header node construction obligations from original words.
O(I+256R+query DAG) construction/space; SMT cost separate, 30 s/query.
No target executes; ordinary call and valid separated-storage cuts are explicit.
"""
import copy
import json
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,TABLE,POOL,qword
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_record_nodes as R

TOKEN=0x886a1ca3
PHASE=0x7795e642
SUCCESS=0x31ae0066
KEY0=0x02e859d27e491464
DEC=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);DEC.detail=True

class Model(Base):
 def __init__(self,e):
  super().__init__(e);self.receipt=e
  self.node,self.result,self.cursor=z3.BitVecs('RN_node64 RN_result64 RN_cursor64',64)
  self.tag,self.encoded_length=z3.BitVecs('RN_tag_channel32 RN_encoded_length32',32);self.kind=z3.BitVec('RN_type16',16)
  self.with_header=self.with_node=self.with_buffer=False;self.branch_guards=[]
  self.table_pcs=set()
  for row in e['spans']:
   for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
    if i.mnemonic=='ldr' and i.reg_name(i.operands[0].reg).startswith('x') and i.operands[1].type==ARM64_OP_MEM and i.operands[1].mem.index and i.reg_name(i.operands[1].mem.base) in ['x7','x11','x21']:self.table_pcs.add(i.address)
 def length(self):return self.encoded_length^SUCCESS
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000)]
  if self.with_header:spans.append((self.header,16))
  if self.with_node:spans.append((self.node,32))
  if self.with_buffer:spans.append((self.result,z3.ZeroExt(32,self.length())+10))
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
    assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('RN_bank_'+name,8)
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
  aa=z3.simplify(a)
  if n==4 and z3.is_bv_value(aa) and aa.as_long() in [0xfffffe000ccc30d0,0xfffffe000ccc32f8]:return z3.BitVec('RN_controller_'+format(self.pc,'x'),32)
  return super().load(a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label)
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   self.pc=i.address;o=i.operands
   if i.mnemonic=='cmn':
    self.visited.add(i.address);self.count+=1;n=self.width(i.reg_name(o[0].reg));a,b=(self.operand(i,x,n) for x in o[:2]);self.equal=a+b==0;self.carry=z3.ULT(a+b,a)
   elif i.mnemonic=='cset' and i.op_str.endswith(', lo') and hasattr(self,'carry'):
    self.visited.add(i.address);self.count+=1;self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.carry),resize(1,32),resize(0,32)));del self.carry
   else:
    oe,oc=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('one');self.e,self.c=oe,oc
  return self
 def returned(self,value):
  for j in [*range(19),30]:self.seed('x'+str(j),z3.BitVec('RN_call_'+str(self.count)+'_X'+str(j),64))
  self.seed('x0',value);return self

def setup(e):
 v=Model(e)
 for reg,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w1',PHASE),('w3',TOKEN),('w30',SUCCESS),('w8',0x54d),
  ('x6',0xfffffe000ccc30d0),('x5',0xa41a4d891208c018),('x28',0xfffffe0007949dd0)]:v.seed(reg,x)
 for o,x in [(0xa08,v.src),(0xa28,v.ctx),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa40,0xfffffe000792fbc0),(0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0),(0x858,0xfffffe000847c020)]:mem(v,v.sp+o,8,x)
 for off,n,x in [(0xcf8,8,v.cursor),(0xa18,4,v.tag),(0x2a0,2,v.kind),(0xa64,4,v.encoded_length),
  (0x2ac,4,0x31ae0066),(0xbb8,8,0x688dbcd0b072e922)]:mem(v,v.src+off,n,x)
 mem(v,v.ctx+0x228,8,v.header);mem(v,v.ctx+0x280,8,v.payload);mem(v,v.sp+0x9ec,4,v.status)
 for off in [0x768,0x458,0x140,0x58]:mem(v,v.ctx+off,8,z3.BitVec('RN_retained_C'+format(off,'x'),64))
 for off,n in [(0xd30,4),(0x94,4),(0x110,4),(0x1b2,2)]:mem(v,v.src+off,n,z3.BitVec('RN_retained_S'+format(off,'x'),8*n))
 return v

def metadata(e):return setup(e).run('header_metadata_return').run('metadata_gate').run('record_kind_gate')
def request(e):return metadata(e).run('record_inputs').run('record_size_gate').run('node_allocate')
def initialized(e):
 v=request(e);return v.returned(v.node).run('node_return').run('node_initialize')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 for r in e['bank_rules']:
  l,rr=(bytes.fromhex(e['banks'][r[n+'_name']]['bytes_hex']) for n in ['left','right'])
  assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check()
  assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited)
  print(label,flush=True)
 def normal(v):return [z3.Not(z3.And(v.tag==SUCCESS,v.kind==0x6685)),v.header!=0,z3.ULE(v.length(),0xfffffff5)]
 v=setup(e)
 for r,x in [('x21',0xfffffe0007949dd0),('x22',0xfffffe000792fbc0),('x28',POOL)]:v.seed(r,x)
 v.run('descriptor_select').run('descriptor_save')
 prove('all_controller32_original_FPTTLVNode_descriptor_root_and_saved_alias',v,
  z3.Or(v.read('x1')!=0xfffffe000847c02c,cell(v,v.sp+0x858,8)!=0xfffffe000847c020))
 v=setup(e).run('header_metadata_return')
 prove('post_header_cursor_tag_type_length_channels_and_separate_success_outcome',v,z3.Or(
  cell(v,v.sp+0xa80,8)!=v.cursor,cell(v,v.src+0xaec,4)!=v.tag,cell(v,v.src+0xa08,2)!=v.kind,
  cell(v,v.src+0x9e8,4)!=v.encoded_length,v.read('w10')!=1,v.read('w23')!=SUCCESS,
  v.read('w12')!=TOKEN,v.read('x8')!=0xfffffe000a6423c0,v.read('x17')!=0xdfc5))
 v.run('metadata_gate')
 prove('valid_header_outcome_enters_metadata_kind_gate',v,z3.Or(v.read('x8')!=0xfffffe000a6423f4,v.read('w24')!=0x50))
 alternate=setup(e).run('header_metadata_return');alternate.seed('w10',0);alternate.run('metadata_gate')
 prove('zero_header_outcome_selects_failure_continuation',alternate,alternate.read('x8')!=0xfffffe000a662440)
 v.run('record_kind_gate')
 prove('all_tag32_type16_exact_reserved_pair_success_bypass',v,z3.Or(v.read('x11')!=z3.If(
  z3.And(v.tag==SUCCESS,v.kind==0x6685),resize(0xfffffe000a6421b0,64),resize(0xfffffe000a642454,64)),
  v.read('w19')!=v.tag,v.read('w12')!=z3.ZeroExt(16,v.kind),v.read('x8')!=v.header,v.read('w10')!=0xc88))
 v.run('record_inputs')
 prove('record_inputs_retain_metadata_body_container_and_nullable_container_gate',v,z3.Or(
  cell(v,v.ctx+0x780,8)!=v.header,cell(v,v.src+0x128,4)!=v.tag,cell(v,v.src+0xb90,2)!=v.kind,
  cell(v,v.src+0xe28,4)!=v.encoded_length,cell(v,v.src+0xdf8,4)!=SUCCESS,
  cell(v,v.sp+0xbe0,8)!=0x688dbcd0b072e922,cell(v,v.ctx+0x348,8)!=v.payload,
  v.read('w22')!=v.encoded_length,v.read('w23')!=0xce515bbf,v.read('x8')!=z3.If(v.header==0,
  resize(0xfffffe000a662440,64),resize(0xfffffe000a6424c8,64))),[z3.Not(z3.And(v.tag==SUCCESS,v.kind==0x6685))])
 v.run('record_size_gate')
 prove('all_encoded_length32_exact_unsigned_payload_plus_ten_guard',v,z3.Or(v.read('x8')!=z3.If(
  z3.ULE(v.length(),0xfffffff5),resize(0xfffffe000a642548,64),resize(0xfffffe000a662440,64)),v.read('w26')!=0x238))
 v.run('node_allocate')
 prove('original_typed_node_allocator_descriptor_and_preserved_phase_request',v,z3.Or(v.read('x0')!=0xfffffe000847c020,
  v.read('x8')!=0xfffffe000c4ba154,v.read('x17')!=0xd0c8,v.read('w20')!=0x766,
  v.read('w23')!=0x2e5,v.read('w24')!=PHASE,v.read('w25')!=TOKEN,v.read('w26')!=0x238),normal(v))
 v.returned(v.node).run('node_return')
 prove('all_node_result64_exact_nullable_gate_and_retained_node',v,z3.Or(cell(v,v.ctx+0x6b8,8)!=v.node,
  v.read('x8')!=z3.If(v.node==0,resize(0xfffffe000a6425fc,64),resize(0xfffffe000a64262c,64))),normal(v))
 null=copy.deepcopy(v);null.run('node_null')
 prove('null_node_result_joins_common_allocation_failure_target',null,z3.Or(cell(null,null.sp+0x50,8)!=0,
  null.read('x8')!=0xfffffe000a6622bc,null.read('w23')!=null.status,null.read('x21')!=TABLE,
  null.read('w14')!=PHASE,null.read('w27')!=0x37),[*normal(null),null.node==0])
 v.with_header=v.with_node=True;v.run('node_initialize')
 prove('nonnull_node_initializes_two_pointer_fields_and_exact_u32_total_extent',v,z3.Or(cell(v,v.node,8)!=0,
  cell(v,v.node+8,8)!=0,cell(v,v.node+0x10,4)!=v.length()+10,v.read('x0')!=z3.ZeroExt(32,v.length()+10),
  v.read('x27')!=v.node,cell(v,v.src+0x100,8)!=z3.ZeroExt(32,v.length())+0x41a549061921706d),normal(v))
 stores=[s for s in v.stores if s['pc'] in [0xfffffe000a6426d8,0xfffffe000a64275c]]
 assert sorted(s['size_bytes'] for s in stores)==[4,8,8]
 v.run('buffer_allocate')
 prove('exact_total_extent_IOMallocData_request_from_separate_bank_pair',v,z3.Or(v.read('x0')!=z3.ZeroExt(32,v.length())+10,
  v.read('x8')!=0xfffffe000c4ba60c,v.read('x17')!=0xca0c,v.read('x21')!=TABLE),normal(v))
 v.returned(v.result).run('buffer_return')
 prove('all_buffer_result64_retained_field_and_exact_nullable_gate',v,z3.Or(cell(v,v.node+0x18,8)!=v.result,
  cell(v,v.sp+0x50,8)!=v.node,v.read('w23')!=v.status,v.read('x0')!=KEY0,
  v.read('x8')!=z3.If(v.result==0,resize(0xfffffe000a6622bc,64),resize(0xfffffe000a64280c,64))),normal(v))
 v.run('buffer_prepare').run('writer_request')
 prove('nonnull_buffer_metadata_preparation_and_shared_writer_request_ABI',v,z3.Or(v.read('x16')!=v.node+0x18,
  v.read('w23')!=(v.tag^0x14ac30f9),v.read('x3')!=v.src,v.read('x11')!=v.ctx,
  v.read('w1')!=SUCCESS,v.read('x0')!=KEY0,v.read('x8')!=0xfffffe000a654ad4,v.read('x17')!=0xdfc5),[*normal(v),v.result!=0])
 v.run('writer_setup')
 prove('writer_setup_uses_same_node_buffer_field_and_type_bytes_then_selects_first_tag_writer',v,z3.Or(
  cell(v,v.sp+0x50,8)!=v.node,v.read('x10')!=v.node+0x18,v.read('x16')!=v.node+0x18,
  v.read('w7')!=(v.encoded_length^0x14ac30f9),v.read('w19')!=(z3.ZeroExt(16,v.kind)>>8)^0x36,
  v.read('w30')!=(z3.ZeroExt(16,v.kind)^0x5e),v.read('x25')!=0xfffffe000a654c64,
  v.read('x17')!=0x682a),[*normal(v),v.result!=0])
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert visited==selected,{'missing':sorted(map(hex,selected-visited))}
 pp=[]
 for name,labels in [('userclient_container_staging_audit.json',['shared_parser_entry_retains_output_continuation_input_and_encoded_extent',
  'nonnull_site_FPTTLV_clears_two_pointer_fields_and_sets_reader_key']),('userclient_input_reader_audit.json',[
  'protected_header_first_word_decodes_tag_channel','protected_header_u16_type_at_offset_four','protected_header_u32_length_channel_at_offset_six'])]:
  prior=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in prior['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000)
   s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 altered=[]
 for label in ['instruction_byte','descriptor_size','size_gate_claim','complete_parser_claim']:
  bad=copy.deepcopy(e)
  if label=='instruction_byte':
   b=bytearray.fromhex(bad['spans'][0]['bytes_hex']);b[0]^=1;bad['spans'][0]['bytes_hex']=b.hex()
  elif label=='descriptor_size':bad['allocation_descriptor']['size_bytes']=16
  elif label=='size_gate_claim':bad['scope']=bad['scope'].replace('plus-ten','plus-eleven')
  else:bad['complete_parser_body_established']=True
  assert bad!=R.build();altered.append({'alteration':label,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
  'source_sha256':e['source_sha256'],'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,
  'proved_source_PCs':sorted(map(hex,visited)),'rechecked_prior_source_proofs':pp,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'bank_composition_input_cases':sum(256 for _ in e['bank_rules']),'altered_evidence_rejections':len(altered)},
  'conditional_record_node_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
 print(json.dumps(a['independent_totals']),flush=True)
