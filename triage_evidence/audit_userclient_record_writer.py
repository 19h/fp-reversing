#!/usr/bin/env python3
"""Instruction-derived record writer obligations; valid storage/call cuts explicit.
O(instruction instances+query DAG) construction/space; SMT cost separate.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,TABLE,qword
from audit_secure_tunnel_table_insertion import cell,mem,resize,IMAGE_REGIONS
from audit_userclient_record_nodes import Model as NodeModel,DEC,TOKEN,PHASE,SUCCESS,KEY0
import audit_userclient_record_nodes as RN
import recover_userclient_record_nodes as RNodes
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_record_writer as R

KEY1=0x4dae26df20976138
def mask(a):return z3.Extract(7,0,z3.LShR((z3.RotateRight(a&resize(-8,64),8)+KEY0)^KEY1,(a&7)<<3))

class Model(NodeModel):
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   js=R.BRANCHES[self.pc];assert n==8;self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if n==4 and z3.eq(z3.simplify(a),z3.simplify(self.src+0x100)):
   return z3.Extract(31,0,self.memory[(z3.simplify(a).sexpr(),8)])
  if self.pc==0xfffffe000a655e58:
   assert n==1;self.address_checks.append(a==self.payload+self.counter-1);return self.protected_byte
  return super().load(a,n)
 def owned(self):
  out=super().owned()
  if self.with_payload:
   n=z3.ZeroExt(32,self.length());a=self.payload;out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in [(self.sp,0x1120),(self.ctx,0x800),(self.src,0x1000),(self.header,16),(self.node,32),
    (self.result,z3.ZeroExt(32,self.length())+10),*[(resize(b,64),m) for b,m in IMAGE_REGIONS]]:
    out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return out
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;o=i.operands;m=i.mnemonic
   if m=='ror' or m=='lsr' and o[2].type==ARM64_OP_REG or m=='tst' or m.startswith('b.'):
    self.visited.add(i.address);self.count+=1
    if m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    elif m=='lsr':
     n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.LShR(self.operand(i,o[1],n),self.operand(i,o[2],n)&(n-1)))
    elif m=='tst':
     n=self.width(i.reg_name(o[0].reg));self.equal=self.operand(i,o[0],n)&self.operand(i,o[1],n)==0
    elif i.address in R.RETAGS:
     assert m=='b.eq' and o[0].imm&(2**64-1)==i.address+8
     self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    else:
     assert i.address in [0xfffffe000a654e7c,0xfffffe000a655444]
     self.branch_guards.append(z3.Not(self.equal) if m=='b.ne' else self.equal)
   else:
    oe,oc=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    super().run('one');self.e,self.c=oe,oc
  return self

def setup(e):
 prior=json.loads(read(ROOT/'userclient_record_nodes_checks.json'));combined=copy.deepcopy(prior);combined['spans']+=e['spans']
 v=RN.setup(combined);v.__class__=Model;v.with_payload=False
 v.counter=z3.BitVec('RW_counter64',64);v.protected_byte=z3.BitVec('RW_protected_source_byte8',8)
 return v

def ready(e):
 v=setup(e).run('phase_token').run('saved_writer_controls');v.seed('w8',0x54d)
 v.run('header_metadata_return').run('metadata_gate').run('record_kind_gate').run('record_inputs').run('record_size_gate').run('node_allocate')
 v.returned(v.node).run('node_return');v.with_header=v.with_node=True;v.run('node_initialize').run('buffer_allocate')
 v.returned(v.result).run('buffer_return');v.with_buffer=True
 return v.run('buffer_prepare').run('writer_request').run('writer_setup')

def header(e):return ready(e).run('word_writer').run('type_writer').run('length_bridge').run('word_writer')

def normal(v):return [z3.Not(z3.And(v.tag==SUCCESS,v.kind==0x6685)),z3.ULE(v.length(),0xfffffff5)]

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build()
 assert json.loads(read(ROOT/'userclient_record_nodes_checks.json'))==RNodes.build()
 qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises)
  assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check()
  assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'pointer_branch_guards':len(v.branch_guards),'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited)
  print(label,flush=True)
 def stores(v,pcs):return [s for s in v.stores if s['pc'] in pcs]
 wordpcs=[0xfffffe000a654ccc,0xfffffe000a654d18,0xfffffe000a654d74,0xfffffe000a654db0]
 v=setup(e).run('phase_token').run('saved_writer_controls')
 prove('original_token_and_fixed_saved_writer_control_values',v,z3.Or(v.read('w15')!=TOKEN,
  cell(v,v.sp+0x570,8)!=0x87b,cell(v,v.sp+0x60c,4)!=0x3f22ccfb))
 v=ready(e).run('word_writer');ss=stores(v,wordpcs);assert len(ss)==4 and all(s['size_bytes']==1 for s in ss)
 prove('all_tag32_first_four_protected_bytes_and_type_writer_continuation',v,z3.Or(
  *[z3.Or(s['address']!=v.result+j,s['value']!=(z3.Extract(31-8*j,24-8*j,v.tag^SUCCESS)^mask(v.result+j))) for j,s in enumerate(ss)],
  v.read('x24')!=0xfffffe000a655068,v.read('x0')!=KEY1,v.read('x26')!=KEY0),normal(v))
 v.run('type_writer');tp=[0xfffffe000a6550b8,0xfffffe000a6550e4];ss=stores(v,tp);assert len(ss)==2 and all(s['size_bytes']==1 for s in ss)
 prove('all_type16_two_protected_bytes_fixed_control_and_length_bridge',v,z3.Or(
  *[z3.Or(s['address']!=v.result+j+4,s['value']!=(z3.Extract(15-8*j,8-8*j,v.kind^0x365e)^mask(v.result+j+4))) for j,s in enumerate(ss)],
  v.read('w25')!=0x439,v.read('x16')!=v.node+0x18,v.read('w23')!=(v.encoded_length^0x14ac30f9),
  v.read('x26')!=0xfffffe000a654c44),normal(v))
 v.run('length_bridge')
 prove('length_bridge_selects_same_word_writer_with_fixed_key',v,z3.Or(v.read('x25')!=0xfffffe000a654c64,
  v.read('x0')!=KEY0,v.read('x16')!=v.node+0x18),normal(v))
 v.run('word_writer');ss=stores(v,wordpcs)[-4:]
 prove('all_length32_final_four_protected_header_bytes_and_type_dispatch',v,z3.Or(
  *[z3.Or(s['address']!=v.result+j+6,s['value']!=(z3.Extract(31-8*j,24-8*j,v.length())^mask(v.result+j+6))) for j,s in enumerate(ss)],
  v.read('x24')!=0xfffffe000a654e70,v.read('x0')!=KEY1,v.read('x26')!=KEY0),normal(v))
 # All header writes are byte stores, at offsets 0..9, with no extra byte.
 hs=stores(v,[*wordpcs,*tp]);assert len(hs)==10 and all(s['size_bytes']==1 for s in hs)
 prove('complete_ten_byte_header_preserves_node_extent_buffer_and_metadata',v,z3.Or(
  cell(v,v.node,8)!=0,cell(v,v.node+8,8)!=0,cell(v,v.node+0x10,4)!=v.length()+10,
  cell(v,v.node+0x18,8)!=v.result,v.read('w5')!=z3.ZeroExt(16,v.kind),v.read('w12')!=v.encoded_length,
  v.read('x10')!=v.node+0x18,cell(v,v.ctx+0x348,8)!=v.payload),normal(v))
 v.run('type_primary_gate').run('type_secondary_gate').run('payload_size_gate')
 prove('type_6685_exact_zero_or_nonzero_payload_dispatch',v,z3.Or(v.read('x8')!=z3.If(v.length()==0,
  resize(0xfffffe000a655ef0,64),resize(0xfffffe000a655df4,64)),
  v.read('w11')!=(v.length()^0x1921706d)),normal(v))
 v.run('payload_request')
 prove('type_6685_nonempty_payload_exact_widened_count_source_and_destination',v,z3.Or(v.read('x8')!=v.result,
  v.read('x9')!=v.payload,v.read('x10')!=z3.ZeroExt(32,v.length()),v.read('x11')!=0xfffffe000a655e2c),
  [*normal(v),v.length()!=0])
 v.with_payload=True;v.seed('x10',v.counter);v.run('payload_copy');ss=stores(v,[0xfffffe000a655ecc]);assert len(ss)==1 and ss[0]['size_bytes']==1
 s=ss[0];source=v.payload+v.counter-1;dest=v.result+v.counter+9
 prove('every_valid_payload_counter64_source_byte8_exact_protected_rebase_and_exit_backedge',v,z3.Or(
  s['address']!=dest,s['value']!=(v.protected_byte^mask(source)^mask(dest)),v.read('x10')!=v.counter-1,
  v.read('x8')!=v.result,v.read('x9')!=v.payload,v.read('x0')!=KEY1,v.read('x26')!=KEY0,
  v.read('x21')!=TABLE,cell(v,v.sp+0x570,8)!=0x87b,v.read('w25')!=TOKEN,
  v.read('x11')!=z3.If(v.counter==1,resize(0xfffffe000a655ef0,64),resize(0xfffffe000a655e2c,64))),
  [*normal(v),z3.UGE(v.counter,1),z3.ULE(v.counter,z3.ZeroExt(32,v.length()))])
 # Generic finite reverse-counter certificate, independent of byte protection.
 v=setup(e);n=z3.BitVec('RW_induction_N32',32);j=z3.BitVec('RW_induction_step64',64);nn=z3.ZeroExt(32,n);i=nn-1-j
 prove('finite_payload_reverse_indices_cover_exactly_L_bytes',v,z3.Or(z3.Not(z3.ULT(i,nn)),
  (i==0)!=(j==nn-1),z3.And(z3.ULT(j+1,nn),nn-1-(j+1)!=i-1),z3.UGE(i+10,nn+10)),[n!=0,z3.ULT(j,nn)])
 for pc in R.RETAGS.values():
  row=next(s for s in e['spans'] if int(s['start'],16)<=pc<int(s['end_exclusive'],16));off=pc-int(row['start'],16)
  b=bytes.fromhex(row['bytes_hex'])[off:off+4];i=next(DEC.disasm(b,pc));reg=i.reg_name(i.operands[0].reg)
  v=setup(e);v.seed(reg,v.result);v.e=v.c={'spans':[{'label':'alternate','start':hex(pc),'bytes_hex':b.hex()}]};v.run('alternate')
  prove('alternate_pointer_MOVK_'+format(pc,'x')+'_bit_transform_only',v,v.read(reg)!=((v.result&0xffffffffffff)|(0xc8a2<<48)))
 selected={int(i['ea'],16) for s in e['spans'] for i in s['instructions']};assert selected<=visited,{'missing':sorted(map(hex,selected-visited))}
 pp=[]
 for name,labels in [('userclient_record_nodes_audit.json',['writer_setup_uses_same_node_buffer_field_and_type_bytes_then_selects_first_tag_writer']),
  ('userclient_input_reader_audit.json',['protected_header_first_word_decodes_tag_channel','protected_header_u16_type_at_offset_four',
   'protected_header_u32_length_channel_at_offset_six','finite_reverse_copy_index_range_and_induction_certificate'])]:
  prior=json.loads(read(ROOT/name))
  for label in labels:
   q=next(q for q in prior['source_proofs'] if q['label']==label);s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']))
   assert s.check()==z3.unsat;pp.append({'label':label,'result':'unsat','source_audit_sha256':sha(ROOT/name)})
 altered=[]
 for label in ['instruction_byte','header_extent','serialization_scope','list_publication_claim']:
  bad=copy.deepcopy(e)
  if label=='instruction_byte':
   b=bytearray.fromhex(bad['spans'][0]['bytes_hex']);b[0]^=1;bad['spans'][0]['bytes_hex']=b.hex()
  elif label=='header_extent':bad['verified_counts']['header_bytes']=11
  elif label=='serialization_scope':bad['scope']=bad['scope'].replace('ten-byte','eleven-byte')
  else:bad['list_publication_established']=True
  assert bad!=R.build();altered.append({'alteration':label,'rejected_by_fresh_evidence_comparison':True})
 return {'generator_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'coverage':coverage,'proved_source_PCs':sorted(map(hex,visited)),
  'rechecked_prior_source_proofs':pp,'altered_evidence_controls':altered,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(pp),'distinct_new_proved_instructions':len(selected),
   'distinct_predecessor_proved_instructions':len(visited-selected),'proof_instruction_instances':sum(c['source_instruction_instances'] for c in coverage),
   'altered_evidence_rejections':len(altered)},'conditional_record_writer_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
