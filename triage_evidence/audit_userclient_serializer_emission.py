#!/usr/bin/env python3
"""Prove node/terminal byte emission and conditional output publication.
O(I+query DAG) construction/space; separate SMT search,30 s/query.
"""
import copy
import json
import z3
from capstone.arm64 import ARM64_OP_REG
from kext_port_tools import ROOT,TABLE,qword
from audit_userclient_auxiliary_copy import Model as AuxModel,mask,SK0,SK1,AK0,AK1
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import DEC,TOKEN,SUCCESS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_serializer_emission as R

PAD_BASE=0x1aad43d4
HEADER_POINTERS=[(0xfffffe000a65f9f4,'x14'),(0xfffffe000a65fa50,'x15'),(0xfffffe000a65fa84,'x15'),
 (0xfffffe000a65fab8,'x14'),(0xfffffe000a65fb28,'x14'),(0xfffffe000a65fb64,'x14'),
 (0xfffffe000a65fc3c,'x14'),(0xfffffe000a65fc8c,'x17'),(0xfffffe000a65fccc,'x17'),(0xfffffe000a65fd0c,'x14')]

class Model(AuxModel):
 def __init__(self,e):
  super().__init__(e)
  self.total,self.offset,self.pad=z3.BitVecs('EM_total32 EM_offset32 EM_pad32',32)
  self.remaining,self.pad_remaining=z3.BitVecs('EM_remaining64 EM_pad_remaining64',64)
  self.with_node=self.with_source=self.with_aux=False;self.read_index=None
  self.certified_rewrites=[]
 def size(self):return z3.ZeroExt(32,self.total)+10+z3.ZeroExt(32,self.pad)
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,4096),(self.src,16384),(self.object,16)]
  if self.with_node:spans.append((self.node,32))
  if self.with_source:spans.append((self.stage,z3.ZeroExt(32,self.extent)))
  if self.with_aux:spans.append((self.aux,self.size()))
  out=[(self.sp&15)==0,z3.UGE(self.pad,1),z3.ULE(self.pad,16),z3.ULE(self.total,resize(0xffffffe5,32))]
  for j,(a,n) in enumerate(spans):
   out.extend([a!=0,z3.ULE(a,resize(2**64-1,64)-n)])
   for b,m in spans[j+1:]:out.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
   for b,m in IMAGE_REGIONS:out.append(z3.Or(z3.ULE(a+n,resize(b,64)),z3.ULE(resize(b+m,64),a)))
  return out
 def load(self,a,n):
  if self.pc in R.BRANCHES:
   assert n==8;js=R.BRANCHES[self.pc];self.address_checks.append(z3.Or(*[a==TABLE+8*j for j in js]));out=resize(0,64)
   for j in js:out=z3.If(a==TABLE+8*j,resize(qword(TABLE+8*j),64),out)
   return out
  if self.pc==0xfffffe000a66022c:
   assert n==1 and self.read_index is not None;self.address_checks.append(a==self.stage+self.read_index);return self.byte
  return Base.load(self,a,n)
 def run(self,label,end=None):
  row=next(s for s in self.e['spans'] if s['label']==label);skip=None
  for i in DEC.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if end is not None and i.address>=end:break
   if i.address==skip:continue
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m in ['ror','cmp','csel'] or m.startswith('b.') or m in ['lsr','lsl'] and o[2].type==ARM64_OP_REG:
    self.visited.add(i.address);self.count+=1
    if m.startswith('b.'):
     assert i.address in R.RETAGS and m=='b.eq' and o[0].imm&(2**64-1)==i.address+8
     self.branch_guards.append(self.equal);skip=R.RETAGS[i.address]
    elif m=='cmp':
     n=self.width(i.reg_name(o[0].reg));self.cmp_left=self.operand(i,o[0],n);self.cmp_right=self.operand(i,o[1],n);self.equal=self.cmp_left==self.cmp_right
    elif m=='csel':
     assert i.op_str.endswith(', ne');self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.read(i.reg_name(o[1].reg)),self.read(i.reg_name(o[2].reg))))
    elif m=='ror':self.write(i.reg_name(o[0].reg),z3.RotateRight(self.read(i.reg_name(o[1].reg)),o[2].imm))
    else:
     n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);s=self.operand(i,o[2],n)&(n-1)
     self.write(i.reg_name(o[0].reg),z3.LShR(a,s) if m=='lsr' else a<<s)
   else:
    old_e,old_c=self.e,self.c;self.e=self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]}
    Base.run(self,'one');self.e,self.c=old_e,old_c
  return self

def setup(e,constants=None):
 v=Model(e)
 for name,value in (constants or {}).items():setattr(v,name,resize(value,getattr(v,name).size()))
 for r,x in [('x0',v.aux),('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w30',SUCCESS),
  ('x21',v.src+0xbe4),('x25',v.object),('w19',0x2a7),('w20',resize(v.size(),32)^0x18b18db2),
  ('w22',PAD_BASE+v.pad),('x27',0xfffffe0007949dd0)]:v.seed(r,x)
 for off,x in [(0xa28,v.ctx),(0xa08,v.src),(0xa60,TABLE)]:mem(v,v.sp+off,8,x)
 for off,x in [(0x198,v.aux),(0x548,v.ctx+0x3c0),(0x468,0xfffffe000a65fea8)]:mem(v,v.ctx+off,8,x)
 mem(v,v.ctx+0x3c0,8,0);mem(v,v.src+0xbe4,4,SUCCESS);mem(v,v.src+0xb40,4,PAD_BASE+v.pad)
 mem(v,v.object,8,v.node);mem(v,v.node,8,v.next);mem(v,v.node+0x10,4,v.extent);mem(v,v.node+0x18,8,v.stage)
 return v

def gate(e):
 v=setup(e).run('copy_setup');v.with_node=True;v.seed('w9',v.offset);return v.run('node_gate')
def node(e):return gate(e).run('node_setup')
def header(e,constants=None,canonical_addresses=False):
 v=setup(e,constants).run('copy_setup');v.with_aux=True;v.seed('w9',v.total);v.seed('w10',0xc7d);v.seed('x11',0)
 if canonical_addresses:
  v.overrides={(pc,reg):v.aux+z3.ZeroExt(32,v.total)+j for j,(pc,reg) in enumerate(HEADER_POINTERS)}
  v.certified_rewrites=[{'lemma':'terminal_header_raw_source_pointer_and_store_addresses',
   'applications':[{'pc':hex(pc),'register':reg,'offset':j} for j,(pc,reg) in enumerate(HEADER_POINTERS)]}]
 return v.run('header')

def node_phase_roots(v):
 return z3.Or(v.read('x0')!=v.aux,v.read('x4')!=v.src,v.read('x7')!=TABLE,v.read('w3')!=TOKEN,
  v.read('w8')!=0x63f42b9b,v.read('x19')!=SK0,v.read('x20')!=AK0,v.read('x21')!=v.src+0xbe4,
  v.read('w22')!=PAD_BASE+v.pad,v.read('x23')!=0x00322000125102d4,v.read('x24')!=resize(-0x2c3,64),
  v.read('x25')!=0x77941ce51aad5b02,v.read('w26')!=0x3a,v.read('x27')!=0xfffffe0007949dd0,
  v.read('w28')!=(resize(v.size(),32)^SUCCESS))

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 def prove(label,v,bad,premises=(),rewrites=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'nominal_pointer_branch_guards':len(v.branch_guards),'certified_rewrites':copy.deepcopy(v.certified_rewrites)+list(rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 v=setup(e).run('copy_setup')
 prove('copy_setup_exact_initial_cursor_keys_extent_and_head_dispatch',v,z3.Or(v.read('w9')!=0,
  v.read('w28')!=(resize(v.size(),32)^SUCCESS),v.read('x19')!=SK0,v.read('x20')!=AK0,
  v.read('x13')!=z3.If(v.node==0,resize(0xfffffe000a65f9a8,64),resize(0xfffffe000a6600ac,64))))
 v=gate(e)
 prove('node_gate_skips_exactly_zero_extent_without_byte_iteration',v,z3.Or(v.read('w15')!=v.extent,
  v.read('w13')!=0x2a7,v.read('w14')!=0x61f,v.read('x10')!=z3.If(v.extent==0,
  resize(0xfffffe000a66005c,64),resize(0xfffffe000a660198,64))))
 d=copy.deepcopy(v).run('node_advance')
 prove('zero_extent_node_advances_link_without_changing_cursor',d,z3.Or(d.read('w9')!=d.offset,
  d.read('x11')!=d.next,d.read('w12')!=0x27d,d.read('w10')!=0xc7d,
  d.read('x13')!=z3.If(d.next==0,resize(0xfffffe000a65f9a8,64),resize(0xfffffe000a6600ac,64)),node_phase_roots(d)),[d.extent==0])
 v=node(e)
 prove('nonnull_node_setup_decodes_extent_counter_and_exact_cursor',v,z3.Or(v.read('x15')!=z3.ZeroExt(32,v.extent),
  v.read('x13')!=z3.ZeroExt(32,v.offset),v.read('x10')!=v.stage,v.read('w12')!=0x61d,
  v.read('x14')!=0xfffffe000a660204,v.read('x8')!=AK1),[v.extent!=0])
 v.with_source=v.with_aux=True;v.seed('x15',v.remaining);v.read_index=v.remaining-1;v.run('node_step')
 j=v.remaining-1;c=z3.ZeroExt(32,v.offset);extent=z3.ZeroExt(32,v.extent)
 fits=z3.ULE(c+extent,z3.ZeroExt(32,v.total));positive=[v.remaining!=0,z3.ULE(v.remaining,extent),fits]
 stored=v.stores[-1]
 prove('arbitrary_node_byte_reverse_addresses_counter_and_exit',v,z3.Or(stored['address']!=v.aux+c+j,
  v.read('x15')!=j,v.read('x1')!=z3.If(j==0,resize(0xfffffe000a66029c,64),resize(0xfffffe000a660204,64))),positive)
 prove('arbitrary_node_byte_preserves_decoded_value_under_auxiliary_mask',v,
  (stored['value']^mask(v.aux+c+j,AK0,AK1))!=(v.byte^mask(v.stage+j,SK0,SK1)),positive)
 prove('arbitrary_node_step_addresses_fit_source_and_node_prefix',v,z3.Or(
  z3.ULT(v.stage+j,v.stage),z3.UGE(v.stage+j,v.stage+extent),
  z3.ULT(v.aux+c+j,v.aux),z3.UGE(v.aux+c+j,v.aux+z3.ZeroExt(32,v.total))),positive)
 prove('node_byte_loop_preserves_next_iteration_and_publication_roots',v,z3.Or(v.read('x0')!=v.aux,
  v.read('x4')!=v.src,v.read('x7')!=TABLE,v.read('x8')!=AK1,v.read('x10')!=v.stage,v.read('x11')!=v.node,
  v.read('w12')!=0x61d,v.read('x13')!=c,v.read('w9')!=v.offset,v.read('x19')!=SK0,v.read('x20')!=AK0,
  v.read('x21')!=v.src+0xbe4,v.read('w22')!=PAD_BASE+v.pad,v.read('x23')!=0x00322000125102d4,
  v.read('x24')!=resize(-0x2c3,64),v.read('x25')!=0x77941ce51aad5b02,v.read('w26')!=0x3a,
  v.read('x27')!=0xfffffe0007949dd0,v.read('w28')!=(resize(v.size(),32)^SUCCESS)),positive)
 d=copy.deepcopy(v).run('node_bridge').run('node_advance')
 prove('completed_node_restores_phase_adds_stable_extent_and_selects_next',d,z3.Or(
  z3.ZeroExt(32,d.read('w9'))!=c+extent,d.read('x11')!=d.next,d.read('w3')!=TOKEN,
  d.read('w12')!=0x27d,d.read('w10')!=0xc7d,d.read('w8')!=0x63f42b9b,
  d.read('x13')!=z3.If(d.next==0,resize(0xfffffe000a65f9a8,64),resize(0xfffffe000a6600ac,64)),node_phase_roots(d)),positive+[v.remaining==1])
 raw=header(e);assert len(raw.stores)==10;l=z3.ZeroExt(32,raw.total);addresses=[]
 for j,((pc,reg),stored) in enumerate(zip(HEADER_POINTERS,raw.stores)):
  addresses.extend([raw.values[(pc,reg)]!=raw.aux+l+j,stored['address']!=raw.aux+l+j])
 prove('terminal_header_raw_source_pointer_and_store_addresses',raw,z3.Or(*addresses))
 v=header(e,canonical_addresses=True);assert len(v.stores)==10;l=z3.ZeroExt(32,v.total)
 expected=[resize(x,8) for x in [0,0,0,0,0x50,0xdb]]+[z3.Extract(31-8*j,24-8*j,v.pad) for j in range(4)]
 plain=[s['value']^mask(v.aux+l+j,AK0,AK1) for j,s in enumerate(v.stores)]
 bad=[]
 for j,s in enumerate(v.stores):
  assert s['size_bytes']==1;bad.extend([s['address']!=v.aux+l+j,plain[j]!=expected[j]])
 prove('terminal_header_exact_ten_addresses_zero_tag_type50db_and_big_endian_length',v,z3.Or(*bad))
 # Explicit congruence cut from the immediately preceding universal byte theorem.
 prove('emitted_terminal_shape_matches_parser_normalized_zero_tag_type6685',v,z3.Or(
  z3.Concat(*expected[:4])!=0,(z3.Concat(*expected[4:6])^0x365e)!=0x6685,
  z3.Concat(*expected[6:])!=v.pad,l+10+z3.ZeroExt(32,z3.Concat(*expected[6:]))!=v.size()),
  rewrites=[{'lemma':'terminal_header_exact_ten_addresses_zero_tag_type50db_and_big_endian_length',
   'applications':'Replace ten decoded source bytes by their proved expected values before parser normalization.'}])
 prove('positive_padding_header_selects_zero_setup_and_restores_output_roots',v,z3.Or(
  v.read('x13')!=0xfffffe000a65fdbc,v.read('w14')!=(v.pad^0xce7edadb),v.read('w12')!=0x4ce,
  v.read('w19')!=0x76,v.read('w1')!=0x62c,v.read('x2')!=v.ctx,v.read('x10')!=v.aux,
  v.read('x20')!=AK0,v.read('x23')!=AK1,v.read('w3')!=TOKEN,
  v.read('w28')!=(resize(v.size(),32)^SUCCESS)))
 v.run('zero_setup')
 prove('zero_setup_exact_padding_counter_body_offset_and_internal_entry',v,z3.Or(
  v.read('x14')!=z3.ZeroExt(32,v.pad),v.read('x9')+v.read('x0')!=l+10,
  v.read('w13')!=0x4b8,v.read('x12')!=0xfffffe000a65fe08))
 v.seed('x14',v.pad_remaining);v.run('zero_step');j=v.pad_remaining-1;s=v.stores[-1]
 pp=[v.pad_remaining!=0,z3.ULE(v.pad_remaining,z3.ZeroExt(32,v.pad))]
 prove('arbitrary_padding_byte_is_protected_zero_at_exact_reverse_address',v,z3.Or(
  s['address']!=v.aux+l+10+j,s['value']!=mask(v.aux+l+10+j,AK0,AK1),v.read('x14')!=j,
  v.read('x12')!=z3.If(j==0,resize(0xfffffe000a65fe6c,64),resize(0xfffffe000a65fe08,64))),pp)
 prove('padding_step_stays_in_declared_payload_and_preserves_publication_state',v,z3.Or(
  z3.ULT(s['address'],v.aux+l+10),z3.UGE(s['address'],v.aux+v.size()),
  v.read('x2')!=v.ctx,v.read('x4')!=v.src,v.read('x7')!=TABLE,v.read('x10')!=v.aux,
  v.read('x20')!=AK0,v.read('x23')!=AK1,v.read('x21')!=v.src+0xbe4,v.read('w11')!=0x614,
  v.read('x9')+v.read('x0')!=l+10,v.read('w13')!=0x4b8,v.read('w19')!=0x76,v.read('w1')!=0x62c,
  v.read('w3')!=TOKEN,v.read('w28')!=(resize(v.size(),32)^SUCCESS)),pp)
 v.run('publish').run('return')
 prove('completed_padding_publishes_exact_buffer_extent_success_and_saved_callback',v,z3.Or(
  cell(v,v.ctx+0x3c0,8)!=v.aux,cell(v,v.src+0xbe4,4)!=(resize(v.size(),32)^SUCCESS),
  v.read('w8')!=1,v.read('w23')!=SUCCESS,v.read('x24')!=0xfffffe000a65fea8,
  v.read('x9')!=0xfffffe000a65fe98,v.read('x28')!=v.read('x27'),v.read('w3')!=TOKEN),pp+[v.pad_remaining==1])
 prior=[]
 wants={'userclient_serializer_extent_audit.json':{
  'size_phase_exact_positive_padding_and_wide_overhead','allocator_original_bank_target_diversity_and_exact_zero_extended_size',
  'copy_setup_encodes_actual_allocation_extent_and_selects_node_or_padding'},
  'userclient_auxiliary_copy_audit.json':{'arbitrary_byte_transcode_preserves_auxiliary_decoded_value'},
  'userclient_record_metadata_audit.json':{'six_staged_header_bytes_produce_transformed_type_and_retain_tag',
   'decoded_zero_tag_type6685_selects_parser_success_before_node_construction'}}
 for name,labels in wants.items():
  found=set()
  for q in json.loads(read(ROOT/name))['source_proofs']:
   if q['label'] not in labels:continue
   solver=z3.Solver();solver.set(timeout=30000);solver.add(*z3.parse_smt2_string(q['query']));assert solver.check()==z3.unsat
   found.add(q['label']);prior.append({'artifact':name,'label':q['label'],'result':'unsat'})
  assert found==labels
 profiles=[]
 for pad in range(1,17):
  total=(-pad-10)&15;address=0x50000000+(pad&7);d=header(e,{'pad':pad,'total':total,'aux':address})
  decoded=[]
  for j,row in enumerate(d.stores):
   assert z3.simplify(row['address']).as_long()==address+total+j
   decoded.append(z3.simplify(row['value']^mask(resize(address+total+j,64),AK0,AK1)).as_long())
  assert bytes(decoded)==bytes([0,0,0,0,0x50,0xdb])+pad.to_bytes(4,'big')
  d.run('zero_setup');assert z3.simplify(d.read('x14')).as_long()==pad;steps=0
  while z3.simplify(d.read('x14')).as_long()!=0:
   d.run('zero_step');steps+=1;row=d.stores[-1];j=pad-steps
   assert z3.simplify(row['address']).as_long()==address+total+10+j
   assert z3.simplify(row['value']^mask(resize(address+total+10+j,64),AK0,AK1)).as_long()==0
   assert z3.simplify(d.read('x12')).as_long()==(0xfffffe000a65fe6c if j==0 else 0xfffffe000a65fe08)
  assert steps==pad and all(z3.is_true(z3.simplify(x)) for x in d.branch_guards)
  d.run('publish').run('return');assert z3.simplify(cell(d,d.ctx+0x3c0,8)).as_long()==address
  assert z3.simplify(cell(d,d.src+0xbe4,4)).as_long()==((total+10+pad)^SUCCESS)
  profiles.append({'padding_bytes':pad,'node_sum_bytes':total,'auxiliary_base_mod8':address&7,
   'decoded_header_hex':bytes(decoded).hex(),'zero_steps':steps,'output_extent_bytes':total+10+pad,'source_instruction_instances':d.count})
 altered=copy.deepcopy(e);row=next(r for r in altered['spans'] if r['label']=='header');b=bytearray.fromhex(row['bytes_hex'])
 off=0xfffffe000a65fb54-int(row['start'],16);word=int.from_bytes(b[off:off+4],'little');b[off:off+4]=(word^(1<<5)).to_bytes(4,'little');row['bytes_hex']=b.hex()
 d=header(altered,{'pad':6,'total':0,'aux':0x50000000});solver=z3.Solver();solver.add(*d.owned(),*d.branch_guards,
  (d.stores[4]['value']^mask(resize(0x50000004,64),AK0,AK1))!=0x50);assert solver.check()==z3.sat
 selected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']}
 assert visited==selected-set(R.RETAGS.values()),selected-visited
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'proof_coverage':coverage,'rechecked_prior_source_proofs':prior,'terminal_profiles':profiles,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(q['source_instruction_instances'] for q in coverage),
   'excluded_retag_instructions':len(R.RETAGS),'terminal_profiles':len(profiles),'profile_zero_byte_steps':sum(p['zero_steps'] for p in profiles),
   'profile_source_instruction_instances':sum(p['source_instruction_instances'] for p in profiles),'profile_base_mod8_cases':len({p['auxiliary_base_mod8'] for p in profiles}),
   'altered_terminal_type_counterexample':True},'conditional_serializer_emission_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
