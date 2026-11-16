#!/usr/bin/env python3
"""Source-bitvector overflow, strict alignment and allocation contracts.
O(I+256R+query DAG) construction/space; SMT separately limited to30 s/query.
"""
import copy
import json
import z3
from kext_port_tools import ROOT,TABLE,qword
from audit_userclient_query_records import Model as QueryModel
from audit_secure_tunnel_table_insertion import Model as Base,cell,mem,resize,IMAGE_REGIONS
from audit_userclient_input_reader import TOKEN,PHASE,SUCCESS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_serializer_extent as R

PAD_BASE=0x1aad43d4
MAGIC=0xa41a4d891208c018

def padding(total):return resize(16,32)-((total+10)&15)
def size64(total):return z3.ZeroExt(32,total)+10+z3.ZeroExt(32,padding(total))
def admitted(total):return z3.ULT(size64(total),resize(2**32,64))

class Model(QueryModel):
 def __init__(self,e):
  super().__init__(e);self.total=z3.BitVec('SE_sum32',32);self.allocated=z3.BitVec('SE_allocation64',64)
  self.argument=z3.BitVec('SE_original_argument64',64)
  self.node_read=False
 def owned(self):
  spans=[(self.sp,0x1120),(self.ctx,4096),(self.src,16384),(self.object,16)]
  if self.node_read:spans.append((self.node,32))
  out=[(self.sp&15)==0]
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
  lp,rp,pp=R.BANK_PCS;r=self.receipt['bank_rules'][0];l,rr=int(r['left'],16),int(r['right'],16)
  if self.pc==lp:
   assert n==1;self.bank_input=z3.Extract(7,0,a-l);self.bank_byte=z3.BitVec('SE_left_bank_byte8',8)
   self.address_checks.append(a==l+z3.ZeroExt(56,self.bank_input));return self.bank_byte
  if self.pc==rp:
   assert n==1;self.address_checks.append(a==rr+z3.ZeroExt(56,self.bank_byte^5))
   self.bank_rewrites.append({'pc':hex(self.pc),'rule':'allocate','inputs':256});return self.bank_input^int(r['constant'],16)
  if self.pc==pp:
   assert n==8;self.address_checks.append(a==int(r['slot'],16));return resize(int(r['original_pointer']['target'],16),64)
  if self.pc in [0xfffffe000a65f854,0xfffffe000a65f85c]:
   expected=0xfffffe000ccc30d0 if self.pc==0xfffffe000a65f854 else 0xfffffe000ccc32f8
   assert n==4;self.address_checks.append(a==expected);return z3.BitVec('SE_controller_'+format(self.pc,'x'),32)
  return Base.load(self,a,n)

def setup(e):
 v=Model(e)
 for r,x in [('x2',v.ctx),('x4',v.src),('x7',TABLE),('w3',TOKEN),('w30',SUCCESS),('x5',MAGIC),
  ('x6',0xfffffe000ccc30d0),('x27',0xfffffe0007949dd0),('x28',0xfffffe0007949dd0),
  ('w25',TOKEN),('w9',0x161),('w10',PHASE),('x11',v.ctx+0x600),('x12',v.ctx+0x3c0),('x21',v.src+0xbe4)]:v.seed(r,x)
 for off,x in [(0xa28,v.ctx),(0xa08,v.src),(0xa60,TABLE),(0xa30,0xfffffe000ccc30d0),(0xa38,0xfffffe000ccc32f8),
  (0xa50,0xfffffe0007941f60),(0xa58,0xfffffe000794a0d0),(0xa00,0xfffffe000792fcc0),
  (0x888,v.src+0xbe4),(0x878,v.argument)]:mem(v,v.sp+off,8,x)
 mem(v,v.sp+0x9ec,4,v.status);mem(v,v.ctx+0x600,8,v.object);mem(v,v.object,8,v.node)
 mem(v,v.node+0x10,4,v.extent);mem(v,v.node,8,v.next)
 return v

def sizing(e):
 v=setup(e).run('entry');v.seed('w9',v.total);v.seed('w11',0x217);v.run('size');return v
def request(e):return sizing(e).run('request')

def audit():
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();qs=[];coverage=[];visited=set()
 r=e['bank_rules'][0];l,rr=(bytes.fromhex(e['banks'][n]['bytes_hex']) for n in ['L','R'])
 assert all(j^rr[l[j]^5]==int(r['constant'],16) for j in range(256))
 def prove(label,v,bad,premises=()):
  s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*v.branch_guards,*premises);assert s.check()==z3.sat,('vacuous',label)
  s.add(z3.simplify(z3.Or(*[z3.Not(c) for c in v.address_checks],bad)));result=s.check();assert result==z3.unsat,(label,str(result),s.reason_unknown())
  qs.append({'label':label,'result':'unsat','premises_nonvacuous':True,'query':s.to_smt2(),
   'certified_bank_rewrites':copy.deepcopy(v.bank_rewrites)})
  coverage.append({'label':label,'source_instruction_instances':v.count,'store_instances':len(v.stores)});visited.update(v.visited);print(label,flush=True)
 # Obligations below bind isolated phase cuts to exact selected source effects.
 v=setup(e).run('entry')
 prove('entry_preserves_output_aliases_callback_and_default_failure_state',v,z3.Or(
  cell(v,v.ctx+0x548,8)!=v.ctx+0x3c0,cell(v,v.ctx+0x468,8)!=0xfffffe000a65fea8,
  cell(v,v.ctx+0x198,8)!=0,cell(v,v.src+0xb40,4)!=PAD_BASE,v.read('x25')!=v.object,
  v.read('w8')!=0,v.read('w23')!=0xce515bbf,v.read('x9')!=0xfffffe000a65f448))
 d=setup(e);mem(d,d.ctx+0x600,8,0);d.run('entry')
 prove('null_container_selects_saved_return_with_flag_zero',d,z3.Or(d.read('x9')!=0xfffffe000a65fe98,
  d.read('w8')!=0,d.read('w23')!=0xce515bbf,cell(d,d.ctx+0x198,8)!=0))
 v.run('head')
 prove('head_initializes_zero_sum_and_selects_empty_or_node_extent',v,z3.Or(v.read('w9')!=0,
  v.read('w11')!=0x217,v.read('w12')!=0xd5f,v.read('x10')!=v.node,
  v.read('x8')!=z3.If(v.node==0,resize(0xfffffe000a65f5e4,64),resize(0xfffffe000a65f494,64))))
 v=setup(e);v.node_read=True
 for reg,val in [('x10',v.node),('w9',v.total),('w12',0xd5f)]:v.seed(reg,val)
 v.run('extent');wide_sum=z3.ZeroExt(32,v.total)+z3.ZeroExt(32,v.extent);fits=z3.ULT(wide_sum,resize(2**32,64))
 prove('node_extent_guard_exact_unsigned_sum_overflow_split',v,z3.Or(v.read('w14')!=v.extent,
  v.read('w9')!=v.total,v.read('w13')!=0x5c7,v.read('w8')!=0,v.read('w23')!=0xce515bb8,
  v.read('x11')!=z3.If(fits,resize(0xfffffe000a65f580,64),resize(0xfffffe000a65fe98,64))))
 v.run('advance')
 prove('accepted_node_adds_exact_extent_and_advances_next_link',v,z3.Or(
  z3.ZeroExt(32,v.read('w9'))!=wide_sum,v.read('x10')!=v.next,v.read('w11')!=0x217,v.read('w12')!=0xd5f,
  v.read('x8')!=z3.If(v.next==0,resize(0xfffffe000a65f5e4,64),resize(0xfffffe000a65f494,64))),[fits])
 v=sizing(e);p=padding(v.total);m=size64(v.total)
 prove('size_phase_exact_positive_padding_and_wide_overhead',v,z3.Or(v.read('w10')!=((v.total+10)&15),
  v.read('w22')!=PAD_BASE+p,cell(v,v.src+0xb40,4)!=PAD_BASE+p,v.cmp_left!=m-10,
  v.cmp_right!=0xfffffff6,v.read('w26')!=0x60a,v.read('w8')!=0,v.read('w23')!=0xce515bb8))
 prove('total_extent_guard_exact_wide_size_admission',v,v.read('x11')!=z3.If(admitted(v.total),
  resize(0xfffffe000a65f700,64),resize(0xfffffe000a65fe98,64)))
 prove('padding_one_through_sixteen_and_strict_next_alignment',v,z3.Or(z3.ULT(p,1),z3.UGT(p,16),
  (m&15)!=0,z3.ULE(m,z3.ZeroExt(32,v.total)+10)))
 prove('exact_largest_accepted_sum_and_allocation_extent_bounds',v,z3.Or(
  admitted(v.total)!=z3.ULE(v.total,resize(0xffffffe5,32)),
  z3.And(admitted(v.total),z3.Or(z3.ULT(m,16),z3.UGT(m,resize(0xfffffff0,64))))))
 v=request(e);m=size64(v.total)
 prove('allocator_original_bank_target_diversity_and_exact_zero_extended_size',v,z3.Or(
  v.read('x8')!=0xfffffe000c4ba60c,v.read('x17')!=0xca0c,v.read('x0')!=m,
  v.read('w20')!=(resize(m,32)^0x18b18db2),v.read('w19')!=0x2a7,
  cell(v,v.ctx+0x198,8)!=0),[admitted(v.total)])
 # Empty-container composition uses original entry/head/size/request instructions.
 d=setup(e);mem(d,d.object,8,0);d.run('entry').run('head').run('size').run('request')
 prove('empty_nonnull_container_requests_sixteen_bytes_with_six_padding_bytes',d,z3.Or(
  d.read('x0')!=16,d.read('w20')!=(16^0x18b18db2),d.read('w22')!=PAD_BASE+6,d.read('x8')!=0xfffffe000c4ba60c))
 v.returned(v.allocated).run('result')
 prove('allocator_result_saved_and_null_or_copy_setup_frontiers_exact',v,z3.Or(
  cell(v,v.ctx+0x198,8)!=v.allocated,v.read('w8')!=0,v.read('w23')!=v.status,
  v.read('x9')!=z3.If(v.allocated==0,resize(0xfffffe000a65fe98,64),resize(0xfffffe000a65f910,64)),
  v.read('x2')!=v.ctx,v.read('x4')!=v.src,v.read('x7')!=TABLE,v.read('w3')!=TOKEN,v.read('w30')!=SUCCESS),[admitted(v.total)])
 v.run('copy_setup');m=size64(v.total)
 prove('copy_setup_encodes_actual_allocation_extent_and_selects_node_or_padding',v,z3.Or(
  v.read('w28')!=(resize(m,32)^SUCCESS),v.read('w9')!=0,v.read('x11')!=v.node,
  v.read('x13')!=z3.If(v.node==0,resize(0xfffffe000a65f9a8,64),resize(0xfffffe000a6600ac,64)),
  v.read('x19')!=0x02e859d27e491464,v.read('x20')!=0xc318995a4ba7c5cd,v.read('w10')!=0xc7d),
  [admitted(v.total),v.allocated!=0])
 # Publication is a predecessor-proved congruence cut, not an executed serializer path.
 mem(v,v.src+0xbe4,4,v.read('w28'));v.seed('w8',1);v.run('consumer_callback');n=resize(v.argument,32)
 prove('source_composed_success_consumer_admits_only_exact_allocated_extent',v,
  v.read('x8')!=z3.If(z3.ZeroExt(32,n)==m,resize(0xfffffe000a65ff38,64),resize(0xfffffe000a656f00,64)),
  [admitted(v.total),v.allocated!=0])
 prove('source_composed_admitted_original_length_is_positive_sixteen_aligned',v,
  z3.And(v.read('x8')==0xfffffe000a65ff38,z3.Or((n&15)!=0,z3.ULT(n,16),z3.UGT(n,resize(0xfffffff0,32)))),
  [admitted(v.total),v.allocated!=0])
 prior=[]
 for name,wanted in [('userclient_query_records_audit.json',{'third_success_passes_container_and_auxiliary_output_aliases_to_next_facility'}),
  ('userclient_auxiliary_copy_audit.json',{'conditional_publication_installs_auxiliary_extent_success_flag_and_callback','callback_flag1_exact_extent_gate_and_frontiers'})]:
  for q in json.loads(read(ROOT/name))['source_proofs']:
   if q['label'] not in wanted:continue
   s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(q['query']));assert s.check()==z3.unsat
   prior.append({'artifact':name,'label':q['label'],'result':'unsat'})
 assert len(prior)==3
 profiles=[]
 for residue in range(16):
  d=setup(e).run('entry');d.seed('w9',residue);d.seed('w11',0x217);d.run('size').run('request')
  actual=z3.simplify(d.read('x0')).as_long();pad=z3.simplify(d.read('w22')).as_long()-PAD_BASE
  assert 1<=pad<=16 and actual==residue+10+pad and actual%16==0 and actual>residue+10
  profiles.append({'node_sum_bytes':residue,'padding_bytes':pad,'allocation_bytes':actual})
 altered=copy.deepcopy(e);row=next(r for r in altered['spans'] if r['label']=='size');b=bytearray.fromhex(row['bytes_hex'])
 off=0xfffffe000a65f694-int(row['start'],16);word=int.from_bytes(b[off:off+4],'little');b[off:off+4]=(word^(1<<10)).to_bytes(4,'little');row['bytes_hex']=b.hex()
 d=sizing(altered);s=z3.Solver();s.add(*d.owned(),d.total==0,cell(d,d.src+0xb40,4)!=PAD_BASE+6);assert s.check()==z3.sat
 selected={int(i['ea'],16) for row in e['spans'] for i in row['instructions']};assert visited==selected,selected-visited
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':e['source_sha256'],
  'scope':R.SCOPE,'source_proofs':qs,'proof_coverage':coverage,'rechecked_prior_source_proofs':prior,'residue_profiles':profiles,
  'independent_totals':{'new_source_queries_unsat':len(qs),'prior_source_queries_unsat':len(prior),
   'distinct_proved_instructions':len(visited),'proof_instruction_instances':sum(q['source_instruction_instances'] for q in coverage),
   'bank_composition_input_cases':256,'allocation_residue_profiles':len(profiles),'altered_padding_literal_counterexample':True},
  'conditional_serializer_extent_contract_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
