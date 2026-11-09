#!/usr/bin/env python3
"""Positive-route layout and nullable slot source lemmas with explicit phases.

Fixed cells, preserved source saved-register/frame premises and abstract memory
reads; O(I) DAG construction/space plus solver cost. No target executes.
"""
import z3
from lskd_values_symbolic import Lift,part,mem,cell,resize
from lskd_state_symbolic import queries as state_queries
def queries(c,state):
 allqs,allcounts=state_queries(state);names=['vault_prospective_lookup_index','allowed_prospective_lookup_index'];qs=[x for x in allqs if x[0]in names];counts={n:allcounts[n]for n in names}
 F=0x51000000;T=0xfffffe000846c420;ROOT=0xfffffe000ccc78d0;I=z3.BitVec('objects_saved_index32',32);R=z3.BitVec('objects_acquire_record64',64);V=z3.BitVec('objects_vector_pointer64',64);O=z3.BitVec('objects_slot_word64',64);E=z3.BitVec('objects_retry_tag32',32)
 def run(name,a,z,seeds,memory=()):
  v=Lift(part(c,name,a,z))
  for n,x in seeds:v.seed(n,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 v=run('vault_saved_index_and_retry_phase',0xfffffe000a54b198,0xfffffe000a54b1b0,[('sp',F),('w10',0x72d)],[(F+0x3c,4,I)]);qs.append(('vault_saved_index_and_retry_phase',z3.Or(cell(v,F+0x18,8)!=z3.ZeroExt(32,I),v.read('w8')!=0x96,v.read('w9')!=0x6f1)))
 v=run('allowed_saved_index_and_retry_phase',0xfffffe000a51160c,0xfffffe000a511620,[('sp',F),('w10',0x8ac)],[(F+0x74,4,I)]);qs.append(('allowed_saved_index_and_retry_phase',z3.Or(cell(v,F+0x58,8)!=z3.ZeroExt(32,I),v.read('w8')!=0,v.read('w9')!=0x34c)))
 for name,a,z,index,off,target in[('vault_saved_retry_callback',0xfffffe000a57ee00,0xfffffe000a57ee08,0x96,0x20,0xfffffe000a52265c),('allowed_saved_retry_callback',0xfffffe000a57272c,0xfffffe000a572734,0,0xb8,0xfffffe000a591b38)]:
  v=run(name,a,z,[('sp',F),('x24',T),('w8',index)],[(T+8*index,8,target)]);qs.append((name,cell(v,F+off,8)!=target))
 v=run('vault_live_index_reload',0xfffffe000a57eef8,0xfffffe000a57eefc,[('sp',F)],[(F+0x18,8,z3.ZeroExt(32,I)),(F+0x20,8,0xfffffe000a52265c)]);qs.append(('vault_live_index_reload',z3.Or(v.read('x13')!=z3.ZeroExt(32,I),v.read('x8')!=0xfffffe000a52265c)))
 v=run('allowed_live_index_reload',0xfffffe000a57282c,0xfffffe000a572834,[('sp',F)],[(F+0x58,8,z3.ZeroExt(32,I)),(F+0xb8,8,0xfffffe000a591b38)]);qs.append(('allowed_live_index_reload',z3.Or(v.read('x13')!=z3.ZeroExt(32,I),v.read('x8')!=0xfffffe000a591b38)))
 v=run('vault_retry_tag_gate',0xfffffe000a522660,0xfffffe000a522684,[('w23',0x72d),('x21',F),('x10',ROOT),('x13',z3.ZeroExt(32,I))],[(F,4,E)]);qs.append(('vault_retry_tag_gate',z3.Or(v.read('w8')!=z3.If(E==0,z3.BitVecVal(0x86b,32),z3.BitVecVal(0x85c,32)),v.read('w11')!=0x42b,v.read('x10')!=ROOT,v.read('x13')!=z3.ZeroExt(32,I))))
 v=run('allowed_retry_tag_gate',0xfffffe000a591b3c,0xfffffe000a591b68,[('w28',0x8ac),('x26',F),('x10',ROOT),('x13',z3.ZeroExt(32,I))],[(F,4,E)]);qs.append(('allowed_retry_tag_gate',z3.Or(v.read('w9')!=z3.If(E==0,z3.BitVecVal(0x275,32),z3.BitVecVal(0x2d0,32)),v.read('w8')!=0x500,v.read('x10')!=ROOT,v.read('x13')!=z3.ZeroExt(32,I))))
 ix=z3.ZeroExt(32,I&0x3ff)
 for name,a,z in[('vault_root_to_slot_word',0xfffffe000a58b7e0,0xfffffe000a58b7e8),('allowed_root_to_slot_word',0xfffffe000a57e29c,0xfffffe000a57e2a4)]:
  v=run(name,a,z,[('x10',ROOT),('x13',ix)],[(ROOT,8,V),(V+(ix<<3),8,O)]);qs.append((name,z3.Or(v.read('x10')!=V,v.read('x12')!=O,z3.UGT(ix*8+8,z3.BitVecVal(8192,64)))))
 v=run('vault_nullable_slot_gate',0xfffffe000a58b7e8,0xfffffe000a58b7fc,[('x12',O),('w9',0x72d),('w11',0x42b)]);qs.append(('vault_nullable_slot_gate',v.read('w10')!=z3.If(O==0,z3.BitVecVal(0x455,32),z3.BitVecVal(0x42b,32))))
 prep=run('allowed_slot_phase',0xfffffe000a57e274,0xfffffe000a57e29c,[('w8',0x500)]);v=run('allowed_nullable_slot_gate',0xfffffe000a57e2a4,0xfffffe000a57e2bc,[('x12',O),('w8',prep.read('w8')),('w9',prep.read('w9')),('w11',prep.read('w11'))]);qs.append(('allowed_nullable_slot_gate',z3.Or(v.read('w10')!=z3.If(O==0,z3.BitVecVal(0x515,32),z3.BitVecVal(0x502,32)),prep.read('w11')!=0x502,prep.read('w9')!=0x8ac)))
 for name,a,z,reg,phase in[('vault_retry_acquire_record',0xfffffe000a57ee08,0xfffffe000a57ee48,'x20',0x72d),('allowed_retry_acquire_record',0xfffffe000a572734,0xfffffe000a572778,'x21',0x8ac)]:
  v=run(name,a,z,[(reg,R),('w10',phase)]);K=(resize(R,32)^0x1d65dad0)*0xe9655f4d;qs.append((name,z3.Or(cell(v,R,8)!=0,cell(v,R+8,4)-K!=0x2d2)))
 return qs,counts
