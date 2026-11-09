#!/usr/bin/env python3
"""Source identities for representation cancellation, nested lookups, byte
bounds and object guards. 30 s solver limit/query; logical source execution,
explicit phase/memory premises, no native reachability or lifetime inference.
"""
import json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG
from daemon_receive_tools import ROOT,IMAGE,TABLE
from prove_daemon_descriptor_producers import ProducerLift,sha
from lskd_values_symbolic import part,mem,cell,resize
class RegistryLift(ProducerLift):
 def run(self,label):
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;row=next(r for r in self.c['spans']if r['label']==label);old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='lsr'and i.operands[2].type==ARM64_OP_REG:
    dest=i.reg_name(i.operands[0].reg);n=self.width(dest);self.write(dest,z3.LShR(self.operand(i,i.operands[1],n),self.operand(i,i.operands[2],n)&(n-1)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};ProducerLift.run(self,'one')
  self.c=old;return self

def obligations(c):
 qs=[];counts={};F=0x6800052060;B=0x6800010000;G=0x1010c67a8;PAY=0x6800018000;P=0x6800020000;S,D,K,N,I,H=z3.BitVecs('registry_mode32 registry_input32 registry_tag32 registry_N32 registry_i32 registry_header32',32);E,Q,A,J,M=z3.BitVecs('registry_word64 registry_encoded_key64 registry_payload_key64 registry_j64 registry_M64',64)
 U=z3.BitVec('registry_query64',64);D=z3.Extract(31,0,U)
 def run(n,a,z,seeds=(),memory=(),v=None):
  if v is None:v=RegistryLift(part(c,n,a,z))
  else:v.c=part(c,n,a,z)
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  old=v.count;v.run(n);counts[n]=v.count-old;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 phase=run('unmask_phase',0x1009f0120,0x1009f0130,[('sp',F)],[(F+0x273c,4,S)]);add('all_u32_unmask_phase',phase.read('w22')!=((S-0x3f0c)|7));add('mode471C_unmask_phase',phase.read('w22')!=0x817,S==0x471c)
 unmask=run('unmask_word',0x1009f0154,0x1009f0170,[('sp',F),('x22',0x817)],[(F+0x2a70,8,E)]);add('all_u64_source_word_unmask',unmask.read('x10')!=(E^0xe3b88695c0d52dbc));add('all_u64_full_input_mask_cancellation',((E^0x9898989898989898^0xe3b88695c0d52dbc)^0xe3b88695c0d52dbc)!=(E^0x9898989898989898))
 outer=run('outer_entry',0x1008bf64c,0x1008bf6e8,[('sp',F),('x30',TABLE),('w12',0x41e9),('x13',U),('w9',N)],[(F+0x26d0,8,G),(G,8,B),(TABLE+0x41e9*8,8,0x100bb01e8)]);outer=run('outer_predicate',0x100bb01e8,0x100bb023c,[('w21',I)],[(B+(z3.ZeroExt(32,I)<<4)+8,4,K)],outer);add('all_u64_query_low32_tag_predicate',outer.equal!=((K^0x8b3dc651)==D))
 advance=run('outer_advance',0x10096928c,0x1009692b8,v=outer);add('all_u32_outer_advance',z3.Or(advance.read('w21')!=I+1,advance.read('w8')!=z3.If(I+1==N,z3.BitVecVal(0xa16e,32),z3.BitVecVal(0x41e9,32))))
 i64=z3.ZeroExt(32,I);n64=z3.ZeroExt(32,N);add('outer_owner_bounds_bytes',z3.UGT((i64<<4)+16,n64<<4),z3.ULT(I,N))
 bound=run('inner_count_gate',0x100963cc0,0x100963ce4,[('x14',0x1010ca2b0),('w13',0x471c),('w10',0x63fb),('w12',0x7aeb)],[(0x1010ca2b0,4,N)]);add('all_u32_inner_count_gate',z3.Or(bound.read('x11')!=z3.ZeroExt(32,N),bound.read('w10')!=z3.If(N==0,z3.BitVecVal(0x7aeb,32),z3.BitVecVal(0x7aec,32))))
 inner=run('inner_init',0x100b252e8,0x100b2537c,[('sp',F),('x30',TABLE),('w8',0xab17),('x9',Q),('x11',M)],[(TABLE+0xab17*8,8,0x10094cbb8),(F+0x26b0,8,0x1010c9288),(0x1010c9288,8,PAY)]);inner.seed('x14',J)
 base=run('inner_base_gate',0x10094cbb8,0x10094cbd8,[('x16',E)],v=inner);add('all_u64_payload_base_gate',base.read('w8')!=z3.If(E==0,z3.BitVecVal(0x7ccd,32),z3.BitVecVal(0x7cfd,32)))
 key=run('inner_key_gate',0x10095e930,0x10095e964,[('x16',PAY)],[(PAY+(J<<5),8,A)],inner);add('all_u64_encoded_zero_key_gate',key.read('w8')!=z3.If(Q==0xe3b88695c0d52dbc,z3.BitVecVal(0x32b1,32),z3.BitVecVal(0x3327,32)))
 comp=run('inner_predicate',0x1008bb504,0x1008bb530,v=inner);add('all_u64_inner_key_equality',comp.equal!=(A==Q));add('all_u64_inner_match_dispatch',comp.read('w12')!=z3.If(A==Q,z3.BitVecVal(0xae11,32),z3.BitVecVal(0xadfe,32)))
 adv=run('inner_advance',0x100839154,0x10083918c,v=inner);add('all_u64_inner_advance',z3.Or(adv.read('x14')!=J+1,adv.read('w8')!=z3.If(J+1==M,z3.BitVecVal(0xab3f,32),z3.BitVecVal(0xab17,32))))
 add('inner_owner_bounds_bytes',z3.UGT((J<<5)+32,M<<5),z3.And(z3.ULT(J,M),z3.ULE(M,0xffffffff)))
 index=run('selected_index',0x100b328c4,0x100b328cc,[('sp',F),('x14',J)],[(F+0x2a68,8,F+0x368c)]);add('selected_index_low32_store',cell(index,F+0x368c,4)!=resize(J,32))
 unlink=run('object_head_unlink',0x100a264dc,0x100a264e4,[('x4',P),('x8',PAY)],[(P+0x360,8,E)]);add('all_u64_head_link_replacement',cell(unlink,PAY+16,8)!=E)
 ptr=run('object_pointer_gate',0x100c744b0,0x100c744e0,[('x8',PAY),('w11',0x465c)],[(PAY+16,8,E)]);add('all_u64_object_pointer_gate',z3.Or(ptr.read('w20')!=0x471c,ptr.read('w13')!=0x2d40,ptr.read('w9')!=z3.If(E==0,z3.BitVecVal(0x465c,32),z3.BitVecVal(0x4673,32))))
 obj=run('object_header',0x1009e2e1c,0x1009e2e4c,[('sp',F),('x4',P),('w13',0x2d40)],[(F+0x326c,4,S),(P,4,H)]);add('all_u32_object_header_guard',obj.read('w10')!=z3.If(H==S,z3.BitVecVal(0x2d6e,32),z3.BitVecVal(0x2d40,32)))
 initial=run('initializer10',0x100bb2418,0x100bb249c,[('sp',F),('x0',B),('w19',S)],[(F+0x24a8,8,0x1010c67d0),(F+0x21a8,8,0x1010c5754)]);bad=[cell(initial,0x1010c67d0,4)!=10,cell(initial,0x1010c5754,4)!=0]
 for j in range(10):bad.extend([cell(initial,B+16*j,8)!=0xe3b88695c0d52dbc,cell(initial,B+16*j+8,4)!=0x8b3dc651,cell(initial,B+16*j+12,4)!=0x8b3dc651])
 add('disjoint_initializer10_layout',z3.Or(*bad))
 allocation=run('malloc320',0x100ac7d44,0x100ac7d48);add('literal_payload_allocation320',allocation.read('w0')!=320)
 add('all_u64_encoded_key_equality_bijection',((Q^0xe3b88695c0d52dbc)==(A^0xe3b88695c0d52dbc))!=(Q==A))
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_registry_lookup_source.json').read_text());qs,counts=obligations(c);rows=[];witnesses=[]
 for name,p in qs:
  original=ROOT/f'daemon_registry_lookup_{name}_original.smt2';simple=ROOT/f'daemon_registry_lookup_{name}.smt2';s=z3.Solver();s.add(p);original.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');simple.write_text(s.to_smt2());rows.append({'name':name,'original_file':original.name,'original_sha256':sha(original),'file':simple.name,'sha256':sha(simple),'result':answer})
  if name in['mode471C_unmask_phase','outer_owner_bounds_bytes','inner_owner_bounds_bytes']:s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':name,'premise':'sat','model':str(s.model())})
 deps=['daemon_registry_lookup_source.json','prove_daemon_descriptor_producers.py','prove_daemon_callback_revisit.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_registry_lookup_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
