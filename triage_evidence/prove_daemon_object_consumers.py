#!/usr/bin/env python3
"""Source-local cleanup,stack-address seed,byte overwrite and key-counter
identities. 30 s solver limit/query. Valid owners and selected phase remain
premises; no native object allocation/PAC/library execution is established.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from prove_daemon_registry_lookup import RegistryLift,sha
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
 qs=[];counts={};F,S,PTR,L,N=z3.BitVecs('destruct_SP64 destruct_counter64 destruct_pointer64 destruct_link64 destruct_remaining64',64);H,K,C,I=z3.BitVecs('destruct_header32 destruct_expected32 destruct_active32 destruct_index32',32);SP=0x6800052060;OBJ=0x6800020000;PREV=0x6800024000;PAY=0x6800018000;KEY=0x6800010000
 def run(name,a,z,seeds=(),memory=()):
  v=RegistryLift(part(c,name,a,z))
  for n,x in seeds:v.seed(n,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(name);counts[name]=v.count;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 p=run('guard310',0x100b31ce4,0x100b31d08,[('x4',OBJ),('w10',0x2ddf)],[(OBJ+0x310,8,PTR)]);add('all_u64_field310_guard',z3.Or(p.read('w27')!=0x471c,p.read('x0')!=PTR,p.read('w8')!=z3.If(PTR==0,z3.BitVecVal(0x2ddf,32),z3.BitVecVal(0x2dfc,32))))
 d=run('guardD8',0x100c70c9c,0x100c70cc0,[('x4',OBJ),('w27',0x471c),('sp',SP)],[(OBJ+0xd8,8,PTR)]);add('all_u64_fieldD8_guard',z3.Or(d.read('x0')!=PTR,d.read('w8')!=z3.If(PTR==0,z3.BitVecVal(0x9b74,32),z3.BitVecVal(0x9b7b,32)),cell(d,SP+0x2a70,8)!=OBJ))
 adv=run('chain_advance',0x100a2ae1c,0x100a2ae34,[('x4',OBJ)],[(OBJ+0x360,8,L)]);add('all_u64_chain_advance',z3.Or(adv.read('x8')!=OBJ,adv.read('x4')!=L,adv.equal!=(L==0)))
 h=run('header_compare',0x100aca37c,0x100aca388,[('x4',OBJ),('w9',K)],[(OBJ,4,H)]);add('all_u32_chain_header_compare',h.equal!=(H==K))
 head=run('head_unlink',0x100a264dc,0x100a264e4,[('x4',OBJ),('x8',PAY)],[(OBJ+0x360,8,L)]);add('all_u64_head_unlink',cell(head,PAY+16,8)!=L)
 mid=run('interior_unlink',0x100926c08,0x100926c10,[('x4',OBJ),('x8',PREV)],[(OBJ+0x360,8,L)]);add('all_u64_interior_unlink',cell(mid,PREV+0x360,8)!=L)
 seed=run('seed',0x100bb1574,0x100bb15d0,[('sp',F),('w27',0x471c)]);add('selected_mode_fill_control',seed.read('w2')!=0x7e8c);add('aligned16_stack_seed64',seed.read('x13')!=(F+0x2ba0)+0x2f40b33d2e85d192,F&15==0)
 constants=run('fill_constants',0x100bb1650,0x100bb16b8,[('x30',0x101039ef0)]);required={'w7':0x4214,'w20':0x8aefa97d,'w21':0xd17a2e6e,'w22':0x887bad6d,'w23':0xb72b493a,'w24':0x5b958712,'w25':0x48948111,'w26':0x6e561c40,'w27':0xd4,'w28':0xe011};add('source_fill_constants',z3.Or(*[constants.read(n)!=v for n,v in required.items()]))
 length=run('fill_length',0x100a048d4,0x100a048e8,[('x8',0x3705faa50a75fd0c)]);add('source_overwrite_length872',length.read('x1')!=872)
 phase=run('fill_phase',0x100a048ec,0x100a048fc,[('w2',0x7e8c),('w7',0x4214),('x13',S)]);add('source_fill_mode_and_counter',z3.Or(phase.read('w4')!=0x471c,phase.read('x11')!=S))
 seeds=[('sp',SP),('x6',OBJ),('x1',N),('x11',S),('w4',0x471c)]+[(n,x)for n,x in required.items()if n!='w7'];body=run('fill_body',0x100a1bf1c,0x100a1bf84,seeds);b=resize(S,32);formula=resize(((b+0x6e)^0xba)*(b+0x7f),8);assert len(body.stores)==2;add('all_u64_counter_byte_formula',z3.Or(body.stores[1]['value']!=formula,body.stores[1]['address']!=OBJ+N-1,body.read('x11')!=S+1,cell(body,SP+0x2ba0,8)!=N-1))
 add('byte_formula_period256',formula!=resize((((b+256)+0x6e)^0xba)*((b+256)+0x7f),8))
 branch=run('fill_loop_gate',0x100a1bf84,0x100a1bf98,[('sp',SP),('w2',0x7e8c),('w28',0xe011)],[(SP+0x2ba0,8,N-1)]);add('positive_remaining_loop_gate',branch.read('w12')!=z3.If(N==1,z3.BitVecVal(0x9e9d,32),z3.BitVecVal(0x7e8c,32)),z3.UGE(N,1));add('overwrite_owner_bounds',z3.Or(z3.UGT(N-1,871),z3.UGT(N,872)),z3.And(z3.UGE(N,1),z3.ULE(N,872)))
 index=z3.ZeroExt(32,I);R=KEY+(index<<4);clear=run('key_clear',0x100b11d40,0x100b11d98,[('x6',R),('w8',0x570a),('x19',index),('sp',SP)],[(SP+0x26d0,8,0x1010c67a8),(0x1010c67a8,8,KEY),(SP+0x21a8,8,0x1010c5754),(0x1010c5754,4,C)]);add('bounded_key_clear_and_all_counter_values',z3.Or(cell(clear,R,8)!=0xe3b88695c0d52dbc,cell(clear,R+8,4)!=0x8b3dc651,cell(clear,R+12,4)!=0x8b3dc651,cell(clear,0x1010c5754,4)!=C-1),z3.ULT(I,3))
 alloc=run('candidate_allocation',0x100c116a8,0x100c116ac);add('literal_malloc_request872',alloc.read('w0')!=872)
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_object_consumers_contracts.json').read_text());qs,counts=obligations(c);rows=[];witness=[]
 for n,p in qs:
  a=ROOT/f'daemon_object_consumers_{n}_original.smt2';b=ROOT/f'daemon_object_consumers_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':n,'result':answer}),flush=True);assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
  if n in['aligned16_stack_seed64','positive_remaining_loop_gate','overwrite_owner_bounds','bounded_key_clear_and_all_counter_values']:s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';witness.append({'proof':n,'premise':'sat','model':str(s.model())})
 deps=['daemon_object_consumers_contracts.json','prove_daemon_registry_lookup.py','prove_daemon_descriptor_producers.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witness,'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_object_consumers_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
