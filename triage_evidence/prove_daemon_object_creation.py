#!/usr/bin/env python3
"""Rebuild original-instruction bitvector obligations for allocation control.
30 s/query; O(lifted instructions + solver resources) time/space. Explicit
cutpoint/owner/phase premises; no native entry, PAC or allocator execution.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from prove_daemon_registry_lookup import RegistryLift,sha
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
 qs=[];counts={};F=0x6800010000;M=0x6800003000;S,Q=z3.BitVecs('creation_incoming32 creation_phase32',32);B8=z3.BitVec('creation_marker8',8);P,X=z3.BitVecs('creation_return64 creation_marker_phase64',64)
 def run(n,a,z,seeds=(),memory=()):
  v=RegistryLift(part(c,n,a,z))
  for reg,value in seeds:v.seed(reg,value)
  for at,nb,value in memory:mem(v,at,nb,value)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 phase=run('phase',0x100a03618,0x100a03668,[('w8',S),('x15',M)],[(M,1,B8)]);b=S+0x354d;l=(b+0xeffc4ff6)&0x10035fbd;h=(b+0x5bf03876)&0xa40f773d;idx=b|(z3.ZeroExt(24,B8)*(l+h-0x8da5))
 add('all_incoming32_marker8_phase_equations',z3.Or(phase.read('w8')!=l,phase.read('w9')!=h,phase.read('w10')!=idx))
 add('selected_phase_all_marker8',z3.Or(phase.read('w8')!=0x471c,phase.read('w9')!=0x471c,phase.read('w10')!=(0x9768|(z3.ZeroExt(24,B8)*0x93))),S==0x621b)
 roots=run('root_restore',0x100a0366c,0x100a03680,[('sp',F)],[(F+o,8,v)for o,v in[(0x2a88,0x6800001000),(0x2a90,0x6800002000),(0x2978,0x100fc4230),(0x2980,0x101031fa0),(0x2990,0x100f4e390)]]);add('declared_frame_root_restoration',z3.Or(*[roots.read(n)!=v for n,v in [('x28',0x6800001000),('x23',0x6800002000),('x24',0x100fc4230),('x25',0x101031fa0),('x14',0x100f4e390)]]))
 mark=run('marker_set',0x1009f735c,0x1009f736c,[('x0',X),('x15',M)]);add('all_u64_marker_phase_index',z3.Or(mark.read('w8')!=resize(X,32)+0x50df,cell(mark,M,1)!=1))
 keep=run('phase_preserve',0x1009f7370,0x1009f7374,[('x0',X)]);add('all_u64_phase_preserve',keep.read('x9')!=X)
 zero=run('zero_entry',0x1009c5844,0x1009c5858,[('sp',F),('w8',0x471c),('x22',X)]);add('zero_marker_first_dispatch',z3.Or(zero.read('w9')!=0x994,zero.read('w10')!=0xa39a,cell(zero,F+0x26f0,8)!=X))
 junction=run('zero_junction',0x100abe63c,0x100abe674,[('sp',F),('w8',0x471c),('w9',0x994),('x15',M),('x30',TABLE)],[(TABLE+0x994*8,8,0x1009f735c),(M,1,B8)]);add('zero_junction_all_marker8',z3.Or(junction.read('w22')!=0x7e9,junction.read('w8')!=(0x344f^(z3.ZeroExt(24,B8)*0x19)),junction.read('x9')!=0x1009f735c,cell(junction,F+0x3488,8)!=0x1009f735c))
 gatephase=run('zero_phase',0x1009c1404,0x1009c1444,[('w22',0x7e9)]);add('zero_marker_lazy_phase',z3.Or(gatephase.read('w8')!=0x471c,gatephase.read('w9')!=0x5e53))
 lazy=run('lazy_gate',0x10064ffbc,0x10064fff8,[('sp',F),('w8',0x471c),('w22',0x7e9),('x30',TABLE)],[(TABLE+0x7e9*8,8,0x100b280c8),(F+0x26c0,8,M),(M,8,P)]);add('all_u64_lazy_cell_with_distinct_callback',z3.Or(lazy.read('x19')!=0x100b280c8,lazy.read('w8')!=z3.If(P==0,z3.BitVecVal(0x443f,32),z3.BitVecVal(0x447c,32))))
 p19=run('phase19',0x100c11650,0x100c11658,[('w9',Q)]);add('all_u32_allocator_phase19',p19.read('w19')!=Q-0x2745)
 p20=run('phase20',0x100c11694,0x100c11698,[('w9',Q),('w11',0x3934)]);add('all_u32_allocator_phase20',p20.read('w20')!=Q+0x3934)
 result=run('allocator_result',0x100c116b4,0x100c116d8,[('sp',F),('x0',P),('w19',Q-0x2745),('w20',Q+0x3934)],[(F+0x29a0,8,TABLE)]);flag=((Q-0x2745)^z3.If(P==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))&1
 add('all_u32_phase_u64_return_dispatch',z3.Or(result.read('w8')!=((Q+0x3934)^(flag*56)),cell(result,F+0x2c08,8)!=P,result.read('x30')!=TABLE))
 add('phase471C_success_failure_dispatch',result.read('w8')!=z3.If(P==0,z3.BitVecVal(0x8050,32),z3.BitVecVal(0x8068,32)),Q==0x471c)
 success=run('success_save',0x1006534bc,0x1006534c8,[('sp',F),('x0',P),('x22',X)]);add('all_u64_success_pointer_save',z3.Or(cell(success,F+0x2a68,8)!=P,cell(success,F+0x26f0,8)!=X,success.read('x10')!=0))
 fail=run('null_result',0x100cb2ba8,0x100cb2bd0,[('w19',0x1fd7),('sp',F)]);add('selected_null_local_result',z3.Or(cell(fail,F+0x30e7,1)!=0,cell(fail,F+0x3554,4)!=0x74c29f35,cell(fail,F+0x3580,8)!=0,cell(fail,F+0x2f94,4)!=0x74c29f35))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_object_creation_contracts.json').read_text());qs,counts=obligations(c);rows=[];witnesses=[]
 for n,p in qs:
  a=ROOT/f'daemon_object_creation_{n}_original.smt2';b=ROOT/f'daemon_object_creation_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));ans=str(s.check());print(json.dumps({'proof':n,'result':ans}),flush=True);assert ans=='unsat',(n,ans,str(s.model())if ans=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans})
  if n in ['selected_phase_all_marker8','phase471C_success_failure_dispatch']:
   s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':n,'premise_result':'sat','model':str(s.model())})
 deps=['daemon_object_creation_contracts.json','prove_daemon_registry_lookup.py','prove_daemon_descriptor_producers.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_object_creation_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
