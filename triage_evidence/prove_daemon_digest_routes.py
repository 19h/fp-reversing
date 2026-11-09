#!/usr/bin/env python3
"""Prove compact source-local routes and 100-byte context/frame contracts.
O(lifted source+solver resources) time/space; 30 s/query. Phase, valid owner,
table-root and frame premises explicit. No actual caller or native PAC claim.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha
from prove_daemon_object_initialization import InitLift
from lskd_values_symbolic import part,mem,cell,resize
from capstone.arm64_const import ARM64_EXT_SXTW,ARM64_EXT_UXTW
class RouteLift(InitLift):
 def address(self,i,o):
  a=resize(self.read(i.reg_name(o.mem.base)),64)+o.mem.disp
  if o.mem.index:
   v=self.read(i.reg_name(o.mem.index));v=z3.SignExt(32,resize(v,32))if o.ext==ARM64_EXT_SXTW else z3.ZeroExt(32,resize(v,32))if o.ext==ARM64_EXT_UXTW else resize(v,64);a=a+(v<<o.shift.value)
  return z3.simplify(a)
def obligations(c):
 F=0x6900040000;O=0x6900010000;P=z3.BitVec('routes_phase32',32);V=z3.BitVec('routes_value32',32);Q,A,B,I,C,R=z3.BitVecs('routes_cursor64 routes_A64 routes_B64 routes_input64 routes_context64 routes_return64',64);qs=[];counts={};details={}
 def run(n,a,z,seeds=(),memory=()):
  v=RouteLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p):qs.append((n,p))
 v=run('new_route',0x100b5c600,0x100b5c614,[('w9',P),('w11',0x5e8e),('sp',F),('x4',C)]);new=v.read('w11');add('all_u32_new_route_index',z3.Or(new!=((P^0xc58)^(P+0x5e8e)),v.read('w12')!=P+0x5e8e));add('all_u32_new_route_compact_cube',(new==0x6eca)!=((P&0x6292)==0x0202))
 v=run('existing_prefix',0x100bae14c,0x100bae15c,[('w9',P),('sp',F)],[(F+0x2a60,8,O),(O+0x6c,4,V)]);add('all_u32_existing_mode_and_counter_capture',z3.Or(v.read('w12')!=P+0x5e48,v.read('w10')!=V))
 v=run('existing_route',0x100bae15c,0x100bae168,[('w9',P)]);old=v.read('w11');add('all_u32_existing_route_index',old!=((P+0x6a4a)^P));add('all_u32_existing_route_compact_cube',(old==0x6eca)!=((P&0x6eca)==0x0240))
 v=run('route780',0x10078080c,0x100780824,[('x10',A),('x17',O),('w16',V),('w11',P)]);add('all_u32_route780_predicate',v.read('w16')!=(P^z3.If(A==0,z3.BitVecVal(0,32),z3.BitVecVal(0x12,32))))
 v=run('route834',0x100834e6c,0x100834ea0,[('w11',P),('x16',O),('x10',R)]);add('all_u32_route834_unique_phase',(v.read('w10')==0x6eca)!=(P==0xe9fe5904))
 v=run('route_a1',0x100a1e4c8,0x100a1e4d8,[('w13',V),('w11',P)]);add('all_u32_route_a1_predicate',v.read('w11')!=(P^((V&1)*0xd4)))
 v=run('new_context',0x100b5c580,0x100b5c600,[('sp',F)],[(F+0x2df8,8,I),(F+0x2b38,8,O),(O+0xe0,4,V),(F+0x2d70,8,A),(F+0x3640,8,B),(F+0x3620,8,Q)]);ctx=z3.BitVecVal(F+0x39f0,64)+Q;assert len(v.stores)==9;words=[0x1b34867e93bc0ef6,0xe4cb79816c43f109,0x00000014372bcc07];add('all_u64_new_context_pointer_cursor_and_input_fields',z3.Or(v.read('x8')!=I,v.read('x2')!=z3.ZeroExt(32,V),v.read('x4')!=ctx,cell(v,F+0x31c8,8)!=ctx+100,cell(v,F+0x3620,8)!=Q+128,cell(v,F+0x3648,8)!=A,cell(v,F+0x35a8,8)!=B));add('all_u64_new_context_SHA1_fields',z3.Or(cell(v,ctx+0x40,8)!=0,cell(v,ctx+0x48,8)!=words[0],cell(v,ctx+0x50,8)!=words[1],cell(v,ctx+0x58,8)!=words[2],cell(v,ctx+0x60,4)!=2))
 v=run('existing_args',0x100bae16c,0x100bae178,[('sp',F)],[(F+0x2988,8,A),(F+0x2a70,8,C),(F+0x2a68,4,V)]);add('all_u64_existing_saved_arguments',z3.Or(v.read('x26')!=A,v.read('x4')!=C,v.read('x2')!=z3.ZeroExt(32,V)))
 v=run('callee_capture',0x100aee3a4,0x100aee3c0,[('sp',F),('x30',TABLE),('w9',P),('x4',C),('x2',R),('x8',I)],[(z3.BitVecVal(TABLE,64)+(z3.SignExt(32,P)<<3),8,A)]);add('all_u64_callee_saved_roots_and_low32_word',z3.Or(cell(v,F+0x2f48,8)!=A,cell(v,F+0x2b88,8)!=C,cell(v,F+0x2c8c,4)!=z3.Extract(31,0,R),cell(v,F+0x3490,8)!=I,v.read('w11')!=0))
 v=run('return_consumer',0x100bb2278,0x100bb2280,[('sp',F)],[(F+0x2f48,8,R)]);add('all_u64_saved_continuation_consumer',z3.Or(v.read('x8')!=R,v.read('x17')!=0x7315))
 v=run('raw_count',0x100aee3c0,0x100aee438,[('w10',P),('w12',0x61b9),('w2',V),('w13',0xffffe563)]);add('all_u32_raw_count_and_common_phase',z3.Or(v.read('w13')!=V+(P&63),v.read('w9')!=0x471c))
 v=run('raw_count_gate',0x100aee3c0,0x100aee44c,[('w10',P),('w12',0x61b9),('w2',V),('w13',0xffffe563)]);add('all_u32_raw_count_gate64',v.read('w13')!=z3.If(z3.ULT(V+(P&63),64),z3.BitVecVal(0x624a,32),z3.BitVecVal(0x61b9,32)))
 # Upper16 phase bits are free; exact predicates count 2^26 and 2^23 u32 values.
 details={'new_context_mask32':'0x6292','new_context_value32':'0x202','new_context_admitted_u32_values':1<<(32-0x6292.bit_count()),'existing_context_mask32':'0x6eca','existing_context_value32':'0x240','existing_context_admitted_u32_values':1<<(32-0x6eca.bit_count()),'route834_unique_phase32':'0xe9fe5904'}
 return qs,counts,details
def main():
 c=json.loads((ROOT/'daemon_digest_routes_contracts.json').read_text());qs,counts,details=obligations(c);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_digest_routes_{n}_original.smt2';b=ROOT/f'daemon_digest_routes_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(json.dumps({'proof':n,'result':answer}),flush=True)
 deps=['daemon_digest_routes_contracts.json','prove_daemon_object_initialization.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'compact_routes':details,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_digest_routes_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
