#!/usr/bin/env python3
"""Arbitrary dead-stack-bit noninterference through first malloc boundary.
Source lift is fail closed; O(I+source loads) DAG construction/time/space,
30 s/query timeout. Fixed source roots/selected phase and equal controller
words follow the preceding serialized source prefix; no PAC/native APIs.
"""
import hashlib,json,struct
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,IMAGE,SOURCE,FIXUPS,TABLE,verify_original_fixups
from prove_daemon_frame_entry import FrameLift
from lskd_values_symbolic import part,mem,cell
class ArenaLift(FrameLift):
 def load(self,a,n):
  a=z3.simplify(a);key=(a.sexpr(),n)
  if key in self.memory:return self.memory[key]
  assert z3.is_bv_value(a),('unseeded symbolic address',str(a),n);at=a.as_long()
  if n==8 and at in FIXUPS:
   target=FIXUPS[at]['target'];self.fixup_reads.append(at)
   if isinstance(target,int):return z3.BitVecVal(target,64)
   assert target=='libSystem/_malloc';return self.malloc_pointer
  return z3.BitVecVal(int.from_bytes(IMAGE.read(at,n),'little'),8*n)
def obligations(c):
 qs=[];counts={};F=z3.BitVec('arena_frame64',64);S,T=z3.BitVecs('unknown_SP5F8_64 unknown_SP540_64',64);S2,T2=z3.BitVecs('other_SP5F8_64 other_SP540_64',64);C=z3.BitVec('equal_controller_word32',32);API=z3.BitVec('malloc_code_pointer64',64)
 v=ArenaLift(c);v.fixup_reads=[];v.malloc_pointer=API
 def run(label,a,z):
  before=v.count;v.c=part(c,label,a,z);v.run(label);counts[label]=v.count-before
 for j in range(31):v.seed('x'+str(j),z3.BitVec('incoming_x'+str(j),64))
 v.seed('sp',F);v.seed('w8',0x49fa);mem(v,F+0x1c8,8,0x1010b6cb8);mem(v,0x1010b6cb8,4,1);run('selected_flag_phase',0x1003308a0,0x1003308e4)
 qs.append(('incoming_selected_phase',z3.Or(v.read('w9')!=0x8a9b8560,v.read('w11')!=0x266c4654)))
 v.seed('x20',TABLE);v.seed('x15',0x1010b5ef0)
 for off,value in [(0x5f8,S),(0x540,T),(0x390,0x1010b7dd8),(0x398,0x1010c4670),(0x350,0x100e99700),(0x348,0x100f4e190)]:mem(v,F+off,8,value)
 mem(v,0x1010b7dd8,4,C);mem(v,0x1010c4670,4,C)
 run('first_branch',0x1003b5724,0x1003b57d0);qs.append(('first_branch_target',v.read('x8')!=0x1003c24b8));qs.append(('first_branch_modifier',v.read('x17')!=0x6587))
 run('second_branch',0x1003c24b8,0x1003c24e0);qs.append(('second_branch_target',v.read('x8')!=0x10032a464));qs.append(('second_branch_modifier',v.read('x17')!=0xb9e1))
 run('before_malloc',0x10032a464,0x10032a4e8);qs.append(('malloc_target_and_ABI',z3.Or(v.read('x8')!=API,v.read('x17')!=0x6aa4,v.read('x0')!=90000,v.read('sp')!=F)));qs.append(('descriptor_zero_store',cell(v,0x1010b5ef0,8)!=0))
 subs=[(S,S2),(T,T2)];qs.append(('all_GPR_dead_bits_noninterference',z3.Or(*[v.read('x'+str(j))!=z3.substitute(v.read('x'+str(j)),*subs)for j in range(31)])))
 qs.append(('source_store_dead_bits_noninterference',z3.Or(*[z3.Or(e['address']!=z3.substitute(e['address'],*subs),e['value']!=z3.substitute(e['value'],*subs))for e in v.stores])))
 qs.append(('dispatch_flags_dead_bits_noninterference',z3.Or(v.equal!=z3.substitute(v.equal,*subs),v.carry!=z3.substitute(v.carry,*subs))))
 return qs,counts,sorted(set(v.fixup_reads))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_arena_entry_contracts.json').read_text());qs,counts,fix=obligations(c);rows=[]
 for n,q in qs:
  op=ROOT/f'daemon_arena_entry_{n}_original.smt2';np=ROOT/f'daemon_arena_entry_{n}.smt2';s=z3.Solver();s.add(q);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(n,result);np.write_text(s.to_smt2());rows.append({'name':n,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 deps=['daemon_arena_entry_contracts.json','prove_daemon_frame_entry.py','daemon_rwlock_lifecycle_symbolic.py','daemon_iokit_sync_symbolic.py','daemon_iokit_class_symbolic.py','daemon_query_fallback_symbolic.py','daemon_query_state_symbolic.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'proofs':rows,'source_lift_counts':counts,'original_fixup_records':verify_original_fixups(fix),'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_entry_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(rows),'lifts':counts,'fixups':len(fix)}),flush=True)
if __name__=='__main__':main()
