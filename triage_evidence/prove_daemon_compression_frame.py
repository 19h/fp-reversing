#!/usr/bin/env python3
"""Rebuild original-source local frame/copy identities; 30 s/query.
O(artifact bytes+lifted instructions+solver resources) time/space. Separated
word cells, valid owners, original roots and source cutpoints are premises.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha
from prove_daemon_digest_routes import RouteLift
from lskd_values_symbolic import part,mem,cell,resize
from recover_daemon_compression_frame import K
def obligations(c):
 F=0x6a00040000;C,I,R,Q,A,J=z3.BitVecs('frame_C64 frame_I64 frame_R64 frame_Q64 frame_A64 frame_J64',64);N,H,E,V,P,L=z3.BitVecs('frame_N32 frame_H32 frame_E32 frame_V32 frame_P32 frame_L32',32);B=z3.BitVec('frame_byte8',8);qs=[];counts={}
 def run(n,a,z,seeds=(),memory=()):
  v=RouteLift(part(c,n,a,z))
  for r,x in seeds:v.seed(r,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 h=H&63
 v=run('long_prepare',0x100bb18ec,0x100bb1958,[('w10',0x6f67867f),('w8',h),('x30',TABLE)],[(TABLE+8*0x71c3,8,0x100b3940c)]);add('all_low6_first_copy_count_and_loop_route',z3.Or(v.read('w9')!=0x71b7,v.read('w20')!=0xe,v.read('w10')!=64-h,v.read('x11')!=z3.ZeroExt(32,64-h)-1,v.read('x12')!=0x100b3940c))
 v=run('copy_byte',0x100b39410,0x100b39424,[('w12',z3.ZeroExt(24,B)),('x4',C),('x8',J)]);add('all_u8_source_copy_encoding',z3.Or(z3.Extract(7,0,v.read('w12'))!=(B^0x98),v.read('x13')!=C+J))
 v=run('copy_gate',0x100b39428,0x100b39440,[('x8',J),('x11',A),('w20',0xe),('w9',0x71b7)]);add('all_u64_copy_position_and_gate',z3.Or(v.read('x8')!=J+1,v.read('w12')!=z3.If(A==0,z3.BitVecVal(0x71b7,32),z3.BitVecVal(0x71c3,32))))
 v=run('copy_finish',0x100926e88,0x100926ebc,[('sp',F),('w20',0xe),('w10',V),('x4',C),('x30',TABLE)],[(TABLE+8*0x385f,8,0x100abee44)]);add('all_u64_long_context_capture_and_shared_phase',z3.Or(cell(v,F+0x2e50,8)!=C,cell(v,F+0x30fc,4)!=V,v.read('x12')!=C,v.read('w8')!=0x471c,v.read('x9')!=0x100abee44))
 v=run('short_call',0x10094a390,0x10094a3ac,[('w8',0x471c),('x4',C),('x30',TABLE)],[(TABLE+8*0x385f,8,0x100abee44)]);add('all_u64_short_compression_call',z3.Or(v.read('w20')!=0x58,v.read('x12')!=C,v.read('x9')!=0x100abee44))
 v=run('frame_common',0x100abee44,0x100abef14,[('sp',F),('w8',0x471c),('w15',0x471c),('x30',TABLE),('w20',P),('x4',C)],[(F+0x31dc,4,E),(F+0x2f50,8,I),(F+0x2e50,8,A),(F+0x2c8c,4,N),(F+0x3490,8,R),(TABLE+8*0x36c8,8,0x100b76438)])
 expected={0x2a08:(4,E),0x2a60:(4,E+0x318c+0x1960f475),0x2a58:(8,I),0x2a50:(8,A),0x2a68:(4,N),0x2a20:(8,R),0x2a18:(4,0x20),0x2a48:(4,0xa243),0x2a10:(4,0x42),0x2a40:(4,0xa34a),0x2a38:(4,K),0x2a30:(4,0xa351),0x2a28:(4,64)}
 add('all_u64_shared_frame_copies_and_controls',z3.Or(*[cell(v,F+off,n)!=val for off,(n,val)in expected.items()],v.read('w1')!=0x318c,v.read('x10')!=0x100b76438,v.read('w9')!=0x98,v.read('w14')!=0xf4f92df7,v.read('w20')!=P,v.read('x4')!=C,v.read('x30')!=TABLE))
 states=z3.BitVecs('frame_state0 frame_state1 frame_state2 frame_state3',32)
 v=run('compression_entry',0x100b76438,0x100b76484,[('sp',F),('w1',0x318c),('w20',P),('x30',TABLE),('x4',C)],[(F+0x3620,8,Q),(z3.BitVecVal(TABLE,64)+(z3.SignExt(32,P)<<3),8,R)]+[(C+0x48+4*j,4,s)for j,s in enumerate(states)])
 add('all_u64_compression_cursor320_continuation_and_state',z3.Or(cell(v,F+0x2de0,8)!=R,cell(v,F+0x3620,8)!=Q+320,v.read('x16')!=F+0x39f0+Q,v.read('x2')!=TABLE,v.read('w11')!=states[0],v.read('w19')!=states[1],v.read('w0')!=states[2],v.read('w30')!=states[3],cell(v,F+0x2ebc,4)!=states[2],cell(v,F+0x303c,4)!=states[3]))
 good=z3.UGE(N,L+64);idx=z3.If(good,z3.BitVecVal(0xa351,32),z3.BitVecVal(0xa34a,32))
 v=run('next_block_gate',0x100b51c00,0x100b51c58,[('sp',F),('x16',F+0x30fc),('x30',TABLE)],[(F+0x2a60,4,N+K),(F+0x30fc,4,L),(F+0x2a38,4,K),(F+0x2a40,4,0xa34a),(z3.BitVecVal(TABLE,64)+(z3.SignExt(32,idx)<<3),8,R),(F+0x2a58,8,I),(F+0x2a50,8,C),(F+0x2a30,4,0xa351),(F+0x2a28,4,64)])
 add('all_u32_next_full_block_predicate',v.read('w12')!=idx,z3.And(z3.UGE(L,1),z3.ULE(L,64)))
 v=run('next_block_arguments',0x100b51c5c,0x100b51c88,[('sp',F)],[(F+0x2a58,8,I),(F+0x2a50,8,C),(F+0x2a30,4,0xa351),(F+0x2a28,4,64)]);add('all_u64_next_block_argument_cells',z3.Or(v.read('x0')!=I,v.read('x1')!=C,v.read('w2')!=0xa351,v.read('w4')!=64))
 v=run('long_return',0x100c0b4d4,0x100c0b4e8,[('sp',F),('x30',TABLE)],[(F+0x2a10,4,0x42),(TABLE+8*0x42,8,0x100b51c00)]);add('source_long_return_next_block_gate',z3.Or(v.read('x11')!=0x100b51c00,v.read('x16')!=F+0x30fc))
 add('all_u32_first_copy_count_fits_declared_count',z3.ULT(N,64-h),z3.UGE(N+h,64))
 v=run('compression_return',0x100bdfaf0,0x100bdfb28,[('sp',F),('x2',TABLE)],[(F+0x3620,8,Q),(F+0x2de0,8,R),(F+0x273c,4,N),(F+0x2978,8,A),(F+0x2980,8,I)]);add('all_u64_compression_return_cursor_root_and_saved_target',z3.Or(cell(v,F+0x3620,8)!=Q-320,v.read('x1')!=R,v.read('x30')!=TABLE,v.read('x15')!=z3.ZeroExt(32,N),v.read('x24')!=A,v.read('x27')!=I,v.read('x0')!=F+0x2e5c,v.read('x16')!=F+0x35e4,v.read('x17')!=0xd737))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_compression_frame_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,p in qs:
  a=ROOT/f'daemon_compression_frame_{name}_original.smt2';b=ROOT/f'daemon_compression_frame_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(json.dumps({'proof':name,'result':answer}),flush=True)
 deps=['daemon_compression_frame_contracts.json','prove_daemon_digest_routes.py','lskd_values_symbolic.py','recover_daemon_compression_frame.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_compression_frame_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
