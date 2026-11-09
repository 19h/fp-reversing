#!/usr/bin/env python3
"""Prove update/count and finalization convention pairs from original source.
O(loaded artifact bytes+lifted instructions+solver resources) time/space, 30 s/query. Fixed mode,
borrowed owners,valid table cells and frame preservation are explicit premises.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE,POOL
from recover_daemon_object_creation import sha
from prove_daemon_digest_routes import RouteLift
from lskd_values_symbolic import part,mem,cell,resize
def obligations(c):
 F=0x6900040000;C,O,A,B,R,Q,I=z3.BitVecs('conventions_context64 conventions_output64 conventions_A64 conventions_B64 conventions_return64 conventions_cursor64 conventions_input64',64);P,N,H=z3.BitVecs('conventions_index32 conventions_count32 conventions_counter32',32);qs=[];counts={}
 def run(n,a,z,seeds=(),memory=()):
  v=RouteLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p):qs.append((n,p))
 v=run('new_finalize_caller',0x10094dec4,0x10094defc,[('sp',F),('x22',TABLE)],[(F+0x273c,4,0x471c),(TABLE+0xac2e*8,8,0x100c03b20)]);add('source_new_finalize_arguments_mode471C',z3.Or(v.read('x10')!=F+0x3388,v.read('x11')!=F+0x31c8,v.read('w9')!=0x9c,v.read('x8')!=0x100c03b20,v.read('x30')!=TABLE,v.read('x0')!=POOL))
 v=run('saved_finalize_caller',0x100baaf1c,0x100baaf54,[('sp',F),('x19',TABLE)],[(F+0x273c,4,0x471c),(TABLE+0xac2e*8,8,0x100c03b20)]);add('source_saved_finalize_arguments_mode471C',z3.Or(v.read('x10')!=F+0x30b8,v.read('x11')!=F+0x3678,v.read('w9')!=0x9b,v.read('x8')!=0x100c03b20,v.read('x30')!=TABLE))
 v=run('fixed20',0x100be25b8,0x100be25fc,[('sp',F),('x22',TABLE)],[(F+0x273c,4,0x471c),(F+0x2f08,8,A),(F+0x30b8,8,C),(TABLE+0x49c6*8,8,0x100a0aad0)]);add('all_u64_fixed20_encoded_update_arguments',z3.Or(v.read('x21')!=A+0x238,v.read('x4')!=C,v.read('w5')!=0x1ad72f26,v.read('w19')!=0x9930,v.read('w20')!=0xb5d,v.read('x8')!=0x100a0aad0,v.read('x30')!=TABLE))
 v=run('wrapped_finalize',0x100c03b20,0x100c03b64,[('sp',F),('x10',F+0x200),('x11',F+0x208),('w9',P),('x30',TABLE),('w13',0x471c)],[(F+0x200,8,C),(F+0x208,8,O),(z3.BitVecVal(TABLE,64)+(z3.SignExt(32,P)<<3),8,R)]);add('all_u64_wrapped_finalize_captures_and_output_gate',z3.Or(cell(v,F+0x3590,8)!=R,cell(v,F+0x2df0,8)!=C,cell(v,F+0x3418,8)!=O,v.read('x4')!=C,v.read('w8')!=0x3b,v.read('w10')!=z3.If(O==0,z3.BitVecVal(0xc554,32),z3.BitVecVal(0xc567,32))))
 v=run('encoded_update',0x100a0aad0,0x100a0ab34,[('sp',F),('x30',TABLE),('w19',0x9930),('w20',P),('x4',C),('x21',I),('w5',N+0x1ad72f12)],[(C+0x44,4,H),(z3.BitVecVal(TABLE,64)+(z3.SignExt(32,P)<<3),8,R)]);S=N+(H&63);add('all_u32_encoded_update_gate_and_frame_capture',z3.Or(cell(v,F+0x2ea8,8)!=R,cell(v,F+0x2bf8,8)!=C,cell(v,F+0x31dc,4)!=N+0x1ad72f12,cell(v,F+0x2f50,8)!=I,v.read('w9')!=0x471c,v.read('w12')!=z3.If(z3.UGE(S,64),z3.BitVecVal(0x995b,32),z3.BitVecVal(0x9930,32))))
 add('all_u32_raw_and_encoded_threshold_equivalence',z3.ULT(S,64)!=z3.Not(z3.ULT(S-64,z3.BitVecVal(0xffffffc0,32))))
 v=run('wrapped_pad',0x100ac0fe8,0x100ac1038,[('w8',0x3b),('x4',C)],[(C+0x44,4,H)]);assert len(v.stores)==1;off=z3.ZeroExt(32,H&63);add('all_u32_wrapped_first_padding_byte_and_gate',z3.Or(v.stores[0]['address']!=C+off,v.stores[0]['value']!=0x18,v.read('w13')!=(H&63)+1,v.read('w8')!=z3.If(z3.UGT(H&63,55),z3.BitVecVal(0xbfc2,32),z3.BitVecVal(0x3b,32))))
 v=run('inline_pad',0x100bb2284,0x100bb22dc,[('sp',F),('w8',0x18),('x4',C),('x10',O)],[(C+0x44,4,H)]);assert len(v.stores)==3;add('all_u32_inline_first_padding_byte_and_gate',z3.Or(cell(v,F+0x2f40,8)!=C,cell(v,F+0x2fe0,8)!=O,v.stores[-1]['address']!=C+off,v.stores[-1]['value']!=0x18,v.read('w15')!=0x471c,v.read('w12')!=(H&63)+1,v.read('w8')!=z3.If(z3.UGT(H&63,55),z3.BitVecVal(0xbe37,32),z3.BitVecVal(0x18,32))))
 v=run('identity_reservation',0x100baff8c,0x100baffb8,[('sp',F)],[(F+0x3238,8,C),(F+0x3620,8,Q),(F+0x2f00,8,A)]);add('all_u64_identity_output_reservation32',z3.Or(cell(v,F+0x3610,8)!=C,cell(v,F+0x31a8,8)!=F+0x39f0+Q,cell(v,F+0x3620,8)!=Q+32,cell(v,F+0x32e8,8)!=A))
 v=run('inline_return',0x100bd9ba0,0x100bd9ba8,[('sp',F)],[(F+0x2ea8,8,R)]);add('all_u64_encoded_update_saved_continuation',z3.Or(v.read('x8')!=R,v.read('x17')!=0xe0d4))
 v=run('post_finalize',0x100a0e340,0x100a0e3d4,[('sp',F),('w13',0x471c)],[(F+0x31c8,8,O),(F+0x3648,8,A),(F+0x35a8,8,B)]);good=z3.And(A!=0,B!=0,O!=0);add('all_u64_post_finalize_saved_fields_and_three_value_gate',z3.Or(cell(v,F+0x37e8,8)!=A+0x2bef09d10e3bdd6e,cell(v,F+0x37f8,8)!=B,cell(v,F+0x3800,8)!=O,cell(v,F+0x3810,8)!=A+0x63604e5d3cff75db,cell(v,F+0x37f0,8)!=B,v.read('w8')!=z3.If(good,z3.BitVecVal(0x3c2d,32),z3.BitVecVal(0x3bff,32))))
 v=run('malloc1028',0x100bb030c,0x100bb0314);add('source_post_finalize_malloc1028_argument',z3.Or(v.read('x0')!=1028,v.read('x17')!=0x6aa4))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_digest_conventions_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_digest_conventions_{n}_original.smt2';b=ROOT/f'daemon_digest_conventions_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(json.dumps({'proof':n,'result':answer}),flush=True)
 deps=['daemon_digest_conventions_contracts.json','prove_daemon_digest_routes.py','prove_daemon_object_initialization.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_digest_conventions_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
