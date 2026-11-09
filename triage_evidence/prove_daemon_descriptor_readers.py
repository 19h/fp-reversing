#!/usr/bin/env python3
"""Full-width source-lift identities for conditional descriptor-reader contracts.
O(source instructions) expression time/space, solver limited to 30 s/query.
Original and simplified counterexample queries are saved; neither supplies
native incoming phases, bank provenance, PAC success nor API implementation.
"""
import json,hashlib
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,POOL,qword
from prove_daemon_callback_revisit import CallbackLift
from lskd_values_symbolic import part,mem,cell,resize
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def obligations(c):
 qs=[];counts={};R,F,P,B,A,z=z3.BitVecs('reader_record64 reader_SP64 reader_pointer64 reader_other64 reader_rootA64 reader_rootB64',64);S,N,V24,V26,U=z3.BitVecs('reader_phase32 reader_count32 reader_saved24_32 reader_saved26_32 reader_phase23_32',32);G=0x1010c8218;K=(resize(R,32)^0x987eac8a)*0x316f29c1;KC=(resize(R,32)^0xeaae0ac9)*0x7398180b
 def run(name,a,end,seeds=(),memory=()):
  v=CallbackLift(part(c,name,a,end))
  for reg,val in seeds:v.seed(reg,val)
  for at,n,val in memory:mem(v,at,n,val)
  v.run(name);counts[name]=v.count;return v
 def add(name,p,premise=z3.BoolVal(True)):qs.append((name,z3.And(premise,p)))
 pre=run('acquire_caller_prekey',0x10021ed5c,0x10021ed90,[('x29',R+0x100),('x20',G)],[(G,8,P)]);add('all_u32_caller_prekey_and_capture',z3.Or(pre.read('w8')!=(resize(R,32)^0x987eac8a),pre.read('x9')!=P))
 pack=run('acquire_caller_pack',0x10021ed90,0x10021edb0,[('x29',R+0x100),('w8',resize(R,32)^0x987eac8a),('x9',P),('w25',S)]);add('all_phase_acquire_pointer_and_encoded_control',z3.Or(cell(pack,R+8,8)!=P,cell(pack,R,4)!=((S+0x1574)^K)))
 helper=run('acquire_callee_key',0x10043e3ac,0x10043e3d4,[('x0',R)]);add('aligned8_acquire_key_agreement',helper.read('w11')!=(resize(R,32)^0x987eac8a),R&7==0)
 multiply=run('acquire_callee_multiply',0x10043e3d4,0x10043e3e0,[('w11',resize(R,32)^0x987eac8a)]);add('all_u32_callee_key_multiplication',multiply.read('w11')!=K)
 unpack=run('acquire_callee_unpack',0x10043e3e0,0x10043e3ec,[('x0',R),('w11',K)],[(R,4,(S+0x1574)^K),(R+8,8,P)]);add('all_phase_acquire_control_and_pointer_decode',z3.Or(unpack.read('w26')!=S+0x1574,unpack.read('x19')!=P));add('selected_phase_acquire_control',S+0x1574!=0x593d,S==0x43c9)
 p24=run('phase24',0x10021ecf4,0x10021ed04,[('w25',S)]);add('all_phase_saved24',p24.read('w24')!=((S-0x3f20)|0x7a06))
 p26=run('phase26',0x10021edf4,0x10021ee04,[('w25',S)]);add('all_phase_saved26',p26.read('w26')!=((S-0x4307)|0x8400))
 gate=run('count_gate',0x10021ee1c,0x10021ee44,[('x20',G),('w25',S),('w24',V24),('w26',V26)],[(G+8,4,N)]);expected=S^z3.If(N==0,V26+V24+0xfffefc94,z3.BitVecVal(0,32));add('all_u32_count_and_phase_index',gate.read('w9')!=expected);add('selected_count_zero_and_nonzero_indices',gate.read('w9')!=z3.If(N==0,z3.BitVecVal(0x43cc,32),z3.BitVecVal(0x43c9,32)),z3.And(S==0x43c9,V24==0x7eaf,V26==0x84c2))
 clean=run('cleanup_pack',0x10025c4e0,0x10025c518,[('x20',G),('x29',R+0x100),('w26',V26)],[(G,8,P)]);add('all_pointer_cleanup_fresh_capture_and_control',z3.Or(cell(clean,R,8)!=P,cell(clean,R+8,4)!=V26+0x1dd1-KC,clean.read('w24')!=V26+0x23a9))
 prefix=run('nonzero_prefix',0x10025f0bc,0x10025f0f0,[('x20',G),('w24',0x7eaf),('w9',0x2db65945),('w23',U)],[(G+16,8,P)]);add('all_phase23_nonzero_pointer_and_next_index',z3.Or(prefix.read('x12')!=P,prefix.read('w13')!=0,prefix.read('w10')!=((125*U)^0x7eaf)))
 b=run('guard_parity',0x100a636ec,0x100a63708,[('w24',S)]);add('all_phase_guard_parity',b.read('w8')&1!=S&1)
 bg=run('guard_pointer_index',0x100a63764,0x100a63790,[('x21',G),('w24',S),('w8',b.read('w8')),('w9',0xffffb391)],[(G+16,8,P)]);flag=(S&1)^z3.If(P==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32));add('all_u32_phase_u64_pointer_guard_index',bg.read('w9')!=((S-0x4c6f)^(flag*(S-0x8a85))))
 stack=run('entry_B_stack',0x100a59be8,0x100a59bf0,[('sp',F)]);add('all_u64_stack_reservation_modulo',stack.read('sp')!=F-57072)
 cursor=run('entry_B_cursor',0x100a59d0c,0x100a59d18,[('x1',R)],[(R,8,P)]);add('all_u64_cursor_increment_modulo',cell(cursor,R,8)!=P+160)
 roots=run('root_bank_constants',0x100387df0,0x100387e40,[('x26',POOL),('sp',F)],[(a,8,qword(a))for a in [0x1010a7ae8,0x1010a4990,0x1010a4328,0x1010a6578]]);add('root_publication_values',z3.Or(*[cell(roots,F+off,8)!=val for off,val in [(0xb00,0x100e99700),(0xb08,0x100f4e190),(0xb60,0x100fc4130),(0xb68,0x101031ea0)]]))
 params=run('root_bank_parameters',0x100387e68,0x100387e70,[('sp',F),('x22',A),('x24',z)]);add('all_u64_root_parameter_publications',z3.Or(cell(params,F+0xb30,8)!=A,cell(params,F+0xb38,8)!=z))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_descriptor_readers_contracts.json').read_text());qs,counts=obligations(c);rows=[];witnesses=[]
 for name,p in qs:
  op=ROOT/f'daemon_descriptor_readers_{name}_original.smt2';sp=ROOT/f'daemon_descriptor_readers_{name}.smt2';s=z3.Solver();s.add(p);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,s.model()if answer=='sat'else'');sp.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':sp.name,'sha256':sha(sp),'result':answer})
  if name in ['aligned8_acquire_key_agreement','selected_phase_acquire_control','selected_count_zero_and_nonzero_indices']:s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':name,'premise_result':'sat','model':str(s.model())})
 deps=['daemon_descriptor_readers_contracts.json','prove_daemon_callback_revisit.py','daemon_callback_simd.py','daemon_global_state_lift.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'composition_cuts':[{'pc':'0x10021ed90','input':'W8=low32(R)^0x987eac8a; X9=captured pointer','producer_obligation':'all_u32_caller_prekey_and_capture'},{'pc':'0x10043e3d4','input':'W11=low32(R)^0x987eac8a under R&7==0','producer_obligation':'aligned8_acquire_key_agreement'},{'pc':'0x10043e3e0','input':'W11=K=(low32(R)^0x987eac8a)*0x316f29c1','producer_obligation':'all_u32_callee_key_multiplication'}],'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_readers_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
