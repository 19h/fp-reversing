#!/usr/bin/env python3
"""Source-local lifecycle gate, partial-store epoch and pointer/status identities.
Linear instruction lifting; each solver query has a 30 s limit. Theorems are
conditional on declared memory/phase/normal execution, not native reachability.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from prove_daemon_descriptor_producers import ProducerLift,sha
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
 qs=[];counts={};F,R,L,B,D,T=z3.BitVecs('life_frame64 life_record64 life_lock64 life_base64 life_data64 life_table64',64);S,N,I=z3.BitVecs('life_status32 life_count32 life_index32',32)
 def run(n,a,z,seeds=(),memory=()):
  v=ProducerLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
 e=run('epoch',0x10097290c,0x100972918,[('w21',0x447c),('sp',F)],[(F+0x2a70,8,D)]);assert len(e.stores)==1 and e.stores[0]['size_bytes']==4;add('mode_low_word_store',z3.Or(cell(e,F+0x2a70,4)!=0x471c,e.stores[0]['address']!=F+0x2a70))
 lazy=run('lazy',0x10064ffbc,0x10064fff8,[('w8',0x471c),('w22',0x40c7),('sp',F),('x30',T)],[(T+0x40c7*8,8,0x100c02f3c),(F+0x26c0,8,R),(R,8,L)]);add('all_lock_values_lazy_creation_gate',z3.Or(lazy.read('w20')!=0x40c7,lazy.read('w21')!=0x447c,lazy.read('w8')!=z3.If(L==0,z3.BitVecVal(0x443f,32),z3.BitVecVal(0x447c,32))))
 gate=run('after_creator',0x1009729e8,0x100972a18,[('w8',S),('w20',0x40c7),('w21',0x447c),('sp',F),('x27',R)],[(F+0x2a70,4,0x471c),(R,8,L)]);add('all_status_lock_values_creation_gate',gate.read('w8')!=z3.If(z3.And(S==0x8b3dc651,L!=0),z3.BitVecVal(0x447c,32),z3.BitVecVal(0x51d7,32)))
 a=run('acquire_key',0x100933c30,0x100933c6c,[('x29',R+0xb0)]);add('aligned8_acquire_record_key',a.read('w10')!=(resize(R,32)^0x987eac8a)*0x316f29c1,R&7==0)
 cleanup=run('cleanup_pack',0x100a20470,0x100a204c0,[('w20',0x471c),('x22',R),('w23',0x3ad05202),('x9',L),('sp',F)]);kc=(resize(R,32)^0xeaae0ac9)*0x7398180b;add('cleanup_record_layout_and_key',z3.Or(cell(cleanup,F+0xde90,8)!=L,cell(cleanup,F+0xde98,4)!=0xa293-kc))
 key=z3.BitVec('life_acquire_key32',32);pack=run('acquire_pack',0x100933c6c,0x100933c84,[('w8',0x1876),('w20',0x40c7),('w10',key),('sp',F),('x9',L)]);add('acquire_record_layout',z3.Or(cell(pack,F+0xde90,4)!=(0x593d^key),cell(pack,F+0xde98,8)!=L))
 body=run('field_gate',0x100b353a4,0x100b353ec,[('w15',0x471c),('sp',F)],[(F+0x3630,8,D),(F+0x24a8,8,R),(R,4,N)]);add('all_u32_field_presence_gate',z3.Or(body.read('x13')!=D,body.read('w12')!=0x41e9,body.read('w8')!=z3.If(N==0,z3.BitVecVal(0x8210,32),z3.BitVecVal(0x821b,32)),cell(body,F+0x326c,4)!=0x8b3dc651))
 zero=run('zero_field',0x1009df7ac,0x1009df7e0,[('sp',F),('w8',S)],[(F+0x26b0,8,R),(R,8,B),(F+0x368c,4,I)]);E=z3.BitVecVal(0x8b3dc651,32);st=z3.If(S==E,z3.If(B==0,z3.BitVecVal(0x74c29f34,32),E),S);ptr=z3.If(S==E,B+(z3.ZeroExt(32,I)<<5),z3.BitVecVal(0,64));add('all_base_index_status_zero_handler',z3.Or(zero.read('w10')!=st,zero.read('x8')!=ptr))
 result=run('result',0x10095f074,0x10095f078,[('x0',R),('w23',S)]);add('all_u32_result_store',cell(result,R+16,4)!=S)
 add('raw_body_status_XOR_interpretation',z3.BitVecVal(0x74c29f00^0x8b3dc651,32)!=z3.BitVecVal(-42671,32))
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_mode471c_lifecycle_contracts.json').read_text());qs,counts=obligations(c);rows=[];w=[]
 for name,p in qs:
  original=ROOT/f'daemon_mode471c_lifecycle_{name}_original.smt2';simple=ROOT/f'daemon_mode471c_lifecycle_{name}.smt2';s=z3.Solver();s.add(p);original.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');simple.write_text(s.to_smt2());rows.append({'name':name,'original_file':original.name,'original_sha256':sha(original),'file':simple.name,'sha256':sha(simple),'result':answer})
  if name=='aligned8_acquire_record_key':s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';w.append({'proof':name,'premise':'sat','model':str(s.model())})
 deps=['daemon_mode471c_lifecycle_contracts.json','prove_daemon_descriptor_producers.py','prove_daemon_callback_revisit.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':w,'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_mode471c_lifecycle_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
