#!/usr/bin/env python3
"""Source proofs for UTF-8 arguments, capacity, context, state and frame roots.
O(lifted instructions+solver resources) time/space, 30 s/query. Native frame,
CF results, owner/lifetime and initial helper state remain explicit premises.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from recover_daemon_object_creation import sha,span
from prove_daemon_object_initialization import InitLift
from lskd_values_symbolic import part,mem,cell
def obligations(c):
 F=0x6800050000;O=F+0x3c70;A,B,R,S,G=z3.BitVecs('identity_A64 identity_B64 identity_return64 identity_state64 identity_global64',64);qs=[];counts={}
 def run(n,a,z,seeds=(),memory=()):
  v=InitLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p):qs.append((n,p))
 v=run('encoding',0x100bab0c4,0x100bab0d0);add('source_UTF8_maximum_arguments',z3.Or(v.read('x1')!=0x08000100,v.read('x17')!=0xf08f))
 v=run('capacity',0x100bab100,0x100bab104,[('x0',R)]);add('all_u64_capacity_plus_one',v.read('x24')!=R+1)
 v=run('malloc_arguments',0x100bab114,0x100bab11c,[('x24',A)]);add('all_u64_malloc_capacity_forward',z3.Or(v.read('x0')!=A,v.read('x17')!=0x6aa4))
 v=run('saved_buffer',0x100bab120,0x100bab124,[('sp',F),('x0',R)]);add('all_u64_saved_temporary_buffer',cell(v,F+0x3308,8)!=R)
 v=run('cstring_arguments',0x100b90f60,0x100b90f78,[('x28',R),('x21',A),('x24',B)]);add('all_u64_CString_arguments',z3.Or(v.read('x0')!=R,v.read('x1')!=A,v.read('x2')!=B,v.read('x3')!=0x08000100,v.read('x17')!=0x7208))
 v=run('context_init',0x1009153b0,0x1009153f4,[('x25',O)]);encoded=[0x93bc0ef6,0x1b34867e,0x6c43f109,0xe4cb7981,0x372bcc07];add('source_100byte_SHA1_context_fields',z3.Or(cell(v,O+0x40,8)!=0,*[cell(v,O+0x48+4*j,4)!=w for j,w in enumerate(encoded)],cell(v,O+0x5c,4)!=20,cell(v,O+0x60,4)!=2))
 v=run('encoded_byte_count',0x10091545c,0x1009154d8,[('x0',R),('w19',0x9930)]);add('all_u64_strlen_low32_encoded_count',v.read('x5')!=z3.ZeroExt(32,z3.Extract(31,0,R)+0x1ad72f12))
 v=run('copy_byte_codec',0x10095eb08,0x10095eb18,[('x1',R)]);add('all_low8_input_byte_XOR98',z3.Extract(7,0,v.read('x1'))!=(z3.Extract(7,0,R)^0x98))
 v=run('helper_state',0x100440bf0,0x100440c34,[('sp',F-16),('x8',0x1010b6000),('x9',S)],[(0x1010c4670,8,G)]);T=(z3.BitVecVal(F-8,64)^S)^G;K=0x0a5cd4cf;C=0x73d046208eaed1a6;add('all_u64_helper_global_updates',z3.Or(cell(v,0x1010b69d0,8)!=((T*K)^C),cell(v,0x1010c4670,8)!=((T^C)*K)))
 v=run('root_producer1',0x1005f51c4,0x1005f51cc,[('sp',F),('x28',A)]);add('all_u64_SP2E50_writer1',cell(v,F+0x2e50,8)!=A+256)
 v=run('root_producer2',0x100926ea4,0x100926ea8,[('sp',F),('x4',R)]);add('all_u64_SP2E50_writer2',cell(v,F+0x2e50,8)!=R)
 v=run('frame_writer32',0x100aee3b8,0x100aee3bc,[('sp',F),('x2',R)]);add('all_u64_SP2C8C_writer_low32',cell(v,F+0x2c8c,4)!=z3.Extract(31,0,R))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_identity_cache_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_identity_cache_{n}_original.smt2';b=ROOT/f'daemon_identity_cache_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(json.dumps({'proof':n,'result':answer}),flush=True)
 deps=['daemon_identity_cache_contracts.json','prove_daemon_object_initialization.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_identity_cache_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
