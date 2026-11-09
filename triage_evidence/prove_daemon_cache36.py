#!/usr/bin/env python3
"""Source-local query arguments, publication, conversion and varargs proofs.
O(lifted instructions+solver resources) time/space; 30 s/query. Fixed phase,
valid owner/frame and library-result premises; no native calls or PAC proof.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha,span
from prove_daemon_object_initialization import InitLift
from lskd_values_symbolic import part,mem,cell
def obligations(c):
 F=0x6800050000;A,B,C,D,E,R,Q=z3.BitVecs('cache36_A64 cache36_B64 cache36_C64 cache36_D64 cache36_E64 cache36_return64 cache36_cursor64',64);W=z3.BitVec('cache36_W0',32);qs=[];counts={}
 def run(n,a,z,seeds=(),memory=()):
  v=InitLift(part(c,n,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,nb,x in memory:mem(v,at,nb,x)
  v.run(n);counts[n]=v.count;return v
 def add(n,p):qs.append((n,p))
 v=run('publication',0x1009c014c,0x1009c0158,[('sp',F),('x20',0x1010c6840),('x0',R)],[(F+0x29a0,8,TABLE)]);add('all_u64_publication_before_null_gate',z3.Or(cell(v,0x1010c6840,8)!=R,cell(v,F+0x21d0,8)!=0x1010c6840))
 for name,a,z,key in [('serial',0x100bab20c,0x100bab21c,0x1010b1af8),('wifi',0x100c9940c,0x100c9941c,0x1010b1ab8),('bluetooth',0x100a42434,0x100a42444,0x1010b1a38),('chip',0x100b2c140,0x100b2c150,0x1010b1b38)]:
  v=run(name,a,z);add(name+'_source_query_arguments',z3.Or(v.read('x0')!=key,v.read('x1')!=0,v.read('x17')!=0x8e26))
 v=run('number_arguments',0x1009ba800,0x1009ba810,[('sp',F)]);add('source_signed64_output_argument',z3.Or(v.read('x2')!=F+0x2b70,v.read('x1')!=4,v.read('x17')!=0x8642))
 v=run('number_gate',0x1009ba818,0x1009ba838,[('w0',W),('w20',0xab4e),('w19',0x471c),('w25',0x8f46)]);add('all_W0_nonzero_conversion_gate',v.read('w8')!=z3.If(W==0,z3.BitVecVal(0x8f46,32),z3.BitVecVal(0x8f4b,32)))
 v=run('chip_vararg',0x1009b42ac,0x1009b42b0,[('sp',F)],[(F+0x2b70,8,R)]);v.c={'spans':[span('chip_stack',0x1009b42c0,0x1009b42d4)]};v.run('chip_stack');counts['chip_vararg']=v.count;add('all_u64_chip_stack_and_format_arguments',z3.Or(cell(v,F,8)!=R,v.read('x2')!=0x1010b1b18,v.read('x1')!=0,v.read('x17')!=0xfe9e))
 v=run('identity_varargs',0x100ad6fa8,0x100ad6fcc,[('sp',F),('x21',A),('x27',B),('x0',C),('x22',D),('x23',E),('x30',TABLE)]);add('all_u64_identity_five_argument_order',z3.Or(*[cell(v,F+8*j,8)!=x for j,x in enumerate([A,B,C,D,E])],v.read('x0')!=0,v.read('x1')!=0,v.read('x2')!=0x1010b1a98,v.read('x17')!=0xfe9e))
 v=run('producer1',0x1007cfa64,0x1007cfa94,[('sp',F)],[(F+0x16d0,8,Q)]);add('all_u64_frame_producer1',z3.Or(cell(v,F+0x3050,8)!=F+0xc070+Q,cell(v,F+0x3300,8)!=F+0xc4f0+Q))
 v=run('failure_fields',0x100bb15d0,0x100bb1620,[('sp',F)],[(F+0x3050,8,R),(F+0x33c8,8,A),(F+0x3108,8,B),(F+0x2da8,8,C),(F+0x34b8,8,D),(F+0x2c28,8,E)]);add('all_u64_failure_base_derived_fields',z3.Or(*[cell(v,F+off,8)!=R+delta for off,delta in [(0x2a68,0x32c),(0x2a48,0x11c),(0x2a40,0x20f),(0x2a30,0),(0x2a38,0xe4)]]))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_cache36_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for n,p in qs:
  a=ROOT/f'daemon_cache36_{n}_original.smt2';b=ROOT/f'daemon_cache36_{n}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());assert answer=='unsat',(n,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':n,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(json.dumps({'proof':n,'result':answer}),flush=True)
 deps=['daemon_cache36_contracts.json','prove_daemon_object_initialization.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_cache36_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
