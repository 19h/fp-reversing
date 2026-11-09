#!/usr/bin/env python3
"""Two local bit-vector getter identities, conditional on recorded source lift.

Proves value selection/noninterference only, not constructor reachability or
native memory validity. SMT time is solver-dependent; finite fixed word sizes.
"""
import hashlib,json
from pathlib import Path
import z3
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 f,g=z3.BitVecs('flag8 other_flag8',8);t,u=z3.BitVecs('type32 other_type32',32);d,p=z3.BitVecs('direct64 indirect64',64);zero=z3.BitVecVal(0,64)
 def lifted(a,b):return z3.If(z3.Extract(6,6,a)==1,zero,z3.If((b&0xf0)==0x20,d,p))
 compact=z3.If((f&0x40)!=0,zero,z3.If(z3.Extract(7,4,t)==2,d,p))
 queries=[('getter_selection',lifted(f,t)!=compact),('getter_ignored_bits',z3.And(((f^g)&0x40)==0,((t^u)&0xf0)==0,lifted(f,t)!=lifted(g,u)))];rows=[]
 for name,bad in queries:
  s=z3.Solver();s.set(timeout=30000);s.add(bad);result=str(s.check());assert result=='unsat',result;path=ROOT/('kext_buffer_'+name+'.smt2');path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'result':result,'scope':'Original getter local word semantics only; no native validity or complete initialization proof.'})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'kext_buffer_contracts.json'),'solver_version':z3.get_version_string(),'proofs':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_buffer_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
