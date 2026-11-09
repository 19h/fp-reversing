#!/usr/bin/env python3
"""Four local attribute/header/candidate-state bit-vector checks.

Solver-dependent complexity; no native entry/lifetime/heap validity proof.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def flags(a):return z3.If(a&0x10000==0,z3.BitVecVal(2,32),z3.BitVecVal(0,32))|z3.If(a&0x20000==0,z3.BitVecVal(0x40,32),z3.BitVecVal(0,32))
def main():
 a,b,s=z3.BitVecs('attribute32 alternate_attribute32 candidate_state32',32);f=flags(a);ix=s^(((s+0xa0)^0xb025e4d5)+0x4fda12ff)
 probes=[('flag_domain',z3.Not(z3.Or(*[f==v for v in[0,2,0x40,0x42]]))),('irrelevant_attribute_bits',(f==flags(b))!=(((a^b)&0x30000)==0)),('new_header_free_tests',z3.Or(((f<<16)&0xcffff)!=0,(f<<16)==0xdddddead)),('store_candidate_state_set',z3.And(z3.ULT(s,2648),(ix==0x8b4)!=((s&0xfffffe61)==0x860)))];rows=[]
 for name,q in probes:
  solver=z3.Solver();solver.add(q);result=str(solver.check());assert result=='unsat',(name,result);p=ROOT/f'rw_lifecycle_{name}.smt2';p.write_text(solver.to_smt2());rows.append({'name':name,'file':p.name,'sha256':sha(p),'result':result})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'rw_lifecycle_contracts.json'),'proofs':rows,'z3_version':z3.get_version_string(),'native_target_executed':False,'cached_cell_publication_proved':False,'full_goal_complete':False};(ROOT/'rw_lifecycle_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
