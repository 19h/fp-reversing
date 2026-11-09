#!/usr/bin/env python3
"""Source-derived workspace fields, selector, first state and status identity.

Fixed distinct symbolic cells and nonwrapping range premise; no allocator,
pointer validity, whole-program, native operation, crypto or IPC proof.
O(I) DAG lift, solver-dependent cost, 30 s per solver.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_execute_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_execute_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_execute_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_execute_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_execute_symbolic.py','lskd_execute_contracts.json']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Decoded field proof uses a shared abstract workspace key after source encoder/decoder equality and record encoding are separately proved. Distinct fixed symbolic cells; nonwrapping range premise is explicit.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_execute_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
