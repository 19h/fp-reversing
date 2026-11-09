#!/usr/bin/env python3
"""Local source cache gates, prospective lookup schemas and saved stop status.

Explicit source phases and distinct fixed symbolic cells. O(I) DAG lift,
solver-dependent cost, 30 s/query. These are local readback lemmas; this
producer executes no target."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_state_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_state_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_state_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_state_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_state_symbolic.py','lskd_state_contracts.json','lskd_values_symbolic.py']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Fixed distinct cells and source phases W23=72d,W28=8ac,W9=3f0. Prospective lookup layouts assume declared saved masked-context and table-pointer cells; no native hot-path reachability or table initialization is proved. Saved stop return assumes X19 preserves the wrapper status across cleanup.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'proof_generator_executed_target':False,'full_goal_complete':False};(ROOT/'lskd_state_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
