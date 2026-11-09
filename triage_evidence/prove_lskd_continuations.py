#!/usr/bin/env python3
"""Source lock gates, encoded continuation fields and conditional cache clear proofs.

Explicit source phases and distinct fixed symbolic cells. O(I) DAG lift,
solver-dependent cost, 30 s/query. These are local readback lemmas; this
producer executes no target."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_continuations_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_continuations_contracts.json').read_text());qs,counts=queries(c,json.loads((ROOT/'lskd_readback_contracts.json').read_text()));rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_continuations_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_continuations_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_continuations_symbolic.py','lskd_continuations_contracts.json','lskd_readback_contracts.json','lskd_values_symbolic.py']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Fixed distinct cells, source selector phases2d2/1d3/52f/72d/8ac and bank-derived global pointer roots. Source controller bank code skipped between named phases is independently resolved. Caller/receiver composition substitutes each canonical address-key basis only after its separate original-source all-address identity. The free clear lemma requires returning from the unexecuted free call. No native synchronization/lifetime proof.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'proof_generator_executed_target':False,'full_goal_complete':False};(ROOT/'lskd_continuations_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
