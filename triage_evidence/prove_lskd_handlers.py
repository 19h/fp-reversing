#!/usr/bin/env python3
"""Source-derived handler codecs, query initializer and lookup word proofs.

Explicit source-entry bindings, distinct cells and the R=B+0x28 relationship.
Key identity lemmas qualify single-register abstractions in composition proofs.
O(I) DAG lift; solver-dependent cost with a 30 s/query timeout."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_handlers_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_handlers_contracts.json').read_text());qs,counts=queries(c,json.loads((ROOT/'lskd_handlers_profiles.json').read_text()),json.loads((ROOT/'lskd_request_contracts.json').read_text()));rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_handlers_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_handlers_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_handlers_symbolic.py','lskd_handlers_contracts.json','lskd_handlers_profiles.json','lskd_request_contracts.json']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Handler record identities assume retained source-entry bindings and R=B+0x28 for the dual-base AVD writes. Each single-register key abstraction has a separate checked source-identity lemma: query key at a51bf88/w10; scalar keys at a52f158/w17 and a52f1b0/w2; span keys at a549d00/w16 and a549d50/w0; generic low32 key at a52ef74/x10. Initializer field composition also assumes its source phase w9=0x34b. Arbitrary record bases, cursor words and wire headers are symbolic; cells are distinct. Native validity, complete handler behavior, arbitrary aliasing and malformed-stream safety are not proved.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'positive_publication_executed':False,'complete_business_handler_executed':False,'full_goal_complete':False};(ROOT/'lskd_handlers_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
