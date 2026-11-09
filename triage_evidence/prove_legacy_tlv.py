#!/usr/bin/env python3
"""Fresh source-derived local TLV/key/serialization/counter refutations.

Original and normalized SMT retained; source lift O(I), solver-dependent time.
No target/API/crypto operation executes. Does not prove native admissibility.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from legacy_tlv_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'legacy_tlv_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'legacy_tlv_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(name,result);path=ROOT/f'legacy_tlv_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['legacy_tlv_symbolic.py','legacy_tlv_contracts.json']},'proofs':rows,'source_lift_counts':counts,'normalization':'z3.simplify before solving and normalized serialization; original source-derived formula also retained','z3_version':z3.get_version_string(),'native_admissibility_proved':False,'full_goal_complete':False};(ROOT/'legacy_tlv_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
