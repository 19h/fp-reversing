#!/usr/bin/env python3
"""Source-derived field codecs, scalar bytes and variable compact headers.

Shared outer/generic key lemmas qualify compositional proofs. Fixed symbolic
cells are distinct; pointer aliases/native validity/crypto/IPC are not proved.
O(I) DAG lifting, solver-dependent cost; each solver is bounded at 30 s.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_fields_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_fields_contracts.json').read_text());tlv=json.loads((ROOT/'legacy_tlv_contracts.json').read_text());qs,counts=queries(c,tlv);rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_fields_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_fields_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_fields_symbolic.py','lskd_fields_contracts.json','legacy_tlv_contracts.json']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Span/u32 decoded fields use shared abstract outer keys after separate source-key equalities; generic inner key, selector/length/tag, payload bytes, variable header/counter properties are separately proved. Distinct symbolic cells; no arbitrary alias or whole-program proof.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_fields_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
