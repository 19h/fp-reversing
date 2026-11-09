#!/usr/bin/env python3
"""Source-only record, metadata, displacement and conditional publication proofs.

Distinct symbolic cells; source-key lemmas qualify shared-key decoding.
Publication proofs are local and assume restored frame/cells, not native
successful processing. O(I) DAG lift, solver-dependent cost, 30 s/call.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_response_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_response_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_response_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_response_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_response_symbolic.py','lskd_response_contracts.json']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Inner fields use an abstract key basis after source encoder/decoder agreement. Publication status/store proofs assume the source frame cells at publication; native successful return/frame preservation are not proved.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'positive_publication_executed':False,'business_request_operation_executed':False,'full_goal_complete':False};(ROOT/'lskd_response_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
