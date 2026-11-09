#!/usr/bin/env python3
"""Pin and solve bounded original-source lookup obligations; no target execution."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from daemon_iokit_census_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_iokit_census_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  orig=z3.Solver();orig.add(q);op=ROOT/f'daemon_iokit_census_{name}_original.smt2';op.write_text(orig.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(name,result,str(s.model())if result=='sat'else'');p=ROOT/f'daemon_iokit_census_{name}.smt2';p.write_text(s.to_smt2());rows.append({'name':name,'file':p.name,'sha256':sha(p),'original_file':op.name,'original_sha256':sha(op),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_iokit_census_symbolic.py','daemon_iokit_census_contracts.json','lskd_values_symbolic.py']},'source_lift_counts':counts,'proofs':rows,'composition_premises':'Source entry W21=9376,X24=101039ef0 and declared shared-frame pointer cells. API results and size_t values are independent symbols; query phases and zero fallback are source-derived. Kext publication is source-local under a returning provider and valid output pointer. Native open, actual provider values, PAC, ports and transport are unproved.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
