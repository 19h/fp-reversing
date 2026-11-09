#!/usr/bin/env python3
"""Pin and solve bounded original-source lookup obligations; no target execution."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_input_buffers_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_input_buffers_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  orig=z3.Solver();orig.add(q);op=ROOT/f'lskd_input_buffers_{name}_original.smt2';op.write_text(orig.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(name,result,str(s.model())if result=='sat'else'');p=ROOT/f'lskd_input_buffers_{name}.smt2';p.write_text(s.to_smt2());rows.append({'name':name,'file':p.name,'sha256':sha(p),'original_file':op.name,'original_sha256':sha(op),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_input_buffers_symbolic.py','lskd_input_buffers_contracts.json','lskd_values_symbolic.py']},'source_lift_counts':counts,'proofs':rows,'composition_premises':'Fixed distinct source frame/region cells; explicit nonnull data-allocation returns and source phase registers. Post-entropy stores/alignment require normal entropy return and preserved callee-saved GP registers; they are source-local proofs, not executed continuations. Native chunk arguments use independent symbolic runtime context/callback/thread values; no entropy or native registration executes.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_input_buffers_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
