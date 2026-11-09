#!/usr/bin/env python3
"""Solve original-source version-fallback BV obligations; no native execution."""
import hashlib,json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from daemon_query_fallback_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_query_fallback_contracts.json').read_text());qs,lifts=queries(c);rows=[]
 for name,q in qs:
  s=z3.Solver();s.add(q);op=ROOT/f'daemon_query_fallback_{name}_original.smt2';op.write_text(s.to_smt2());p=ROOT/f'daemon_query_fallback_{name}.smt2';s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(name,result,str(s.model())if result=='sat'else'');p.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':p.name,'sha256':sha(p),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_query_fallback_symbolic.py','daemon_query_fallback_contracts.json','lskd_values_symbolic.py']},'source_lift_counts':lifts,'proofs':rows,'z3_version':z3.get_version_string(),'composition_premises':'QS1-QS12; source-prepared16B input with initially unknown result at+0x10; exact cached byte encodings and source-dispatch slots. Decision source phases compose through those slots. Normal return requires unchanged private guard. Native entry/query values/concurrency/PAC unknown.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
