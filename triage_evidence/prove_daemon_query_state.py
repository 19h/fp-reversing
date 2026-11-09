#!/usr/bin/env python3
"""Solve original-source query-state BV obligations; no native execution."""
import hashlib,json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from daemon_query_state_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_query_state_contracts.json').read_text());qs,lifts=queries(c);rows=[]
 for name,q in qs:
  s=z3.Solver();s.add(q);op=ROOT/f'daemon_query_state_{name}_original.smt2';op.write_text(s.to_smt2());p=ROOT/f'daemon_query_state_{name}.smt2';s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(name,result,str(s.model())if result=='sat'else'');p.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':p.name,'sha256':sha(p),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_query_state_symbolic.py','daemon_query_state_contracts.json','lskd_values_symbolic.py']},'source_lift_counts':lifts,'proofs':rows,'z3_version':z3.get_version_string(),'composition_premises':'Fixed source phase W20=4ef4; shared original frame and record aliases; exhaustive bank/slot targets; record preserved across controller/root instructions. State-cache claims end before fallback body. Normal return marker requires helper return. Full native entry, query values and PAC unknown.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_query_state_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
