#!/usr/bin/env python3
"""Solve original caller/callee record and result-consumer obligations."""
import hashlib,json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from daemon_iokit_callers_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_iokit_callers_contracts.json').read_text());sync=json.loads((ROOT/'daemon_iokit_sync_contracts.json').read_text());qs,lifts=queries(c,sync);rows=[];lemma_deps={'caller313_unique_init_phase':['caller313_selector_decode'],'callerAF_unique_init_phase':['callerAF_selector_decode']}
 for name,q in qs:
  s=z3.Solver();s.add(q);op=ROOT/f'daemon_iokit_callers_{name}_original.smt2';op.write_text(s.to_smt2());np=ROOT/f'daemon_iokit_callers_{name}.smt2';s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(name,result,str(s.model())if result=='sat'else'');np.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result,'depends_on':lemma_deps.get(name,[])});print(json.dumps({'proof':name,'result':result}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['daemon_iokit_callers_symbolic.py','daemon_iokit_callers_contracts.json','daemon_iokit_sync_contracts.json','daemon_iokit_sync_symbolic.py','daemon_iokit_class_symbolic.py','daemon_query_fallback_symbolic.py','daemon_query_state_symbolic.py','lskd_values_symbolic.py']},'source_lift_counts':lifts,'proofs':rows,'z3_version':z3.get_version_string(),'composition_premises':'Declared caller roots/table/controller/saved-stack fields,8-byte record alignment and source-fixed phase preimages. Native upstream context,authentication and complete caller graph unknown.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_callers_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
