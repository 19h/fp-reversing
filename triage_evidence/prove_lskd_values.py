#!/usr/bin/env python3
"""Source u64 consumption, status channels, query append and publication proofs.

Explicit source phases and distinct fixed symbolic cells. The query appender
uses a checked caller/decoder key lemma and shared-key composition. O(I) DAG
lift, solver-dependent cost, 30 s/query. This producer executes no target."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_values_symbolic import queries
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_values_contracts.json').read_text());qs,counts=queries(c,json.loads((ROOT/'lskd_handlers_contracts.json').read_text()),json.loads((ROOT/'lskd_fields_contracts.json').read_text()),json.loads((ROOT/'lskd_response_contracts.json').read_text()));rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_values_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r,str(s.model())if r=='sat'else'');path=ROOT/f'lskd_values_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_values_symbolic.py','lskd_values_contracts.json','lskd_handlers_contracts.json','lskd_fields_contracts.json','lskd_response_contracts.json']},'source_lift_counts':counts,'proofs':rows,'composition_lemmas':'Common bridge gates assume decoded state0x148 and raw success0x5e561849. Query append proof composes a checked caller/decoder key identity with one shared key basis and the frozen u32 bridge phase w17=0xfffffffe. Query initializer gate assumes source phases w19=0x30c,w20=w21=0x3be. Publication is a local store lemma; actual frame/displacement and publication premises are checked in fresh private cases, not native execution. Fixed symbolic cells are distinct except declared frame aliases.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'proof_generator_executed_target':False,'full_goal_complete':False};(ROOT/'lskd_values_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
