#!/usr/bin/env python3
"""Source-derived constructor/initializer key, selector and field identities.

O(I) lift; solver-dependent proof cost. Distinct abstract record/heap cells;
no native allocation, provider execution, cryptography or IPC proof.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from lskd_request_symbolic import queries,key_forms
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'lskd_request_contracts.json').read_text());qs,counts=queries(c);rows=[]
 for name,q in qs:
  original=z3.Solver();original.add(q);op=ROOT/f'lskd_request_{name}_original.smt2';op.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));r=str(s.check());assert r=='unsat',(name,r);path=ROOT/f'lskd_request_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':op.name,'original_sha256':sha(op),'result':r});print(json.dumps({'proof':name,'result':r}),flush=True)
 R,ko,kd,_=key_forms(c);s=z3.Solver();s.set(timeout=30000);s.add(ko!=kd);assert str(s.check())=='sat';model=s.model();address=model.eval(R,model_completion=True).as_long();assert address&7;ce={'scope':'Algebraic counterexample to an unrestricted key identity, not a native call or memory execution.','record_address64':hex(address),'encoder_key32':hex(model.eval(ko,model_completion=True).as_long()),'decoder_key32':hex(model.eval(kd,model_completion=True).as_long()),'required_proof_precondition':'record_address64 & 7 == 0','native_target_executed':False};cp=ROOT/'lskd_request_alignment_counterexample.json';cp.write_text(json.dumps(ce,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_request_symbolic.py','lskd_request_contracts.json','legacy_tlv_symbolic.py']},'source_lift_counts':counts,'proofs':rows,'alignment_counterexample_sha256':sha(cp),'composition_lemmas':'Decoded field/initializer proofs use shared abstract keys; constructor equality requires 8-byte-aligned records. Original source slices tie the keys and fields.','z3_version':z3.get_version_string(),'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_request_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
