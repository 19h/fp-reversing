#!/usr/bin/env python3
"""Local wrapper word identities; no provider-policy or accepted-operation proof."""
import hashlib,json
from pathlib import Path
import z3
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 x=z3.BitVec('input64',64);low=z3.Extract(31,0,x);queries=[('operation_bit_flip',(low^1)!=z3.Concat(z3.Extract(31,1,x),~z3.Extract(0,0,x))),('length_zero_extension',z3.ZeroExt(32,low)!=(x&0xffffffff)),('provider_status_fold',z3.If(low==0,z3.BitVecVal(0,64),z3.BitVecVal(0xffffffea,64))!=z3.If((x&0xffffffff)==0,z3.BitVecVal(0,64),z3.BitVecVal(0xffffffea,64)))];rows=[]
 for name,query in queries:
  s=z3.Solver();s.set(timeout=30000);s.add(query);result=str(s.check());assert result=='unsat';p=ROOT/('kext_aes_handoff_'+name+'.smt2');p.write_text(s.to_smt2());rows.append({'name':name,'file':p.name,'sha256':sha(p),'result':result,'scope':'Local source-lift word operation only; no native provider or accepted-operation claim.'})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'kext_aes_handoff_contracts.json'),'solver_version':z3.get_version_string(),'proofs':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_aes_handoff_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
