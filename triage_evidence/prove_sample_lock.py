#!/usr/bin/env python3
"""Nine source-expression u32 equivalences; conditional context algebra only.

Solver cost is solver-dependent. No native, lock, crypto or IDB execution.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=z3.BitVec('record_low32',32);w=z3.BitVec('first_context_state32',32)
 prep=(p^0x7abbf985)*0xded29631;acq=(p^0x6133a0c8)*0x84d77373;rel=(p^0x734a22b2)*0x8c229611
 expressions=[('first_preparer_codec',((((p<<1)|0xec2c31ca)-p+0x09e9e71b)^0x8cade160)*0xded29631,prep),('second_preparer_codec',(((p|0x9a38fdb0)-(p&0x9a38fdb0))^0xe0830435)*0xded29631,prep),('first_acquire_codec',((-2-(p|0xadfc8222)-(z3.BitVecVal(0x52037ddd,32)|~p))^0x3330dd15)*0x84d77373,acq),('second_acquire_codec',(((p&0xd355173d)|~(p|0xd355173d))^0x4d99480a)*0x84d77373,acq),('first_release_codec',(((p&0x3b5c342c)*2-p+0xc4a3cbd3)^0xb7e9e961)*0x8c229611,rel),('second_release_codec',((0xa1d70f55-(p|0xa1d70f55)+(p|0x5e28f0aa))^0x2d62d218)*0x8c229611,rel),('preparer_context_equivalence',w+0x4f7,w+0x243+0x2b4),('acquire_context_equivalence',w+0x219,w+0x243-0x2a),('release_context_equivalence',w+0x723,w+0x243+0x4e0)]
 rows=[]
 for name,a,b in expressions:
  s=z3.Solver();s.add(a!=b);result=str(s.check());assert result=='unsat',(name,result,s.model()if result=='sat'else None);path=ROOT/f'sample_lock_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'result':result})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'sample_lock_contracts.json'),'proofs':rows,'z3_version':z3.get_version_string(),'entry_reachability_proved':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'sample_lock_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
