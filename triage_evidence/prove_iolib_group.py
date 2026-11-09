#!/usr/bin/env python3
"""Local ready-bit and bounded registry/flag word identities.

Solver-dependent complexity. No native registry/startup/lifetime proof.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 r=z3.BitVec('ready_byte8',8);token=z3.BitVec('registry_token16',16);flags=z3.BitVec('flags32',32);word=z3.ZeroExt(16,token)|flags
 queries=[('ready_bit_partition',((z3.ZeroExt(24,r)&1)!=0)!=(z3.URem(r,2)==1)),('bounded_header_word',z3.And((flags&0xfffcffff)==0,z3.Or((word&0xffff)!=z3.ZeroExt(16,token),(word&0x30000)!=flags,(word&0x80000000)!=0)))];rows=[]
 for name,q in queries:
  s=z3.Solver();s.add(q);result=str(s.check());assert result=='unsat';path=ROOT/f'iolib_group_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'result':result})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'iolib_group_contracts.json'),'proofs':rows,'z3_version':z3.get_version_string(),'native_startup_proved':False,'full_goal_complete':False};(ROOT/'iolib_group_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
