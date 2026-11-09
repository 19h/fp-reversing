#!/usr/bin/env python3
"""Source-lift count/address/status identities, not native reachability proof."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
from sample_caller_word_lift import lift
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=z3.BitVec('record64',64);c,s,r=z3.BitVecs('count_word_decoded32 selector32 result32',32)
 address_mba=((p|0xf00a5ad91453e344)-(p&0xf00a5ad91453e344))^0xff651020835a7884
 k=z3.Extract(31,0,address_mba*0xef54ff65);simple_k=(z3.Extract(31,0,p)^0x97099bc0)*0xef54ff65
 n=z3.BitVec('element_count32',32);encoded=n-0x8899d805+simple_k
 status_index=s^z3.If(r!=0,((s+0x231)|1)^0x735,z3.BitVecVal(0,32))
 len64=z3.ZeroExt(32,lift(c))<<2
 q=z3.BitVec('samples_length64',64);kk=address_mba*0xef54ff65;encq=q-kk-0xecb67a32353f2154
 builder2_mba=((p|0xaa65bd958cf4f022)-(p|0x559a426a730b0fdd)+0x559a426a730b0fdd)^0xa50af76c1bfd6be2
 first_count=(c^0xff7e3ffb)+((c<<1)&0xfefc7ff6)+0x77e7e800+0x8899d805
 small=z3.ZeroExt(32,c);first_length=(small^0x37fbffbffdf75bff)+((small<<1)&0x1fbeeb7fe)+0xdb4d860dccc982ad+0xecb67a32353f2154
 second_length=(q^0xf34d9fcdcbdffefc)+((q<<1)&0xe69b3f9b97bffdf8)+0x1ffbe5fffee0dfb0+0xecb67a32353f2154
 queries=[('record_key',k!=simple_k),('record_key64',address_mba!=(p^0x0f6f4af997099bc0)),('count_mba',lift(c)!=(c+0x8899d805)),('element_roundtrip',lift(encoded-simple_k)!=n),('length64_no_wrap',len64!=(z3.ZeroExt(32,c+0x8899d805)*4)),('create_status_index',z3.And(s==0x507,status_index!=z3.If(r==0,z3.BitVecVal(0x507,32),z3.BitVecVal(0x50b,32)))),('samples_length_roundtrip',(encq+kk+0xecb67a32353f2154)!=q),('initializer_status_fold',((r+0x31ae0066)-((r<<1)&0x635c00cc))!=(r^0x31ae0066)),('builder2_key',builder2_mba!=(p^0x0f6f4af997099bc0)),('builder1_count',first_count!=c),('builder1_length',first_length!=small),('builder2_length',second_length!=q)]
 rows=[]
 for name,q in queries:
  solver=z3.Solver();solver.set(timeout=30000);solver.add(q);result=str(solver.check());assert result=='unsat',(name,result);path=ROOT/('sample_caller_'+name+'.smt2');path.write_text(solver.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'result':result})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['sample_caller_word_lift.py','kext_port_tools.py']},'contracts_sha256':sha(ROOT/'sample_caller_contracts.json'),'solver_version':z3.get_version_string(),'proofs':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'sample_caller_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
