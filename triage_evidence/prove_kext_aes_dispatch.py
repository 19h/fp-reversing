#!/usr/bin/env python3
"""Local byte-index and cleanup record codec identities; not reachability proof."""
import hashlib,json
from pathlib import Path
import z3
ROOT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p,state,x,y=z3.BitVecs('record_low32 state32 input32 other_input32',32);left=z3.Array('left',z3.BitVecSort(8),z3.BitVecSort(8));right=z3.Array('right',z3.BitVecSort(8),z3.BitVecSort(8));key=z3.BitVec('key8',8)
 def select(v):
  b=z3.Extract(7,0,v);return b^z3.Select(right,z3.Select(left,b)^key)
 mba=z3.BitVecVal(0xfffffffe,32)-((p|0x1c96683e)+(z3.BitVecVal(0xe36997c1,32)|~p));mba=mba^0x73e8c364;encoded=(p^0x908154a5)*0x51a7c57b+state+0x451;decoded=encoded-mba*0x51a7c57b
 classifier_mba=((p+0x4bf75321)-((p&0x4bf75321)<<1))^0x45e59dc7
 dispatch_mba=((p&0x406fdd12)|~(p|0x406fdd12))^0x3b8c94a8
 tag=z3.BitVec('decoded_tag32',32)
 queries=[('dispatcher_address_mba',dispatch_mba!=(p^0x841cb645)),('dispatcher_tag_test',((tag+0xe1ca99c3)==0xe41e53b9)!=(tag==0x0253b9f6)),('classifier_address_mba',classifier_mba!=(p^0x0e12cee6)),('byte_index_upper_bits',z3.And(z3.Extract(7,0,x)==z3.Extract(7,0,y),select(x)!=select(y))),('cleanup_address_mba',mba!=(p^0x908154a5)),('cleanup_record_roundtrip',decoded!=(state+0x451))];rows=[]
 for name,q in queries:
  s=z3.Solver();s.set(timeout=30000);s.add(q);r=str(s.check());assert r=='unsat',r;path=ROOT/('kext_aes_dispatch_'+name+'.smt2');path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'result':r,'scope':'Local source-lift word semantics; no valid record/entry/native state claim.'})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'kext_aes_dispatch_contracts.json'),'solver_version':z3.get_version_string(),'proofs':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_aes_dispatch_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
