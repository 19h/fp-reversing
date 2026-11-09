#!/usr/bin/env python3
"""Local metadata width, block geometry and conditional operation identities."""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 result=z3.BitVec('read_return64',64);size,index,offset=z3.BitVecs('size32 index32 offset32',32);h=z3.BitVec('header_byte0',8);aligned=z3.ZeroExt(32,size)&0xfffffff0;direct=z3.If(h==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32));buffered=z3.ZeroExt(24,h)^1;batch=z3.BitVec('buffered_bytes32',32);mask=z3.BitVec('mask_slots32',32)
 queries=[('metadata_result_width',(z3.Extract(31,0,result)==4)!=((result&0xffffffff)==4)),('aligned_block_geometry',aligned!=(z3.LShR(z3.ZeroExt(32,size),4)<<4)),('block_threshold',(z3.UGT(size,15))!=(z3.UGE(aligned,16))),('metadata_offset_width',(z3.ZeroExt(32,index)<<2)!=(z3.ZeroExt(32,index)*4)),('direct_offset_zero_extension',(z3.ZeroExt(32,offset)&0xffffffff)!=z3.ZeroExt(32,offset)),('operation_domain_equivalence',(direct==buffered)!=z3.Or(h==0,h==1)),('batch_capacity_without_wrap',z3.And(z3.ULE(size,8192),z3.ULE(batch,8192),z3.ULE(size+batch,8192),z3.UGT((size&0xfffffff0)+batch,8192))),('mask_stride_bound',z3.And(z3.ULE(mask,512),z3.UGT(z3.ZeroExt(32,mask)*16,8192)))];rows=[]
 for name,q in queries:
  s=z3.Solver();s.set(timeout=30000);s.add(q);r=str(s.check());assert r=='unsat',(name,r);path=ROOT/('sample_transfer_'+name+'.smt2');path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'result':r})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'sample_transfer_contracts.json'),'solver_version':z3.get_version_string(),'proofs':rows,'native_target_executed':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'sample_transfer_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
