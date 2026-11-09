#!/usr/bin/env python3
"""Local fixed-width record/key/stack identities, not native reachability.

Solver-dependent complexity. No target/API/provider operation executes.
"""
import hashlib,json
from pathlib import Path
import z3
from kext_port_tools import ROOT
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=z3.BitVec('record_address64',64);w=z3.BitVec('input_W1',32);k=z3.BitVec('key32',32);a=z3.BitVec('arg32',32);old=z3.BitVec('old_state32',32);new=z3.BitVec('new_state32',32);x=z3.BitVec('input_X2',64)
 ca=z3.BitVecVal(0x44cbe1f371e35af7,64);cb=z3.BitVecVal(0x6f39b59a838e35dd,64);cc=z3.BitVecVal(0x84e24a0dd4f3697b,64);cd=z3.BitVecVal(0x7b1db5f22b0c9684,64)
 q1=(((p|ca)-(p&ca))^cb)*0xeac8f755;q2=(((p|cc)-(p|cd)+cd)^0xaf101e64269e0651)*0xeac8f755;compact=(p^0x2bf25469f26d6f2a)*0xeac8f755
 sub=new-old;delta=z3.ZeroExt(32,(sub<<4)&0xffff0);want=z3.ZeroExt(48,z3.Extract(15,0,sub))<<4
 key64=z3.BitVec('operand_key64',64);encoded=(x*0x0af36ba5d7ced8c7+0x23aeddd02b5fde50)^key64;decoded=(encoded^key64)*0x18f01f1601c468f7+0xe7a119c63f2f7a3e
 queries=[('shared_key64',z3.Or(q1!=compact,q2!=compact)),('scalar16_period',z3.Extract(15,0,k+w*0x7e23+0x64ca)!=z3.Extract(15,0,k+(w+0x10000)*0x7e23+0x64ca)),('record64_word_roundtrips',z3.Or((k+a)-k!=a,(a-k)+k!=a,(k^a)^k!=a)),('stack_displacement_projection',z3.Or(delta!=want,(delta&15)!=0,z3.UGT(delta,1048560))),('bridge64_affine_operand',decoded!=x+0x442b0f63903f796e)]
 rows=[]
 for name,query in queries:
  original=z3.Solver();original.add(query);source=ROOT/f'legacy_stack_{name}_original.smt2';source.write_text(original.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(query));result=str(s.check());assert result=='unsat',(name,result);path=ROOT/f'legacy_stack_{name}.smt2';path.write_text(s.to_smt2());rows.append({'name':name,'file':path.name,'sha256':sha(path),'original_file':source.name,'original_sha256':sha(source),'result':result,'normalization':'z3.simplify on original query in this pinned generator before solver/SMT serialization'})
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'contracts_sha256':sha(ROOT/'legacy_stack_contracts.json'),'proofs':rows,'z3_version':z3.get_version_string(),'native_reachability_proved':False,'full_goal_complete':False};(ROOT/'legacy_stack_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs_unsat':len(rows)}),flush=True)
if __name__=='__main__':main()
