#!/usr/bin/env python3
"""Original readback byte-bank/PAC roots, typed metadata and codec proofs.

O(B+256R+I) time/space plus solver-dependent cost (30 s/query). No target
executes. Raw pointer chain membership and exact names are independently read.
"""
import hashlib,json,struct
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_cold_init import pointer
from lskd_readback_codec_symbolic import queries

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();c=json.loads((ROOT/'lskd_readback_contracts.json').read_text());TABLE=0xfffffe000846c420;POOL=0xfffffe00084716e0
 specs=[('u32_lookup',0x79171c0,0x7919bb0,0xca,0x957,TABLE,0,0xfffffe000a52eed4),('raw8_lookup',0x7920d10,0x79173c0,0xbb,0x92d,TABLE,0,0xfffffe000a52eed4),('stream_typed_free',0x79174c0,0x7919db0,0x0d,0x9fe,TABLE,0,0xfffffe000c4ba368),('stream_free_view',0x79172c0,0x7919cb0,0x8d,0x63,POOL,-12,0xfffffe000847af60),('raw8_dispatch_table',0x7920c10,0x79170c0,0x20,0x15,POOL,-8,TABLE),('u32_dispatch_table',0x7920d10,0x79173c0,0xbb,-0x58,POOL,-8,TABLE),('cleanup_dispatch_table',0x7920c10,0x79170c0,0xaa,-0x19,POOL,-8,TABLE),('cleanup_controller',0x7920c10,0x79170c0,0x20,0x18,POOL,0,0xfffffe000ccc2ea0),('cleanup_shared_controller',0x79172c0,0x7919cb0,0x27,-15,POOL,0,0xfffffe000ccc2c60)]
 rules=[]
 for name,l,r,key,add,base,bias,expected in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base,bias=bias);assert int(b['target'],16)==expected,(name,b);b.update(label=name,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 roots=[pointer(k,POOL+off)for off in[0x2f8,0x630,0x4f0,0x600,0x308,0x420,0x150,0x2c0]];nameptr=pointer(k,0xfffffe000847af70);metadata_name=k.read(int(nameptr['target'],16),80).split(b'\0')[0];assert metadata_name==b'site.LSKDDispatchStream';raw=k.read(0xfffffe000847af60,64);flags,size=struct.unpack_from('<II',raw,40);assert(flags,size)==(100,160)
 compared=[{'address':hex(a),'original64_hex':k.read(a,64).hex()}for a in[0xfffffe000847b160,0xfffffe000847ae60,0xfffffe000847b020]];assert all(v['original64_hex']==raw.hex()for v in compared)
 qs,lifts=queries(c);proofs=[]
 for name,q in qs:
  solver=z3.Solver();solver.add(q);op=ROOT/f'lskd_readback_{name}_original.smt2';op.write_text(solver.to_smt2());solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.simplify(q));result=str(solver.check());assert result=='unsat',(name,result);np=ROOT/f'lskd_readback_{name}.smt2';np.write_text(solver.to_smt2());proofs.append({'name':name,'file':np.name,'sha256':sha(np),'original_file':op.name,'original_sha256':sha(op),'result':result});print(json.dumps({'proof':name,'result':result}),flush=True)
 packing=next(q for name,q in qs if name=='u32_outer_record_pack');unrestricted=packing.arg(1);solver=z3.Solver();solver.set(timeout=30000);solver.add(unrestricted);assert str(solver.check())=='sat';model=solver.model();stack=model.eval(z3.BitVec('readback_stack_address64',64),model_completion=True).as_long();tag=model.eval(z3.BitVec('readback_tag32',32),model_completion=True).as_long();assert stack&15;cp=ROOT/'lskd_readback_u32_pack_unrestricted.smt2';cp.write_text(solver.to_smt2());counterexample={'file':cp.name,'sha256':sha(cp),'result':'sat','stack_pointer64':hex(stack),'tag32':hex(tag),'violates_16byte_stack_alignment':True,'scope':'Unrestricted outer record-packing formula only; no native reachability or failure inference.'}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_readback_contracts.json','lskd_readback_codec_symbolic.py','lskd_values_symbolic.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'bank_rules':rules,'original_bank_roots':roots,'typed_free_metadata':{'address':'0xfffffe000847af60','original64_hex':raw.hex(),'name_pointer':nameptr,'name':metadata_name.decode(),'metadata_flags32':flags,'metadata_size32':size,'initial_runtime_links16_hex':raw[:16].hex(),'native_runtime_links_known':False,'equal_original64_views':compared},'source_lift_counts':lifts,'proofs':proofs,'packing_alignment_counterexample':counterexample,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_readback_auxiliary.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'exhaustive_rules':len(rules),'proofs_unsat':len(proofs),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
