#!/usr/bin/env python3
"""Source-lift contracts for the 720-byte candidate. 30 s per solver query.
O(lifted instructions + solver resources) time/space. No native reachability.
"""
import json
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,TABLE
from capture_daemon_record720 import sha
from prove_daemon_registry_lookup import RegistryLift
from lskd_values_symbolic import part,mem,cell,resize

def expected_stores():
    # Independent layout specification: (base name, offset, width, value).
    return ([('P',0x2c0,8,0),('P',0x2c8,4,0x8b3dc651),('P',0x2bc,1,0)]
            +[('P',o,2,0)for o in range(0x278,0x2b4,2)]
            +[('P',0x2b4,4,0)]
            +[('P',o,2,0)for o in range(0,20,2)]
            +[('P',o,2,0)for o in range(0x238,0x274,2)]
            +[('P',0x274,4,0)])

def obligations(c):
    F=0x6800010000;Q=z3.BitVec('record720_phase32',32);P=z3.BitVec('record720_pointer64',64);FP=z3.BitVec('record720_FP64',64);A,B=z3.BitVecs('record720_A64 record720_B64',64);qs=[];counts={}
    def run(n,a,z,seeds=(),memory=()):
        v=RegistryLift(part(c,n,a,z))
        for reg,value in seeds:v.seed(reg,value)
        for address,nb,value in memory:mem(v,address,nb,value)
        v.run(n);counts[n]=v.count;return v
    def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
    phase=run('phase',0x100badfc0,0x100badff0,[('sp',F),('x25',A),('x22',B),('x23',0x12345678),('w9',Q)])
    s=(Q+0x29fb14db)&0xd604ff8d;t=(Q-0x71c)|0x423
    add('all_u32_phase_and_preserved_roots',z3.Or(phase.read('w23')!=s,phase.read('w24')!=t,phase.read('x26')!=A,phase.read('x11')!=0x12345678,cell(phase,F+0x26f0,8)!=B))
    arg=run('allocation_argument',0x100bae040,0x100bae048);add('allocation_argument_720_and_modifier',z3.Or(arg.read('x0')!=720,arg.read('x17')!=0x6aa4))
    gate=run('return_gate',0x100bae04c,0x100bae074,[('sp',F),('x0',P),('w23',s),('w19',Q+0xf75)],[(F+0x2970,8,0x100e99a00),(F+0x29a0,8,TABLE)])
    idx=(Q+0xf75)^z3.If(P==0,z3.BitVecVal(0,32),s^0x5b86)
    add('all_u32_phase_u64_return_save_and_gate',z3.Or(gate.read('w8')!=idx,cell(gate,F+0x3118,8)!=P,gate.read('x30')!=TABLE,gate.read('x16')!=0x100e99a00,gate.read('x25')!=0))
    add('phase471C_return_partition',gate.read('w8')!=z3.If(P==0,z3.BitVecVal(0x5691,32),z3.BitVecVal(0x5692,32)),Q==0x471c)
    init=run('initializer',0x100b0b6fc,0x100b0b87c,[('sp',F),('x0',P),('w23',Q),('x29',FP)],[(F+0x3118,8,P)])
    expected=expected_stores();assert len(init.stores)==len(expected)
    bad=[]
    for actual,(_,off,width,value)in zip(init.stores,expected):
        assert actual['size_bytes']==width
        bad.extend([actual['address']!=P+off,actual['value']!=resize(value,width*8)])
    disjoint=z3.And(z3.ULE(P,(1<<64)-1-720),z3.Or(z3.ULE(P+720,F),z3.UGE(P,F+0x10000)))
    add('initializer_all_stores_disjoint_u64_owner',z3.Or(*bad),disjoint)
    add('initializer_preserves_owner_alias',z3.Or(init.read('x0')!=P,init.read('x25')!=P),disjoint)
    # Mathematical access bound, separate from modular source store equations.
    add('valid720_owner_covers_all_accesses',z3.Or(*[z3.Or(z3.ULT(P+o,P),z3.UGT(P+o+n,P+720))for _,o,n,_ in expected]),z3.ULE(P,(1<<64)-1-720))
    return qs,counts

def main():
    c=json.loads((ROOT/'daemon_record720_source.json').read_text());qs,counts=obligations(c);rows=[]
    for name,p in qs:
        s=z3.Solver();s.add(p);a=ROOT/f'daemon_record720_{name}_original.smt2';a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));ans=str(s.check());assert ans=='unsat',(name,ans);b=ROOT/f'daemon_record720_{name}.smt2';b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans});print(name,ans,flush=True)
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_source.json','capture_daemon_record720.py','prove_daemon_registry_lookup.py','prove_daemon_descriptor_producers.py','prove_daemon_callback_revisit.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'nonempty_premises':{'phase471C_return_partition':'Q=0x471C permits arbitrary P','valid720_owner_covers_all_accesses':'P=0x6800040000 satisfies unsigned no-wrap bound'},'initializer_store_count':len(expected_stores()),'initializer_bytes_written':sum(x[2]for x in expected_stores()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'daemon_record720_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
