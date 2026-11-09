#!/usr/bin/env python3
"""Source-local allocator-return, caller dispatch, CASAL value and signed-byte
load contracts. O(source instructions + BV DAGs) construction, solver resources
separate (30 s/query). Fixed disjoint memory cells, no native concurrency/PAC.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from capture_daemon_record720 import sha
from daemon_arena_consumer_symbolic import ConsumerFlags
from lskd_values_symbolic import mem,cell,resize

def obligations():
    qs=[];counts={};S=0x680001f250
    def run(name,a,z,seeds=(),memory=()):
        v=ConsumerFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
        for r,val in seeds:v.seed(r,val)
        for at,n,val in memory:mem(v,at,n,val)
        v.run(name);counts[name]=v.count;return v
    P=z3.BitVec('consumer_payload64',64);I=z3.BitVec('consumer_first_index32',32)
    v=run('first_result',0x10031f248,0x10031f264,[('sp',S),('x23',P)],[(S+0x9c,4,I)])
    qs.append(('all_u64_first_payload_preserved',cell(v,S+0x1a8,8)!=P))
    qs.append(('all_u64_u32_first_null_dispatch',v.read('w8')!=(I^z3.If(P==0,z3.BitVecVal(0x2e,32),z3.BitVecVal(0,32)))))
    A,B,F=z3.BitVecs('consumer_second_A32 consumer_second_B32 consumer_second_phase32',32)
    v=run('second_result',0x1004818f8,0x100481920,[('sp',S),('x23',P),('w24',F)],[(S+0x18,4,A),(S+0x1c,4,B)])
    qs.append(('all_u64_second_payload_preserved',cell(v,S+0x1b0,8)!=P))
    qs.append(('all_u64_u32_second_null_dispatch',v.read('w8')!=((F+0x9d7)^z3.If(P==0,A+B-0xb2dc,z3.BitVecVal(0,32)))))
    G=z3.BitVec('consumer_gate32',32);gate=0x1010b5de0
    v=run('shared_gate',0x100503d14,0x100503d1c,[('x21',gate),('w12',0xa94ef)],[(gate,4,G)])
    qs.append(('all_u32_CASAL_gate_values',z3.Or(v.read('w11')!=G,cell(v,gate,4)!=z3.If(G==0x5d96,z3.BitVecVal(0xa94ef,32),G))))
    b=z3.BitVec('consumer_signed_byte8',8);record=0x6800020000
    v=run('signed_byte',0x100607350,0x100607354,[('x12',record)],[(record+0x20,1,b)])
    qs.append(('all_u8_signed_byte_to_W32_then_zero_extend',v.read('x13')!=z3.ZeroExt(32,z3.SignExt(24,b))))
    return qs,counts
if __name__=='__main__':
    qs,counts=obligations();rows=[]
    for name,query in qs:
        a=ROOT/f'daemon_arena_consumer_{name}_original.smt2';b=ROOT/f'daemon_arena_consumer_{name}.smt2';s=z3.Solver();s.add(query);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(query));answer=str(s.check());assert answer=='unsat';b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
    r={'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(IMAGE.path)if hasattr(IMAGE,'path')else sha('/Users/___/Downloads/zut/fairplayd.arm64e'),'dependencies':{n:sha(ROOT/n)for n in ['daemon_arena_consumer_source.json','daemon_arena_consumer_symbolic.py','daemon_arena_list_symbolic.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_consumer_proofs.json').write_text(json.dumps(r,indent=2)+'\n')
