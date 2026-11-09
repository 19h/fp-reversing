#!/usr/bin/env python3
"""Original-instruction private-record and cursor equations. O(lifted source
+ solver resources) time/space; 30 s per query. Separate component contracts,
not a proof of native temporal continuity, full handler semantics or IPC.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from prove_daemon_registry_lookup import RegistryLift
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
    F=0x6800020000;R=F+0xde90;H=0x68000c0000;T=0x6800010000;G1=0x1010b8e78;G2=0x1010c4670
    P,U,C,A,B,K0,S0,Y=z3.BitVecs('handoff_P64 handoff_U64 handoff_cursor64 handoff_A64 handoff_B64 handoff_multiplier64 handoff_SP64 handoff_result64',64)
    D,V,M,S,CTRL,STATUS=z3.BitVecs('handoff_D32 handoff_V32 handoff_mode32 handoff_phase32 handoff_control32 handoff_status32',32);qs=[];counts={}
    def run(n,a,z,seeds=(),memory=()):
        v=RegistryLift(part(c,n,a,z))
        for name,value in seeds:v.seed(name,value)
        for address,nb,value in memory:mem(v,address,nb,value)
        v.run(n);counts[n]=v.count;return v
    def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
    phase=run('input_phase',0x10095af18,0x10095af30,[('sp',F)],[(F+0x273c,4,M)])
    add('input_all_u32_mode_phase',phase.read('w8')!=((M^0x4719)*0x1e17))
    fields=run('input_fields',0x10095af50,0x10095afc0,[('sp',F),('x2',H),('x6',0xe3b88695c0d52dbc),('w8',0x9673)],[(F+0x2a70,8,U^0xe3b88695c0d52dbc)]+[(H+8+j,1,z3.Extract(31-8*j,24-8*j,D)^0x98)for j in range(4)])
    add('all_u64_query_word_unmask',cell(fields,F+0x2dc0,8)!=U)
    add('all_u32_input_field_decoder',cell(fields,F+0x2fec,4)!=(D^0x8b3dc651))
    RP=z3.BitVec('handoff_record64',64);RK=(resize(RP,32)^0x7cf28be0)*0x83918153
    caller_key=run('caller_key',0x100b0b854,0x100b0b894,[('sp',F),('x12',RP),('x25',0x6800070000)],[(F+0x2dc0,8,U),(F+0x2fec,4,V)])
    add('all_u64_record_key_caller',caller_key.read('w10')!=RK)
    key=(z3.BitVecVal(R&0xffffffff,32)^0x7cf28be0)*0x83918153
    caller=run('caller_record',0x100b0b854,0x100b0b8b8,[('sp',F),('x12',R),('x25',P),('w23',S),('w11',0x1eb5)],[(F+0x2dc0,8,U),(F+0x2fec,4,V)])
    validP=z3.And(z3.ULE(P,(1<<64)-1-720),z3.Or(z3.ULE(P+720,F),z3.UGE(P,F+0x10000)))
    add('disjoint_owner_values_u32_phase_caller_fields',z3.Or(cell(caller,R,4)!=((S+0x1eb5)^key),cell(caller,R+8,8)!=U,cell(caller,R+16,8)!=P,cell(caller,R+24,4)!=V+key),validP)
    # R is symbolic for the decoder key identity; caller layout proof above fixes
    # its owned frame address and checks values independently of native aliases.
    head=run('decode_key',0x1005239e8,0x100523a24,[('x0',RP)])
    add('all_u64_record_key_decoder',head.read('w8')!=RK)
    head=run('decode_record',0x100523a24,0x100523a3c,[('x0',R),('sp',F-0x2000),('w8',key)],[(R,4,CTRL^key),(R+8,8,U),(R+24,4,V+key)])
    add('disjoint_record_u32_control_aux_decode',z3.Or(head.read('w24')!=CTRL,head.read('x17')!=U,head.read('w21')!=V))
    add('selected_control7A3A',((z3.BitVecVal(0x5b85,32)+0x1eb5)^key)^key!=0x7a3a)
    lcg=run('adapter_LCG',0x100536fc0,0x100536fcc,[('x21',C)])
    add('all_u64_adapter_LCG',lcg.read('x16')!=C*0x2e9d+1)
    reserve=16*(z3.LShR(Y,60)+1)
    alloc=run('adapter_reserve',0x10053702c,0x100537050,[('x16',Y),('x21',C),('sp',S0)])
    assert len(alloc.stores)==1 and alloc.stores[0]['size_bytes']==8
    add('all_u64_adapter_reserve_and_bias',z3.Or(alloc.read('sp')!=S0-reserve,alloc.read('x20')!=S0-reserve,alloc.stores[0]['address']!=S0-reserve,alloc.stores[0]['value']!=C-176))
    add('all_u64_reserve_bounds',z3.Or(z3.ULT(reserve,16),z3.UGT(reserve,256),reserve&15!=0))
    cursor=run('entry_cursor',0x1005239dc,0x1005239e8,[('x1',T)],[(T,8,C-176)])
    add('all_u64_nested_cursor_bias_cancellation',cell(cursor,T,8)!=C)
    delta=run('adapter_delta',0x100537104,0x100537114,[('x20',T),('x21',C),('x19',F+0x3988)],[(T,4,resize(Y,32))])
    expected=z3.ZeroExt(48,z3.Extract(15,0,Y-C))<<4
    add('all_u32_return_counter_to_u64_delta',cell(delta,F+0x3988,8)!=expected)
    gate=run('handler_gate',0x10062a624,0x10062a65c,[('sp',F),('w9',0x5e2c),('x10',32),('x14',U),('x19',P),('w27',26)])
    add('all_u64_handler_zero_gate',gate.read('w9')!=z3.If(z3.Or(U==0,P==0),z3.BitVecVal(0x5e36,32),z3.BitVecVal(0x5e2c,32)))
    ret=run('result_store',0x10061aab8,0x10061aac0,[('sp',F),('w9',STATUS)],[(F+0x20,8,R)])
    add('all_u32_result_store_at_record1C',cell(ret,R+28,4)!=STATUS)
    post=run('caller_status',0x100b0b97c,0x100b0b998,[('x19',F+0xde15),('w24',0x8b3dc651),('w26',0xb44d),('w23',0x5b85)],[(R+28,4,STATUS)])
    add('all_u32_caller_status_gate',post.read('w8')!=z3.If(STATUS==0x8b3dc651,z3.BitVecVal(0x5b85,32),z3.BitVecVal(0x5b87,32)))
    mix=run('adapter_state',0x100536f7c,0x100536fbc,[('x16',A),('x1',B),('x29',S0+0x28),('x12',K0),('x13',G1),('x14',0),('x15',G2),('x17',0)])
    t=(A^B)+S0
    add('all_u64_adapter_runtime_state_updates',z3.Or(cell(mix,G1,8)!=t*K0+0x98c1c57ff8a0fd3a,cell(mix,G2,8)!=(t^0x73d046208eaed1a6)*K0))
    return qs,counts

def main():
    c=json.loads((ROOT/'daemon_record720_handoff_source.json').read_text());qs,counts=obligations(c);rows=[]
    for name,p in qs:
        a=ROOT/f'daemon_handoff720_{name}_original.smt2';b=ROOT/f'daemon_handoff720_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));ans=str(s.check());assert ans=='unsat',(name,ans,str(s.model())if ans=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans});print(name,ans,flush=True)
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_handoff_source.json','prove_daemon_registry_lookup.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'native_temporal_continuity':False,'full_goal_complete':False};(ROOT/'daemon_record720_handoff_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
