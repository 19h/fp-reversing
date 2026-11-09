#!/usr/bin/env python3
"""Source equations for release, count/index input and zero-modifier callback.
O(lifted instructions+solver resources) time/space; 30 s/query. Local contracts
have explicit phase/alignment/owner premises; no native format or IPC proof.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from prove_daemon_registry_lookup import RegistryLift
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
    F=0x6800020000;R=F+0xde90;S=0x680001f250;FP=S+0xd50;A=FP-0xa8;OWNER=0x6800070000;INDEX=0x68000d0000
    RP,P,Q,U,X,Y,STACK=z3.BitVecs('release_record64 release_pointer64 release_child64 release_input64 release_X64 release_Y64 release_stack64',64)
    C,D,I,V,RESULT=z3.BitVecs('release_control32 release_count32 release_index32 release_aux32 release_result32',32);BYTE=z3.BitVec('release_input_byte8',8);qs=[];counts={}
    def run(n,a,z,seeds=(),memory=()):
        v=RegistryLift(part(c,n,a,z))
        for reg,value in seeds:v.seed(reg,value)
        for addr,nb,value in memory:mem(v,addr,nb,value)
        v.run(n);counts[n]=v.count;return v
    def add(n,p,pre=z3.BoolVal(True)):qs.append((n,z3.And(pre,p)))
    prekey=run('release_caller_key',0x100be0ba8,0x100be0bd8,[('x29',RP+0xb0)])
    add('even_record_release_prekey',prekey.read('w9')!=(resize(RP,32)^0xb5da7ac1),RP&1==0)
    K=(z3.BitVecVal(R&0xffffffff,32)^0xb5da7ac1)*0x5de29be3
    emit=run('release_caller_fields',0x100be0ba8,0x100be0bfc,[('sp',F),('x29',F+0xdf40),('x25',P),('w22',C)])
    add('all_u64_pointer_u32_release_caller_fields',z3.Or(cell(emit,R+8,8)!=P,cell(emit,R+16,4)!=(C+0x7497-K)))
    KK=(resize(RP,32)^0xb5da7ac1)*0x5de29be3
    dec=run('release_decode',0x100435cd8,0x100435d0c,[('x19',RP)],[(RP+16,4,C-KK),(RP+8,8,P)])
    add('all_record_release_control_pointer_decode',z3.Or(dec.read('w15')!=C,dec.read('x20')!=P))
    gate1=run('release_gate1',0x100435d0c,0x100435d1c,[('x20',P),('w15',C)])
    gate2=run('release_gate2',0x100435d44,0x100435d48,[('w16',gate1.read('w16')),('w17',gate1.read('w17'))])
    gate3=run('release_gate3',0x100435d58,0x100435d5c,[('w10',gate2.read('w10')),('w15',C)])
    idx=C^z3.If(P==0,C-0xbb46,z3.BitVecVal(0,32))
    add('all_u64_pointer_u32_release_dispatch',gate3.read('w9')!=idx)
    add('controlBBB3_null_nonnull_partition',idx!=z3.If(P==0,z3.BitVecVal(0xbbde,32),z3.BitVecVal(0xbbb3,32)),C==0xbbb3)
    child=run('owner_child_gate',0x100260f00,0x100260f34,[('w15',0xbbb3),('x20',OWNER)],[(OWNER+0x2c0,8,Q)])
    add('all_u64_optional_child_gate',z3.Or(child.read('x0')!=Q,child.read('w24')!=0x7143,child.read('w25')!=0x47bc,child.read('w8')!=z3.If(Q==0,z3.BitVecVal(0x47bc,32),z3.BitVecVal(0x479a,32))))
    phase=run('child_return_phase',0x1002084f0,0x100208508,[('w25',0x47bc)])
    add('child_free_preserves_final_return_phase',phase.read('w24')!=0x7143)
    clear=run('child_clear',0x100208580,0x100208584,[('x20',OWNER)])
    add('child_slot_clear_after_normal_free_return',cell(clear,OWNER+0x2c0,8)!=0)
    arg=run('owner_free_arg',0x1001c60f8,0x1001c6100,[('x20',P)])
    add('all_u64_owner_free_argument_modifier',z3.Or(arg.read('x0')!=P,arg.read('x17')!=0x46a2))
    status=run('free_return_value',0x1001c6108,0x1001c6114)
    add('post_free_raw_result',status.read('w8')!=0x364c5349)
    store=run('release_result',0x100270ac4,0x100270ac8,[('x19',R),('w8',RESULT)])
    add('all_u32_release_record_result',cell(store,R,4)!=RESULT)
    readkey=(resize(RP,32)^0xe732d262)*0xba209ef7
    callerkey=run('reader_caller_key',0x1003e5514,0x1003e554c,[('x29',RP+0xa8)])
    add('aligned8_reader_record_key_caller',callerkey.read('w9')!=readkey,RP&7==0)
    decoder=run('reader_decode_key',0x10044dd8c,0x10044ddc4,[('x0',RP)])
    add('all_u64_reader_record_key_decoder',decoder.read('w11')!=readkey)
    KA=(z3.BitVecVal(A&0xffffffff,32)^0xe732d262)*0xba209ef7
    fields=run('reader_caller_fields',0x1003e54a4,0x1003e5598,[('sp',S),('x29',FP),('w26',0x1fc1),('w21',D^0x8b3dc651)],[(S+0x148,8,U)])
    expected=[(0,4,0x80d1-KA),(8,8,U),(0x18,8,S+0x324),(0x20,8,S+0x278),(0x28,4,D+0x67ac8198-KA),(0x30,8,S+0x21c),(0x38,8,S+0x1a4)]
    add('all_u32_count_u64_input_reader_fields',z3.Or(*[cell(fields,A+o,n)!=resize(value,n*8)for o,n,value in expected]))
    cg=run('reader_count_guard',0x10044ddc4,0x10044de3c,[('x0',A),('w11',KA)],[(A+0x28,4,D+0x67ac8198-KA),(A+0x38,8,INDEX),(INDEX,4,I-0xaf506591),(A,4,0x80d1-KA)])
    admitted=z3.ULE(I+1,D)
    add('all_u32_count_index_guard',z3.Or(cg.read('w16')!=z3.If(admitted,z3.BitVecVal(0x35,32),z3.BitVecVal(0,32)),cg.read('w11')!=0x80d1,cg.read('w14')!=0xb048))
    add('nonwrapping_index_count_bound',admitted!=z3.ULT(I,D),I!=0xffffffff)
    address=run('first_byte_address',0x100315abc,0x100315ae8,[('x0',A),('w13',I-0xaf506591),('w14',0xb048)],[(A+8,8,U)])
    add('all_u64_input_u32_first_byte_address',z3.Or(address.read('x11')!=U,address.read('w12')!=I,address.read('w16')!=0x80d1,address.read('w15')!=0xbad1))
    tag=run('first_byte_gate',0x100315aec,0x100315b24,[('w12',z3.ZeroExt(24,BYTE)),('w14',0xb048),('w16',0x80d1),('w15',0xbad1)])
    add('all_u8_first_byte_gate_and_value',z3.Or(tag.read('w14')!=z3.If(BYTE&31==31,z3.BitVecVal(0xb087,32),z3.BitVecVal(0xb048,32)),tag.read('w12')!=z3.ZeroExt(24,BYTE^0x22)+0x21e8ae00))
    cb=run('callback_load',0x100478eec,0x100478ef4,[('x10',0x1010389a0),('sp',S)],[(0x1010389a8,8,0x10040f7a4),(S+0xe0,8,U)])
    add('zero_modifier_callback_target_and_argument',z3.Or(cb.read('x8')!=0x10040f7a4,cb.read('x0')!=U))
    cbin=run('callback_input',0x10040f7c8,0x10040f7cc,[('x1',P)])
    add('all_u64_callback_second_argument_preserved',cbin.read('x20')!=P)
    mix=run('reader_runtime_state',0x10044dd54,0x10044dd8c,[('sp',STACK),('x8',0x1010b9000),('x11',0x1010c4000),('x9',X),('x10',Y)])
    t=STACK+8+X+Y;mult=z3.BitVecVal(0xa5cd4cf,64)
    add('all_u64_reader_state_updates',z3.Or(cell(mix,0x1010b9278,8)!=t*mult+0x73d046208eaed1a6,cell(mix,0x1010c4670,8)!=(t^0x73d046208eaed1a6)*mult))
    mix2=run('release_runtime_state',0x100435c98,0x100435cd8,[('sp',STACK),('x15',Y),('x16',X),('x11',0xa5cd4cf),('x21',0x1010b6570),('x22',0x1010c4670)])
    t2=STACK+8+(X^Y)
    add('all_u64_release_state_updates',z3.Or(cell(mix2,0x1010b6570,8)!=t2*mult+0x98c1c57ff8a0fd3a,cell(mix2,0x1010c4670,8)!=(t2^0x73d046208eaed1a6)*mult))
    return qs,counts
def main():
    c=json.loads((ROOT/'daemon_record720_release_source.json').read_text());qs,counts=obligations(c);rows=[]
    for name,p in qs:
        a=ROOT/f'daemon_release720_{name}_original.smt2';b=ROOT/f'daemon_release720_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));ans=str(s.check());print(name,ans,flush=True);assert ans=='unsat',(name,ans,str(s.model())if ans=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans})
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_release_source.json','prove_daemon_registry_lookup.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_record720_release_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
