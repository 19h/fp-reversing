#!/usr/bin/env python3
"""Source-lifted certificate metadata, name-capacity and readiness identities.
O(lifted instructions + solver resources) time/space, 30 s/query. Fixed
source phases and nonaliasing cells; no native pointer/ownership proof.
"""
import json
import z3
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from prove_daemon_record720_fingerprint import FingerprintLift
from lskd_values_symbolic import part,mem,cell,resize

def obligations(c):
    I=0x68000d0000;C=0x68000e0000;OUT=0x68000f0000
    L,N,COUNT,PHASE=z3.BitVecs('fields_length32 fields_raw32 fields_count32 fields_phase32',32)
    B,A,G=z3.BitVecs('fields_byte8 fields_expected8 fields_ready8',8)
    P,X,Y,S=z3.BitVecs('fields_pointer64 fields_X64 fields_Y64 fields_SP64',64)
    qs=[];counts={}
    def run(name,a,z,seeds=(),memory=()):
        v=FingerprintLift(part(c,name,a,z))
        for r,x in seeds:v.seed(r,x)
        for address,n,x in memory:mem(v,address,n,x)
        v.run(name);counts[name]=v.count;return v
    def add(name,bad):qs.append((name,bad))
    key=z3.BitVecVal(0x8b3dc651,32)
    gate=run('version_length',0x10041f7b0,0x10041f7e0,[('x1',I)],[(I+4,4,L^key)])
    add('all_u32_version_length_is_one',gate.read('w8')!=z3.If(L==1,z3.BitVecVal(0xfdc9,32),z3.BitVecVal(0,32)))
    v=run('version_byte',0x100161be8,0x100161c10,[('w10',z3.ZeroExt(24,B)),('x0',C)])
    add('all_u8_version_additive_representation',cell(v,C+0x10,4)!=z3.ZeroExt(24,B)+0x428bf564)
    for name,start,offset,src_offset in [('TBS',0x10044f7a4,0,0x10),('OID',0x1004150f0,0x18,4),('issuer',0x100413254,0x28,4),('subject',0x10000cd38,0x38,4)]:
        source_pointer_offset=0x18 if name=='TBS'else 8
        v=run(name,start,start+16,[('x0',C),('x1',I)],[(I+src_offset,4,N),(I+source_pointer_offset,8,P)])
        add('all_bits_'+name+'_length_pointer_copy',z3.Or(cell(v,C+offset,4)!=N,cell(v,C+offset+8,8)!=P))
    serial=run('serial_bound',0x10040f230,0x10040f2a0,[('x1',I)],[(I+4,4,L^key)])
    add('all_u32_serial_length_limit20',serial.read('w8')!=z3.If(z3.UGT(L,20),z3.BitVecVal(0x380,32),z3.BitVecVal(0,32)))
    v=run('serial_copy',0x1000abd5c,0x1000abd68,[('x0',C),('w10',N)],[(C+0x60,8,OUT)])
    add('all_u32_serial_length_workspace_copy',cell(v,OUT+0x18,4)!=N)
    v=run('serial_byte',0x1000af104,0x1000af114,[('w16',z3.ZeroExt(24,B)),('w14',1)])
    add('all_u8_serial_output_codec',resize(v.read('w16'),8)!=(B^0x98))
    v=run('name_capacity',0x10043aa98,0x10043ab10,[('x0',OUT),('x1',I)],[(OUT,4,COUNT),(I+4,4,L^key)])
    admit=z3.ULT(COUNT+L+1,201)
    add('all_u32_name_capacity_modular_guard',v.read('w8')!=z3.If(admit,z3.BitVecVal(0xcd23,32),z3.BitVecVal(0,32)))
    v=run('name_byte_comparison',0x100610bd8,0x100610be8,[('w12',z3.SignExt(24,B)),('w14',z3.ZeroExt(24,A))])
    add('all_u8_name_byte_equality',v.read('w9')!=z3.If(B==(A^0x11),z3.BitVecVal(0,32),z3.BitVecVal(1,32)))
    v=run('readiness_choice',0x10048d698,0x10048d6c4,[('w9',z3.ZeroExt(24,G)),('w8',0x3820)])
    add('all_u8_readiness_choice',v.read('w8')!=z3.If(G==1,z3.BitVecVal(0x3820,32),z3.BitVecVal(0x3831,32)))
    v=run('version_state_update',0x10041f77c,0x10041f7b0,[('x9',X),('x11',Y),('sp',S),('x8',0x1010c5000),('x10',0x1010c4000)])
    update=(((Y^X)+(S+8))^0x73d046208eaed1a6)*0xa5cd4cf
    add('all_u64_version_state_updates',z3.Or(cell(v,0x1010c5320,8)!=update,cell(v,0x1010c4670,8)!=update))
    return qs,counts

if __name__=='__main__':
    c=json.loads((ROOT/'daemon_record720_fields_source.json').read_text());qs,counts=obligations(c);rows=[]
    for name,expr in qs:
        a=ROOT/f'daemon_fields720_{name}_original.smt2';b=ROOT/f'daemon_fields720_{name}.smt2';s=z3.Solver();s.add(expr);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(expr));ans=str(s.check());print(name,ans,flush=True);assert ans=='unsat',(name,ans,str(s.model())if ans=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':ans})
    out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record720_fields_source.json','prove_daemon_record720_fingerprint.py','lskd_values_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_record720_fields_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
