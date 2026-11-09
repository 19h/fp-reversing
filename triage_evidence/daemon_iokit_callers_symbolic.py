#!/usr/bin/env python3
"""Original caller keys,selector preimages,full64 arguments and result gates.
O(I) BV DAG time/space plus30 s/query; source-fixed roots and aligned records.
"""
import z3
from daemon_iokit_sync_symbolic import SyncLift
from lskd_values_symbolic import part,mem,cell
def queries(c,sync):
 c={'spans':c['spans']+sync['spans']};qs=[];counts={};R,F=z3.BitVecs('caller_record64 caller_SP64',64);P,Y=z3.BitVecs('caller_phase32 caller_raw_result32',32);r=z3.Extract(31,0,R)
 def run(n,a,z,seeds=(),memory=()):
  v=SyncLift(part(c,n,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,size,val in memory:mem(v,at,size,val)
  v.run(n);counts[n]=v.count;return v
 pre=run('caller313_prekey',0x100313440,0x10031346c,[('x29',R+0x98)]);qs.append(('caller313_prekey',z3.And(R&7==0,pre.read('w8')!=(r^0x966e5812))))
 pack=run('caller313_pack',0x10031346c,0x100313480,[('x29',R+0x98),('w8',pre.read('w8')),('w21',P)]);assert len(pack.stores)==1 and pack.stores[0]['size_bytes']==4
 callee=run('callee_prekey',0x10046031c,0x10046034c,[('x19',R)])
 dec=run('caller313_selector_decode',0x100460380,0x100460384,[('w12',callee.read('w12')),('w13',callee.read('w13')),('w17',cell(pack,R,4))]);qs.append(('caller313_selector_decode',z3.And(R&7==0,dec.read('w12')!=P-0xed9)));qs.append(('caller313_unique_init_phase',z3.Xor(P-0xed9==0x5784,P==0x665d)))
 phase=run('caller313_phase',0x100313428,0x100313440,[('w21',0x665d)]);qs.append(('caller313_phase',phase.read('w24')!=0x1b19))
 arg=run('caller313_arguments',0x1003134cc,0x1003134d4,[('x29',R+0x98)]);qs.append(('caller313_arguments',z3.Or(arg.read('x0')!=R,arg.read('x17')!=0xa74)))
 gate=run('caller313_result_gate',0x1003134d8,0x1003134fc,[('x29',R+0x98),('w21',0x665d),('w24',phase.read('w24'))],[(R+4,4,Y)]);qs.append(('caller313_result_gate',z3.Or(z3.Xor(gate.equal,(Y^0x8b3dc651)==0),gate.read('w8')!=z3.If(Y==0x8b3dc651,z3.BitVecVal(0x6915,32),z3.BitVecVal(0x665d,32)))))
 pre=run('callerAF_prekey',0x100afed5c,0x100afed6c,[('x29',R+0x98)]);qs.append(('callerAF_prekey',pre.read('w9')!=(r^0x966e5812)))
 pack=run('callerAF_pack',0x100afed6c,0x100afed84,[('x29',R+0x98),('w9',pre.read('w9')),('w22',P)]);assert len(pack.stores)==1 and pack.stores[0]['size_bytes']==4
 dec=run('callerAF_selector_decode',0x100460380,0x100460384,[('w12',callee.read('w12')),('w13',callee.read('w13')),('w17',cell(pack,R,4))]);qs.append(('callerAF_selector_decode',dec.read('w12')!=P+0x131c));qs.append(('callerAF_unique_init_phase',z3.Xor(P+0x131c==0x5784,P==0x4468)))
 phase=run('callerAF_phase_prefix',0x100afed54,0x100afed5c,[('w22',0x4468)]);phase=run('callerAF_phase',0x100afedb8,0x100afedbc,[('w8',phase.read('w8'))]);qs.append(('callerAF_phase',phase.read('w21')!=0x8678))
 arg=run('callerAF_arguments',0x100afedcc,0x100afedd4,[('x29',R+0x98)]);qs.append(('callerAF_arguments',z3.Or(arg.read('x0')!=R,arg.read('x17')!=0xa74)))
 gate=run('callerAF_result_gate',0x100afede0,0x100afee04,[('x29',R+0x98),('w21',phase.read('w21')),('w22',0x4468)],[(R+4,4,Y)]);qs.append(('callerAF_result_gate',z3.Or(z3.Xor(gate.equal,(Y^0x8b3dc651)==0),gate.read('w8')!=z3.If(Y==0x8b3dc651,z3.BitVecVal(0x4fa3,32),z3.BitVecVal(0x4468,32)))))
 return qs,counts
