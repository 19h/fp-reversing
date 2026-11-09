#!/usr/bin/env python3
"""Original A64 arithmetic lifts for query packing, cache publication and branch.

All u32/u64 arithmetic is modular. Byte-table and fixup lemmas compose under
explicit frame premises. O(I) DAG time/space plus bounded SMT cost; no target.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG
from lskd_values_symbolic import Lift,part,mem,cell,resize
class QueryLift(Lift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,int(row['start'],16)));assert len(ins)*4==len(raw);original=self.c
  for i in ins:
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m=='ubfx':
    n=self.width(i.reg_name(o[0].reg));v=z3.LShR(self.operand(i,o[1],n),o[2].imm)&((1<<o[3].imm)-1);self.write(i.reg_name(o[0].reg),v);self.count+=1
   elif m=='lsr'and o[2].type==ARM64_OP_REG:
    n=self.width(i.reg_name(o[0].reg));v=z3.LShR(self.operand(i,o[1],n),self.operand(i,o[2],n)&(n-1));self.write(i.reg_name(o[0].reg),v);self.count+=1
   else:
    self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};Lift.run(self,'one')
  self.c=original;return self

def queries(c):
 qs=[];counts={};F=z3.BitVec('state_frame64',64);R=F+0xa8;V,C=z3.BitVecs('query_version32 query_capabilities32',32);K=(z3.Extract(31,0,R)^0xc6d66014)*0x6b86592f;S=0x1010b6380
 def run(name,a,z,seeds=(),memory=()):
  x=QueryLift(part(c,name,a,z))
  for n,v in seeds:x.seed(n,v)
  for at,n,v in memory:mem(x,at,n,v)
  x.run(name);counts[name]=x.count;return x
 b1=z3.LShR(V,8)&255;b2=z3.LShR(V,16)&255;b3=z3.LShR(V,24)
 pack=run('query_record_pack',0x1003c39b0,0x1003c3a94,[('sp',F),('x29',F+0x120),('w20',0x4ef4),('w8',C)],[(F+0x64,4,V)])
 expected=[0x2757-K,K+b2+0x0e62359a,(C^0xc49697f0)-K,K+b3+0x0bfd3da4,K+b1+0x0da54c41]
 qs.append(('query_record_pack',z3.Or(*[cell(pack,R+4*j,4)!=v for j,v in enumerate(expected)])))
 qs.append(('query_record_key',pack.values[(0x1003c3a2c,'w16')]!=K))
 dec=run('helper_record_key',0x100013bf4,0x100013c20,[('x0',R)]);qs.append(('helper_record_key',dec.read('w15')!=K))
 # Compose exact packed cells; intervening controller/lookup source has no
 # stores into the record. Its selected state pointer is an exhaustive lemma.
 unpack=run('helper_record_unpack',0x100013c20,0x100013c34,[('x0',R),('w15',K)],[(R+4*j,4,cell(pack,R+4*j,4))for j in range(5)])
 cache=run('helper_cache_and_branch',0x100013c8c,0x100013ce0,[('w0',unpack.read('w0')),('w15',K),('x3',0x1020c48b3),('w16',unpack.read('w16')),('w2',unpack.read('w2')),('w17',unpack.read('w17')),('w1',unpack.read('w1'))])
 qs.append(('helper_cache_fields',z3.Or(cache.read('x19')!=S,cell(cache,S+8,4)!=b3+0x0bfd3da4,cell(cache,S+12,4)!=b2+0x0e62359a,cell(cache,S+16,4)!=b1+0x0da54c41,cell(cache,S+20,4)!=(C^0xc49697f0))))
 qs.append(('helper_zero_capability_dispatch',z3.Or(cache.read('w20')!=0x2757,cache.read('w15')!=z3.If(C==0,z3.BitVecVal(0x58fc,32),z3.BitVecVal(0x2757,32)))))
 flag=run('caller_normal_return_marker',0x1003c3aec,0x1003c3af8,[('sp',F)],[(F+0x58,8,S)]);qs.append(('caller_normal_return_marker',cell(flag,S,1)!=10))
 A,B,H=z3.BitVecs('controller_A64 controller_B64 helper_SP64',64);MA,MB=0x1010b9028,0x1010c4670
 upd=run('helper_controller_updates',0x100013bbc,0x100013bf4,[('sp',H),('x10',MA),('x11',MB),('x15',A),('x8',0x0a5cd4cf)],[(MB,8,B)]);D=B-A-(H+8);T=z3.BitVecVal(0x73d046208eaed1a6,64);M=z3.BitVecVal(0x0a5cd4cf,64)
 qs.append(('helper_controller_updates',z3.Or(cell(upd,MA,8)!=((D*M)^T),cell(upd,MB,8)!=((D^T)*M))))
 Q=H+0x14;KP=z3.BitVec('fallback_prekey32',32);KF=z3.BitVec('fallback_key32',32)
 pre=run('fallback_key_prefix',0x1000115a0,0x1000115c4,[('sp',H)]);qs.append(('fallback_key_prefix',pre.read('w12')!=(z3.Extract(31,0,Q)^0x8515cfbd)))
 mul=run('fallback_key_material',0x1000115c4,0x1000115d0,[('w12',KP)]);qs.append(('fallback_key_material',mul.read('w12')!=KP*0xc7f6dca7))
 fall=run('fallback_local_record',0x1000115d0,0x100011608,[('sp',H),('w12',KF),('w20',0x2757)]);fs=[KF+0x50ebc19f,KF^0x7b3d5095,0x6d25-KF,KF^0x0862cc88]
 qs.append(('fallback_local_record',z3.Or(*[cell(fall,Q+j*4,4)!=v for j,v in enumerate(fs)])))
 Z=z3.BitVec('open_return_handle64',64);op=run('saved_connection_pointer',0x100478b98,0x100478bac,[('sp',F),('x0',Z)],[(F+0x58,8,S)]);qs.append(('saved_connection_pointer',z3.Or(op.read('x3')!=S+4,cell(op,F+8,8)!=S+4,op.read('x2')!=0,op.read('x20')!=Z)))
 return qs,counts
