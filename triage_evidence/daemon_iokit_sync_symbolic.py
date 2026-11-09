#!/usr/bin/env python3
"""Bounded original A64 synchronization/record/controller obligations.
Modular u32/u64 arithmetic; selected phases and explicit alignment premises.
O(I) DAG construction time/space plus30 s/query; no native/PAC execution.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_iokit_class_symbolic import ClassLift
from lskd_values_symbolic import part,mem,cell
class SyncLift(ClassLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='cset'and i.op_str.endswith(', hs'):
    self.write(i.reg_name(i.operands[0].reg),z3.If(self.carry,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
   else:
    self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};ClassLift.run(self,'one')
  self.c=old;return self
def queries(c):
 qs=[];counts={};R,H,A,B,Q=z3.BitVecs('sync_record64 sync_SP64 sync_controller_A64 sync_controller_B64 sync_pointer64',64);r=z3.Extract(31,0,R);K=z3.BitVec('sync_shared_key32',32);W=z3.BitVec('sync_return32',32);M=0xa5cd4cf;T=0x73d046208eaed1a6
 def run(name,a,z,seeds=(),memory=()):
  x=SyncLift(part(c,name,a,z))
  for n,v in seeds:x.seed(n,v)
  for at,n,v in memory:mem(x,at,n,v)
  x.run(name);counts[name]=x.count;return x
 v=run('entry_selector_prekey',0x10046031c,0x10046034c,[('x19',R)]);qs.append(('entry_selector_prekey',z3.Or(v.read('w12')!=(r^0x966e5812),v.read('w13')!=0x592e2f77)))
 v=run('entry_selector_unpack',0x100460380,0x100460384,[('w12',r^0x966e5812),('w13',0x592e2f77),('w17',K+((r^0x966e5812)*0x592e2f77))]);qs.append(('entry_selector_unpack',v.read('w12')!=K))
 caller=run('acquire_caller_prekey',0x1003ccff0,0x1003cd020,[('x29',R+0x78)])
 callee=run('acquire_callee_prekey',0x10043e3ac,0x10043e3d4,[('x0',R)])
 qs.append(('acquire_prekey_equality_aligned8',z3.And(R&7==0,caller.read('w14')!=callee.read('w11'))))
 v=run('acquire_record_pack',0x1003cd02c,0x1003cd038,[('x29',R+0x78),('x11',Q),('w12',0x593d),('w14',K)]);qs.append(('acquire_record_pack',z3.Or(cell(v,R,4)!=(0x593d^K),cell(v,R+8,8)!=Q)))
 v=run('acquire_record_unpack',0x10043e3e0,0x10043e3ec,[('x0',R),('w11',K)],[(R,4,0x593d^K),(R+8,8,Q)]);qs.append(('acquire_record_unpack',z3.Or(v.read('w26')!=0x593d,v.read('x19')!=Q)))
 v=run('cleanup_caller_prekey',0x100383b08,0x100383b40,[('x29',R+0x78)]);qs.append(('cleanup_caller_prekey',v.read('w9')!=(r^0xeaae0ac9)))
 v=run('cleanup_record_pack',0x100383b40,0x100383b54,[('x29',R+0x78),('x8',Q),('w9',K),('w10',0x7398180b),('w26',0x5784)]);qs.append(('cleanup_record_pack',z3.Or(cell(v,R,8)!=Q,cell(v,R+8,4)!=(0xa293-K*0x7398180b))))
 v=run('cleanup_callee_prekey',0x10044251c,0x100442544,[('x0',R)]);qs.append(('cleanup_callee_prekey',v.read('w11')!=(r^0xeaae0ac9)))
 v=run('cleanup_record_unpack',0x100442544,0x100442558,[('x0',R),('w11',K)],[(R+8,4,0xa293-K*0x7398180b),(R,8,Q)]);qs.append(('cleanup_record_unpack',z3.Or(v.read('w25')!=0xa293,v.read('x19')!=Q)))
 v=run('callback_controller_updates',0x10040ecc4,0x10040ed04,[('sp',H),('x17',A),('x15',B),('x9',M),('x13',0x1010c5088),('x14',0x1010c4670)]);D=(A^B)+(H+8);qs.append(('callback_controller_updates',z3.Or(cell(v,0x1010c5088,8)!=D*M+0x673e3a80075f02c6,cell(v,0x1010c4670,8)!=(D^T)*M)))
 v=run('cleanup_controller_updates',0x1004424ec,0x10044251c,[('sp',H),('x24',0x1010c4670),('x22',0x1010b6738),('x10',A),('x20',M)],[(0x1010c4670,8,B)]);D=((A-(H+8)+B)^T)*M;qs.append(('cleanup_controller_updates',z3.Or(cell(v,0x1010b6738,8)!=D,cell(v,0x1010c4670,8)!=D)))
 v=run('outer_result_publication',0x100336fcc,0x100336fd0,[('x19',R),('w11',W)]);qs.append(('outer_result_publication',cell(v,R+4,4)!=W))
 v=run('write_lock_arguments',0x100361dec,0x100361df4,[('x19',Q)]);qs.append(('write_lock_arguments',z3.Or(v.read('x0')!=Q,v.read('x17')!=0x4c4d)))
 gate=run('acquire_primary_gate',0x10043e50c,0x10043e548,[('x19',Q),('w26',0x593d)]);qs.append(('acquire_primary_gate',gate.read('w8')!=z3.If(Q==0,z3.BitVecVal(0x5f67,32),z3.BitVecVal(0x593d,32))))
 v=run('write_lock_postreturn_index',0x100361df8,0x100361e20,[('w0',W),('w27',gate.read('w27'))]);qs.append(('write_lock_postreturn_index',v.read('w8')!=0x593c))
 return qs,counts
