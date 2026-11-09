#!/usr/bin/env python3
"""Source workspace/frame stores, scratch loop and unsigned CCMP guard lemmas.

Fixed distinct cells and source phases qualify composition. O(I) DAG lift
space/time plus solver cost. No target or native allocator executes.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from lskd_values_symbolic import Lift,part,mem,cell
class CarryLift(Lift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;original=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='ccmp':
    assert i.op_str.rsplit(',',1)[1].strip()=='ne';n=self.width(i.reg_name(i.operands[0].reg));a=self.operand(i,i.operands[0],n);b=self.operand(i,i.operands[1],n);take=z3.Not(self.equal);nzcv=i.operands[2].imm;self.lower=z3.If(take,z3.ULT(a,b),z3.BoolVal(not bool(nzcv&2)));self.equal=z3.If(take,a==b,z3.BoolVal(bool(nzcv&4)));self.count+=1;continue
   if i.mnemonic=='cset'and i.op_str.rsplit(',',1)[1].strip()=='lo':self.write(i.reg_name(i.operands[0].reg),z3.If(self.lower,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1;continue
   self.c={'spans':[{'label':'instruction','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('instruction')
   if i.mnemonic=='cmp':self.lower=z3.ULT(self.cmp_left,self.cmp_right)
  self.c=original;return self
def queries(c):
 qs=[];counts={};F=0x51000000;W,A=z3.BitVecs('core_workspace64 core_auxiliary64',64)
 def run(name,a,z,seeds,memory=(),typ=Lift):
  v=typ(part(c,name,a,z))
  for n,x in seeds:v.seed(n,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 errors=[];catalog_count=0
 for row in c['frame_pointer_pairs']:
  name='pointer_pair';a=int(row['add_PC'],16);v=Lift(part(c,name,a,a+8));v.seed('sp',F);v.seed(row['base_register'],W if row['region']=='workspace'else A);v.run(name);catalog_count+=v.count;errors.append(cell(v,F+row['frame_SP_offset_bytes'],8)!=(W if row['region']=='workspace'else A)+row['region_offset_bytes'])
 counts['source_frame_pointer_catalog']=catalog_count;qs.append(('source_frame_pointer_catalog',z3.Or(*errors)))
 v=run('workspace_start_order_argument',0xfffffe000a53056c,0xfffffe000a530570,[('x23',W)]);w0=v.read('x0');v=run('workspace_end_order_argument',0xfffffe000a5305b0,0xfffffe000a5305b4,[('x23',W)]);w1=v.read('x1');v=run('typed_start_order_argument',0xfffffe000a5305d4,0xfffffe000a5305d8,[('x24',A)]);a0=v.read('x0');v=run('typed_end_order_argument',0xfffffe000a530610,0xfffffe000a530614,[('x24',A)]);a1=v.read('x1');qs.append(('source_ordering_arguments',z3.Or(w0!=W+0xd00,w1!=W+0x4000,a0!=A+0x400,a1!=A+0x1000)))
 v=run('workspace_ordering_frame',0xfffffe000a5305c4,0xfffffe000a5305cc,[('sp',F),('x0',w0),('x1',w1)]);u=run('typed_ordering_frame',0xfffffe000a530624,0xfffffe000a53062c,[('sp',F),('x0',a0),('x1',a1)]);qs.append(('source_ordering_frame_pointers',z3.Or(cell(v,F+0x7f8,8)!=W+0xd00,cell(v,F+0x7f0,8)!=W+0x4000,cell(u,F+0x800,8)!=A+0x400,cell(u,F+0x7e8,8)!=A+0x1000)))
 v=run('source_workspace_seed_words',0xfffffe000a530724,0xfffffe000a530748,[('x23',W)]);qs.append(('source_workspace_seed_words',z3.Or(cell(v,W+0x638,8)!=0x908b69373110a675,cell(v,W+0x25c,4)!=0x13f6f63f,cell(v,W+0x160,4)!=0x13f6f63f)))
 v=run('source_zero_counter_seed',0xfffffe000a530638,0xfffffe000a53063c,[]);qs.append(('source_zero_counter_seed',v.read('x8')!=0))
 v=run('source_clear_loop_control',0xfffffe000a530ab0,0xfffffe000a530ac0,[('sp',F)]);qs.append(('source_clear_loop_control',z3.Or(v.read('w10')!=0x4bb,v.read('x11')!=F+0xf68,v.read('w12')!=0x4cd,v.read('x17')!=0x97f6)))
 I=z3.BitVec('core_clear_index64',64);v=run('source_clear_loop_step',0xfffffe000a56d120,0xfffffe000a56d140,[('x11',F+0xf68),('x8',I),('w12',0x4cd)]);qs.append(('source_clear_loop_step',z3.Or(cell(v,z3.BitVecVal(F+0xf68,64)+I,1)!=0,v.read('x8')!=I+1,v.read('w9')!=z3.If(I==0x447,z3.BitVecVal(0x4d2,32),z3.BitVecVal(0x4cd,32)),z3.And(z3.ULE(I,1095),z3.UGT(z3.BitVecVal(F+0xf68,64)+I,z3.BitVecVal(F+0x13af,64))))))
 D=z3.BitVec('core_input_pointer64',64);L=z3.BitVec('core_input_length32',32);v=run('source_numeric_input_guard',0xfffffe000a594c74,0xfffffe000a594cdc,[('sp',F),('w10',0x4bb)],[(F+0xae4,4,L),(F+0xad8,8,D)],CarryLift);good=z3.And(D!=0,z3.UGE(L,16),z3.ULE(L,65536));qs.append(('source_numeric_input_guard',v.read('w8')!=z3.If(good,z3.BitVecVal(0x76a,32),z3.BitVecVal(0x4bb,32))))
 return qs,counts
