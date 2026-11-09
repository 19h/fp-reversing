#!/usr/bin/env python3
"""Source allocation fields, post-entropy alignment and kernel chunk ABI lemmas.

O(I) bit-vector DAG time/space plus solver cost. No entropy/PAC/registration
executes. Post-entropy claims require normal return and callee-saved registers.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from lskd_values_symbolic import Lift,part,mem,cell,resize
class NativeLift(Lift):
 def run(self,label):
  original=self.c;row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m=='adrp':self.write(i.reg_name(o[0].reg),o[1].imm);self.count+=1;continue
   if m=='tst':
    n=self.width(i.reg_name(o[0].reg));self.equal=(self.operand(i,o[0],n)&self.operand(i,o[1],n))==0;self.count+=1;continue
   if m=='csel':
    n=self.width(i.reg_name(o[0].reg));cond=i.op_str.rsplit(',',1)[1].strip();assert cond in['lo','eq'];take=z3.ULT(self.cmp_left,self.cmp_right)if cond=='lo'else self.equal;self.write(i.reg_name(o[0].reg),z3.If(take,self.operand(i,o[1],n),self.operand(i,o[2],n)));self.count+=1;continue
   if m=='subs':
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);v=a-b;self.write(i.reg_name(o[0].reg),v);self.equal=v==0;self.count+=1;continue
   self.c={'spans':[{'label':'instruction','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('instruction')
  self.c=original;return self

def queries(c):
 merged={'spans':c['spans']+c['external_source_spans']};qs=[];counts={};F=0x51000000;A,D,O,W=z3.BitVecs('auxiliary64 input_sized_region64 output_sized_region64 workspace64',64)
 def run(name,a,z,seeds=(),memory=()):
  v=NativeLift(part(merged,name,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,n,val in memory:mem(v,at,n,val)
  v.run(name);counts[name]=v.count;return v
 v=run('source_input_sized_pointer_store',0xfffffe000a56d234,0xfffffe000a56d23c,[('sp',F),('x0',D)],[(F+0xd40,8,A)]);qs.append(('source_input_sized_pointer_store',cell(v,A+0x60,8)!=D))
 v=run('source_first_nonnull_dispatch',0xfffffe000a56d23c,0xfffffe000a56d254,[('x0',D),('w19',0xbf3cd4e0),('w23',0x40c32b20),('w21',0x8de)]);qs.append(('source_first_nonnull_dispatch',z3.And(D!=0,v.read('w8')!=0x8de)))
 S=z3.BitVec('saved_phase32',32);v=run('source_output_allocation_phase',0xfffffe000a5440a0,0xfffffe000a5440d0,[('sp',F),('x0',D),('w21',0x8de),('w9',S)]);qs.append(('source_output_allocation_phase',z3.Or(v.read('x20')!=D,v.read('w19')!=0x4b3,v.read('w21')!=0x2bc,v.read('w23')!=0xbf3cd4e0,cell(v,F+0xa54,4)!=S)))
 C=z3.BitVec('output_capacity32',32);v=run('source_output_allocation_size',0xfffffe000a544100,0xfffffe000a544108,[('sp',F)],[(F+0xd68,4,C)]);u=run('source_saved_output_allocation_size',0xfffffe000a544118,0xfffffe000a54411c,[('sp',F),('x0',v.read('x0'))]);qs.append(('source_output_allocation_size',z3.Or(v.read('x0')!=z3.ZeroExt(32,C),cell(u,F+0x468,8)!=z3.ZeroExt(32,C))))
 L=z3.BitVec('saved_input_length32',32);v=run('source_output_sized_pointer_store',0xfffffe000a544124,0xfffffe000a544130,[('sp',F),('x0',O)],[(F+0xae4,4,L),(F+0xd40,8,A)]);qs.append(('source_output_sized_pointer_store',z3.Or(cell(v,A+0x1a0,8)!=O,v.read('w12')!=L)))
 v=run('source_second_nonnull_dispatch',0xfffffe000a544130,0xfffffe000a544154,[('x0',O),('w19',0x4b3),('w21',0x2bc),('w23',0xbf3cd4e0)]);qs.append(('source_second_nonnull_dispatch',z3.And(O!=0,v.read('w8')!=0x4b3)))
 v=run('source_entropy_phase_prefix',0xfffffe000a58c3c4,0xfffffe000a58c3d8,[('w21',0x2bc)]);u=run('source_entropy_phase_suffix',0xfffffe000a58c408,0xfffffe000a58c40c,[('w21',0x2bc),('w8',v.read('w8'))]);qs.append(('source_entropy_preserved_phase',z3.Or(v.read('w23')!=0x10,v.read('w27')!=0x8535f22b,u.read('w26')!=0x8535f4fd)))
 v=run('source_entropy_call_arguments',0xfffffe000a58c41c,0xfffffe000a58c424,[('x0',O),('w12',L)]);qs.append(('source_entropy_call_arguments',z3.Or(v.read('x0')!=O,v.read('x1')!=28,v.read('x19')!=z3.ZeroExt(32,L))))
 v=run('source_conditional_postentropy_stores',0xfffffe000a58c430,0xfffffe000a58c444,[('sp',F),('x20',D)],[(F+0xd40,8,A),(F+0x8e8,8,W+12)]);qs.append(('source_conditional_postentropy_stores',z3.Or(cell(v,A+0x78,8)!=D,cell(v,A+0x340,8)!=0,cell(v,W+12,4)!=0)))
 v=run('source_conditional_alignment_guard',0xfffffe000a58c444,0xfffffe000a58c45c,[('w19',L),('w26',0x8535f4fd),('w23',0x10),('w27',0x8535f22b),('w21',0x2bc)]);qs.append(('source_conditional_alignment_guard',v.read('w8')!=z3.If((L&15)==0,z3.BitVecVal(0x47a,32),z3.BitVecVal(0x2bc,32))))
 N64=z3.BitVec('native_random_length64',64);v=run('source_native_length_truncation',0xfffffe000be57db0,0xfffffe000be57db4,[('x20',N64)]);qs.append(('source_native_length_truncation',v.read('x22')!=z3.ZeroExt(32,z3.Extract(31,0,N64))))
 R=z3.BitVec('native_random_remaining32',32);rv=z3.ZeroExt(32,R);v=run('source_native_chunk_limit',0xfffffe000be57dc4,0xfffffe000be57dc8);u=run('source_native_chunk_select',0xfffffe000be57dcc,0xfffffe000be57dd4,[('x22',rv),('x25',v.read('x25'))]);chunk=z3.If(z3.ULT(rv,256),rv,z3.BitVecVal(256,64));qs.append(('source_native_chunk_limit',u.read('x20')!=chunk))
 CTX,FN,TH,DST,N=z3.BitVecs('native_context64 native_generate_pointer64 native_thread_base64 native_destination64 native_chunk64',64);INDEX=z3.BitVec('native_thread_field16',16);v=run('source_native_generate_arguments',0xfffffe000be57dd4,0xfffffe000be57de8,[('x26',0xfffffe0007e6c000),('x21',0xfffffe000cb88000),('x24',TH),('x20',N),('x19',DST)],[(0xfffffe0007e6c9a8,8,FN),(0xfffffe000cb88f48,8,CTX),(TH+0x1b8,2,INDEX)]);qs.append(('source_native_generate_arguments',z3.Or(v.read('x8')!=FN,v.read('x0')!=CTX,v.read('x1')!=z3.ZeroExt(48,INDEX),v.read('x2')!=N,v.read('x3')!=DST)))
 v=run('source_native_chunk_update',0xfffffe000be57dec,0xfffffe000be57df8,[('x19',DST),('x20',chunk),('x22',rv)]);qs.append(('source_native_chunk_update',z3.And(R!=0,z3.Or(v.read('x19')!=DST+chunk,v.read('x22')!=rv-chunk,v.equal!=z3.ULE(R,256),z3.Not(z3.ULT(v.read('x22'),rv))))))
 v=run('source_native_context_publication',0xfffffe000c6393f4,0xfffffe000c6393fc,[('x20',CTX)]);qs.append(('source_native_context_publication',cell(v,0xfffffe000cb88f48,8)!=CTX))
 return qs,counts
