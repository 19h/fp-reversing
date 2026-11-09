#!/usr/bin/env python3
"""Source creator codecs,allocation/init/status/publication and state predicates.
O(I) BV DAG time/space plus30 s/query. Fixed selected control AED7,original
roots and valid disjoint cells; native allocation/locking/PAC remain unknown.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_iokit_sync_symbolic import SyncLift
from lskd_values_symbolic import part,mem,cell
class RwLift(SyncLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;o=i.operands
   if i.mnemonic=='cmp':
    n=self.width(i.reg_name(o[0].reg));self.sleft,self.sright=[self.operand(i,x,n)for x in o[:2]];self.equal=self.sleft==self.sright;self.carry=z3.UGE(self.sleft,self.sright);self.count+=1
   elif i.mnemonic=='cset'and i.op_str.rsplit(',',1)[1].strip()in ['ge','gt']:
    cc=i.op_str.rsplit(',',1)[1].strip();cond=self.sleft>=self.sright if cc=='ge'else self.sleft>self.sright;self.write(i.reg_name(o[0].reg),z3.If(cond,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};SyncLift.run(self,'one')
  self.c=old;return self
def queries(c):
 qs=[];counts={};R,Q,H,A,B=z3.BitVecs('rw_record64 rw_cell_address64 rw_heap64 rw_controller_A64 rw_controller_B64',64);F=z3.BitVec('rw_SP64',64);K,S,Y=z3.BitVecs('rw_key32 rw_init_status32 rw_result32',32);r=z3.Extract(31,0,R);M=0x8b3dc651
 def run(n,a,z,seeds=(),memory=()):
  v=RwLift(part(c,n,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,size,val in memory:mem(v,at,size,val)
  v.run(n);counts[n]=v.count;return v
 v=run('first_record_prekey',0x1002dab48,0x1002dab74,[('x29',R+0xd8)]);qs.append(('first_record_prekey',z3.And(R&7==0,v.read('w10')!=(r^0xdc40790b))))
 v=run('callee_record_prekey',0x10043a364,0x10043a390,[('x19',R)]);qs.append(('callee_record_prekey',z3.And(R&7==0,v.read('w15')!=(r^0xdc40790b))))
 v=run('second_record_prekey',0x1002dac4c,0x1002dac90,[('x22',R)]);qs.append(('second_record_prekey',v.read('w8')!=(r^0xdc40790b)))
 v=run('first_record_control_pack',0x1002dab74,0x1002dab84,[('x29',R+0xd8),('w10',K),('w24',0xaed7)]);qs.append(('first_record_control_pack',cell(v,R,4)!=0xaed7-K*0x5973a279))
 v=run('second_record_control_pack',0x1002dac90,0x1002daca8,[('x29',R+0xd8),('w8',K),('w24',0xaed7)]);qs.append(('second_record_control_pack',cell(v,R,4)!=0xaed7-K*0x5973a279))
 v=run('creator_record_unpack',0x10043a390,0x10043a3a4,[('x19',R),('w15',K)],[(R,4,0xaed7-K*0x5973a279),(R+8,8,Q)]);qs.append(('creator_record_unpack',z3.Or(v.read('w15')!=0xaed7,v.read('x22')!=Q)))
 gate=run('creator_cell_gate',0x10043a3a4,0x10043a3c4,[('x22',Q),('w15',0xaed7)]);sel=run('creator_cell_selector',0x10043a3e8,0x10043a3ec,[('w17',gate.read('w17')),('w16',gate.read('w16'))]);sel=run('creator_cell_selector_final',0x10043a3fc,0x10043a400,[('w12',sel.read('w12')),('w15',0xaed7)]);qs.append(('creator_cell_gate',z3.Or(gate.read('w28')!=0x5625,sel.read('w11')!=z3.If(Q==0,z3.BitVecVal(0xaedc,32),z3.BitVecVal(0xaed7,32)))))
 phase=run('allocation_phase',0x1001937e4,0x1001937f0,[('w28',0x5625)]);qs.append(('allocation_phase',phase.read('w27')!=0xa03c))
 v=run('allocation_size',0x100193854,0x10019385c);qs.append(('allocation_size',z3.Or(v.read('x0')!=200,v.read('x17')!=0x6aa4)))
 v=run('allocation_return_gate',0x100193860,0x100193878,[('x0',H),('w28',0x5625),('w27',0xa03c)]);qs.append(('allocation_return_gate',v.read('w8')!=z3.If(H==0,z3.BitVecVal(0x5640,32),z3.BitVecVal(0x5625,32))))
 init=run('heap_header_zero',0x100130f60,0x100130f80,[('x0',H),('w27',0xa03c)]);qs.append(('heap_header_zero',z3.Or(init.read('x20')!=H,*[cell(init,H+2*j,2)!=0 for j in range(4)])))
 phase=run('init_status_phase',0x100130fb0,0x100130fb4,[('w8',init.read('w8')),('w9',init.read('w9'))]);qs.append(('init_status_phase',phase.read('w23')!=0x8dc6))
 v=run('initializer_attributes',0x100130fc4,0x100130fcc,[('x0',H)]);qs.append(('initializer_attributes',z3.Or(v.read('x0')!=H,v.read('x1')!=0,v.read('x17')!=0xa027)))
 first=run('init_signed_ge12',0x1003131a4,0x1003131c0,[('w0',S),('w23',0x8dc6)]);qs.append(('init_signed_ge12',first.read('w8')!=z3.If(S>=12,z3.BitVecVal(0x8e30,32),z3.BitVecVal(0x8dc6,32))))
 zero=run('init_zero_gate',0x10014d86c,0x10014d8a8,[('w0',S),('w23',0x8dc6)]);qs.append(('init_zero_gate',z3.Or(zero.read('w10')!=z3.If(S==0,z3.BitVecVal(0x6ac3,32),z3.BitVecVal(0x3bbf,32)),zero.read('w9')!=0x6f7f,zero.read('w8')!=0x5640)))
 large=run('init_signed_gt15',0x100276ba0,0x100276bd4,[('w0',S),('w23',0x8dc6)]);qs.append(('init_signed_gt15',z3.Or(large.read('w8')!=z3.If(S>15,z3.BitVecVal(0x82ea,32),z3.BitVecVal(0x82d2,32)),large.read('w9')!=0x3b73)))
 memory=run('init_status12',0x1002c67e0,0x1002c6810,[('w0',S),('w9',0x3b73)]);qs.append(('init_status12',memory.read('w9')!=z3.If(S==12,z3.BitVecVal(0x6f7f,32),z3.BitVecVal(0x3bbf,32))))
 busy=run('init_status16',0x100269a88,0x100269aac,[('w0',S),('w9',0x3b73)]);qs.append(('init_status16',z3.Or(busy.read('w9')!=z3.If(S==16,z3.BitVecVal(0x3b73,32),z3.BitVecVal(0x3bbf,32)),busy.read('w8')!=0x5640)))
 values={}
 for name,a,z,seeds,expect in [('default',0x10043a410,0x10043a418,[],0x74c29d88),('memory',0x10019387c,0x100193884,[],0x74c29d85),('generic',0x10014d32c,0x10014d334,[],0x74c29d83),('busy',0x1001a84c8,0x1001a84d0,[],0x74c29d82),('zero',0x1002097e4,0x1002097ec,[],M)]:
  v=run('result_'+name,a,z,seeds);values[name]=v.read('w10');qs.append(('result_'+name,v.read('w10')!=expect))
 result=z3.If(first.read('w8')==0x8dc6,z3.If(zero.read('w10')==0x6ac3,values['zero'],values['generic']),z3.If(large.read('w8')==0x82d2,z3.If(memory.read('w9')==0x6f7f,values['memory'],values['generic']),z3.If(busy.read('w9')==0x3b73,values['busy'],values['generic'])))
 expected=z3.If(S==0,z3.BitVecVal(M,32),z3.If(S==12,z3.BitVecVal(0x74c29d85,32),z3.If(S==16,z3.BitVecVal(0x74c29d82,32),z3.BitVecVal(0x74c29d83,32))));qs.append(('all_u32_initializer_status',result!=expected))
 publish=z3.And(first.read('w8')==0x8dc6,zero.read('w10')==0x6ac3);qs.append(('initializer_publication_predicate',publish!=(S==0)))
 v=run('publish_allocated_pointer',0x1002097dc,0x1002097e0,[('x20',H),('x22',Q)]);qs.append(('publish_allocated_pointer',cell(v,Q,8)!=H))
 v=run('creator_result_store',0x1001c0128,0x1001c012c,[('x19',R),('w10',Y)]);qs.append(('creator_result_store',cell(v,R+16,4)!=Y))
 v=run('controller_update',0x10043a334,0x10043a364,[('sp',F),('x23',0x1010c5040),('x26',0x1010c4670),('x16',A),('x8',0xa5cd4cf)],[(0x1010c4670,8,B)]);D=((A+B+F+8)^0x73d046208eaed1a6)*0xa5cd4cf;qs.append(('controller_update',z3.Or(cell(v,0x1010c5040,8)!=D,cell(v,0x1010c4670,8)!=D)))
 v=run('caller_control',0x1002dab40,0x1002dab48,[('w19',0x6293)]);qs.append(('caller_control',v.read('w24')!=0xaed7))
 v=run('second_result_caller_gate',0x1002dad4c,0x1002dad78,[('sp',F),('x29',R+0xd8),('w19',0x6293),('w21',0x8a9b8560)],[(F+0x358,4,0x8a9b8560),(R+16,4,Y)]);qs.append(('second_result_caller_gate',v.read('w8')!=z3.If(Y==M,z3.BitVecVal(0x70bb,32),z3.BitVecVal(0x6293,32))))
 v=run('state09_store',0x1001f1fe8,0x1001f1ffc,[('x9',0x1010b6380-0xfffffffffeff1acd)]);qs.append(('state09_store',cell(v,0x1010b6380,1)!=9))
 v=run('state_path_join',0x1001f1f98,0x1001f1fa4,[('w12',0x8a9b8560)]);qs.append(('state_path_join',v.read('w8')!=0x6293))
 return qs,counts
