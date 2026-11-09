#!/usr/bin/env python3
"""Source-derived record decoder, threshold CFG, output marker and bit update.

Fixed source phases compose through pinned original slots and byte-bank roots.
All arithmetic uses modular u32/u64, comparisons explicit unsigned. O(I) BV DAG
time/space plus solver cost; no native/API/PAC execution.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_query_state_symbolic import QueryLift
from lskd_values_symbolic import part,mem,cell,resize
TABLE=0x101039ef0;STATE=0x1010b6380
class FlagLift(QueryLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,int(row['start'],16)));assert len(ins)*4==len(raw);original=self.c
  for i in ins:
   self.pc=i.address;m=i.mnemonic;o=i.operands
   if m in['cmp','cmn']:
    n=self.width(i.reg_name(o[0].reg));a,b=[self.operand(i,x,n)for x in o[:2]]
    if m=='cmp':self.carry=z3.UGE(a,b);self.equal=a==b
    else:
     x=z3.ZeroExt(1,a)+z3.ZeroExt(1,b);self.carry=z3.Extract(n,n,x)==1;self.equal=z3.Extract(n-1,0,x)==0
    self.count+=1
   elif m in['cset','cinc']:
    cc=i.op_str.rsplit(',',1)[1].strip();assert cc in['lo','hi','eq','ne'];cond=z3.Not(self.carry)if cc=='lo'else z3.And(self.carry,z3.Not(self.equal))if cc=='hi'else self.equal if cc=='eq'else z3.Not(self.equal);v=z3.If(cond,z3.BitVecVal(1,32),z3.BitVecVal(0,32))
    if m=='cinc':v+=self.operand(i,o[1],32)
    self.write(i.reg_name(o[0].reg),v);self.count+=1
   else:
    self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};QueryLift.run(self,'one')
  self.c=original;return self

def queries(c):
 qs=[];counts={};V=z3.BitVec('fallback_version32',32);b3=z3.LShR(V,24);b2=z3.LShR(V,16)&255;b1=z3.LShR(V,8)&255;H,R=z3.BitVecs('fallback_helper_SP64 fallback_record64',64)
 def run(name,a,z,seeds=(),memory=()):
  x=FlagLift(part(c,name,a,z))
  for n,v in seeds:x.seed(n,v)
  for at,n,v in memory:mem(x,at,n,v)
  x.run(name);counts[name]=x.count;return x
 def idx(slot):assert(slot-TABLE)%8==0;return(slot-TABLE)//8
 pre=run('callee_record_prekey',0x10043bd60,0x10043bdb0,[('x0',R)]);qs.append(('callee_record_prekey',pre.read('w8')!=(z3.Extract(31,0,R)^0x8515cfbd)))
 K=z3.BitVec('fallback_prekey32',32);sel=run('callee_control_word',0x10043bdbc,0x10043bdc0,[('w8',K),('w9',0xc7f6dca7),('w10',0x6d25-K*0xc7f6dca7)]);qs.append(('callee_control_word',sel.read('w9')!=0x6d25))
 A,B=z3.BitVecs('fallback_controller_A64 fallback_controller_B64',64);upd=run('callee_controller_update',0x10043bd28,0x10043bd60,[('sp',H),('x8',0x1010b6000),('x10',0x1010c4000),('x9',A)],[(0x1010c4670,8,B)]);T=z3.BitVecVal(0x73d046208eaed1a6,64);M=z3.BitVecVal(0xa5cd4cf,64);D=(B-A)^((H+8)^T);out=D*M;qs.append(('callee_controller_update',z3.Or(cell(upd,0x1010b6918,8)!=out,cell(upd,0x1010c4670,8)!=out)))
 a=run('byte3_high_gate',0x10043be14,0x10043be40,[('x10',STATE+8),('w9',0x6d25)],[(STATE+8,4,b3+0xbfd3da4)])
 ai=run('byte3_high_index',0x10043be68,0x10043be6c,[('w14',a.read('w14')),('w9',a.read('w9'))]);high=z3.UGE(b3,47);e46=b3==46
 qs.append(('byte3_high_index',ai.read('w13')!=z3.If(high,z3.BitVecVal(idx(0x101070b20),32),z3.BitVecVal(idx(0x101070818),32))))
 b=run('byte3_equal_gate',0x10025784c,0x10025789c,[('w11',a.read('w11')),('w10',b3+0xbfd3da4)])
 qs.append(('byte3_equal_index',z3.And(z3.Not(high),b.read('w10')!=z3.If(e46,z3.BitVecVal(idx(0x10104d4a0),32),z3.BitVecVal(idx(0x10104d3a8),32)))))
 d=run('byte2_high_gate',0x10036c670,0x10036c6b0,[('w12',b.read('w12')),('x8',STATE)],[(STATE+12,4,b2+0xe62359a)]);up=z3.UGE(b2,31);e30=b2==30
 qs.append(('byte2_high_index',z3.And(z3.Not(high),e46,d.read('w11')!=z3.If(up,z3.BitVecVal(idx(0x10107d7e0),32),z3.BitVecVal(idx(0x10107d698),32)))))
 e=run('byte2_equal_gate',0x10034f538,0x10034f588,[('w10',d.read('w10')),('w13',d.read('w13'))])
 qs.append(('byte2_equal_index',z3.And(z3.Not(high),e46,z3.Not(up),e.read('w10')!=z3.If(e30,z3.BitVecVal(idx(0x10105f500),32),z3.BitVecVal(idx(0x10105f7b8),32)))))
 f=run('byte1_marker',0x100275b80,0x100275bb8,[('w11',e.read('w11')),('x8',STATE)],[(STATE+16,4,b1+0xda54c41)])
 qs.append(('byte1_marker',z3.And(e46,e30,f.read('w14')!=z3.If(b1==0,z3.BitVecVal(0x3a9c01da,32),z3.BitVecVal(0x3a9c01db,32)))))
 qs.append(('final_result_store_index',z3.And(e46,e30,f.read('w11')!=idx(0x10107d7e0))))
 defaults=[]
 for name,start,value in[('high3_default',0x10043be7c,0x3a9c01db),('low3_default',0x1002578a0,0x3a9c01d9),('high2_default',0x10036c6b4,0x3a9c01db),('low2_default',0x10034f58c,0x3a9c01d9)]:
  x=run(name,start,start+8);defaults.append(x.read('w14')!=value)
 qs.append(('source_default_markers',z3.Or(*defaults)))
 marker=z3.If(high,z3.BitVecVal(0x3a9c01db,32),z3.If(z3.Not(e46),z3.BitVecVal(0x3a9c01d9,32),z3.If(up,z3.BitVecVal(0x3a9c01db,32),z3.If(z3.Not(e30),z3.BitVecVal(0x3a9c01d9,32),f.read('w14')))))
 threshold=z3.UGE(z3.LShR(V,16),0x2e1e);expected=z3.If(z3.Not(threshold),z3.BitVecVal(0x3a9c01d9,32),z3.If(z3.And(z3.LShR(V,16)==0x2e1e,b1==0),z3.BitVecVal(0x3a9c01da,32),z3.BitVecVal(0x3a9c01db,32)))
 qs.append(('composed_version_marker',marker!=expected));qs.append(('composed_marker_threshold',z3.UGT(marker,0x3a9c01d9)!=threshold))
 O=z3.BitVec('fallback_output_marker32',32);pub=run('record_output_publication',0x1001a88f8,0x1001a8900,[('x0',R),('sp',H),('w14',O)]);qs.append(('record_output_publication',z3.Or(cell(pub,R+16,4)!=O,pub.read('sp')!=H+16,pub.read('x0')!=R)))
 caller=run('caller_marker_dispatch',0x100011678,0x100011698,[('sp',H),('w20',0x2757)],[(H+0x24,4,O)]);qs.append(('caller_marker_dispatch',caller.read('w8')!=z3.If(z3.UGT(O,0x3a9c01d9),z3.BitVecVal(0x3a37,32),z3.BitVecVal(0x2757,32))))
 C=z3.BitVec('encoded_capability32',32);bit=run('capability_bit_store',0x100015278,0x100015284,[('x19',STATE)],[(STATE+20,4,C)]);qs.append(('capability_bit_store',cell(bit,STATE+20,4)!=(C|8)))
 qs.append(('composed_capability_fallback',z3.If(threshold,z3.BitVecVal(0xc49697f0|8,32),z3.BitVecVal(0xc49697f0,32))!=z3.If(z3.UGE(V,0x2e1e0000),z3.BitVecVal(0xc49697f8,32),z3.BitVecVal(0xc49697f0,32))))
 return qs,counts
