#!/usr/bin/env python3
"""Source-derived local readback lemmas; fixed distinct symbolic cells.

O(I) expression-DAG construction and space; solver-dependent checking cost.
Local gates/loads/stores are distinct from whole-method or native proofs.
"""
import z3
from lskd_values_symbolic import Lift,part,mem,cell
F=0x51000000;R=0x52000000;D=0x53000000;O=0x54000000
def queries(c):
 c={'spans':c['spans']+[c['query_caller_static']]}
 qs=[];counts={}
 def run(name,a,z,seeds,memory):
  v=Lift(part(c,name,a,z))
  for reg,value in seeds:v.seed(reg,value)
  for at,n,value in memory:mem(v,at,n,value)
  v.run(name);counts[name]=v.count;return v
 p=z3.BitVec('readback_payload_pointer64',64);length=z3.BitVec('readback_length16',16)
 v=run('u32_pointer_length_gate',0xfffffe000a57dc00,0xfffffe000a57dc18,[('sp',F)],[(F+0x10,8,p),(F+0xe,2,length)])
 qs.append(('u32_pointer_length_gate',v.read('w11')!=z3.If(z3.And(p!=0,length==4),z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
 v=run('raw8_pointer_length_gate',0xfffffe000a521bfc,0xfffffe000a521c14,[('sp',F)],[(F+8,8,p),(F+0x16,2,length)])
 qs.append(('raw8_pointer_length_gate',v.read('w9')!=z3.If(z3.And(p!=0,length==8),z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
 b=[z3.BitVec('readback_byte'+str(j),8)for j in range(4)]
 v=run('source_BE32_output',0xfffffe000a525d8c,0xfffffe000a525ddc,[('x19',R),('x9',D)],[(R+8,8,O)]+[(D+j,1,x)for j,x in enumerate(b)])
 qs.append(('source_BE32_output',cell(v,O,4)!=z3.Concat(*b)))
 raw=z3.BitVec('raw8_payload64',64);v=run('source_raw8_copy',0xfffffe000a544010,0xfffffe000a54401c,[('x19',R),('x8',D)],[(R+8,8,O),(D,8,raw)])
 qs.append(('source_raw8_copy',cell(v,O,8)!=raw))
 status=z3.BitVec('readback_raw_status32',32)
 for name,a,z,offset,reg in [('u32_record_status',0xfffffe000a522d50,0xfffffe000a522d54,24,'w11'),('raw8_record_status',0xfffffe000a536800,0xfffffe000a536804,16,'w9')]:
  v=run(name,a,z,[('x19',R),(reg,status)],[]);qs.append((name,cell(v,R+offset,4)!=status))
 v=run('cleanup_inline_or_null_buffer',0xfffffe000a57f240,0xfffffe000a57f254,[('x20',R)],[(R+144,8,p)])
 qs.append(('cleanup_inline_or_null_buffer',v.read('w8')!=z3.If(z3.Or(p==0,p==R+16),z3.BitVecVal(1,32),z3.BitVecVal(0,32))))
 result=z3.BitVec('query_saved_result32',32);v=run('query_final_saved_word',0xfffffe000a505624,0xfffffe000a505628,[('sp',F)],[(F+12,4,result)])
 qs.append(('query_final_saved_word',v.read('w0')!=result))
 return qs,counts
