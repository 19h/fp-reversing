#!/usr/bin/env python3
"""Selector18 caller/frame/bank and status-cell source lemmas.

Fixed distinct cells, declared source phases and resolved bank indices qualify
composition. O(I) lift space/time plus solver cost. No target executes.
"""
import z3
from lskd_values_symbolic import Lift,part,mem,cell,resize
def queries(c):
 qs=[];counts={};F=0x51000000;POOL=0xfffffe00084716e0;O=z3.BitVec('writers_output64',64);P,A,N=z3.BitVecs('writers_provider64 writers_mapped_address64 writers_descriptor_length64',64);args=z3.BitVecs('writers_arg0 writers_arg1 writers_arg2 writers_arg3 writers_arg4 writers_arg5',64);S=z3.BitVec('writers_status32',32)
 def run(name,a,z,seeds,memory=()):
  v=Lift(part(c,name,a,z))
  for n,x in seeds:v.seed(n,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 v=run('provider_six_argument_forward',0xfffffe000a50582c,0xfffffe000a505844,[(f'x{j+1}',x)for j,x in enumerate(args)]);qs.append(('provider_six_argument_forward',z3.Or(*[v.read(f'x{j}')!=x for j,x in enumerate(args)])))
 v=run('userclient_provider_call_fields',0xfffffe000a50475c,0xfffffe000a504774,[('x19',O),('x21',P),('x22',A),('x2',N)]);qs.append(('userclient_provider_call_fields',z3.Or(v.read('x0')!=P,v.read('x1')!=A,v.read('x2')!=N,v.read('x3')!=O+20,v.read('x4')!=3072,v.read('x5')!=O+12,v.read('x6')!=O+16)))
 v=run('core_six_argument_frame',0xfffffe000a530330,0xfffffe000a530348,[('sp',F),*[(f'x{j}',x)for j,x in enumerate(args)]]);qs.append(('core_six_argument_frame',z3.Or(*[cell(v,F+off,n)!=resize(args[j],n*8)for j,off,n in[(5,0x610,8),(4,0xa58,8),(3,0xd68,4),(2,0x5d8,8),(1,0xae4,4),(0,0xad8,8)]])))
 v=run('left_bank_frame_publication',0xfffffe000a530438,0xfffffe000a530440,[('sp',F),('x27',POOL)],[(POOL+0x510,8,0xfffffe0007920c10)]);qs.append(('left_bank_frame_publication',cell(v,F+0xc28,8)!=0xfffffe0007920c10))
 v=run('right_bank_frame_publication',0xfffffe000a530450,0xfffffe000a53045c,[('sp',F),('x27',POOL)],[(POOL+0x1a0,8,0xfffffe00079170cc)]);qs.append(('right_bank_frame_publication',cell(v,F+0xc30,8)!=0xfffffe00079170c0))
 v=run('conditional_tag_table_pointer_store',0xfffffe000a589930,0xfffffe000a58993c,[('sp',F),('x23',POOL),('w17',0x83)],[(POOL+0x83*8,8,0xfffffe000ccc7b10)]);qs.append(('conditional_tag_table_pointer_store',cell(v,F+0xd28,8)!=0xfffffe000ccc7b08))
 U=z3.BitVec('writers_bank_input32',32);v=run('conditional_bank_input_byte',0xfffffe000a5898b4,0xfffffe000a5898b8,[('w16',U)]);qs.append(('conditional_bank_input_byte',v.read('x17')!=z3.ZeroExt(32,U&255)))
 v=run('conditional_bank_post_index',0xfffffe000a58991c,0xfffffe000a589928,[('w16',U),('w17',(U&255)^0x76)]);qs.append(('conditional_bank_post_index',v.read('x17')!=0x83))
 v=run('first_allocator_arguments',0xfffffe000a5304bc,0xfffffe000a5304c8,[]);qs.append(('first_allocator_arguments',z3.Or(v.read('x0')!=16384,v.read('x1')!=64,v.read('x17')!=0x3fc0)))
 v=run('embedded_status_store',0xfffffe000a504780,0xfffffe000a504784,[('x19',O),('w0',S)]);qs.append(('embedded_status_store',cell(v,O+0xc14,4)!=S))
 v=run('failure_count_clear',0xfffffe000a504788,0xfffffe000a50478c,[('x19',O)]);qs.append(('failure_count_clear',cell(v,O+12,4)!=0))
 v=run('mapping_failure_cells',0xfffffe000a5047b0,0xfffffe000a5047bc,[('x19',O)]);qs.append(('mapping_failure_cells',z3.Or(cell(v,O+0xc14,4)!=0xffffffd9,cell(v,O+12,4)!=0)))
 v=run('outer_transport_return',0xfffffe000a5047bc,0xfffffe000a5047c0,[]);qs.append(('outer_transport_return',v.read('x0')!=0))
 return qs,counts
