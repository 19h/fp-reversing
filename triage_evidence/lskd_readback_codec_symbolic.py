#!/usr/bin/env python3
"""Original readback address-key and u32 record-pack lemmas.

O(I) DAG construction and space; solver-dependent cost. All source address
bits and tag bits remain symbolic; outer record packing assumes SP modulo16
is zero. No target or memory operation executes.
"""
import z3
from lskd_values_symbolic import Lift,part,resize,cell

def queries(c):
 qs=[];counts={};R=z3.BitVec('readback_record_address64',64);T=z3.BitVec('readback_tag32',32);S=z3.BitVec('readback_stack_address64',64);Q=z3.BitVec('readback_request64',64);O=z3.BitVec('readback_output64',64)
 def run(name,a,z,seeds):
  v=Lift(part(c,name,a,z))
  for reg,value in seeds:v.seed(reg,value)
  v.run(name);counts[name]=v.count;return v
 v=run('u32_receiver_address_key',0xfffffe000a551438,0xfffffe000a55146c,[('x19',R)]);K=resize((R^0xae0701e7)*0x952f3cb7,32);qs.append(('u32_receiver_address_key',v.read('w17')!=K))
 v=run('raw8_receiver_address_key',0xfffffe000a50edd8,0xfffffe000a50ee18,[('x19',R)]);qs.append(('raw8_receiver_address_key',v.read('w15')!=resize((R^0xefb8ef0d)*0xe384f389,32)))
 v=run('cleanup_receiver_address_key',0xfffffe000a560564,0xfffffe000a560598,[('x19',R)]);qs.append(('cleanup_receiver_address_key',v.read('w12')!=resize((R^0xddd14603)*0xb90ee68b,32)))
 v=run('u32_outer_record_pack',0xfffffe000a50e264,0xfffffe000a50e2d0,[('sp',S),('w1',T),('x0',Q),('x2',O)]);A=S+8;K=resize((A^0xae0701e7)*0x952f3cb7,32);qs.append(('u32_outer_record_pack',z3.And((S&15)==0,z3.Or(cell(v,A,4)!=0x26c-K,cell(v,A+4,2)!=resize(K+T+0x5def,16),cell(v,A+8,8)!=O,cell(v,A+16,8)!=Q))))
 status=z3.BitVec('outer_readback_status32',32)
 for name,a,z in [('u32_outer_status_normalization',0xfffffe000a50e384,0xfffffe000a50e390),('metadata_outer_status_normalization',0xfffffe000a50ea90,0xfffffe000a50ea9c)]:
  v=run(name,a,z,[('w8',status)]);qs.append((name,v.read('w0')!=status-0x5e561849))
 v=run('cleanup_outer_status_normalization',0xfffffe000a50d274,0xfffffe000a50d288,[('w8',status)]);qs.append(('cleanup_outer_status_normalization',v.read('w0')!=(status-0x7b7c2c7c)*0xd0b18b03))
 return qs,counts
