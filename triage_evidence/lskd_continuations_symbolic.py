#!/usr/bin/env python3
"""Local original-source lock gates and continuation record decoding.

O(I) DAG construction/space; solver-dependent checking. Entry phases, fixed
distinct cells and bank-derived global pointer roots are explicit premises.
No native operation or target executes.
"""
import z3
from lskd_values_symbolic import Lift,part,mem,cell,resize
F=0x51000000;CELL=0x52000000

def queries(c,prior):
 c={'spans':c['spans']+prior['spans']}
 qs=[];counts={};R=z3.BitVec('continuation_record64',64);E=z3.BitVec('continuation_encoded_selector32',32);P=z3.BitVec('continuation_pointer64',64);G=z3.BitVec('cached_RW_pointer64',64);V=z3.BitVec('continuation_encoded_value64',64);S=z3.BitVec('continuation_scratch64',64);L=z3.BitVec('continuation_limit64',64)
 def run(name,a,z,seeds,memory=(),overrides=None):
  v=Lift(part(c,name,a,z));v.overrides=overrides or{}
  for reg,x in seeds:v.seed(reg,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 v=run('acquire_record_selector',0xfffffe000a54e300,0xfffffe000a54e338,[('x0',R)],[(R+8,4,E)]);qs.append(('acquire_record_selector',v.read('w16')!=E-resize((R^0x1d65dad0)*0xe9655f4d,32)))
 v=run('acquire_explicit_pointer_gate',0xfffffe000a54e338,0xfffffe000a54e378,[('x0',R),('w16',0x2d2)],[(R,8,P)]);qs.append(('acquire_explicit_pointer_gate',v.read('w16')!=z3.If(P==0,z3.BitVecVal(0x8d7,32),z3.BitVecVal(0x2d2,32))))
 v=run('acquire_cached_pointer_gate',0xfffffe000a55da48,0xfffffe000a55da68,[('x11',CELL),('w13',0x15),('w14',0x2d2),('w15',0x2c7)],[(CELL,8,G)]);qs.append(('acquire_cached_pointer_gate',v.read('w11')!=z3.If(G==0,z3.BitVecVal(0x2c7,32),z3.BitVecVal(0x2d2,32))))
 v=run('unlock_record_selector',0xfffffe000a55201c,0xfffffe000a552038,[('x0',R)],[(R,4,E)]);qs.append(('unlock_record_selector',v.read('w17')!=E-resize((R^0xdfb9786f)*0x1e2776fd,32)))
 v=run('unlock_explicit_pointer_gate',0xfffffe000a552038,0xfffffe000a552078,[('x0',R),('w17',0x1d3)],[(R+8,8,P)]);qs.append(('unlock_explicit_pointer_gate',v.read('w17')!=z3.If(P==0,z3.BitVecVal(0x1d3,32),z3.BitVecVal(0x1e0,32))))
 v=run('unlock_cache_phase',0xfffffe000a588a8c,0xfffffe000a588ab0,[('w1',0x1e0)]);v.c={'spans':part(c,'unlock_cache_gate',0xfffffe000a588ae8,0xfffffe000a588b04)['spans']};v.seed('x11',CELL);mem(v,CELL,8,G);v.run('unlock_cache_gate');counts['unlock_cached_pointer_gate']=v.count;ret=((0x1e0+0x57bb91f3)&0xa8446dff)+13;ret=(ret^((0x1e0+16)|0x20d))^0x1e0;qs.append(('unlock_cached_pointer_gate',v.read('w11')!=z3.If(G==0,z3.BitVecVal(ret&0xffffffff,32),z3.BitVecVal(0x1e0,32))));counts.pop('unlock_cache_phase')
 v=run('free_record_key',0xfffffe000a552a94,0xfffffe000a552aa0,[('x0',R)]);v.c=part(c,'free_selector_load',0xfffffe000a552ac8,0xfffffe000a552ad4);mem(v,R,4,E);v.run('free_selector_load');v.c=part(c,'free_selector_decode',0xfffffe000a552ae4,0xfffffe000a552ae8);v.run('free_selector_decode');counts['free_record_selector']=v.count;counts.pop('free_record_key');qs.append(('free_record_selector',v.read('w19')!=E-resize((R^0xb0a65f3a)*0x4ca11177,32)))
 v=run('free_cached_pointer_gate',0xfffffe000a552ae8,0xfffffe000a552b00,[('x20',CELL),('w19',0x52f)],[(CELL,8,G)]);qs.append(('free_cached_pointer_gate',v.read('w15')!=z3.If(G==0,z3.BitVecVal(0x52f,32),z3.BitVecVal(0x595,32))))
 v=run('conditional_cached_pointer_clear',0xfffffe000a5793bc,0xfffffe000a5793c0,[('x20',CELL)]);qs.append(('conditional_cached_pointer_clear',cell(v,CELL,8)!=0))
 v=run('vault_address_key64',0xfffffe000a52fb18,0xfffffe000a52fb38,[('x0',R)]);K=resize((R^0x0cf045eec410a4c0)*0xaed3b63b,64);qs.append(('vault_address_key64',v.read('x13')!=K))
 v=run('vault_record_fields',0xfffffe000a52fb38,0xfffffe000a52fb54,[('x0',R),('x13',K),('sp',F)],[(R+16,4,E),(R+32,8,S),(R+48,8,L),(R+64,8,V)]);qs.append(('vault_record_fields',z3.Or(v.read('w23')!=E+resize(K,32),v.read('x20')!=S,v.read('x1')!=L,cell(v,F+40,8)!=V^K)))
 v=run('vault_cookie_gate',0xfffffe000a52fbf4,0xfffffe000a52fc24,[('sp',F),('w23',0x72d)],[(F+40,8,V)]);qs.append(('vault_cookie_gate',v.read('w9')!=z3.If(V==0xe5fc6c5572d2c184,z3.BitVecVal(0x76c,32),z3.BitVecVal(0x72d,32))))
 v=run('allowed_address_key64',0xfffffe000a55cf58,0xfffffe000a55cfa8,[('x0',R)]);K=resize((R^0x0448a65ef71c80fa)*0xdd76ff8f,64);qs.append(('allowed_address_key64',v.read('x13')!=K))
 v=run('allowed_selector_field',0xfffffe000a55d014,0xfffffe000a55d020,[('x0',R),('x13',K),('sp',F)],[(R+48,4,E)]);v.c=part(c,'allowed_cookie_field',0xfffffe000a55d024,0xfffffe000a55d02c);mem(v,R+40,8,V);v.run('allowed_cookie_field');counts['allowed_record_fields']=v.count;counts.pop('allowed_selector_field');qs.append(('allowed_record_fields',z3.Or(v.read('w28')!=E+resize(K,32),v.read('x23')!=V^K)))
 v=run('allowed_bounds_arguments',0xfffffe000a55d050,0xfffffe000a55d060,[('x0',R),('sp',F)],[(R+56,8,S),(R+24,8,L)]);qs.append(('allowed_bounds_arguments',z3.Or(v.read('x0')!=S+128,v.read('x1')!=L)))
 v=run('allowed_cookie_gate',0xfffffe000a55d074,0xfffffe000a55d09c,[('sp',F),('x23',V),('w28',0x8ac)]);qs.append(('allowed_cookie_gate',v.read('w8')!=z3.If(V==0xfc6c08b9c3804423,z3.BitVecVal(0x93a,32),z3.BitVecVal(0x8ac,32))))
 v=run('vault_caller_key_basis',0xfffffe000a5960f8,0xfffffe000a596140,[('sp',F)],[(F+0x128,8,R)]);qs.append(('vault_caller_key_basis',v.read('x10')!=(R^0x0cf045eec410a4c0)))
 v=run('allowed_caller_key_basis',0xfffffe000a518a00,0xfffffe000a518a48,[('sp',F)],[(F+0x128,8,R)]);qs.append(('allowed_caller_key_basis',v.read('x11')!=(R^0x0448a65ef71c80fa)))
 context=z3.BitVec('source_context64',64);scalar=z3.BitVec('source_allowed_scalar32',32);OUT=0x53000000
 K=resize((R^0x0cf045eec410a4c0)*0xaed3b63b,64);v=run('vault_context_roundtrip',0xfffffe000a5960c4,0xfffffe000a596160,[('sp',F),('x19',R),('w20',0x3be)],[(F+0x1e0,8,context),(F+0x128,8,R),(R,8,P)],{(0xfffffe000a59613c,'x10'):R^0x0cf045eec410a4c0});qs.append(('vault_context_roundtrip',z3.Or(cell(v,R+16,4)!=0x72d-resize(K,32),(cell(v,R+64,8)^K)!=(context^0xe5fc6c5572d2c184))))
 K=resize((R^0x0448a65ef71c80fa)*0xdd76ff8f,64);v=run('allowed_context_and_scalar_pack',0xfffffe000a5189b4,0xfffffe000a518a8c,[('sp',F),('x22',OUT),('w19',0x3be)],[(F+0x1d0,8,context),(OUT,4,scalar),(F+0x128,8,R),(F+0x130,8,L),(F+0x138,8,S)],{(0xfffffe000a518a44,'x11'):R^0x0448a65ef71c80fa});qs.append(('allowed_context_and_scalar_pack',z3.Or((cell(v,R+40,8)^K)!=(context^0xfc6c08b9c3804423),cell(v,R+48,4)!=0x8ac-resize(K,32),cell(v,R+32,4)!=scalar+0x04ccbe9b-resize(K,32),cell(v,R+56,8)!=S)))
 return qs,counts
