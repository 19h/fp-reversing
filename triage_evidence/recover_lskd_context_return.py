#!/usr/bin/env python3
"""Context re-encoding, signed operation routing and conditional wrapper return.

Original-source scalar/SIMD/overlapping-byte certificates. Stable seed, slot,
frame and nonaliasing object/call epochs are premises. No target or IDB action.
O(N+I+L+256R) extraction/expression time and space for source/index bytes N,
instruction instances I, modeled byte lanes L and bank rules R; SMT cost separate.
"""
import argparse
import json
import re

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG

from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer as original_pointer
from recover_lskd_context_codec import CodecLift,pack,lanes,permutation,affine,FACTOR,SEED_FACTOR
from lskd_values_symbolic import resize,part
from verify_daemon_reader_record_payloads_publication import read,sha

TABLE=0xfffffe000846c420
SPANS={
 'rewrap':(0xfffffe000a527b24,0xfffffe000a527ebc),
 'selector_entry':(0xfffffe000a5323f0,0xfffffe000a532464),
 'selector_lt4':(0xfffffe000a533a60,0xfffffe000a533a8c),
 'selector_ge4':(0xfffffe000a532820,0xfffffe000a53285c),
 'selector_lt2':(0xfffffe000a55c0d0,0xfffffe000a55c12c),
 'selector_2_3':(0xfffffe000a55267c,0xfffffe000a5526b8),
 'selector_ge5':(0xfffffe000a595bb4,0xfffffe000a595c0c),
 'selector_4_state':(0xfffffe000a5184d4,0xfffffe000a518540),
 'selector_2_state':(0xfffffe000a526c7c,0xfffffe000a526ccc),
 'state_one':(0xfffffe000a5536a8,0xfffffe000a5536d4),
 'state_ten':(0xfffffe000a5144f0,0xfffffe000a514518),
 'common_body_frontier':(0xfffffe000a52a7d8,0xfffffe000a52a854),
 'release':(0xfffffe000a52a508,0xfffffe000a52a5c8),
 'result':(0xfffffe000a50ef94,0xfffffe000a50efec),
 'outer_result':(0xfffffe000a50e864,0xfffffe000a50e8a8),
 'release_bank_root':(0xfffffe000a5614f8,0xfffffe000a561528),
}
INDICES=[0x17,0x418,0x498,0x1ab,0x1c7,0x69e,0x68f,0x58f,0x580,0x999,0x9ab,0x220,0x980,0x34e,0x325,0x30a,0x4d1,0x106]


class ReturnLift(CodecLift):
 def load(self,address,n):
  a=z3.simplify(resize(address,64))
  if z3.is_bv_value(a) and 0xfffffe0007920f10<=a.as_long()<a.as_long()+n<=0xfffffe0007920fd0:
   raw=IMAGE.read(a.as_long(),n);self.static_reads[hex(a.as_long())]={'size_B':n,'bytes_hex':raw.hex()}
   return resize(int.from_bytes(raw,'little'),n*8)
  return super().load(address,n)
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  data=bytes.fromhex(row['bytes_hex']);instructions=list(cs.disasm(data,int(row['start'],16)));assert len(instructions)*4==len(data)
  for ins in instructions:
   self.pc=ins.address
   if ins.mnemonic=='lsr' and ins.operands[2].type==ARM64_OP_REG:
    d,a,b=[ins.reg_name(o.reg) for o in ins.operands];width=self.width(d)
    self.write(d,z3.LShR(self.read(a),resize(self.read(b),width)&(width-1)));self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def prove(capture):
 q={};counts={};pieces={};f=0xfffffe0051000000;fp=f+0x340
 p,r,k=z3.BitVecs('context_pointer64 outer_record64 entry_key64',64)
 seed,t,opcode,status=z3.BitVecs('seed32 mixed_seed32 original_W1_32 private_status32',32)
 mask=z3.BitVec('pointer_mask64',64);indices=[z3.BitVec('j'+str(d)+'_8',8) for d in [7,6,5,3]]
 bound=z3.And(*[z3.ULT(j,d) for j,d in zip(indices,[7,6,5,3])])
 def run(name,a,z,seeds,regions=(),cells=(),vectors=(),active=None,writes=(),obj=None):
  obj=obj or ReturnLift(part(capture,name,a,z));obj.c=part(capture,name,a,z)
  for reg,value in seeds.items():obj.seed(reg,value)
  for base,value in regions:obj.region(base,value)
  for at,n,value in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]=resize(value,n*8)
  for at,n in writes:obj.fixed_stores.add((z3.simplify(resize(at,64)).sexpr(),n))
  for reg,value in vectors:obj.vectors[reg]=resize(value,128)
  obj.active=active;before=obj.count;obj.run(name);counts[name]=obj.count-before
  pieces[name]={'start':hex(a),'end':hex(z),'instructions':(z-a)//4};assert counts[name]==(z-a)//4
  if obj.guards:q[name+'_bounds']=z3.And(bound,z3.Not(z3.And(*obj.guards)))
  return obj
 def value(obj,at,n):return obj.fixed[(z3.simplify(resize(at,64)).sexpr(),n)]
 # Exact signed selector tree over all original W1 bit patterns.
 obj=run('selector_decode_and_lt4',0xfffffe000a5323f4,0xfffffe000a532458,
  {'sp':f,'w8':0x6e3},cells=[(f+0x110,8,r),(r+0x3c,4,opcode-resize(k,32)),(f+0xe8,8,k)])
 first=obj.read('w10');q['selector_decode_and_lt4']=z3.Or(obj.read('w20')!=opcode,obj.read('w9')!=0x68f,
  obj.read('w11')!=0x1ab,first!=z3.If(opcode<4,resize(0x1ab,32),resize(0x1c7,32)))
 obj=run('selector_lt2',0xfffffe000a533a64,0xfffffe000a533a80,{'w9':0x68f,'w20':opcode})
 second=obj.read('w8');q['selector_lt2']=z3.Or(obj.read('w10')!=0x17,second!=z3.If(opcode<2,resize(0x69e,32),resize(0x68f,32)))
 obj=run('selector_eq1',0xfffffe000a55c0d4,0xfffffe000a55c114,{'w10':0x17,'w20':opcode})
 low=obj.read('w8');q['selector_eq1']=z3.Or(obj.read('w22')!=0x6e3,low!=z3.If(opcode==1,resize(0x9ab,32),resize(0x999,32)))
 obj=run('selector_eq1_default_code',0xfffffe000a55c118,0xfffffe000a55c124,{'x22':0x6e3})
 q['selector_eq1_default_code']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w21')!=0x06367832)
 obj=run('selector_eq2',0xfffffe000a552680,0xfffffe000a5526a4,{'w10':0x17,'w20':opcode})
 middle=obj.read('w10');q['selector_eq2']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w9')!=0x30a,middle!=z3.If(opcode==2,resize(0x220,32),resize(0x17,32)))
 obj=run('selector_eq2_default_code',0xfffffe000a5526a8,0xfffffe000a5526b0,{})
 q['selector_eq2_default_code']=obj.read('w21')!=0x06367832
 obj=run('selector_lt5',0xfffffe000a532824,0xfffffe000a532850,{'w8':0x6e3,'w20':opcode})
 third=obj.read('w10');q['selector_lt5']=z3.Or(obj.read('w8')!=0x580,obj.read('w9')!=0x17,third!=z3.If(opcode<5,resize(0x58f,32),resize(0x580,32)))
 obj=run('selector_eq5',0xfffffe000a595bb8,0xfffffe000a595bf8,{'w9':0x17,'w20':opcode})
 high=obj.read('w9');q['selector_eq5']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w22')!=0x6e3,high!=z3.If(opcode==5,resize(0x980,32),resize(0x17,32)))
 obj=run('selector_eq5_default_code',0xfffffe000a595bfc,0xfffffe000a595c04,{})
 q['selector_eq5_default_code']=obj.read('w21')!=0x06367832
 final=z3.If(first==0x1ab,z3.If(second==0x69e,low,middle),z3.If(third==0x58f,resize(0x58f,32),high))
 expected=z3.If(opcode<2,z3.If(opcode==1,resize(0x9ab,32),resize(0x999,32)),
  z3.If(opcode<4,z3.If(opcode==2,resize(0x220,32),resize(0x17,32)),
  z3.If(opcode==4,resize(0x58f,32),z3.If(opcode==5,resize(0x980,32),resize(0x17,32)))))
 q['complete_signed_selector_partition']=final!=expected
 # Existing encoded state word, distinct from flag174 and limit178.
 state=z3.BitVec('context_field144_32',32);base=0x13f6f63f
 obj=run('selector4_state',0xfffffe000a5184d8,0xfffffe000a518534,
  {'sp':f,'w8':0x580},cells=[(f+0x1f8,8,p),(p+0x144,4,state)])
 q['selector4_state']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w22')!=0x6e3,
  obj.read('w9')!=z3.If(state==base,resize(0x34e,32),resize(0x325,32)))
 obj=run('selector2_state',0xfffffe000a526c80,0xfffffe000a526cc0,
  {'sp':f,'w9':0x30a},cells=[(f+0x1f8,8,p),(p+0x144,4,state)])
 q['selector2_state']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w22')!=0x6e3,
  obj.read('w9')!=z3.If(state==base,resize(0x30a,32),resize(0x325,32)))
 for name,a,z,expected_state in [('state_one',0xfffffe000a5536ac,0xfffffe000a5536c4,base+1),('state_ten',0xfffffe000a5144f4,0xfffffe000a514508,base+10)]:
  obj=run(name,a,z,{'sp':f,'w8':0x6e3},cells=[(f+0x1f8,8,p)],writes=[(p+0x144,4)])
  q[name]=z3.Or(value(obj,p+0x144,4)!=expected_state,obj.read('w9')!=0x325)
 # Re-encoding prefix is the paired writer codec in the reader's frame.
 a,b=f+0x210,f+0x218
 obj=run('rewrap_seed_and_zero',0xfffffe000a527b28,0xfffffe000a527b54,{'sp':f},[(a,None)],cells=[
  (f+0x198,8,0xfffffe000ccc78b8),(f+0x1a0,8,0xfffffe000ccc78e0),
  (0xfffffe000ccc78e0,4,255),(0xfffffe000ccc78b8,8,0xfffffe000ccc78f4),(0xfffffe000ccc7910,4,seed)])
 q['rewrap_seed_and_zero']=z3.Or(obj.word(a)!=0,obj.read('w16')!=seed,obj.read('w9')!=seed*SEED_FACTOR,obj.read('x10')!=0)
 obj=run('rewrap_indices',0xfffffe000a527b54,0xfffffe000a527bec,{'w9':t})
 actual=[obj.read('w14'),obj.read('w13'),obj.read('w12'),obj.read('w11')]
 expected_indices=[]
 for d,magic,shift in [(7,0x24924925,None),(6,0xaaaaaaab,2),(5,0xcccccccd,2),(3,0xaaaaaaab,1)]:
  n=((t+d)^t)*FACTOR;h=z3.Extract(63,32,z3.ZeroExt(32,n)*magic)
  quotient=z3.LShR(z3.LShR(n-h,1)+h,2) if shift is None else z3.LShR(h,shift)
  expected_indices.append(n-quotient*d)
 q['rewrap_indices']=z3.Or(*[x!=y for x,y in zip(actual,expected_indices)],
  obj.vectors[0]!=resize(pack([t,t]),128),obj.vectors[1]!=resize(pack([resize(FACTOR,32)]*2),128))
 obj=run('rewrap_mask_and_context_save',0xfffffe000a527bec,0xfffffe000a527ca4,
  {'sp':f,'w8':0x6e3,'w9':t,**dict(zip(['w14','w13','w12','w11'],indices))},[(a,0),(b,None)],
  cells=[(f+0x1f8,8,p)],vectors=[(0,pack([t,t])),(1,pack([resize(FACTOR,32)]*2))],active=a)
 m=pack([t*t^t,(t*t+t)^t])
 q['rewrap_mask_and_context_save']=z3.And(bound,z3.Or(obj.word(a)!=m,obj.word(b)!=p,obj.vectors[0]!=resize(m,128),obj.read('w9')!=0x106))
 obj=run('rewrap_key',0xfffffe000a527ca4,0xfffffe000a527cb0,
  {'sp':f,'w2':SEED_FACTOR,'w16':seed},[(b,p)])
 q['rewrap_key']=obj.read('w16')!=((resize(p,32)*SEED_FACTOR)^seed)
 # Complete re-encoding block, distinct register allocation from population.
 key=z3.BitVec('rewrap_key32',32);offset=z3.BitVec('block_offset64',64);block=z3.BitVec('plain_block128',128)
 obj=run('rewrap_SIMD_setup',0xfffffe000a527cb0,0xfffffe000a527d04,{'w16':key})
 q['rewrap_SIMD_setup']=z3.Or(obj.vectors[1]!=pack([key]*4),*[
  obj.vectors[v]!=pack([resize(j,32) for j in range(start,start+4)]) for v,start in [(2,12),(3,8),(4,4),(5,0)]],
  obj.vectors[19]!=pack([resize(0x93,8)]*16),obj.vectors[20]!=pack([resize(16,32)]*4),*[
  obj.vectors[v]!=resize(int.from_bytes(IMAGE.read(addr,16),'little'),128) for v,addr in [(6,0xfffffe0007920f90),(7,0xfffffe0007920fa0),(16,0xfffffe0007920fb0),(17,0xfffffe0007920fc0),(18,0xfffffe0007920f80)]])
 vectors=[(v,pack([resize(offset,32)+j for j in range(start,start+4)])) for v,start in [(2,12),(3,8),(4,4),(5,0)]]
 vectors += [(1,pack([key]*4)),(19,pack([resize(0x93,8)]*16)),(20,pack([resize(16,32)]*4))]
 vectors += [(v,resize(int.from_bytes(IMAGE.read(addr,16),'little'),128)) for v,addr in [(6,0xfffffe0007920f90),(7,0xfffffe0007920fa0),(16,0xfffffe0007920fb0),(17,0xfffffe0007920fc0),(18,0xfffffe0007920f80)]]
 at=z3.simplify(p+offset)
 obj=run('rewrap_SIMD_body',0xfffffe000a527d04,0xfffffe000a527d7c,
  {'x15':p,'x10':offset},cells=[(at,16,block)],vectors=vectors,writes=[(at,16)])
 expected_bytes=[]
 for j,x in enumerate(lanes(block,8)):
  n=resize(offset,32)+j;expected_bytes.append((x^resize(key,8)^resize((n+key)*(n-key),8))*0x93)
 q['rewrap_SIMD_body']=obj.stores[0]['value']!=pack(expected_bytes)
 q['rewrap_SIMD_step']=z3.Or(obj.read('x10')!=offset+16,*[
  obj.vectors[v]!=pack([resize(offset+16,32)+j for j in range(start,start+4)]) for v,start in [(2,12),(3,8),(4,4),(5,0)]])
 idx=z3.BitVec('rewrap_word_index64',64);rem=z3.BitVec('rewrap_remainder32',32)
 obj=run('rewrap_shuffle_setup',0xfffffe000a527d84,0xfffffe000a527d90,{})
 q['rewrap_shuffle_setup']=z3.Or(obj.read('x10')!=63,obj.read('w3')!=FACTOR)
 obj=run('rewrap_shuffle_numerator',0xfffffe000a527d90,0xfffffe000a527d9c,{'w16':key,'x10':idx,'w3':FACTOR})
 q['rewrap_shuffle_numerator']=obj.read('w17')!=((key+resize(idx,32))^key)*FACTOR
 left,right=p+(idx<<3),p+(resize(rem,64)<<3);lv,rv=z3.BitVecs('rewrap_swap_left64 rewrap_swap_right64',64)
 obj=run('rewrap_swap',0xfffffe000a527da4,0xfffffe000a527dd0,
  {'x15':p,'x10':idx,'w17':rem},cells=[(left,8,lv),(right,8,rv)],writes=[(left,8),(right,8)])
 q['rewrap_swap']=z3.Or(value(obj,left,8)!=rv,value(obj,right,8)!=lv)
 obj=run('rewrap_shuffle_counter',0xfffffe000a527dd0,0xfffffe000a527ddc,{'x10':idx})
 q['rewrap_shuffle_counter']=z3.And(z3.UGE(idx,1),z3.ULE(idx,63),
  z3.Or(obj.read('x10')!=idx-1,(obj.cmp_left>obj.cmp_right)!=(idx>1)))
 obj=run('rewrap_pointer_permutation',0xfffffe000a527de0,0xfffffe000a527e58,
  {'sp':f,**dict(zip(['w14','w13','w12','w11'],indices))},[(b,p)],vectors=[(0,mask)],active=b)
 represented=affine(permutation(p,indices),mask)^mask
 q['rewrap_pointer_permutation']=z3.And(bound,obj.word(b)!=permutation(p,indices))
 obj=run('rewrap_pointer_affine',0xfffffe000a527e58,0xfffffe000a527e70,
  {'sp':f},[(b,p)],vectors=[(0,mask)])
 q['rewrap_pointer_affine']=obj.word(b)!=affine(p,mask)
 obj=run('rewrap_saved_word',0xfffffe000a527e70,0xfffffe000a527e80,{'sp':f},
  [(a,mask),(b,affine(permutation(p,indices),mask)),(f+0x1f8,None)])
 q['rewrap_saved_word']=obj.word(f+0x1f8)!=represented
 obj=run('rewrap_release_route',0xfffffe000a527e80,0xfffffe000a527ea0,{'w9':0x106})
 q['rewrap_release_route']=z3.Or(obj.read('w10')!=0x4d1,obj.read('w9')!=0x106)
 obj=run('rewrap_release_roots',0xfffffe000a527ea4,0xfffffe000a527eb4,
  {'sp':f},cells=[(f+0x1d8,8,0xfffffe000ccc2c80),(f+0x190,8,0xfffffe00079174c0)])
 q['rewrap_release_roots']=z3.Or(obj.read('w23')!=0xea5ebdeb,obj.read('x25')!=0xfffffe000ccc2c80,obj.read('x26')!=0xfffffe00079174c0)
 obj=run('release_bank_left_root',0xfffffe000a561508,0xfffffe000a56150c,
  {'x16':0xfffffe00084716e0},cells=[(0xfffffe00084719e8,8,0xfffffe00079174c0)])
 q['release_bank_left_root']=obj.read('x26')!=0xfffffe00079174c0
 obj=run('release_bank_right_root',0xfffffe000a561518,0xfffffe000a561520,
  {'sp':f,'x16':0xfffffe00084716e0},cells=[(0xfffffe0008471b00,8,0xfffffe0007919db0)],writes=[(f+0x1c0,8)])
 q['release_bank_right_root']=value(obj,f+0x1c0,8)!=0xfffffe0007919db0
 obj=run('release_next_target',0xfffffe000a52a50c,0xfffffe000a52a510,
  {'x28':TABLE,'w9':0x106},cells=[(TABLE+8*0x106,8,0xfffffe000a50ef94)])
 q['release_next_target']=obj.read('x20')!=0xfffffe000a50ef94
 # Release record uses null explicit pointer, choosing the cached domain.
 record=z3.BitVec('release_record64',64);lo=(resize(record,32)^0xdfb9786f)*0xe1d88903
 obj=run('release_record',0xfffffe000a52a510,0xfffffe000a52a560,{'x29':record+0xb0,'w8':0x6e3},writes=[(record,4),(record+8,8)])
 q['release_record']=z3.Or(value(obj,record,4)+lo!=0x1d3,value(obj,record+8,8)!=0)
 obj=run('release_return_join',0xfffffe000a52a5b4,0xfffffe000a52a5c0,
  {'sp':f},cells=[(f+0x1f4,4,0x6e3),(f+0x1ac,4,0x0636781f)])
 q['release_return_join']=z3.Or(obj.read('w8')!=0x6e3,obj.read('w10')!=0x0636781f)
 obj=run('result_store',0xfffffe000a50ef98,0xfffffe000a50efac,
  {'sp':f,'w21':status},cells=[(f+0x110,8,r)],writes=[(r+0x38,4)])
 q['result_store']=value(obj,r+0x38,4)!=status+0xf9c8e134
 obj=run('outer_result_zero_displacement',0xfffffe000a50e864,0xfffffe000a50e878,
  {'sp':f},cells=[(f+8,8,0),(f+0x50,4,status)])
 q['outer_result_zero_displacement']=z3.Or(obj.read('w0')!=status,obj.read('x0')!=z3.ZeroExt(32,status),obj.read('sp')!=f)
 negative={}
 u,limit=z3.BitVecs('decoded_accumulator64 normalized_limit64',64)
 for name,query in {
  'unsigned_selector_partition_is_different':z3.ULT(opcode,4)!=(opcode<4),
  'clock_predicate_does_not_establish_zero_return':z3.And(z3.ULT(u,limit),opcode==0,final==0x999,
   resize(0x06367832,32)+0xf9c8e134!=0)}.items():
  s=z3.Solver();s.set(timeout=10000);s.add(query);assert s.check()==z3.sat;model=s.model()
  negative[name]={'result':'sat','query':s.sexpr(),'model':{str(v):hex(model[v].as_long()) for v in model}}
 results={}
 for name,query in q.items():
  s=z3.Solver();s.set(timeout=10000);s.add(query);outcome=s.check();print(name,outcome,flush=True)
  assert outcome==z3.unsat,(name,str(outcome),s.reason_unknown())
  results[name]={'result':'unsat','query':s.sexpr()}
 return {'proofs':results,'negative_controls':negative,'source_lift_counts':counts,'source_pieces':pieces,
  'conditional_status32_map':{hex(v):hex((v+0xf9c8e134)&0xffffffff) for v in [0x06371ecc,0x06371ecb,0x0636782c,0x06367832]},
  'selected_contract':{'phase32':'0x6e3','selector_source':'original outer W1','signed_selector32':True,
   'common_operation_inputs':[1,2,4,5],'state144_bias32':'0x13f6f63f','object_extent_B':512,
   'outer_result_requires_zero_displacement':True,'cached_release_ownership_proven':False,
   'full_named_operation_completed':False,'native_epoch_matched':False,'daemon_request_lineage_proven':False},
  'verified_counts':{'queries_unsat':len(results),'negative_controls_sat':len(negative),
   'source_lifted_instances':sum(counts.values()),'source_pieces':len(pieces)},
  'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


def build():
 k=Kernel();spans=[]
 for label,(a,z) in SPANS.items():
  row=span(k,a,z);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
 output=prove({'spans':spans});slots={hex(i):original_pointer(k,TABLE+8*i) for i in INDICES}
 bank=selected(0xfffffe00079174c0,0xfffffe0007919db0,0x18,0x930,base=TABLE)
 bank['original_fixup']=original_pointer(k,int(bank['slot'],16))
 bank['left256_hex']=k.read(int(bank['left'],16),256).hex();bank['right256_hex']=k.read(int(bank['right'],16),256).hex()
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;audits={}
 for name,a,z,protected in [
  ('rewrap_middle',0xfffffe000a527ca4,0xfffffe000a527de0,{'x11','x12','x13','x14','v0','x9','sp','x29','x21'}),
  ('rewrap_zero_counter_preserved',0xfffffe000a527b54,0xfffffe000a527d04,{'x10','sp','x29','x21'})]:
  rows=[]
  for ins in cs.disasm(k.read(a,z-a),a):
   writes=[]
   for reg in ins.regs_access()[1]:
    n=ins.reg_name(reg);n={'fp':'x29','lr':'x30'}.get(n,n);n=re.sub(r'^w(?=\d)','x',n);writes.append(re.sub(r'^[bhsdq](?=\d)','v',n))
   assert not set(writes)&protected and not ins.mnemonic.startswith('bl'),(hex(ins.address),writes)
   rows.append({'pc':hex(ins.address),'writes':writes})
  audits[name]={'start':hex(a),'end':hex(z),'protected_registers':sorted(protected),'rows':rows,
   'indirect_object_writes_disjoint_from_frame_is_premise':True}
 output['verified_counts'].update(spans=len(spans),instructions=sum(len(s['instructions']) for s in spans),
  code_B=sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),original_slots=len(slots),bank_rules=1,bank_byte_inputs=256,
  preservation_audit_rows=sum(len(a['rows']) for a in audits.values()))
 reference=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(reference).splitlines(keepends=True)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,'normalized_image_sha256':sha(SOURCE),
  'spans':spans,'slots':slots,'release_bank':bank,'register_preservation_audits':audits,
  'bank_root_slots':{hex(a):original_pointer(k,a) for a in [0xfffffe00084719e8,0xfffffe0008471b00]},
  'constants':{'start':'0xfffffe0007920f10','bytes_hex':k.read(0xfffffe0007920f10,192).hex()},
  'supplied_reference':{'path':reference.name,'sha256':sha(reference),'excerpts':[
   {'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(41069,41390),(49932,49987)]]},
  'dependencies':{n:sha(ROOT/n) for n in ['recover_lskd_context_codec.py','lskd_context_codec_checks.json',
   'lskd_reader_lineage_checks.json','lskd_context_compare_checks.json','legacy_stack_proofs.json',
   'lskd_continuations_proofs.json','kernel_native_reader.py','kext_port_tools.py','recover_kext_cold_init.py',
   'recover_aes_cleanup_epoch.py','lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py']},
  'solver_version':z3.get_version_string(),**output}


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
 output=build();path=ROOT/'lskd_context_return_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
