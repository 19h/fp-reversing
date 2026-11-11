#!/usr/bin/env python3
"""Operation 1/5 byte-span split, shared builder and bounded alias-aware copies.

Original-source scalar/array certificates. The threshold selects source arms;
short-arm scratch origins, native epochs and whole-operation overlap behavior
remain open. Extraction O(N+I+M) time/space for source/index bytes N, lifted
instances I and retained memory events M; SMT cost separate. No target executes.
"""
import argparse
import json

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG

from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from recover_lskd_operation_preflight import PreflightLift,POOL
from recover_lskd_context_return import TABLE
from lskd_values_symbolic import resize,part
from verify_daemon_reader_record_payloads_publication import read,sha

C=0xc9e6da8e97b74733
M=0x2f6e8e66
F=0xfffffe0053000000
SPANS={
 'threshold':(0xfffffe000a535ad8,0xfffffe000a535b34),
 'block_split':(0xfffffe000a57f8e8,0xfffffe000a57f970),
 'small_arm':(0xfffffe000a51a934,0xfffffe000a51a9b0),
 'builder':(0xfffffe000a55b624,0xfffffe000a55b858),
 'phase_hop':(0xfffffe000a52e530,0xfffffe000a52e54c),
 'dispatch_hop':(0xfffffe000a5237d8,0xfffffe000a5237f0),
 'pointer_dispatch':(0xfffffe000a52dfc4,0xfffffe000a52e028),
 'backward_gate':(0xfffffe000a5148a0,0xfffffe000a5148cc),
 'forward_gate':(0xfffffe000a529488,0xfffffe000a5294d4),
 'backward_setup':(0xfffffe000a51a1b0,0xfffffe000a51a224),
 'backward_tail':(0xfffffe000a51236c,0xfffffe000a5123b4),
 'backward_bulk_gate':(0xfffffe000a533e30,0xfffffe000a533e74),
 'backward_bulk_setup':(0xfffffe000a535888,0xfffffe000a5358c8),
 'backward_bulk':(0xfffffe000a519aec,0xfffffe000a519b74),
 'forward_setup':(0xfffffe000a5603c0,0xfffffe000a560410),
 'forward_pair_setup':(0xfffffe000a53285c,0xfffffe000a53287c),
 'forward_pairs':(0xfffffe000a5776c4,0xfffffe000a577718),
 'forward_odd_gate':(0xfffffe000a57dd3c,0xfffffe000a57dd70),
 'forward_odd':(0xfffffe000a5157c4,0xfffffe000a5157e4),
 'copy_return':(0xfffffe000a545d44,0xfffffe000a545d74),
 'suffix_entry':(0xfffffe000a55db14,0xfffffe000a55db34),
 'suffix_roots':(0xfffffe000a5285a8,0xfffffe000a5285d0),
 'bulk_gate':(0xfffffe000a535784,0xfffffe000a5357b8),
 'bulk_frontier':(0xfffffe000a518008,0xfffffe000a51805c),
}


class ByteLift(PreflightLift):
 def __init__(self,*args):
  super().__init__(*args);self.byte_memory=z3.Array('initial_byte_memory',z3.BitVecSort(64),z3.BitVecSort(8))
  self.initial_memory=self.byte_memory;self.byte_events=[];self.table_loads=[]
 def load(self,address,n):
  a=z3.simplify(resize(address,64));key=(a.sexpr(),n)
  if key in self.fixed:return super().load(a,n)
  if n==8 and z3.is_bv_value(a) and TABLE<=a.as_long()<POOL:
   at=a.as_long();assert (at-TABLE)%8==0
   value=int.from_bytes(IMAGE.read(at,8),'little');self.table_loads.append({'pc':hex(self.pc),'slot':hex(at),'target':hex(value)})
   return resize(value,64)
  if n==1:
   # Relational read normalization: every earlier write/read inequality is
   # retained and proved from source direction/ranges below. The generic
   # array read-over-write lemmas justify this snapshot expression.
   value=z3.Select(self.initial_memory,a);self.byte_events.append(('load',self.pc,a,value));return value
  return super().load(a,n)
 def store(self,address,n,value,pc):
  a=z3.simplify(resize(address,64))
  if z3.is_bv_value(a) and F<=a.as_long()<a.as_long()+n<=F+0x350:
   self.fixed_stores.add((a.sexpr(),n));return super().store(a,n,value,pc)
  if n==1:
   v=resize(value,8);self.byte_memory=z3.Store(self.byte_memory,a,v)
   self.byte_events.append(('store',pc,a,v));return
  return super().store(a,n,value,pc)
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  data=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(data,int(row['start'],16)));assert len(insns)*4==len(data)
  for ins in insns:
   self.pc=ins.address;m=ins.mnemonic;o=ins.operands
   if m in ['lsl','lsr'] and o[2].type==ARM64_OP_REG:
    d,a,b=[ins.reg_name(x.reg) for x in o];width=self.width(d);shift=resize(self.read(b),width)&(width-1)
    self.write(d,self.read(a)<<shift if m=='lsl' else z3.LShR(self.read(a),shift));self.count+=1
   elif m=='umull' and ins.reg_name(o[0].reg).startswith('x'):
    d,a,b=[ins.reg_name(x.reg) for x in o];self.write(d,z3.ZeroExt(32,self.read(a))*z3.ZeroExt(32,self.read(b)));self.count+=1
   elif m=='adds':
    d=ins.reg_name(o[0].reg);width=self.width(d);v=self.operand(ins,o[1],width)+self.operand(ins,o[2],width)
    self.write(d,v);self.equal=self.read(d)==0;self.cmp_left=self.read(d);self.cmp_right=resize(0,width);self.count+=1
   elif m=='csinc':
    assert ins.op_str.endswith(', ne');d,a,b=[ins.reg_name(x.reg) for x in o[:3]]
    self.write(d,z3.If(z3.Not(self.equal),self.read(a),self.read(b)+1));self.count+=1
   elif m=='cset' and ins.op_str.endswith(', hi'):
    self.write(ins.reg_name(o[0].reg),z3.If(z3.UGT(self.cmp_left,self.cmp_right),resize(1,32),resize(0,32)));self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def prove(capture):
 q={};counts={};pieces={};loads={};cases=[]
 array=z3.Array('array_lemma_memory',z3.BitVecSort(64),z3.BitVecSort(8))
 wa,ra=z3.BitVecs('array_write_address64 array_read_address64',64);bv=z3.BitVec('array_byte8',8)
 q['array_read_over_write_unequal']=z3.And(wa!=ra,z3.Select(z3.Store(array,wa,bv),ra)!=z3.Select(array,ra))
 q['array_read_over_write_equal']=z3.Select(z3.Store(array,wa,bv),wa)!=bv
 n=z3.BitVec('original_X4_low32',32);op=z3.BitVec('original_W1_32',32)
 h=z3.If(op==1,resize(16,32),resize(0,32));r=n&15;rounded=n&0xfffffff0;bulk=rounded-h
 admitted=z3.And(z3.Or(op==1,op==5),z3.UGE(n,h+16))
 src,dst,outer,context=z3.BitVecs('original_X2_source64 original_X3_destination64 outer_record64 working_context64',64)
 def run(name,a,z,seeds=(),cells=(),obj=None):
  obj=obj or ByteLift(part(capture,name,a,z));obj.c=part(capture,name,a,z)
  for reg,v in dict(seeds).items():obj.seed(reg,v)
  for at,width,v in cells:obj.fixed[(z3.simplify(resize(at,64)).sexpr(),width)]=resize(v,width*8)
  before=obj.count;obj.run(name);used=obj.count-before;assert used==(z-a)//4
  if name not in pieces:pieces[name]={'start':hex(a),'end':hex(z),'instructions':used,'instances':0}
  assert pieces[name]['start']==hex(a) and pieces[name]['end']==hex(z)
  pieces[name]['instances']+=1;counts[name]=counts.get(name,0)+used
  for row in obj.table_loads:loads[row['slot']]=row['target']
  return obj
 def val(obj,off,width):return obj.fixed[(resize(F+off,64).sexpr(),width)]
 v=run('block_split',0xfffffe000a57f8ec,0xfffffe000a57f93c,
  {'sp':F,'w8':0x11e,'x5':resize(n,64),'x10':resize(h,64),'x28':TABLE})
 q['block_split_fields']=z3.Or(val(v,0x24,4)!=h+r,val(v,0x74,4)!=n-h-r,
  val(v,0x98,8)!=z3.ZeroExt(32,rounded),val(v,0x18,8)!=resize(h,64),v.read('w13')!=0x6ab,
  v.read('x9')!=C-resize(h,64),v.read('x11')!=0xfffffe000a55b624,v.read('x2')!=C)
 q['admitted_span_partition']=z3.And(admitted,z3.Or(z3.ULT(bulk,16),(bulk&15)!=0,
  h+bulk+r!=n,z3.UGT(rounded,n),z3.UGT(h,rounded),z3.UGT(r,15)))
 v=run('small_arm',0xfffffe000a51a938,0xfffffe000a51a980,
  {'sp':F,'w12':0x11b,'x5':resize(n,64),'x28':TABLE})
 q['short_arm_count_bound']=z3.And(z3.Or(op==1,op==5),z3.ULT(n,h+16),z3.UGT(n,31))
 q['small_arm_shared_target']=z3.Or(v.read('w13')!=0x6ab,v.read('x11')!=0xfffffe000a55b624,v.read('w8')!=0x11b,v.read('x9')!=resize(n,64)+C-((resize(n,64)<<1)&M))
 # Source frame values outside the new split remain independent unknowns.
 aux10,aux14,aux124,aux1e4=z3.BitVecs('scratch10_32 scratch14_32 scratch124_32 scratch1e4_32',32)
 old70=z3.BitVec('short_arm_old70_32',32)
 v=run('block_split_constants',0xfffffe000a57f93c,0xfffffe000a57f968,{'sp':F},[(F+0x124,4,aux124)])
 q['block_split_constants']=z3.Or(v.read('x10')!=0x7ed6766d7e6951b1,v.read('x12')!=0x4360c2459cc8eba4,v.read('w3')!=M,v.read('w4')!=aux124)
 v=run('small_arm_constants',0xfffffe000a51a980,0xfffffe000a51a9a8,{'sp':F},[(F+0x70,4,old70),(F+0x124,4,aux124)])
 q['small_arm_constants']=z3.Or(v.read('x10')!=0x7ed6766d7e6951b1,v.read('x12')!=0x4360c2459cc8eba4,v.read('w16')!=old70,v.read('w4')!=aux124)
 v=run('builder_metadata',0xfffffe000a55b628,0xfffffe000a55b7ec,
  {'sp':F,'w13':0x6ab,'x5':resize(n,64),'x2':C,'x3':M,'w16':r,'w4':aux124},
  [(F+0x110,8,outer),(outer+0x10,8,dst),(F+0x98,8,z3.ZeroExt(32,rounded)),
   (F+0x1e4,4,aux1e4),(F+0x14,4,aux14),(F+0x10,4,aux10),(F+0x1e8,8,src),
   (F+0x1f8,8,context),(F+0x74,4,bulk),(F+0x24,4,h+r)])
 encode=lambda x:resize(x,64)+C-((resize(x,64)<<1)&M)
 q['suffix_base_metadata']=z3.Or(val(v,0x178,8)!=0x7ed6766d7e6951b1+resize(rounded,64),
  val(v,0x170,8)!=0x4360c2459cc8eba4+resize(rounded,64),val(v,0x168,8)!=encode(r))
 q['builder_source_destination']=z3.Or(v.read('x6')!=dst,v.read('x17')!=src,v.read('w11')!=0x389,
  val(v,0x50,8)!=dst+resize(aux10,64),val(v,0x58,8)!=src+resize(aux10,64),val(v,0x90,8)!=context+0x134)
 q['builder_full_arm_status']=z3.And(admitted,z3.Or(val(v,0x4c,4)!=0x06371ecc,val(v,0x48,4)!=0))
 v=run('builder_handler',0xfffffe000a55b820,0xfffffe000a55b824,{'x28':TABLE,'w13':0x6ab})
 q['builder_handler']=v.read('x13')!=0xfffffe000a52e530
 scratch120=z3.BitVec('scratch120_32',32)
 v=run('builder_handoff',0xfffffe000a55b824,0xfffffe000a55b850,
  {'sp':F,'x30':0x6e3,'x6':dst,'x17':src},[(F+0x120,4,scratch120)])
 q['builder_handoff']=z3.Or(v.read('x14')!=src,v.read('x15')!=dst,val(v,0x1b8,8)!=dst,
  v.read('w16')!=0x3a0,v.read('w1')!=0x2b,v.read('w0')!=scratch120,v.read('w22')!=0x53,v.read('x21')!=resize(-0x6e7,64))
 v=run('source_pointer_preparation',0xfffffe000a55b7ec,0xfffffe000a55b7fc,{'sp':F,'x17':src},[(F+0x18,8,resize(h,64))])
 tagmask=resize(0xffc0000000000000,64)
 q['source_pointer_preparation']=z3.Or(v.read('x15')!=src+resize(h,64),v.equal!=(((src^(src+resize(h,64)))&tagmask)==0))
 v=run('destination_pointer_preparation',0xfffffe000a55b808,0xfffffe000a55b814,{'x6':dst,'x14':resize(h,64)})
 q['destination_pointer_preparation']=z3.Or(v.read('x15')!=dst+resize(h,64),v.equal!=(((dst^(dst+resize(h,64)))&tagmask)==0))
 raw_pointer=z3.BitVec('pointer_before_high16_replacement64',64)
 v=run('pointer_high16_replacement',0xfffffe000a55b800,0xfffffe000a55b804,{'x15':raw_pointer})
 q['pointer_high16_replacement']=v.read('x15')!=((raw_pointer&0x0000ffffffffffff)|0xc8a2000000000000)
 lo=z3.BitVec('copy_length32',32)
 q['copy_length_decode_low32']=(resize(encode(lo),32)^resize(C,32))!=lo
 # Pointer comparison strips the source's additive masks and yields original roots.
 v=run('pointer_dispatch',0xfffffe000a52dfc8,0xfffffe000a52e01c,
  {'x28':TABLE,'w8':0x11e,'w13':0x78b,'x12':0x4360c2459cc8eba4,'x10':0x7ed6766d7e6951b1,'x14':src,'x15':dst})
 q['pointer_direction_and_zero_offsets']=z3.Or(v.read('x11')!=0xfffffe000a55db14,v.read('x8')!=0,v.read('x10')!=0,v.read('w16')!=0x600,
  v.read('w12')!=z3.If(z3.UGT(src,dst),resize(0x7a6,32),resize(0x78b,32)))
 v=run('short_pointer_dispatch',0xfffffe000a52dfc8,0xfffffe000a52e01c,
  {'x28':TABLE,'w8':0x11b,'w13':0x78b,'x12':0x4360c2459cc8eba4,'x10':0x7ed6766d7e6951b1,'x14':src,'x15':dst})
 q['short_arm_reencoding_continuation']=v.read('x11')!=0xfffffe000a527b24
 v=run('suffix_pointer_dispatch',0xfffffe000a52dfc8,0xfffffe000a52e01c,
  {'x28':TABLE,'w8':0x149,'w13':0x78b,'x12':0x4360c2459cc8eba4+resize(rounded,64),
   'x10':0x7ed6766d7e6951b1+resize(rounded,64),'x14':src,'x15':dst})
 q['suffix_pointer_direction_and_offsets']=z3.Or(v.read('x8')!=resize(rounded,64),v.read('x10')!=resize(rounded,64),
  v.read('w12')!=z3.If(z3.UGT(src+resize(rounded,64),dst+resize(rounded,64)),resize(0x7a6,32),resize(0x78b,32)))
 v=run('phase_hop',0xfffffe000a52e534,0xfffffe000a52e540,{'x28':TABLE,'w11':0x389,'w16':0x3a0,'w1':0x2b})
 q['phase_hop']=z3.Or(v.read('w16')!=0x6e3,v.read('x11')!=0xfffffe000a5237d8)
 v=run('dispatch_hop',0xfffffe000a5237dc,0xfffffe000a5237e8,{'x28':TABLE,'w16':0x6e3})
 q['dispatch_hop']=z3.Or(v.read('w13')!=0x78b,v.read('x11')!=0xfffffe000a52dfc4)
 # Generic byte-copy helper for every length required by prefix/suffix passes.
 rows={int(s['start'],16):s for s in capture['spans']}
 copy_starts={0xfffffe000a5148a0,0xfffffe000a529488,0xfffffe000a51a1b0,0xfffffe000a51236c,
  0xfffffe000a533e30,0xfffffe000a535888,0xfffffe000a519aec,0xfffffe000a5603c0,
  0xfffffe000a53285c,0xfffffe000a5776c4,0xfffffe000a57dd3c,0xfffffe000a5157c4}
 copy_results={};offset=z3.BitVec('common_byte_offset64',64)
 for direction,start in [('backward',0xfffffe000a5148a0),('forward',0xfffffe000a529488)]:
  for length in range(32):
   obj=ByteLift(capture)
   for reg,value in {'sp':F,'x28':TABLE,'x14':src-offset,'x15':dst-offset,'x8':offset,'x10':offset,'w16':0x600,
    'x9':C+length-((2*length)&M),'x21':(-0x6e7)&((1<<64)-1),'w22':0x53,'x30':0x6e3}.items():obj.seed(reg,value)
   current=start;visits=[]
   while current!=0xfffffe000a545d44:
    assert current in copy_starts and len(visits)<40,(direction,length,hex(current),visits)
    row=rows[current];end=int(row['end'],16);label='copy_'+row['label']
    obj=run(label,current+4,end-8,obj=obj);visits.append(hex(current))
    branch=row['instructions'][-1];assert branch['mnemonic']=='braa'
    current=z3.simplify(obj.read(branch['operands'].split(',')[0])).as_long()
   reads=[e for e in obj.byte_events if e[0]=='load'];writes=[e for e in obj.byte_events if e[0]=='store']
   assert len(reads)==len(writes)==length
   order=list(range(length-1,-1,-1)) if direction=='backward' else list(range(length))
   assert all(z3.simplify(e[2]-src).as_long()==j for e,j in zip(reads,order))
   assert all(z3.simplify(e[2]-dst).as_long()==j for e,j in zip(writes,order))
   valid=z3.And(z3.ULE(src,resize((1<<64)-1-length,64)),z3.ULE(dst,resize((1<<64)-1-length,64)))
   ordering=z3.ULE(src,dst) if direction=='backward' else z3.UGT(src,dst)
   bad=z3.simplify(z3.Or(*[z3.Select(obj.byte_memory,dst+j)!=z3.Select(obj.initial_memory,src+j) for j in range(length)]))
   previous=[];clauses=[]
   for event in obj.byte_events:
    if event[0]=='load':clauses.extend(event[2]!=address for address in previous)
    else:previous.append(event[2])
   no_interference=z3.And(*clauses)
   q['copy_order_'+direction+'_'+str(length)]=z3.And(valid,ordering,z3.Not(no_interference))
   q['copy_'+direction+'_'+str(length)]=z3.And(no_interference,bad)
   assert all(z3.eq(z3.simplify(read[3]),z3.simplify(write[3])) for read,write in zip(reads,writes)),(direction,length)
   exact=obj.initial_memory;last=None
   for event in obj.byte_events:
    if event[0]=='load':last=z3.Select(exact,event[2])
    else:assert last is not None;exact=z3.Store(exact,event[2],last);last=None
   exact_bad=z3.Or(*[z3.Select(exact,dst+j)!=z3.Select(obj.initial_memory,src+j) for j in range(length)])
   copy_results[(direction,length)]=(obj,valid,exact_bad)
   cases.append({'arbitrary_common_offset64':True,'read_over_write_premises_proven':True,'direction':direction,'length_B':length,'source_offsets_B':order,'destination_offsets_B':order,
    'visits':visits,'exit':hex(current),'table_loads':obj.table_loads})
 # Post-copy return selects the saved continuation and publishes private zero.
 saved27,saved10=z3.BitVecs('saved_1e4_32 saved_1f0_32',32)
 v=run('copy_return',0xfffffe000a545d48,0xfffffe000a545d6c,
  {'sp':F,'x30':0x6e3},[(F+0x1e4,4,saved27),(F+0x1c8,8,1),(F+0x1d0,8,2),(F+0x1f0,4,saved10)])
 q['copy_return']=z3.Or(v.read('w21')!=0x06371ecc,v.read('w22')!=0,v.read('w8')!=0x6e3,v.read('w27')!=saved27,v.read('w10')!=saved10)
 q['short_copy_conditional_outer_zero']=(v.read('w21')+0xf9c8e134)!=0
 v=run('suffix_entry',0xfffffe000a55db18,0xfffffe000a55db2c,
  {'sp':F,'x30':0x6e3,'x28':TABLE},[(F+0x170,8,0x4360c2459cc8eba4+resize(rounded,64)),
   (F+0x178,8,0x7ed6766d7e6951b1+resize(rounded,64)),(F+0x168,8,encode(r))])
 q['suffix_entry']=z3.Or(v.read('w8')!=0x149,v.read('x11')!=0xfffffe000a5285a8,v.read('x9')!=encode(r))
 v=run('suffix_roots',0xfffffe000a5285ac,0xfffffe000a5285c8,
  {'sp':F,'x30':0x6e3,'x28':TABLE},[(F+0x1b8,8,dst),(F+0x1e8,8,src)])
 q['suffix_roots']=z3.Or(v.read('x14')!=src,v.read('x15')!=dst,v.read('x11')!=0xfffffe000a52dfc4,
  v.read('w13')!=0x78b,v.read('x21')!=resize(-0x6e7,64),v.read('w22')!=0x53)
 v=run('bulk_gate',0xfffffe000a535788,0xfffffe000a5357a8,
  {'sp':F,'x30':0x6e3},[(F+0x48,4,0),(F+0x4c,4,0x06371ecc)])
 q['bulk_gate']=z3.Or(v.read('w8')!=0x963,v.read('w21')!=0x06371ecc,v.read('w9')!=0x17)
 prepared_src,prepared_dst=z3.BitVecs('prepared_source64 prepared_destination64',64)
 v=run('bulk_frontier',0xfffffe000a51800c,0xfffffe000a518054,{'sp':F,'w9':0x17,'x28':TABLE},
  [(F+0x90,8,context+0x134),(F+0x38,8,prepared_dst),(F+0x40,8,prepared_src),(F+0x74,4,bulk)])
 q['bulk_frontier']=z3.Or(val(v,0x6c,4)!=0,val(v,0xd8,8)!=prepared_dst,val(v,0xe0,8)!=prepared_src,
  v.read('w0')!=bulk,v.read('x14')!=context+0x134,v.read('x10')!=0xfffffe000a5722b8)
 results={}
 for name,query in q.items():
  s=z3.Solver();s.set(timeout=10000);s.add(query);result=s.check();print(name,result,flush=True)
  assert result==z3.unsat,(name,str(result),s.reason_unknown());results[name]={'result':'unsat','query':s.sexpr()}
 obj,valid,bad=copy_results[('backward',2)]
 control=z3.And(valid,src==dst+1,bad);s=z3.Solver();s.add(control);assert s.check()==z3.sat
 negative={'wrong_direction_can_change_snapshot_copy':{'result':'sat','query':s.sexpr(),
  'source':hex(s.model().eval(src).as_long()),'destination':hex(s.model().eval(dst).as_long()),'length_B':2,
  'native_target_state':False}}
 return {'proofs':results,'negative_controls':negative,'source_pieces':pieces,'source_lift_counts':counts,
  'table_loads':loads,'byte_copy_cases':cases,'verified_counts':{'queries_unsat':len(results),'negative_controls_sat':1,
   'source_pieces':len(pieces),'source_lifted_instances':sum(counts.values()),'byte_copy_cases':len(cases),
   'byte_copy_loads':sum(c['length_B'] for c in cases),'byte_copy_stores':sum(c['length_B'] for c in cases)},
  'selected_contract':{'original_operations':[1,5],'full_split_minimum_N':{'1':32,'5':16},
   'threshold_is_complete_rejection_test':False,'N_is_low32_original_X4':True,'source_is_original_X2':True,
   'destination_is_original_X3':True,'bounded_copy_lengths_B':list(range(32)),
   'arbitrary_common_offset64':True,'relational_read_normalization_uses_proven_array_lemmas':True,'per_pass_snapshot_only':True,'whole_operation_overlap_contract_proven':False,'short_arm_scratch_origins_proven':False,
   'native_epoch_matched':False,'daemon_request_lineage_proven':False},
  'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


def build():
 k=Kernel();spans=[]
 for label,(a,z) in SPANS.items():
  row=span(k,a,z);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
 output=prove({'spans':spans});addresses={int(a,16) for a in output['table_loads']}
 addresses|={TABLE+8*i for i in [0x996,0x988,0x262,0x6ab,0x389,0x33c,0x78b,0x7a6,0x11e,0x11b,0x149,0x963]}
 slots={hex(a):pointer(k,a) for a in sorted(addresses)}
 output['verified_counts'].update(spans=len(spans),instructions=sum(len(s['instructions']) for s in spans),
  code_B=sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),original_loaded_slots=len(output['table_loads']),original_slots=len(slots))
 source=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(source).splitlines(keepends=True)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
  'normalized_image_sha256':sha(SOURCE),'spans':spans,'slots':slots,'solver_version':z3.get_version_string(),
  'supplied_reference':{'path':source.name,'sha256':sha(source),'excerpts':[
   {'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(28791,28800),(79137,79193),(109621,109695)]]},
  'dependencies':{n:sha(ROOT/n) for n in ['recover_lskd_operation_preflight.py','lskd_operation_preflight_checks.json',
   'lskd_context_return_checks.json','lskd_reader_lineage_checks.json','kernel_native_reader.py','kext_port_tools.py',
   'recover_kext_cold_init.py','recover_aes_cleanup_epoch.py','lskd_values_symbolic.py',
   'verify_daemon_reader_record_payloads_publication.py']},**output}


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
 output=build();path=ROOT/'lskd_byte_spans_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
