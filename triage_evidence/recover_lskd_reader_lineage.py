#!/usr/bin/env python3
"""Named-wrapper lineage, reader frame origins and context byte gate.

Static source/fixup/bank certificates. The intervening context transform is
captured with a bounded register/store audit, without a numerical pointer/data
codec theorem. Valid access, stable epochs and returning calls remain premises.
No target execution or IDB change. O(N+I+W+256R) extraction time/space for input
bytes/indexes N, retained instructions I, text words W and bank rules R; SMT cost
separate. Scalar expression construction is O(I).
"""
import argparse
import bisect
import hashlib
import json
import struct

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM

from kext_port_tools import ROOT,SOURCE,IMAGE,selected,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from recover_aes_cleanup_epoch import span
from recover_lskd_context_compare import CompareLift
from lskd_values_symbolic import part,mem,cell,resize
from verify_daemon_reader_record_payloads_publication import read,sha

TABLE=0xfffffe000846c420
POOL=0xfffffe00084716e0
SPANS={
 'outer':(0xfffffe000a50e618,0xfffffe000a50e8a8),
 'bridge':(0xfffffe000a570cf4,0xfffffe000a570f0c),
 'inner_entry':(0xfffffe000a561344,0xfffffe000a561600),
 'nonnull_input':(0xfffffe000a592994,0xfffffe000a5929c0),
 'acquire_dispatch':(0xfffffe000a5294d4,0xfffffe000a5295d0),
 'vector_presence':(0xfffffe000a595708,0xfffffe000a59574c),
 'first_tag':(0xfffffe000a536720,0xfffffe000a536798),
 'shared_release_route':(0xfffffe000a536908,0xfffffe000a536924),
 'release_dispatch':(0xfffffe000a52a508,0xfffffe000a52a5c8),
 'first_status':(0xfffffe000a5362a0,0xfffffe000a5362ec),
 'second_tag':(0xfffffe000a539780,0xfffffe000a5397e4),
 'second_acquire_route':(0xfffffe000a57e830,0xfffffe000a57e850),
 'third_tag':(0xfffffe000a577718,0xfffffe000a57775c),
 'vector_slot':(0xfffffe000a55c958,0xfffffe000a55c9c4),
 'context_transform':(0xfffffe000a5315b0,0xfffffe000a531914),
 'context_save':(0xfffffe000a50fa5c,0xfffffe000a50fa80),
 'status_route':(0xfffffe000a54d474,0xfffffe000a54d4cc),
 'context_presence':(0xfffffe000a514c44,0xfffffe000a514c88),
 'flag_producer':(0xfffffe000a528f8c,0xfffffe000a5290d0),
 'flag_decoder':(0xfffffe000a52f730,0xfffffe000a52f7d0),
 'time_presence':(0xfffffe000a526d80,0xfffffe000a526e14),
 'reader':(0xfffffe000a517624,0xfffffe000a517898),
 'sysctl_wrapper':(0xfffffe000a508d74,0xfffffe000a508d7c),
 'sysctl_stub':(0xfffffe000a69f3b4,0xfffffe000a69f3c4),
}
B=(0xfffffe00079172c0,0xfffffe0007919cb0)
C=(0xfffffe0007920d10,0xfffffe00079173c0)
D=(0xfffffe000791d3b0,0xfffffe0007920e10)
E=(0xfffffe00079174c0,0xfffffe0007919db0)
F=(0xfffffe0007920c10,0xfffffe00079170c0)
G=(0xfffffe00079171c0,0xfffffe0007919bb0)
RULES={
 'dispatch_table':(B,0x27,0x2a,POOL,-8,0xfffffe000846c420),
 'controller_A':(C,0x2f,0x91,POOL,0,0xfffffe000ccc2c80),
 'controller_B':(D,0xe3,-0xa6,POOL,0,0xfffffe000ccc2c60),
 'tag_table':(D,0x65,-0x71,POOL,-8,0xfffffe000ccc7b08),
 'seed_cell':(D,0x65,-0x32,POOL,0,0xfffffe000ccc78b8),
 'flag_cell':(E,0x18,-0xd5,POOL,0,0xfffffe000ccc78e0),
 'vector_cell':(B,0x8d,0x68,POOL,0,0xfffffe000ccc78d0),
 'cached_acquire':(F,0xaa,0x90a,TABLE,0,0xfffffe000a54e220),
 'cached_release':(E,0x18,0x930,TABLE,0,0xfffffe000a551f38),
 'flag_decoder':(E,0x18,0x92f,TABLE,0,0xfffffe000a52f730),
 'time_cell':(C,0xbb,-0x69,POOL,-4,0xfffffe000ccc78c0),
 'reader_acquire':(B,0x27,0x94d,TABLE,0,0xfffffe000a54e220),
 'reader_sysctl':(F,0x20,0x9a7,TABLE,0,0xfffffe000a508d74),
 'reader_release':(G,0x58,0x984,TABLE,0,0xfffffe000a551f38),
 'reader_comparator':(C,0x2f,0x9fe,TABLE,0,0xfffffe000a52f458),
}
INDICES=[0x6e3,0x703,0x3e2,0xb6,0xcc,0x53a,0x577,0x4b4,0x4d1,0x10d,0x778,
 0x629,0x658,0x895,0x896,0x1ca,0x1e9,0x121,0x865,0x106,0x2a1,0x2ab,0x13e,0x155,0x71a,0x737]


class OriginLift(CompareLift):
 def load(self,address,width):
  address=z3.simplify(resize(address,64));key=(address.sexpr(),width)
  if key in self.memory:return super().load(address,width)
  assert z3.is_bv_value(address) and POOL<=address.as_long()<address.as_long()+width<=POOL+0x880,('unseeded origin read',address,width)
  return resize(int.from_bytes(IMAGE.read(address.as_long(),width),'little'),width*8)
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  data=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(data,int(row['start'],16)));assert len(insns)*4==len(data)
  for ins in insns:
   self.pc=ins.address
   if ins.mnemonic=='adrp':self.write(ins.reg_name(ins.operands[0].reg),ins.operands[1].imm);self.count+=1
   elif ins.mnemonic=='ldr' and ins.writeback:
    op=ins.operands[1];address=self.address(ins,op);dest=ins.reg_name(ins.operands[0].reg)
    self.write(dest,self.load(address,self.width(dest)//8));self.write(ins.reg_name(op.mem.base),address);self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def prove(capture):
 q={};counts={};controls={};f=0x51000000
 r=z3.BitVec('record64',64);context=z3.BitVec('context_key64',64)
 entry_key=(r^0x4bb20883b0a65f3a)*0x4ca11177
 phase=z3.BitVec('decoded_phase32',32)
 def bit(p):return z3.If(p,z3.BitVecVal(1,32),z3.BitVecVal(0,32))
 def run(label,a,z,seeds,cells=()):
  obj=OriginLift(part(capture,label,a,z))
  for reg,v in seeds.items():obj.seed(reg,v)
  for addr,n,v in cells:mem(obj,addr,n,v)
  obj.run(label);counts[label]=obj.count;return obj

 inputs=[z3.BitVec('outer_input'+str(i)+'_64',64) for i in range(8)]
 obj=run('outer_record',0xfffffe000a50e71c,0xfffffe000a50e78c,
  {'sp':r-0x18,**{'x'+str(i):v for i,v in enumerate(inputs)}})
 outer_key=obj.values[(0xfffffe000a50e754,'w16')]
 q['outer_record_fields']=z3.Or(cell(obj,r,4)!=outer_key+resize(inputs[7],32),
  cell(obj,r+4,4)!=(outer_key^0x6e3),cell(obj,r+8,4)!=resize(inputs[4],32)-outer_key,
  cell(obj,r+16,8)!=inputs[3],cell(obj,r+24,4)!=(outer_key^resize(inputs[6],32)),
  cell(obj,r+32,8)!=inputs[5],cell(obj,r+40,8)!=inputs[2],cell(obj,r+48,8)!=inputs[0],
  cell(obj,r+60,4)!=resize(inputs[1],32)-outer_key)
 obj=run('entry_key',0xfffffe000a561464,0xfffffe000a5614a0,{'x0':r,'x8':~r})
 q['entry_key']=obj.read('x17')!=entry_key
 q['aligned_outer_entry_key_join']=z3.And((r&1)==0,outer_key!=resize(entry_key,32))
 q['aligned_outer_selector_join']=z3.And((r&1)==0,((outer_key^0x6e3)^resize(entry_key,32))!=0x6e3)
 controls['odd_record_key_join_fails']=z3.And((r&1)!=0,outer_key!=resize(entry_key,32))
 obj=run('entry_phase_and_record',0xfffffe000a561528,0xfffffe000a561538,
  {'sp':f,'x0':r,'x17':entry_key},[(r+4,4,phase^resize(entry_key,32))])
 q['entry_saved_record_and_phase']=z3.Or(cell(obj,f+0x110,8)!=r,cell(obj,f+0xe8,8)!=entry_key,obj.read('w15')!=phase)
 obj=run('entry_context_key',0xfffffe000a5614a0,0xfffffe000a5614b8,
  {'sp':f,'x0':r},[(r+48,8,context)])
 q['entry_context_key']=z3.Or(cell(obj,f+0xa8,8)!=context,obj.read('w8')!=bit(context!=0)*0x1e0)
 obj=run('entry_table',0xfffffe000a561538,0xfffffe000a56154c,
  {'x16':POOL,'w9':0x61,'w8':bit(context!=0)*0x1e0,'w15':phase})
 q['entry_table_and_partition']=z3.Or(obj.read('x28')!=TABLE,obj.read('w8')!=(phase^(bit(context!=0)*0x1e0)))
 obj=run('entry_flag_root',0xfffffe000a561550,0xfffffe000a561560,
  {'sp':f,'x16':POOL,'w14':0xdf})
 q['entry_flag_root']=cell(obj,f+0x1a0,8)!=0xfffffe000ccc78e0
 obj=run('entry_seed_root',0xfffffe000a561598,0xfffffe000a5615a4,
  {'sp':f,'x16':POOL,'w8':0xf4})
 q['entry_seed_root']=cell(obj,f+0x198,8)!=0xfffffe000ccc78b8
 obj=run('entry_static_frame',0xfffffe000a5615a4,0xfffffe000a5615f8,
  {'sp':f,'x16':POOL,'x15':resize(phase,64),'x25':0xfffffe000ccc2c80,
   'x24':0xfffffe000ccc2c60,'x26':0xfffffe00079174c0})
 expected={0x100:0xfffffe0007920c10,0x108:0xfffffe00079170c0,0x128:0xfffffe0007919cb0,
  0x130:0xfffffe00079172c0,0x1d8:0xfffffe000ccc2c80,0x1b0:0xfffffe000ccc2c60,0x190:0xfffffe00079174c0}
 q['entry_static_frame']=z3.Or(*[cell(obj,f+o,8)!=v for o,v in expected.items()],
  cell(obj,f+0x1f4,4)!=phase,cell(obj,f+0x1ac,4)!=0x0636781f,cell(obj,f+0xd4,4)!=0xffffffff)
 cursor,seed=z3.BitVecs('cursor64 seed64',64)
 obj=run('entry_cursor_advance',0xfffffe000a561458,0xfffffe000a561464,
  {'x1':cursor},[(cursor,8,seed-0x40)])
 q['entry_cursor_advance']=cell(obj,cursor,8)!=seed
 q['bridge_zero_displacement_if_preserved']=z3.ZeroExt(32,((resize(cell(obj,cursor,8),32)-resize(seed,32))<<4)&0xffff0)!=0
 sp=z3.BitVec('inner_entry_SP64',64);body=sp-0x350;fp=sp-0x10;rec=fp-0xb0
 q['frame_record_alignment']=z3.And((sp&15)==0,z3.Or((rec&15)!=0,rec!=body+0x290))

 # Field174 is read before the branch-record codec and remains in callee-saved X19.
 field=z3.BitVec('working_context_field174_u8',8);working=z3.BitVec('working_context64',64)
 obj=run('flag_record_producer',0xfffffe000a528f90,0xfffffe000a529030,
  {'sp':f,'x29':r+0xb0,'w8':0x6e3},[(f+0x1f8,8,working),(working+0x174,1,field)])
 flag_key=obj.read('x12');k=resize(flag_key,32)
 compact=(r^0xb5172dc7dfb9786f)*0xe1d88903
 q['flag_producer_key']=flag_key!=compact
 q['flag_source_and_fields']=z3.Or(obj.read('x19')!=resize(field,64),
  cell(obj,r+8,8)!=(resize(field,64)^flag_key),cell(obj,r+16,8)!=(flag_key^1),
  cell(obj,r+24,4)!=k,cell(obj,r+28,4)!=(k^0xad228785),
  cell(obj,r+36,4)!=k+0xad2286d0,cell(obj,r+40,4)!=0xad2286bb-k)
 obj=run('flag_decoder_key',0xfffffe000a52f734,0xfffffe000a52f780,{'x0':r})
 q['flag_decoder_key']=obj.read('x8')!=compact
 ks=z3.BitVec('flag_codec_key64',64);lo=resize(ks,32)
 lhs,rhs=z3.BitVecs('flag_decoded_left64 flag_decoded_right64',64)
 mode,mask,yes,no=z3.BitVecs('flag_mode32 flag_mask32 flag_yes32 flag_no32',32)
 obj=run('flag_decoder_operands',0xfffffe000a52f780,0xfffffe000a52f7a4,{'x0':r,'x8':ks},
  [(r+8,8,lhs^ks),(r+16,8,rhs^ks),(r+36,4,no+lo),(r+40,4,yes-lo),
   (r+24,4,mode+lo),(r+28,4,mask^lo)])
 q['flag_decoder_operands']=z3.Or(obj.read('x11')!=lhs,obj.read('x12')!=rhs,
  obj.read('w15')!=mode,obj.read('w13')!=no,obj.read('w14')!=yes,obj.read('w8')!=mask)
 obj=run('flag_decoder_predicate',0xfffffe000a52f7a4,0xfffffe000a52f7bc,
  {'x11':lhs,'x12':rhs,'x9':lhs^ks,'x10':rhs^ks,'w15':mode})
 pred=z3.If((mode&1)!=0,z3.UGT(lhs,rhs),lhs==rhs)
 q['flag_decoder_predicate']=obj.read('w9')!=bit(pred)
 selected=z3.BitVec('flag_predicate32',32)
 obj=run('flag_decoder_result',0xfffffe000a52f7bc,0xfffffe000a52f7cc,
  {'x0':r,'w9':selected,'w14':yes,'w13':no,'w8':mask})
 q['flag_decoder_result']=cell(obj,r,4)!=(mask^z3.If(selected!=0,yes,no))
 q['selected_flag_gate_indices']=(z3.If(field==1,z3.BitVecVal(0xad2286bb,32),z3.BitVecVal(0xad2286d0,32))^0xad228785)!=z3.If(field==1,z3.BitVecVal(0x13e,32),z3.BitVecVal(0x155,32))
 obj=run('post_flag_frame_banks',0xfffffe000a529094,0xfffffe000a5290c4,{'sp':f})
 q['post_flag_frame_banks']=z3.Or(cell(obj,f+0x138,8)!=0xfffffe0007919bb0,
  cell(obj,f+0x140,8)!=0xfffffe00079171c0,cell(obj,f+0x180,8)!=0xfffffe00079173c0,
  cell(obj,f+0x188,8)!=0xfffffe0007920d10)
 time=z3.BitVec('secure_time_object64',64)
 obj=run('time_presence_gate',0xfffffe000a526ddc,0xfffffe000a526df8,
  {'x13':0xfffffe000ccc78c4,'w12':0x6e3},[(0xfffffe000ccc78c0,8,time)])
 q['time_presence_gate']=z3.Or(obj.read('x13')!=0xfffffe000ccc78c0,obj.read('x9')!=time,
  obj.read('w8')!=z3.If(time!=0,z3.BitVecVal(0x737,32),z3.BitVecVal(0x71a,32)))
 obj=run('reader_control_store',0xfffffe000a517628,0xfffffe000a51762c,
  {'sp':f,'x19':resize(field,64)})
 q['reader_control_store']=cell(obj,f+0x1e8,8)!=resize(field,64)
 u,limit=z3.BitVecs('decoded_accumulator64 decoded_limit64',64)
 final=z3.And(z3.ULT(u,limit),field==1)
 q['matched_reader_gate_reduction']=z3.And(field==1,final!=z3.ULT(u,limit))
 obj=run('context_root_copy',0xfffffe000a50fa68,0xfffffe000a50fa70,
  {'sp':f},[(f+0x118,8,working)])
 q['context_root_copy']=cell(obj,f+0x1f8,8)!=working
 obj=run('transform_result_publication',0xfffffe000a5318f0,0xfffffe000a5318f8,
  {'sp':f},[(f+0x228,8,working)])
 q['transform_result_publication']=cell(obj,f+0x118,8)!=working
 # A satisfiable missing-relation control, not execution of the unlifted codec.
 raw_slot=z3.BitVec('unmodeled_raw_vector_slot64',64)
 controls['unmodeled_transform_does_not_prove_pointer_identity']=working!=raw_slot

 results={}
 for name,query in q.items():
  s=z3.Solver();s.set(timeout=10000);s.add(query);result=s.check();print(name,result,flush=True)
  assert result==z3.unsat,(name,str(result),s.model() if result==z3.sat else s.reason_unknown())
  results[name]={'result':str(result),'query':s.sexpr()}
 negative={}
 for name,query in controls.items():
  s=z3.Solver();s.set(timeout=10000);s.add(query);assert s.check()==z3.sat;m=s.model()
  negative[name]={'result':'sat','query':s.sexpr(),'model':{str(v):hex(m[v].as_long()) for v in sorted(m,key=str)}}
 return results,counts,negative


def census(k,entry):
 text=next(s for s in entry['segments'] if s['name']=='__TEXT_EXEC');a=text['address'];n=text['file_size']
 raw=k.read(a,n);assert raw==IMAGE.read(a,n) and n%4==0
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;catalog=starts(k,entry)
 rows=[];unknown=[];decoded=0
 for off in range(0,n,4):
  insns=list(cs.disasm(raw[off:off+4],a+off))
  if not insns:unknown.append({'pc':hex(a+off),'bytes_hex':raw[off:off+4].hex()});continue
  ins=insns[0];decoded+=1
  if ins.mnemonic not in ['str','stur','strb','sturb','strh','sturh','stp','stnp']:continue
  operand=next((o for o in ins.operands if o.type==ARM64_OP_MEM),None)
  if operand is None or ins.reg_name(operand.mem.base)!='sp' or operand.mem.index:continue
  reg=ins.reg_name(ins.operands[0].reg)
  width=1 if ins.mnemonic in ['strb','sturb'] else 2 if ins.mnemonic in ['strh','sturh'] else 8 if reg in ['fp','lr'] else {'x':8,'w':4,'q':16,'d':8,'s':4,'h':2,'b':1}[reg[0]]
  size=width*(2 if ins.mnemonic in ['stp','stnp'] else 1)
  hits=[v for v,nfield in [(0x1e8,8),(0x1f4,4),(0x1f8,8)]
   if max(operand.mem.disp,v)<min(operand.mem.disp+size,v+nfield)]
  if not hits:continue
  j=bisect.bisect_right(catalog,ins.address)-1
  rows.append({'pc':hex(ins.address),'mnemonic':ins.mnemonic,'operands':ins.op_str,'bytes_hex':bytes(ins.bytes).hex(),
   'SP_offset_B':operand.mem.disp,'size_B':size,'touches_offsets_B':hits,'writeback':ins.writeback,
   'physical_compiler_start':hex(catalog[j]),'physical_compiler_end':hex(catalog[j+1]),'reaching_frame_identity_proven':False})
 return {'scope':'Every aligned TEXT_EXEC word decoded separately; only explicit immediate-SP STR/STUR/STP/STNP forms. Physical envelopes are metadata, not logical-frame or producer proof.',
  'text_start':hex(a),'text_B':n,'text_sha256':hashlib.sha256(raw).hexdigest(),'words':n//4,
  'decoded':decoded,'undecoded':unknown,'matching_stores':rows}


def build():
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');spans=[]
 for label,bounds in SPANS.items():
  row=span(k,*bounds);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
 proofs,counts,controls=prove({'spans':spans});banks={}
 for name,(pair,key,add,base,bias,target) in RULES.items():
  row=selected(*pair,key,add,base=base,bias=bias);assert int(row['target'],16)==target
  row.update(left256_hex=IMAGE.read(pair[0],256).hex(),right256_hex=IMAGE.read(pair[1],256).hex(),
   original_fixup=pointer(k,int(row['slot'],16)));assert ((int(row['original_fixup']['target'],16)+bias)&((1<<64)-1))==target
  banks[name]=row
 slots={hex(i):pointer(k,TABLE+8*i) for i in INDICES}
 for slot in [0xfffffe00084713c0,0xfffffe0008471610,0xfffffe000847c508,
  0xfffffe0008471bd0,0xfffffe0008471ce0,0xfffffe00084719d8,0xfffffe0008471d10]:slots[hex(slot)]=pointer(k,slot)
 source_ref=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(source_ref).splitlines(keepends=True)
 transform=next(s for s in spans if s['label']=='context_transform');cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
 critical=[];stores=[]
 for ins in cs.disasm(bytes.fromhex(transform['bytes_hex']),int(transform['start'],16)):
  rr,ww=ins.regs_access();writes=[ins.reg_name(v) for v in ww]
  if 0xfffffe000a5316c0<=ins.address<0xfffffe000a5318f0:
   assert not any(r in ['w8','x8','w9','x9'] for r in writes)
   critical.append({'pc':hex(ins.address),'writes':writes})
  if ins.mnemonic.startswith('st'):
   for o in ins.operands:
    if o.type==ARM64_OP_MEM and ins.reg_name(o.mem.base)=='sp':stores.append({'pc':hex(ins.address),'mnemonic':ins.mnemonic,'operands':ins.op_str,'SP_offset_B':o.mem.disp})
 assert all(0x220<=s['SP_offset_B']<=0x22f or s['SP_offset_B'] in [0x118,0x14c] for s in stores)
 scan=census(k,entry)
 symbols=k.symbols([0xfffffe000a50e618,0xfffffe000a561344,0xfffffe000c2de71c])
 assert any(s['name']=='_Vt05NUgPD3Xy28y1R3R' for s in symbols['0xfffffe000a50e618'])
 assert any(s['name']=='_kernel_sysctlbyname' for s in symbols['0xfffffe000c2de71c'])
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
  'normalized_image_sha256':sha(SOURCE),'spans':spans,'proofs':proofs,'source_lift_counts':counts,'negative_controls':controls,
  'banks':banks,'slots':slots,'exact_symbols':symbols,'saved_cell_store_census':scan,
  'transform_boundary_audit':{'range_start':'0xfffffe000a5316c0','range_end':'0xfffffe000a5318f0',
   'register_write_rows':critical,'direct_SP_stores':stores,'numerical_pointer_identity_proven':False,
   'nonaliasing_transform_access_is_premise':True,'qword_swap_iterations':63,'vector16B_iterations':32},
  'supplied_reference':{'path':source_ref.name,'sha256':sha(source_ref),'excerpts':[
   {'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(18425,18448),(84475,84496)]]},
  'selected_contract':{'outer_record_required_even':True,'named_outer_source_phase':'0x6e3',
   'entry_frame_B':0x350,'entry_local_B':0x2d0,'entry_save_B':0x80,'reader_record_from_body_SP_B':0x290,
   'context_control_offset_B':0x174,'context_comparison_offset_B':0x178,'reader_control_byte_required':1,
   'all_reader_banks_bound_on_selected_source_template':True,'saved_phase_bound_on_selected_source_template':True,
   'transform_pointer_codec_proven':False,'whole_named_operation_completed':False,
   'daemon_request_lineage_proven':False,'native_epoch_matched':False},
  'verified_counts':{'spans':len(spans),'instructions':sum(len(s['instructions']) for s in spans),
   'code_B':sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),'source_lifted_instances':sum(counts.values()),
   'queries_unsat':len(proofs),'negative_controls_sat':len(controls),'bank_rules':len(banks),
   'bank_byte_inputs':256*len(banks),'original_slots':len(slots),'text_words_scanned':scan['words'],
   'text_words_decoded':scan['decoded'],'text_words_undecoded':len(scan['undecoded']),
   'saved_cell_store_candidates':len(scan['matching_stores']),'transform_register_audit_rows':len(critical)},
  'dependencies':{n:sha(ROOT/n) for n in ['recover_lskd_context_compare.py','recover_lskd_clock_reader.py',
   'lskd_context_compare_checks.json','lskd_clock_reader_checks.json','lskd_clock_accumulator_checks.json',
   'legacy_stack_contracts.json','legacy_stack_proofs.json','kernel_native_reader.py','kext_port_tools.py',
   'recover_kext_cold_init.py','recover_kext_aes_handoff.py','recover_aes_cleanup_epoch.py',
   'lskd_values_symbolic.py','verify_daemon_reader_record_payloads_publication.py']},
  'solver_version':z3.get_version_string(),'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify',action='store_true');args=p.parse_args()
 output=build();path=ROOT/'lskd_reader_lineage_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
