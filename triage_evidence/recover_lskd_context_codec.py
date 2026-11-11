#!/usr/bin/env python3
"""Paired context-slot and 512 B representation contracts from original A64.

Static scalar/SIMD/byte-memory lifting; no target or IDB execution. Pointer,
seed, frame and object epochs are premises. O(N+I+L) extraction and expression
construction for input bytes N, retained/lifted instructions I and byte lanes L;
SMT cost separate. Shuffle inversion uses a transposition lemma and reverse
schedule, not a new native or 512 B instruction execution.
"""
import argparse
import json
import re

import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_UXTB

from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_aes_cleanup_epoch import span
from recover_lskd_context_compare import CompareLift
from lskd_values_symbolic import resize,part,mem,cell
from verify_daemon_reader_record_payloads_publication import read,sha

FACTOR=0x01000193
INVERSE=0x359c449b
SEED_FACTOR=0x030c5e1f
SPANS={
 'writer':(0xfffffe000a51b9d8,0xfffffe000a51bd54),
 'reader':(0xfffffe000a5315b0,0xfffffe000a531914),
 'context_save':(0xfffffe000a50fa5c,0xfffffe000a50fa80),
 'initial_reader_fields':(0xfffffe000a5342d4,0xfffffe000a5342f8),
 'reader_factor_init':(0xfffffe000a55c9b4,0xfffffe000a55c9bc),
}


def pack(values):return z3.Concat(*reversed(values))


def lanes(value,width,count=None):
 return [z3.Extract(j+width-1,j,value) for j in range(0,width*(count or value.size()//width),width)]


class CodecLift(CompareLift):
 """Fail-closed source interpreter with overlapping eight-byte scratch views.

 Dynamic scratch addresses use a selected region and retain a separate bounds
 obligation. Initial scratch bytes are symbolic; zeroing is an original store.
 """
 def __init__(self,*args):
  super().__init__(*args);self.vectors={};self.regions={};self.active=None
  self.guards=[];self.fixed={};self.fixed_stores=set();self.static_reads={};self.byte_accesses=[]
 def region(self,base,value=None):
  self.regions[base]=lanes(resize(value,64),8) if value is not None else [z3.BitVec('initial_'+hex(base)+'_'+str(j),8) for j in range(8)]
 def width(self,name):
  return {'b':8,'h':16,'s':32,'d':64,'q':128}[name[0]] if re.fullmatch('[bhsdq][0-9]+',name) else super().width(name)
 def read(self,name):
  if re.fullmatch('[bhsdq][0-9]+',name):return resize(self.vectors[int(name[1:])],self.width(name))
  return super().read(name)
 def write(self,name,value):
  if re.fullmatch('[bhsdq][0-9]+',name):self.vectors[int(name[1:])]=resize(resize(value,self.width(name)),128)
  else:super().write(name,value)
 def address(self,ins,operand):
  if operand.mem.index and operand.ext==ARM64_EXT_UXTB:
   return z3.simplify(self.read(ins.reg_name(operand.mem.base))+operand.mem.disp+resize(resize(self.read(ins.reg_name(operand.mem.index)),8),64))
  return super().address(ins,operand)
 def operand(self,ins,operand,width):
  if operand.ext==ARM64_EXT_UXTB:
   assert not operand.shift.type
   return resize(resize(self.read(ins.reg_name(operand.reg)),8),width)
  return super().operand(ins,operand,width)
 def locate(self,address,n):
  address=z3.simplify(resize(address,64))
  if z3.is_bv_value(address):
   a=address.as_long()
   for base in self.regions:
    if base<=a<a+n<=base+8:return base,resize(a-base,64)
   return None
  assert self.active in self.regions,('unclassified dynamic address',self.pc,address)
  base=self.active;offset=z3.simplify(address-base)
  self.guards.append(z3.And(z3.UGE(address,base),z3.ULE(address,base+8-n)))
  return base,offset
 def load(self,address,n):
  address=z3.simplify(resize(address,64));key=(address.sexpr(),n)
  if key in self.fixed:return resize(self.fixed[key],n*8)
  where=self.locate(address,n)
  if where:
   base,offset=where;values=self.regions[base];out=[]
   for j in range(n):
    value=z3.BitVec('out_of_region_read_'+str(self.pc)+'_'+str(j),8)
    for i in range(8):value=z3.If(offset+j==i,values[i],value)
    out.append(z3.simplify(value))
   self.byte_accesses.append({'pc':hex(self.pc),'operation':'load','region':hex(base),'width_B':n})
   return z3.simplify(pack(out)) if n>1 else out[0]
  if z3.is_bv_value(address) and 0xfffffe0007920f10<=address.as_long()<address.as_long()+n<=0xfffffe0007920f90:
   a=address.as_long();raw=IMAGE.read(a,n);self.static_reads[hex(a)]={'size_B':n,'bytes_hex':raw.hex()}
   return resize(int.from_bytes(raw,'little'),n*8)
  raise AssertionError(('undefined fixed cell',self.pc,key))
 def store(self,address,n,value,pc):
  address=z3.simplify(resize(address,64));key=(address.sexpr(),n)
  if key in self.fixed_stores:
   self.fixed[key]=resize(value,n*8);self.stores.append({'pc':pc,'address':address,'size_bytes':n,'value':resize(value,n*8)});return
  where=self.locate(address,n)
  assert where is not None,('unclassified store',hex(pc),address,n)
  base,offset=where;old=self.regions[base];new=lanes(resize(value,n*8),8)
  for i in range(8):
   v=old[i]
   for j in range(n):v=z3.If(offset+j==i,new[j],v)
   old[i]=z3.simplify(v)
  self.byte_accesses.append({'pc':hex(pc),'operation':'store','region':hex(base),'width_B':n})
  self.stores.append({'pc':pc,'address':address,'size_bytes':n,'value':resize(value,n*8)})
 def word(self,base):return z3.simplify(pack(self.regions[base]))
 def run(self,label):
  saved=self.c;row=next(s for s in saved['spans'] if s['label']==label)
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  raw=bytes.fromhex(row['bytes_hex']);insns=list(cs.disasm(raw,int(row['start'],16)));assert len(insns)*4==len(raw)
  for ins in insns:
   self.pc=ins.address;m=ins.mnemonic;op=ins.op_str;handled=True
   if m=='adrp':self.write(ins.reg_name(ins.operands[0].reg),ins.operands[1].imm)
   elif m in ['ldurb','ldurh','sturb','sturh']:
    reg=ins.reg_name(ins.operands[0].reg);n=1 if m.endswith('b') else 2;a=self.address(ins,ins.operands[1])
    if m.startswith('ld'):self.write(reg,self.load(a,n))
    else:self.store(a,n,self.read(reg),ins.address)
   elif m=='ubfx':
    d,s=[ins.reg_name(o.reg) for o in ins.operands[:2]];shift,width=[o.imm for o in ins.operands[2:]]
    self.write(d,z3.Extract(shift+width-1,shift,self.read(s)))
   elif m=='fneg':
    d,s=[ins.reg_name(o.reg) for o in ins.operands];assert self.width(d)==64
    value=z3.simplify(self.read(s));assert z3.is_bv_value(value) and value.as_long()==0x8000000080000000
    self.write(d,self.read(s)^(1<<63))
   elif m=='fmov':
    d,s=[ins.reg_name(o.reg) for o in ins.operands];self.write(d,self.read(s))
   elif m=='mov' and re.fullmatch(r'w\d+, v\d+\.s\[1\]',op):
    d,v=map(int,re.findall(r'\d+',op)[:2]);self.write('w'+str(d),lanes(self.vectors[v],32)[1])
   elif m=='mov' and re.fullmatch(r'v\d+\.s\[1\], w\d+',op):
    v,_,s=map(int,re.findall(r'\d+',op));a=lanes(self.vectors[v],32);a[1]=self.read('w'+str(s));self.vectors[v]=pack(a)
   elif m=='mov' and op.startswith('v'):
    d,s=map(int,re.findall(r'v(\d+)',op));assert '.16b' in op;self.vectors[d]=self.vectors[s]
   elif m=='dup':
    match=re.fullmatch(r'v(\d+)\.(2s|4s), w(\d+)',op);assert match,op
    d,shape,s=match.groups();self.vectors[int(d)]=resize(pack([self.read('w'+s)]*(2 if shape=='2s' else 4)),128)
   elif m=='movi':
    match=re.fullmatch(r'v(\d+)\.(2s|4s|4h|8h|16b), #(0x[0-9a-f]+)(?:, lsl #(\d+))?',op);assert match,op
    d,shape,literal,shift=match.groups();n,width={'2s':(2,32),'4s':(4,32),'4h':(4,16),'8h':(8,16),'16b':(16,8)}[shape]
    self.vectors[int(d)]=resize(pack([resize(int(literal,16)<<(int(shift) if shift else 0),width)]*n),128)
   elif m in ['eor','eor3'] and op.startswith('v'):
    regs=list(map(int,re.findall(r'v(\d+)',op)));d,*args=regs;v=self.vectors[args[0]]
    for r in args[1:]:v=v^self.vectors[r]
    self.vectors[d]=resize(resize(v,64 if '.8b' in op else 128),128)
   elif m in ['add','sub','mul','mla','mls'] and op.startswith('v'):
    d,a,b=map(int,re.findall(r'v(\d+)',op));shapes=re.findall(r'\.(2s|4s|16b)',op);assert len(shapes)==3 and len(set(shapes))==1
    n,width={'2s':(2,32),'4s':(4,32),'16b':(16,8)}[shapes[0]];out=[]
    for j,(x,y) in enumerate(zip(lanes(self.vectors[a],width,n),lanes(self.vectors[b],width,n))):
     out.append(x+y if m=='add' else x-y if m=='sub' else x*y if m=='mul' else lanes(self.vectors[d],width,n)[j]+x*y if m=='mla' else lanes(self.vectors[d],width,n)[j]-x*y)
    self.vectors[d]=resize(pack(out),128)
   elif m in ['umull','umull2']:
    d,a,b=map(int,re.findall(r'v(\d+)',op));shapes=re.findall(r'\.(2d|2s|4s|4h|8h)',op)
    target,source,_=shapes;w=32 if source=='2s' else 16;n=2 if w==32 else 4;start=n if m.endswith('2') else 0
    left=lanes(self.vectors[a],w);right=lanes(self.vectors[b],w)
    self.vectors[d]=pack([resize(left[j],2*w)*resize(right[j],2*w) for j in range(start,start+n)])
   elif m=='shrn':
    d,s=map(int,re.findall(r'v(\d+)',op));shift=ins.operands[-1].imm
    assert '.2s' in op and '.2d' in op
    self.vectors[d]=resize(pack([resize(z3.LShR(x,shift),32) for x in lanes(self.vectors[s],64)]),128)
   elif m in ['ushr','ushl']:
    regs=list(map(int,re.findall(r'v(\d+)',op)));d,s=regs[:2];out=[]
    for j,x in enumerate(lanes(self.vectors[s],32,2)):
     shift=ins.operands[-1].imm if m=='ushr' else z3.simplify(z3.Extract(7,0,lanes(self.vectors[regs[2]],32)[j])).as_long()
     if m=='ushl' and shift>=128:shift-=256
     out.append(z3.LShR(x,abs(shift)) if m=='ushr' or shift<0 else x<<shift)
    self.vectors[d]=resize(pack(out),128)
   elif m in ['ushll','ushll2']:
    d,s=map(int,re.findall(r'v(\d+)',op));assert ins.operands[-1].imm==0
    bs=lanes(self.vectors[s],8);start=8 if m.endswith('2') else 0
    self.vectors[d]=pack([resize(v,16) for v in bs[start:start+8]])
   elif m=='tbl':
    d,*regs=map(int,re.findall(r'v(\d+)',op));index=regs.pop();source=sum([lanes(self.vectors[r],8) for r in regs],[])
    indices=[z3.simplify(x).as_long() for x in lanes(self.vectors[index],8)]
    self.vectors[d]=pack([source[j] if j<len(source) else resize(0,8) for j in indices])
   else:handled=False
   if handled:self.count+=1
   else:
    self.c={'spans':[{'label':label,'start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run(label)
  self.c=saved;return self


def permutation(value,indices,inverse=False):
 bs=lanes(value,8);j7,j6,j5,j3=indices
 def swap(a,b):
  old=bs[:];picked=old[b] if isinstance(b,int) else None
  if picked is None:
   picked=resize(0,8)
   for n in range(8):picked=z3.If(b==n,old[n],picked)
  for n in range(8):bs[n]=picked if n==a else z3.If(b==n,old[a],old[n]) if not isinstance(b,int) else old[a] if n==b else old[n]
 if inverse:
  bs[:3]=[bs[2],bs[0],bs[1]]
  for a,b in [(3,j3),(4,0),(5,j5),(6,j6),(7,j7)]:swap(a,b)
 else:
  for a,b in [(7,j7),(6,j6),(5,j5),(4,0),(3,j3)]:swap(a,b)
  bs[:3]=[bs[1],bs[2],bs[0]]
 return z3.simplify(pack(bs))


def affine(value,mask,inverse=False):
 return pack([(x-y)*INVERSE if inverse else x*FACTOR+y for x,y in zip(lanes(value,32),lanes(mask,32))])


def prove(capture):
 q={};counts={};accesses={};pieces={};f=0xfffffe0051000000;fp=f+0x300
 pointer,encoded,mask=z3.BitVecs('allocation_pointer64 encoded_slot64 mask64',64)
 seed=z3.BitVec('seed32',32);t=z3.BitVec('mixed_seed32',32)
 indices=[z3.BitVec('j'+str(d)+'_8',8) for d in [7,6,5,3]]
 bound=z3.And(*[z3.ULT(j,d) for j,d in zip(indices,[7,6,5,3])])
 def fixed(obj,address,n,value):obj.fixed[(z3.simplify(resize(address,64)).sexpr(),n)]=resize(value,n*8)
 def run(name,a,z,seeds,regions=(),cells=(),vectors=(),active=None,obj=None):
  obj=obj or CodecLift(part(capture,name,a,z));obj.c=part(capture,name,a,z)
  for reg,value in seeds.items():obj.seed(reg,value)
  for base,value in regions:obj.region(base,value)
  for address,n,value in cells:fixed(obj,address,n,value)
  for reg,value in vectors:obj.vectors[reg]=resize(value,128)
  obj.active=active;before=obj.count;obj.run(name);counts[name]=obj.count-before
  pieces[name]={'start':hex(a),'end':hex(z),'instructions':(z-a)//4}
  assert counts[name]==(z-a)//4
  accesses[name]=obj.byte_accesses[:]
  if obj.guards:q[name+'_dynamic_access_bounds']=z3.And(bound,z3.Not(z3.And(*obj.guards)))
  return obj
 obj=run('writer_seed_selection',0xfffffe000a51b9dc,0xfffffe000a51ba08,
  {'sp':f,'x29':fp},[(fp-0xc0,None)],cells=[(f+0x78,8,0xfffffe000ccc78e0),
   (f+0x80,8,0xfffffe000ccc78b8),(0xfffffe000ccc78e0,4,255),
   (0xfffffe000ccc78b8,8,0xfffffe000ccc78f4),(0xfffffe000ccc7910,4,seed)])
 q['writer_seed_selection']=z3.Or(obj.read('w14')!=seed,obj.read('w15')!=seed*SEED_FACTOR)
 obj=run('reader_seed_selection',0xfffffe000a5315b4,0xfffffe000a5315e0,
  {'sp':f},[(f+0x220,None)],cells=[(f+0x198,8,0xfffffe000ccc78b8),
   (f+0x1a0,8,0xfffffe000ccc78e0),(0xfffffe000ccc78e0,4,255),
   (0xfffffe000ccc78b8,8,0xfffffe000ccc78f4),(0xfffffe000ccc7910,4,seed)])
 q['reader_seed_selection']=z3.Or(obj.read('w10')!=seed,obj.read('w13')!=seed*SEED_FACTOR,obj.read('x8')!=0)
 # Exact low-vector source dataflow, separate from mathematical quotient lemmas.
 obj=run('writer_indices',0xfffffe000a51ba08,0xfffffe000a51baa0,{'w15':t})
 reader=run('reader_indices_76',0xfffffe000a5315e0,0xfffffe000a531640,{'w13':t})
 reader=run('reader_indices_53',0xfffffe000a531670,0xfffffe000a5316ac,{},obj=reader)
 actual_writer=[obj.read('w12'),obj.read('w11'),obj.read('w10'),obj.read('w9')]
 q['writer_index_vector_preservation']=z3.Or(obj.vectors[0]!=resize(pack([t,t]),128),
  obj.vectors[1]!=resize(pack([resize(FACTOR,32)]*2),128))
 actual_reader=[reader.read('w12'),reader.read('w14'),reader.read('w15'),reader.read('w17')]
 expected=[];math=[]
 for d,magic,shift in [(7,0x24924925,None),(6,0xaaaaaaab,2),(5,0xcccccccd,2),(3,0xaaaaaaab,1)]:
  numerator=((t+d)^t)*FACTOR;high=z3.Extract(63,32,z3.ZeroExt(32,numerator)*magic)
  quotient=z3.LShR(z3.LShR(numerator-high,1)+high,2) if shift is None else z3.LShR(high,shift)
  expected.append(numerator-quotient*d)
  x=z3.Int('quotient_input_'+str(d));h=x*magic/(1<<32)
  qi=((x-h)/2+h)/4 if shift is None else h/(1<<shift)
  q['unsigned_divide_by_'+str(d)]=z3.And(x>=0,x<(1<<32),z3.Or(qi*d>x,x>=(qi+1)*d,h>x,h<0,(x-h)/2+h>=(1<<32)))
  math.append({'divisor':d,'magic':hex(magic),'post_shift':shift,'domain':'unsigned 32-bit integer; high product is floor(x*magic/2^32)'})
 q['writer_index_source_formulas']=z3.Or(*[a!=b for a,b in zip(actual_writer,expected)])
 q['reader_index_source_formulas']=z3.Or(*[a!=b for a,b in zip(actual_reader,expected)])
 q['writer_reader_index_match']=z3.Or(*[a!=b for a,b in zip(actual_writer,actual_reader)])
 # Source scratch-zero + affine-mask production, using independently bounded indices.
 writerA,writerB=fp-0xc0,fp-0xb8
 obj=run('writer_zero',0xfffffe000a51ba00,0xfffffe000a51ba04,{'x29':fp},[(writerA,None)])
 q['writer_original_zero_store']=obj.word(writerA)!=0
 obj=run('writer_mask_and_pointer_save',0xfffffe000a51baa0,0xfffffe000a51bb68,
  {'x29':fp,'w20':0x82c,'w15':t,'x13':pointer,**dict(zip(['w12','w11','w10','w9'],indices))},
  [(writerB,None)],vectors=[(0,pack([t,t])),(1,pack([resize(FACTOR,32)]*2))],active=writerA,obj=obj)
 m=pack([t*t^t,(t*t+t)^t])
 q['writer_mask_and_pointer_save']=z3.And(bound,z3.Or(obj.word(writerA)!=m,obj.word(writerB)!=pointer,obj.read('w3')!=0x4f7,obj.vectors[0]!=resize(m,128)))
 # The writer's final pointer byte permutation and affine/XOR publication.
 obj=run('writer_pointer_permutation',0xfffffe000a51bca4,0xfffffe000a51bd1c,
  {'x29':fp,**dict(zip(['w12','w11','w10','w9'],indices))},[(writerB,pointer)],active=writerB)
 perm=permutation(pointer,indices)
 q['writer_pointer_permutation']=z3.And(bound,obj.word(writerB)!=perm)
 obj=run('writer_affine',0xfffffe000a51bd1c,0xfffffe000a51bd34,{'x29':fp},
  [(writerB,pointer)],vectors=[(0,mask)])
 q['writer_affine']=obj.word(writerB)!=affine(pointer,mask)
 obj=run('writer_slot_xor',0xfffffe000a51bd34,0xfffffe000a51bd3c,{'x29':fp},
  [(writerA,mask),(writerB,affine(pointer,mask))])
 q['writer_slot_xor']=obj.read('x8')!=(affine(pointer,mask)^mask)
 # Reader reproduces the mask, removes XOR, inverts word-affine mapping and bytes.
 readerA,readerB=f+0x220,f+0x228
 obj=run('reader_zero',0xfffffe000a5315d4,0xfffffe000a5315d8,{'sp':f},[(readerA,None)])
 q['reader_original_zero_store']=obj.word(readerA)!=0
 obj=run('reader_zero_permutation_76',0xfffffe000a531640,0xfffffe000a531670,
  {'sp':f,'w8':0,'w12':indices[0],'w14':indices[1]},active=readerA,obj=obj)
 obj=run('reader_mask_and_slot_xor',0xfffffe000a5316ac,0xfffffe000a53173c,
  {'sp':f,'w13':t,'w3':FACTOR,'w9':0x6e3,'x11':encoded,'w17':indices[3],'x15':indices[2]},
  [(readerB,None)],active=readerA,obj=obj)
 q['reader_mask_and_slot_xor']=z3.And(bound,z3.Or(obj.word(readerA)!=m,obj.word(readerB)!=(encoded^m),obj.read('w8')!=0x1ca))
 obj=run('reader_inverse_affine',0xfffffe000a53173c,0xfffffe000a531760,
  {'sp':f,'w13':resize(encoded,32),'w16':resize(mask,32),'w11':resize(z3.LShR(mask,32),32)},[(readerB,encoded)])
 q['reader_inverse_affine']=obj.word(readerB)!=affine(encoded,mask,True)
 obj=run('reader_inverse_pointer_permutation',0xfffffe000a531760,0xfffffe000a5317d8,
  {'sp':f,'w13':resize(pointer,32),'w11':resize(z3.LShR(pointer,32),32),
   **dict(zip(['x12','x14','x15','x17'],indices))},[(readerB,pointer)],active=readerB)
 q['reader_inverse_pointer_permutation']=z3.And(bound,obj.read('x11')!=permutation(pointer,indices,True))
 q['pointer_byte_permutation_roundtrip']=z3.And(bound,permutation(permutation(pointer,indices),indices,True)!=pointer)
 q['word_affine_roundtrip']=affine(affine(pointer,mask),mask,True)!=pointer
 q['pointer_xor_roundtrip']=((encoded^mask)^mask)!=encoded
 scratch=z3.BitVec('aligned_scratch64',64);index=z3.BitVec('scratch_index8',8)
 q['aligned_OR_equals_byte_add']=z3.And((scratch&7)==0,z3.ULT(index,8),
  (scratch|resize(index,64))!=scratch+resize(index,64))
 slot=affine(permutation(pointer,indices),mask)^mask
 recovered=permutation(affine(slot^mask,mask,True),indices,True)
 q['composed_pointer_codec_roundtrip']=z3.And(bound,recovered!=pointer)
 obj=run('reader_data_key',0xfffffe000a5317d8,0xfffffe000a5317e0,
  {'x11':pointer,'w2':SEED_FACTOR,'w10':seed})
 q['reader_data_key']=obj.read('w12')!=((resize(pointer,32)*SEED_FACTOR)^seed)
 obj=run('writer_data_key',0xfffffe000a51bb68,0xfffffe000a51bb74,
  {'x29':fp,'w2':SEED_FACTOR,'w14':seed},[(writerB,pointer)])
 q['writer_data_key']=obj.read('w14')!=((resize(pointer,32)*SEED_FACTOR)^seed)
 # Reader SIMD body: complete byte widening, word multiplication and TBL path.
 offset=z3.BitVec('reader_block_offset64',64);key=z3.BitVec('context_data_key32',32);original=z3.BitVec('reader_block128',128)
 vectors=[(v,pack([resize(offset,32)+j for j in range(start,start+4)])) for v,start in [(0,12),(1,8),(2,4),(3,0)]]
 vectors.extend([(4,pack([resize(0x9b,16)]*4)),(5,pack([key]*4)),(6,pack([resize(0x9b,16)]*8)),(7,pack([resize(16,32)]*4)),
  (16,resize(int.from_bytes(IMAGE.read(0xfffffe0007920f80,16),'little'),128))])
 obj=CodecLift(part(capture,'reader_SIMD_body',0xfffffe000a53186c,0xfffffe000a5318e8))
 at=z3.simplify(pointer+offset);obj.fixed_stores.add((at.sexpr(),16))
 obj=run('reader_SIMD_body',0xfffffe000a53186c,0xfffffe000a5318e8,
  {'x11':pointer,'x10':offset},cells=[(at,16,original)],vectors=vectors,obj=obj)
 expected_bytes=[]
 for j,b in enumerate(lanes(original,8)):
  n=resize(offset,32)+j;expected_bytes.append((b*0x9b)^resize(key,8)^resize((n+key)*(n-key),8))
 q['reader_SIMD_byte_relation']=obj.stores[0]['value']!=pack(expected_bytes)
 q['reader_SIMD_coordinate_step']=z3.Or(obj.read('x10')!=offset+16,*[
  obj.vectors[v]!=pack([resize(offset+16,32)+j for j in range(start,start+4)]) for v,start in [(0,12),(1,8),(2,4),(3,0)]])
 obj=run('reader_SIMD_setup',0xfffffe000a531830,0xfffffe000a53186c,{'w12':key})
 q['reader_SIMD_setup']=z3.Or(obj.read('x10')!=0,obj.vectors[5]!=pack([key]*4),*[
  obj.vectors[v]!=pack([resize(j,32) for j in range(start,start+4)]) for v,start in [(0,12),(1,8),(2,4),(3,0)]],
  obj.vectors[4]!=resize(pack([resize(0x9b,16)]*4),128),obj.vectors[6]!=pack([resize(0x9b,16)]*8),
  obj.vectors[7]!=pack([resize(16,32)]*4),obj.vectors[16]!=resize(int.from_bytes(IMAGE.read(0xfffffe0007920f80,16),'little'),128))
 obj=run('reader_factor_init',0xfffffe000a55c9b4,0xfffffe000a55c9bc,{})
 q['reader_factor_init']=obj.read('w3')!=FACTOR
 byte=z3.BitVec('context_byte8',8);n=z3.BitVec('context_coordinate32',32)
 bmask=resize(key,8)^resize((n+key)*(n-key),8)
 q['context_byte_relation_roundtrip']=((byte^bmask)*0x93)*0x9b^bmask!=byte
 # A generic same-index transposition is involutive; reverse source schedules cancel.
 memory=z3.Array('context_words',z3.IntSort(),z3.BitVecSort(64));i,j=z3.Ints('swap_i swap_j')
 def swap(a):return z3.Store(z3.Store(a,i,z3.Select(a,j)),j,z3.Select(a,i))
 q['word_transposition_involution']=z3.And(i!=j,swap(swap(memory))!=memory)
 # Actual reader numerator and XOR-swap, with fixed-cell nonaliasing premise.
 idx=z3.BitVec('reader_swap_counter64',64);idx32=resize(idx,32)
 obj=CompareLift(part(capture,'reader_swap_numerator',0xfffffe000a5317e4,0xfffffe000a5317f0))
 for reg,value in [('w12',key),('x10',idx),('w3',FACTOR)]:obj.seed(reg,value)
 obj.run('reader_swap_numerator');counts['reader_swap_numerator']=obj.count
 pieces['reader_swap_numerator']={'start':'0xfffffe000a5317e4','end':'0xfffffe000a5317f0','instructions':3}
 q['reader_swap_numerator']=obj.read('w13')!=((key+idx32)^key)*FACTOR
 a,b=z3.BitVecs('swap_left64 swap_right64',64);rem=z3.BitVec('reader_swap_remainder32',32)
 obj=CompareLift(part(capture,'reader_swap_body',0xfffffe000a5317f8,0xfffffe000a531824))
 left=pointer+(idx<<3);right=pointer+(resize(rem,64)<<3)
 for reg,value in [('x11',pointer),('x10',idx),('w13',rem)]:obj.seed(reg,value)
 mem(obj,left,8,a);mem(obj,right,8,b);obj.run('reader_swap_body');counts['reader_swap_body']=obj.count
 pieces['reader_swap_body']={'start':'0xfffffe000a5317f8','end':'0xfffffe000a531824','instructions':11}
 q['reader_swap_body']=z3.Or(cell(obj,left,8)!=b,cell(obj,right,8)!=a)
 # Counter range and exact inverse order are source loop-structure obligations.
 ni,di=z3.Ints('reader_numerator_u32 reader_divisor')
 q['reader_remainder_range']=z3.And(ni>=0,ni<1<<32,di>=1,di<=63,z3.Or(ni%di<0,ni%di>=di))
 q['reader_counter_extent']=z3.And(z3.UGE(idx,1),z3.ULE(idx,63),
  z3.Or(idx*8+8>512,(idx+1==64)!=(idx==63)))
 block=z3.BitVec('reader_block_number64',64)
 q['reader_block_extent']=z3.And(z3.ULT(block,32),
  z3.Or(z3.UGT(block*16+16,512),(block*16+16==512)!=(block==31)))
 obj=CompareLift(part(capture,'reader_counter_initial',0xfffffe000a5317e0,0xfffffe000a5317e4));obj.seed('x10',idx);obj.run('reader_counter_initial')
 q['reader_counter_initial']=obj.read('x10')!=1;counts['reader_counter_initial']=obj.count
 pieces['reader_counter_initial']={'start':'0xfffffe000a5317e0','end':'0xfffffe000a5317e4','instructions':1}
 obj=CompareLift(part(capture,'reader_counter_step',0xfffffe000a531824,0xfffffe000a53182c));obj.seed('x10',idx);obj.run('reader_counter_step')
 q['reader_counter_step']=z3.And(z3.UGE(idx,1),z3.ULE(idx,63),z3.Or(obj.read('x10')!=idx+1,obj.equal!=(idx==63)))
 counts['reader_counter_step']=obj.count;pieces['reader_counter_step']={'start':'0xfffffe000a531824','end':'0xfffffe000a53182c','instructions':2}
 obj=CompareLift(part(capture,'reader_SIMD_counter_initial',0xfffffe000a531830,0xfffffe000a531834));obj.run('reader_SIMD_counter_initial')
 q['reader_SIMD_counter_initial']=obj.read('x10')!=0;counts['reader_SIMD_counter_initial']=obj.count
 pieces['reader_SIMD_counter_initial']={'start':'0xfffffe000a531830','end':'0xfffffe000a531834','instructions':1}
 obj=CompareLift(part(capture,'initial_reader_fields',0xfffffe000a5342d4,0xfffffe000a5342f8));obj.seed('x0',pointer);obj.run('initial_reader_fields')
 initial_word=0x54ac365113f503fb
 q['initial_reader_fields']=z3.Or(cell(obj,pointer+0x174,1)!=0,cell(obj,pointer+0x175,1)!=1,
  cell(obj,pointer+0x178,8)!=initial_word,cell(obj,pointer+0x180,1)!=0)
 counts['initial_reader_fields']=obj.count;pieces['initial_reader_fields']={'start':'0xfffffe000a5342d4','end':'0xfffffe000a5342f8','instructions':9}
 q['initial_context_limit_normalizes_to_zero']=resize(initial_word,64)+0xab53c9aeec0afc05!=0
 q['initial_context_limit_cannot_exceed_accumulator']=z3.ULT(pointer,resize(initial_word,64)+0xab53c9aeec0afc05)
 # Abstract input counters and valid nonaliasing objects, not native executions.
 def fixture(mixed):
  js=[((((mixed+d)^mixed)*FACTOR)&0xffffffff)%d for d in [7,6,5,3]]
  low=((mixed*mixed)^mixed)&0xffffffff;high=(((mixed*mixed+mixed)&0xffffffff)^mixed)&0xffffffff
  return js,resize(low|(high<<32),64)
 js0,m0=fixture(0);js1,m1=fixture(SEED_FACTOR)
 zero_seed_slot=affine(permutation(pointer,js0),m0)^m0
 wrong_seed=permutation(affine(zero_seed_slot^m1,m1,True),js1,True)
 negative={}
 for name,query in {
  'encoded_slot_is_not_generically_raw_pointer':z3.And((pointer&15)==0,pointer!=0,zero_seed_slot!=pointer),
  'mismatched_seed_can_change_decoded_pointer':z3.And((pointer&15)==0,pointer!=0,wrong_seed!=pointer)}.items():
  solver=z3.Solver();solver.set(timeout=10000);solver.add(query);assert solver.check()==z3.sat
  model=solver.model();negative[name]={'result':'sat','query':solver.sexpr(),'model':{str(v):hex(model[v].as_long()) for v in model}}
 results={}
 for name,query in q.items():
  solver=z3.Solver();solver.set(timeout=10000);solver.add(query);result=solver.check();print(name,result,flush=True)
  assert result==z3.unsat,(name,str(result),solver.reason_unknown())
  results[name]={'result':str(result),'query':solver.sexpr()}
 return {'proofs':results,'negative_controls':negative,'source_lift_counts':counts,'source_pieces':pieces,
  'memory_accesses':accesses,'division_domain_lemmas':math,
  'shuffle_schedule':{'writer':list(range(63,0,-1)),'reader':list(range(1,64)),
   'same_index_formula':'u32(((K+i) XOR K)*0x01000193) modulo i','transposition_involution_used':True},
  'selected_contract':{'flag32':255,'seed_byte_offset_B':28,'object_extent_B':512,
   'frame_fixture_base':hex(f),'frame_fixture_is_native':False,
   'same_seed_and_slot_epoch_required':True,'same_context_allocation_pointer_under_paired_codec':True,
   'native_context_identity_proven':False,'daemon_request_lineage_proven':False},
  'verified_counts':{'queries_unsat':len(results),'negative_controls_sat':len(negative),
   'source_lifted_instances':sum(counts.values()),'source_pieces':len(counts)},
  'new_IDA_access':False,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


def build():
 k=Kernel();spans=[]
 for label,bounds in SPANS.items():
  row=span(k,*bounds);row['bytes_hex']=row.pop('bytes');row['label']=label;spans.append(row)
 constants=k.read(0xfffffe0007920f10,128);assert constants==IMAGE.read(0xfffffe0007920f10,128)
 output=prove({'spans':spans})
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;audits={}
 for name,a,z,protected in [
  ('writer_middle',0xfffffe000a51bb68,0xfffffe000a51bca4,{'x9','x10','x11','x12','v0','sp','x29'}),
  ('reader_seed_to_data',0xfffffe000a5315e0,0xfffffe000a5317d8,{'x10','x2','x3','sp','x29'}),
  ('reader_data_to_publication',0xfffffe000a5317d8,0xfffffe000a5318f0,{'sp','x29','x8','x9'})]:
  rows=[]
  for ins in cs.disasm(k.read(a,z-a),a):
   written=[]
   for r in ins.regs_access()[1]:
    reg=ins.reg_name(r);reg={'fp':'x29','lr':'x30'}.get(reg,reg)
    reg=re.sub(r'^w(?=\d)', 'x',reg);reg=re.sub(r'^[bhsdq](?=\d)','v',reg);written.append(reg)
   assert not set(written)&protected,(name,hex(ins.address),written)
   assert not ins.mnemonic.startswith('bl')
   rows.append({'pc':hex(ins.address),'writes':written})
  audits[name]={'start':hex(a),'end':hex(z),'protected_registers':sorted(protected),'rows':rows,
   'indirect_object_writes_disjoint_from_stack_is_premise':True}
 output['register_preservation_audits']=audits
 output['verified_counts'].update(spans=len(spans),instructions=sum(len(s['instructions']) for s in spans),
  code_B=sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),
  preservation_audit_rows=sum(len(a['rows']) for a in audits.values()))
 output['dependencies']={n:sha(ROOT/n) for n in ['recover_lskd_context_compare.py','lskd_values_symbolic.py',
  'recover_lskd_element_population.py','lskd_element_population_checks.json','lskd_reader_lineage_checks.json',
  'lskd_vector_origin_checks.json','kernel_native_reader.py','kext_port_tools.py','recover_aes_cleanup_epoch.py',
  'verify_daemon_reader_record_payloads_publication.py']}
 output['solver_version']=z3.get_version_string()
 reference=ROOT.parent/'com.apple.driver.FairPlayIOKit.c';lines=read(reference).splitlines(keepends=True)
 output['supplied_reference']={'path':reference.name,'sha256':sha(reference),'excerpts':[
  {'first_line':a,'last_line':z,'text':''.join(lines[a-1:z])} for a,z in [(29860,30081),(48721,48980),(52363,52380)]]}
 output['external_primary_reference']={
  'title':'Arm A64 Instruction Set for A-profile architecture, DDI 0602 (ID032025)',
  'url':'https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85',
  'download_sha256':'b7baa6869789722df70da60170d999a62810409aaabbb6db1ef729ed68686bdf',
  'download_size_B':15314151,'instruction_page':1460,
  'semantic_scope':'FNEG low 64-bit result for the non-NaN literal 0x8000000080000000; FPNeg shared pseudocode flips the sign bit outside its AH/NaN special case. Upper-vector merge behavior is unused.',
  'full_document_committed':False}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'kernel_collection_sha256':k.sha256,
  'normalized_image_sha256':sha(SOURCE),'spans':spans,'constants':{'start':'0xfffffe0007920f10','bytes_hex':constants.hex()},**output}


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify',action='store_true');args=p.parse_args()
 output=build();path=ROOT/'lskd_context_codec_checks.json'
 if args.verify:assert json.loads(read(path))==output
 else:path.write_text(json.dumps(output,indent=2)+'\n')
 print(json.dumps(output['verified_counts']))
