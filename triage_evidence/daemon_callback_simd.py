"""Lane-accurate AdvSIMD subset used by the callback continuation.
Fixed-width bit vectors; USHL uses signed low-byte counts, without scalar
shift masking. Reference: Arm Instruction Set Reference Guide, D6.271,
https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab
"""
import re
import z3
from lskd_values_symbolic import resize
WIDTH={'b':8,'h':16,'s':32,'d':64}
def qname(name):return 'q'+name[1:]
def arrangement(text):
 match=re.search(r'\.([0-9]+)([bhsd])',text);assert match,text;return int(match[1]),WIDTH[match[2]]
def lanes(value,width,count):return[z3.Extract(width*(j+1)-1,width*j,value)for j in range(count)]
def packed(values):return values[0]if len(values)==1 else z3.Concat(*reversed(values))
def apply(v,i):
 m=i.mnemonic;o=i.operands;text=i.op_str;parts=[s.strip()for s in text.split(',')];name=lambda j:i.reg_name(o[j].reg)
 if m=='fmov'and name(0).startswith('d')and name(1).startswith('d'):
  v.pc=i.address;v.write(qname(name(0)),resize(v.read(qname(name(1))),64));return True
 if m=='fmov'and name(0).startswith('w')and name(1).startswith('s'):
  v.pc=i.address;v.write(name(0),resize(v.read(qname(name(1))),32));return True
 if m=='mov'and '.s['in text:
  v.pc=i.address
  if name(0).startswith('w'):
   lane=o[1].vector_index;v.write(name(0),z3.Extract(32*lane+31,32*lane,v.read(qname(name(1)))))
  else:
   lane=o[0].vector_index;old=v.read(qname(name(0)));mask=((1<<32)-1)<<(32*lane);v.write(qname(name(0)),(old&~mask)|(resize(v.read(name(1)),128)<<(32*lane)))
  return True
 if not parts[0].startswith('v')or'.'not in parts[0]:return False
 count,width=arrangement(parts[0]);bits=count*width;assert bits in [64,128];v.pc=i.address;dest=qname(name(0));vec=lambda j:v.read(qname(name(j)))
 if m=='movi':
  value=o[1].imm<<o[1].shift.value;v.write(dest,packed([z3.BitVecVal(value,width)]*count));return True
 if m=='tbl':
  table=[]
  for operand in o[1:-1]:table.extend(lanes(v.read(qname(i.reg_name(operand.reg))),8,16))
  indices=lanes(v.read(qname(name(len(o)-1))),8,count);values=[]
  for index in indices:
   value=z3.BitVecVal(0,8)
   for j,byte in enumerate(table):value=z3.If(index==j,byte,value)
   values.append(z3.simplify(value))
  v.write(dest,packed(values));return True
 if m=='eor3':v.write(dest,vec(1)^vec(2)^vec(3));return True
 if m=='ushll':
  source_width=width//2;values=lanes(vec(1),source_width,count);v.write(dest,packed([z3.ZeroExt(source_width,x)<<o[2].imm for x in values]));return True
 if m=='xtn':
  values=lanes(vec(1),2*width,count);v.write(dest,packed([resize(x,width)for x in values]));return True
 if m=='uzp1':
  a,b=lanes(vec(1),width,count),lanes(vec(2),width,count);v.write(dest,packed(a[::2]+b[::2]));return True
 if m=='mov':v.write(dest,resize(vec(1),bits));return True
 if m=='dup':value=resize(v.read(name(1)),width);v.write(dest,packed([value]*count));return True
 if m in ['eor','and','orr','bic','eon','orn']:
  a,b=resize(vec(1),bits),resize(vec(2),bits);value=a^b if m=='eor'else a&b if m=='and'else a|b if m=='orr'else a&~b if m=='bic'else a^~b if m=='eon'else a|~b;v.write(dest,value);return True
 if m=='umull':
  source_width=width//2;assert bits==128;a,b=lanes(vec(1),source_width,count),lanes(vec(2),source_width,count);v.write(dest,packed([z3.ZeroExt(source_width,x)*z3.ZeroExt(source_width,y)for x,y in zip(a,b)]));return True
 if m=='shrn':
  source_width=2*width;assert bits==64;shift=o[2].imm;values=lanes(vec(1),source_width,count);v.write(dest,packed([resize(z3.LShR(x,shift),width)for x in values]));return True
 if m in ['add','sub','mul','mla','mls','ushr','ushl']:
  a=lanes(vec(1),width,count);b=lanes(vec(2),width,count)if m!='ushr'else None;old=lanes(v.read(dest),width,count)if m in ['mla','mls']else None;values=[]
  for j,x in enumerate(a):
   if m=='add':value=x+b[j]
   elif m=='sub':value=x-b[j]
   elif m=='mul':value=x*b[j]
   elif m=='mls':value=old[j]-x*b[j]
   elif m=='mla':value=old[j]+x*b[j]
   elif m=='ushr':value=z3.LShR(x,o[2].imm)
   else:
    shift=z3.SignExt(width-8,z3.Extract(7,0,b[j]));value=z3.If(shift<0,z3.LShR(x,-shift),x<<shift)
   values.append(value)
  v.write(dest,packed(values));return True
 return False
