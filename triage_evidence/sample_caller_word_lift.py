#!/usr/bin/env python3
"""Fail-closed lift of the original straight-line sample-count calculation.

O(I) fixed-width operations/space for I source instructions; solver complexity
is separate. This lift does not model branches, memory, tasks or native APIs.
"""
from kext_port_tools import IMAGE,CS
START=0xfffffe000a6249a8
END=0xfffffe000a624af8
def lift(count):
 regs={'w22':count}
 def value(text):return int(text[1:],0)if text.startswith('#')else regs[text]
 for i in CS.disasm(IMAGE.read(START,END-START),START):
  op=[x.strip()for x in i.op_str.split(',')];d=op[0];m=i.mnemonic
  if m=='str':assert i.address==0xfffffe000a624ae4 and i.op_str=='w22, [sp, #0x74]';continue
  assert d.startswith('w'),(hex(i.address),i.mnemonic,i.op_str)
  if m=='mov':v=value(op[1])
  elif m=='movk':
   shift=int(op[2].split('#')[1],0)if len(op)>2 else 0;mask=0xffff<<shift;v=(regs[d]&(~mask&0xffffffff))|(value(op[1])<<shift)
  elif m=='lsl':v=value(op[1])<<value(op[2])
  else:
   assert m in('and','orr','eor'),(hex(i.address),m,i.op_str)
   a,b=value(op[1]),value(op[2])
   if len(op)>3:assert op[3].startswith('lsl #');b=b<<int(op[3].split('#')[1],0)
   v={'and':lambda:a&b,'orr':lambda:a|b,'eor':lambda:a^b}[m]()
  regs[d]=v&0xffffffff
 return regs['w8']
