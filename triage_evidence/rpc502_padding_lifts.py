"""Source-pinned byte/word transforms for the exported-block checker.

O(instructions) symbolic construction. Recorded dispatch seeds are explicit;
local algebra is distinct from whole-program or native reachability.
"""
from rpc502_parser_lift import Lift

def header_lift(a,b):return Lift({'w25':0x7249,'w8':a,'w9':b}).run(0x1009d8fd8,0x1009d9014).regs['w8']
def pad_lift(state,b):return Lift({'w8':state,'w14':b,'w10':0x67d0}).run(0x100a75c00,0x100a75c30).regs['w8']
def separator_lift(state,b):
 q=Lift({'w8':state,'w10':0x67d0}).run(0x1009329a8,0x1009329b4);q.regs['w11']=b;q.run(0x1009329b8,0x1009329e8);return q.regs['w8']
def prefix_lift(state,a,b):return Lift({'w8':state,'w17':a,'w0':b}).run(0x100656dc8,0x100656dd8).regs['w8']
def difference_lift(a,b):return Lift({'w15':0x4a29,'w20':a,'w5':b}).run(0x100a46c04,0x100a46cc4).regs['w14']
def failure_fold_lift(b):return Lift({'w8':0x40df015d,'w9':b}).run(0x100a7c674,0x100a7c6a4).regs['w8']
