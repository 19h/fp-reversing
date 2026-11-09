"""Source-pinned late width and pointer-offset scalar lifts;no guest writes.

O(instructions) symbolic expression construction. Width proof retains the
observed dispatch seed1daa;local modular arithmetic is not extent validity.
"""
import z3
from rpc502_parser_lift import Lift
K=0x8b3dc651;BIAS=0x693be708

def width_lift(stored_count,C,seed=0x1daa):
 q=Lift({'w12':seed,'w13':stored_count},{'[sp, #0x68]':C^K}).run(0x100a21958,0x100a21ac8);return q.regs['w13']==1

def auxiliary_offset_lift(aux,saved_status,seed):
 w12=seed+0x83b4;expected=(w12^0x8b3d25e5)+seed;diff=(saved_status-expected)|(expected-saved_status);return aux+seed+((~diff)>>31)+0xd59ecc1e

def auxiliary_offset_oracle(aux,saved_status,seed):
 M=0xffffffff;expected=((((seed+0x83b4)&M)^0x8b3d25e5)+seed)&M;return(aux+seed+0xd59ecc1e-(saved_status==expected))&M
