#!/usr/bin/env python3
"""Small source-pinned ARM32 ALU expression lifter for local parser proofs.

Only reviewed scalar operations and declared stack loads are supported; unknown
32-bit operations fail. X-register/pointer setup and stores are retained as
source context,not interpreted as complete memory or control-flow semantics.
O(I) expression construction;solver cost is separate and timeout-bounded.
"""
import re
import z3
from daemon_receive_tools import CS,IMAGE


def b32(v):return z3.BitVecVal(v&0xffffffff,32)

class Lift:
    def __init__(self,registers=None,loads=None):self.regs={k:(v if z3.is_expr(v)else b32(v))for k,v in (registers or {}).items()};self.loads=loads or {};self.stores={};self.cmp=None
    def value(self,s):
        s=s.strip()
        if s=='wzr':return b32(0)
        if s.startswith('#'):return b32(int(s[1:],0))
        assert re.fullmatch('w[0-9]+',s),s
        assert s in self.regs,s
        return self.regs[s]
    def condition(self,s):
        a,b=self.cmp
        return {'eq':lambda:a==b,'ne':lambda:a!=b,'lt':lambda:a<b,'le':lambda:a<=b,'ge':lambda:a>=b,'gt':lambda:a>b,'lo':lambda:z3.ULT(a,b),'ls':lambda:z3.ULE(a,b),'hs':lambda:z3.UGE(a,b),'hi':lambda:z3.UGT(a,b)}[s]()
    def run(self,start,end):
        for i in CS.disasm(IMAGE.read(start,end-start),start):
            m=i.mnemonic;args=[v.strip()for v in i.op_str.split(',')]
            if m=='cmp':self.cmp=(self.value(args[0]),self.value(args[1]));continue
            if m in ['str','stur']and args[0].startswith('w'):
                self.stores[', '.join(args[1:])]=self.value(args[0]);continue
            if not args[0].startswith('w'):continue
            dst=args[0]
            if m=='ldr':
                key=', '.join(args[1:]);assert key in self.loads,key;self.regs[dst]=self.loads[key];continue
            if m=='mov':self.regs[dst]=self.value(args[1]);continue
            if m=='movk':
                shift=int(args[2].split('#')[1],0)if len(args)>2 else 0;mask=0xffff<<shift;self.regs[dst]=(self.value(dst)&b32(~mask))|(self.value(args[1])<<shift);continue
            if m=='cset':self.regs[dst]=z3.If(self.condition(args[1]),b32(1),b32(0));continue
            if m=='csel':self.regs[dst]=z3.If(self.condition(args[3]),self.value(args[1]),self.value(args[2]));continue
            a=self.value(args[1]);b=self.value(args[2])
            if len(args)>3:
                shift=args[3].split();assert shift[0]=='lsl';b=b<<int(shift[1][1:],0)
            if m=='add':v=a+b
            elif m=='sub':v=a-b
            elif m=='eor':v=a^b
            elif m=='eon':v=a^~b
            elif m=='orr':v=a|b
            elif m=='and':v=a&b
            elif m=='bic':v=a&~b
            elif m=='mul':v=a*b
            elif m=='lsl':v=a<<(b&31)
            elif m=='lsr':v=z3.LShR(a,b&31)
            else:raise ValueError((hex(i.address),m,i.op_str))
            self.regs[dst]=v
        return self
