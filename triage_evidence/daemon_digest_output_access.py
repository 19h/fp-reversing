#!/usr/bin/env python3
"""Correct a Capstone shift-alias access overapproximation locally.
LSL/LSR write their destination; its old value is read only when also an
explicit source (including a variable shift amount). O(operand count) space/time.
"""
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG
from daemon_receive_tools import IMAGE
def key(n):return'x'+n[1:]if n.startswith('w')else{'fp':'x29','lr':'x30'}.get(n,n)
def register_access(i):
 reads,writes=i.regs_access()
 if i.mnemonic in ['lsl','lsr']:
  dest=key(i.reg_name(i.operands[0].reg));sources={key(i.reg_name(o.reg))for o in i.operands[1:]if o.type==ARM64_OP_REG}
  if dest not in sources:reads=[r for r in reads if key(i.reg_name(r))!=dest]
 return reads,writes
def audit():
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;rows=[]
 for a,wanted in [(0x100be71e4,{'x9'}),(0x100be7218,{'x14'}),(0x1008b6078,{'x16','x8'})]:
  raw=IMAGE.read(a,4);i=next(cs.disasm(raw,a));rr,ww=i.regs_access();r,w=register_access(i);assert{key(i.reg_name(x))for x in r}==wanted
  rows.append({'address':hex(a),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str,'reported_reads':[i.reg_name(x)for x in rr],'corrected_reads':[i.reg_name(x)for x in r],'writes':[i.reg_name(x)for x in w],'scope':'Architectural shift operand semantics; no incoming destination value fabricated.'})
 return rows
