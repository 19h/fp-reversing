#!/usr/bin/env python3
"""Restore the sealed, independently replayed prefix journal without rerunning it.
Validate source bytes, read/write consistency and complete boundary GPRs.
O(prefix visits+byte events) time/space; no target or imports execute.
"""
import z3
from daemon_entropy_return_symbolic import EntropyReturn,CALL
from daemon_receive_tools import IMAGE
from replay_daemon_context_transfer import unpack

def expression(s,F):
 if'hex'in s:return z3.BitVecVal(int.from_bytes(bytes.fromhex(s['hex']),'little'),8*len(bytes.fromhex(s['hex'])))
 assert'terms'in s
 return z3.Concat(*[z3.BitVecVal(x,8)if isinstance(x,int)else z3.BitVec('unknown_'+hex(F+x['origin']),8)for x in reversed(s['terms'])])

def restore(base,context):
 t=unpack(context);v=EntropyReturn(base);assert t['boundary']['pc']==hex(CALL)
 for row in t['steps']:
  a=int(row['pc'],16);assert IMAGE.read(a,4).hex()==row['bytes_hex']
  for e in row['events']:
   a=int(e['address'],16);n=e['size_bytes'];value=expression(e['value'],v.F)
   for j in range(n):
    b=z3.simplify(z3.Extract(j*8+7,j*8,value))
    if e['kind']=='read'and a+j in v.bytes:assert z3.is_true(z3.simplify(v.bytes[a+j]==b)),(row['pc'],hex(a+j))
    v.bytes[a+j]=b
  for reg,s in row['registers_after'].items():v.regs[v.key(reg)]=expression(s,v.F)
  if'NZCV_after'in row:v.n,v.z,v.carry,v.overflow=[z3.BoolVal(bool(row['NZCV_after']&(1<<(31-j))))for j in range(4)]
 for j,s in enumerate(t['boundary']['registers31']):assert z3.is_true(z3.simplify(v.read('x'+str(j))==expression(s,v.F)))
 assert v.concrete(v.read('sp'),'SP')==int(t['boundary']['SP'],16)
 v.origins={int(o['address'],16):{k:x for k,x in o.items()if k!='address'}for o in t['origins']};return v
