#!/usr/bin/env python3
"""Source-local rejection status, allocation argument and frame restore lemmas.

O(I) bit-vector DAG time/space plus solver cost. Fixed cells and phase
premises are explicit; no native target/PAC/heap operation executes.
"""
import z3
from lskd_values_symbolic import Lift,part,mem,cell
def queries(c):
 qs=[];counts={};F=0x51000000
 def run(name,a,z,seeds=(),memory=()):
  v=Lift(part(c,name,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,n,val in memory:mem(v,at,n,val)
  v.run(name);counts[name]=v.count;return v
 v=run('source_guard_encoded_rejection_seed',0xfffffe000a594cf8,0xfffffe000a594d00);qs.append(('source_guard_encoded_rejection_seed',v.read('x16')!=0xad677e52))
 v=run('source_guard_selector_phase',0xfffffe000a594c8c,0xfffffe000a594c90,[('w10',0x4bb)]);qs.append(('source_guard_selector_phase',v.read('w21')!=0x8de))
 E=z3.BitVec('core_rejection_encoded64',64);v=run('source_rejection_callee_saved_status',0xfffffe000a58c0c0,0xfffffe000a58c0c4,[('x16',E)]);u=run('source_rejection_status_decode',0xfffffe000a58c1b0,0xfffffe000a58c1bc,[('x21',v.read('x21'))]);qs.append(('source_rejection_status_transformation',u.read('w0')!=(z3.Extract(31,0,E)^0x52982734)))
 L=z3.BitVec('core_shape_length32',32);A=z3.BitVec('core_typed_pointer64',64);v=run('source_selected_allocation_length',0xfffffe000a56d208,0xfffffe000a56d20c,[('w13',L)]);u=run('source_selected_saved_arguments',0xfffffe000a56d21c,0xfffffe000a56d224,[('sp',F),('x0',v.read('x0')),('x1',A)]);qs.append(('source_selected_allocation_arguments',z3.Or(v.read('x0')!=z3.ZeroExt(32,L),cell(u,F+0x4f8,8)!=z3.ZeroExt(32,L),cell(u,F+0xd40,8)!=A)))
 W=z3.BitVec('core_workspace_pointer64',64);v=run('source_aligned_cleanup_arguments',0xfffffe000a58c188,0xfffffe000a58c190,[('sp',F)],[(F+0xd50,8,W)]);qs.append(('source_aligned_cleanup_arguments',z3.Or(v.read('x0')!=W,v.read('x1')!=16384)))
 v=run('source_rejection_frame_reclaim',0xfffffe000a58c1bc,0xfffffe000a58c1c4,[('sp',F)]);qs.append(('source_rejection_frame_reclaim',v.read('sp')!=F+0x13c0))
 regs=['x29','x30','x20','x19','x22','x21','x24','x23','x26','x25','x28','x27'];offs=[0x90,0x98,0x80,0x88,0x70,0x78,0x60,0x68,0x50,0x58,0x40,0x48];values=[z3.BitVec('core_entry_'+reg,64)for reg in regs];v=run('source_rejection_GP_restore',0xfffffe000a58c1c4,0xfffffe000a58c1dc,[('sp',F+0x13c0)],[(F+0x13c0+o,8,x)for o,x in zip(offs,values)]);qs.append(('source_rejection_GP_restore',z3.Or(*[v.read(reg)!=val for reg,val in zip(regs,values)])))
 return qs,counts
