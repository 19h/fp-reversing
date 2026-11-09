#!/usr/bin/env python3
"""Source-derived query arguments, status/size gates, fallback and kext publication.

O(I) BV DAG time/space plus solver cost. Shared-frame phases are explicit;
no IOKit, native provider, Mach or PAC operation executes.
"""
import z3
from lskd_values_symbolic import Lift,part,mem,cell

def queries(c):
 merged={'spans':c['spans']+c['kext_spans']};qs=[];counts={};F=0x51000000;S=z3.BitVec('query_status32',32);N=z3.BitVec('query_returned_size64',64)
 def run(name,a,z,seeds=(),memory=()):
  v=Lift(part(merged,name,a,z))
  for n,x in seeds:v.seed(n,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 v=run('query22_phase',0x10036439c,0x1003643b0,[('x21',0x9376)]);qs.append(('query22_phase',z3.Or(v.read('w19')!=0x9376,v.read('w26')!=0x2ae9,v.read('w21')!=0x5222)))
 v=run('query22_capacity',0x1003643b0,0x1003643b8,[('sp',F)]);qs.append(('query22_capacity',cell(v,F+0x70,8)!=4))
 C=z3.BitVec('connection32',32);CP=0x52000000;v=run('query22_connection',0x1003643f4,0x1003643f8,[('x20',CP)],[(CP,4,C)]);u=run('query22_arguments',0x100364408,0x100364420,[('sp',F),('x0',v.read('x0'))]);qs.append(('query22_arguments',z3.Or(u.read('x0')!=z3.ZeroExt(32,C),u.read('x1')!=22,u.read('x2')!=0,u.read('x3')!=0,u.read('x4')!=F+0x64,u.read('x5')!=F+0x70,u.read('x17')!=0x7a6c)))
 v=run('query22_status_and_size',0x100364424,0x100364460,[('sp',F),('w0',S),('w21',0x5222),('w19',0x9376)],[(F+0x70,8,N)]);good=z3.And(S==0,N==4);qs.append(('query22_status_and_size',v.read('w8')!=z3.If(good,z3.BitVecVal(0x9380,32),z3.BitVecVal(0x9376,32))))
 v=run('query22_failure_clear',0x100628754,0x100628760,[('sp',F),('w21',0x5222)]);qs.append(('query22_failure_clear',z3.Or(v.read('w26')!=0x2ae9,cell(v,F+0x64,4)!=0)))
 v=run('query23_phase',0x1004ba914,0x1004ba934,[('w26',0x2ae9)]);qs.append(('query23_phase',z3.Or(v.read('w21')!=0x66ac,v.read('w25')!=0x66ac)))
 v=run('query23_capacity',0x1004ba934,0x1004ba93c,[('sp',F)]);qs.append(('query23_capacity',cell(v,F+0x70,8)!=4))
 v=run('query23_connection',0x1004ba93c,0x1004ba940,[('x20',CP)],[(CP,4,C)]);u=run('query23_arguments',0x1004ba9ac,0x1004ba9c4,[('sp',F),('x0',v.read('x0'))]);qs.append(('query23_arguments',z3.Or(u.read('x0')!=z3.ZeroExt(32,C),u.read('x1')!=23,u.read('x2')!=0,u.read('x3')!=0,u.read('x4')!=F+0x6c,u.read('x5')!=F+0x70,u.read('x17')!=0x7a6c)))
 v=run('query23_status_and_size',0x1004ba9c8,0x1004baa0c,[('sp',F),('w0',S),('w25',0x66ac),('w26',0x2ae9)],[(F+0x70,8,N)]);qs.append(('query23_status_and_size',v.read('w8')!=z3.If(good,z3.BitVecVal(0x2b07,32),z3.BitVecVal(0x2ae9,32))))
 O=z3.BitVec('query_output32',32);v=run('query23_success_publication',0x100332734,0x100332740,[('sp',F),('w21',0x66ac)],[(F+0x6c,4,O)]);qs.append(('query23_success_publication',z3.Or(v.read('w20')!=0x4ef4,v.read('w8')!=O)))
 v=run('query23_failure_publication',0x1004d6be4,0x1004d6c04,[('sp',F),('w25',0x66ac)]);qs.append(('query23_failure_publication',z3.Or(v.read('w20')!=0x4ef4,v.read('w8')!=0,cell(v,F+0x6c,4)!=0)))
 R=z3.BitVec('provider_result64',64);OUT=z3.BitVec('query_output_pointer64',64)
 for label,a in[('kext_version_publication',0xfffffe000a505108),('kext_capability_publication',0xfffffe000a505160)]:
  v=run(label,a,a+12,[('x0',R),('x19',OUT)]);qs.append((label,z3.Or(v.read('w0')!=0,cell(v,OUT,4)!=z3.Extract(31,0,R))))
 return qs,counts
