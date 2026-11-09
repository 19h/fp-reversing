#!/usr/bin/env python3
"""Source discovery/open/status/argument/alias proofs;explicit API summaries.

O(I) BV DAG time/space plus30 s/query. No native IOKit/Mach/PAC operation.
"""
import z3
from daemon_query_fallback_symbolic import FlagLift
from lskd_values_symbolic import part,mem,cell,resize

def queries(c):
 qs=[];counts={};F=z3.BitVec('objects_frame64',64);MP,IT,SV,TP,ST,REL=z3.BitVecs('main_port32 iterator32 service32 owning_task32 API_status32 release_status32',32);D=z3.BitVec('matching_dictionary64',64);S=0x1010b6380;TABLE=0x101039ef0
 def run(name,a,z,seeds=(),memory=()):
  x=FlagLift(part(c,name,a,z))
  for n,v in seeds:x.seed(n,v)
  for at,n,v in memory:mem(x,at,n,v)
  x.run(name);counts[name]=x.count;return x
 v=run('matching_saved_banks',0x1003f94ec,0x1003f94f4,[('sp',F),('x0',D),('x19',0x101031ea0),('x25',0x100fc4130)])
 qs.append(('matching_saved_banks',z3.Or(v.read('x1')!=D,cell(v,F+0x18,8)!=0x101031ea0,cell(v,F+0x20,8)!=0x100fc4130)))
 phase=run('matching_phase',0x1003f94f4,0x1003f951c,[('w28',0xb606)]);qs.append(('matching_phase',z3.Or(phase.read('w19')!=0x6e12,phase.read('w25')!=0x597a)))
 port=run('matching_port',0x1003f9578,0x1003f957c,[('sp',F)],[(F+0x7c,4,MP)]);v=run('matching_output_pointer',0x1003f958c,0x1003f9594,[('sp',F),('x0',port.read('x0')),('x1',D)]);qs.append(('matching_arguments',z3.Or(v.read('x0')!=z3.ZeroExt(32,MP),v.read('x1')!=D,v.read('x2')!=F+0x68,v.read('x17')!=0xa027)))
 gate=run('matching_status_gate',0x1003f9598,0x1003f95b8,[('w0',ST),('w19',phase.read('w19')),('w25',phase.read('w25')),('w28',0xb606)]);qs.append(('matching_status_gate',gate.read('w8')!=z3.If(ST==0,z3.BitVecVal(0xb60d,32),z3.BitVecVal(0xb606,32))))
 v=run('iterator_phase',0x10036c42c,0x10036c450,[('sp',F),('x26',0x100e99a00),('w19',0x6e12)]);qs.append(('iterator_phase',z3.Or(v.read('w26')!=0x5784,v.read('w25')!=0xab5b,cell(v,F+0x10,8)!=0x100e99a00)))
 v=run('iterator_argument',0x10036c48c,0x10036c490,[('sp',F)],[(F+0x68,4,IT)]);qs.append(('iterator_argument',v.read('x0')!=z3.ZeroExt(32,IT)))
 v=run('iterator_result_gate',0x10036c4a8,0x10036c4c4,[('w0',SV),('w25',0xab5b),('w19',0x6e12)]);qs.append(('iterator_result_gate',v.read('w8')!=z3.If(SV==0,z3.BitVecVal(0x6e61,32),z3.BitVecVal(0x6e12,32))))
 v=run('open_phase',0x100478b40,0x100478b44,[('w8',0x382d),('w25',0xab5b)]);qs.append(('open_phase',v.read('w26')!=0x9376))
 SYM=z3.BitVec('mach_task_self_symbol_storage64',64);v=run('task_bind_addend_cancellation',0x100478b54,0x100478b60,[('x8',SYM+0x7bf13863)]);qs.append(('task_bind_addend_cancellation',v.read('x8')!=SYM))
 v=run('task_storage_load',0x100478b60,0x100478b64,[('x8',SYM)],[(SYM,4,TP)]);qs.append(('task_storage_load',v.read('x1')!=z3.ZeroExt(32,TP)))
 v=run('open_arguments',0x100478b98,0x100478bb0,[('sp',F),('x0',z3.ZeroExt(32,SV)),('x1',z3.ZeroExt(32,TP))],[(F+0x58,8,S)]);qs.append(('open_arguments',z3.Or(v.read('x0')!=z3.ZeroExt(32,SV),v.read('x1')!=z3.ZeroExt(32,TP),v.read('x2')!=0,v.read('x3')!=S+4,v.read('x20')!=z3.ZeroExt(32,SV),cell(v,F+8,8)!=S+4,v.read('x17')!=0xe82b)))
 folded=run('open_status_fold',0x100478bb4,0x100478be0,[('w0',ST),('x26',0x9376)]);encoded=run('open_status_save',0x100478c10,0x100478c14,[('w8',folded.read('w8')),('w9',folded.read('w9'))]);constant=(0x7fbf9d37+0x9376+0xec7ce876)&0xffffffff
 qs.append(('open_status_encoding',encoded.read('w27')!=ST+constant))
 v=run('service_release_argument',0x100478c24,0x100478c2c,[('x20',z3.ZeroExt(32,SV))]);qs.append(('service_release_argument',z3.Or(v.read('x0')!=z3.ZeroExt(32,SV),v.read('x17')!=0xbe7e)))
 v=run('open_status_gate_after_release',0x100478c30,0x100478c50,[('w25',0xab5b),('w27',encoded.read('w27')),('w0',REL)]);qs.append(('open_status_gate_after_release',v.read('w8')!=z3.If(ST==0,z3.BitVecVal(0xab6b,32),z3.BitVecVal(0xab5b,32))))
 v=run('empty_iterator_result',0x1004a89f4,0x1004a8a04,[('sp',F),('w26',0x5784)]);qs.append(('empty_iterator_result',z3.Or(v.read('w8')!=0x4ef4,cell(v,F+0x60,4)!=0x74c29c07)))
 v=run('iterator_release_argument',0x100483ca8,0x100483cac,[('sp',F)],[(F+0x68,4,IT)]);qs.append(('iterator_release_argument',v.read('x0')!=z3.ZeroExt(32,IT)))
 v=run('cleanup_dispatch',0x100483cc4,0x100483cd0,[('sp',F),('x24',TABLE),('w20',0x597a),('w0',REL)],[(TABLE+0x597a*8,8,0x100383b00),(F+0x40,8,0x100e99800),(F+0x48,8,0x100f4e290)]);qs.append(('cleanup_dispatch',z3.Or(v.read('x8')!=0x100383b00,v.read('x13')!=0x100e99800,v.read('x12')!=0x100f4e290,v.read('x17')!=0x7b16)))
 v=run('candidate_frame668_pointer',0x1002903f8,0x100290414,[('sp',F),('w7',0x43),('x1',0x1010a1960)],[(0x1010a2d78,8,0x1020c48b3)]);qs.append(('candidate_frame668_pointer',z3.Or(v.read('x14')!=S,cell(v,F+0x668,8)!=S)))
 v=run('candidate_frame80_pointer',0x100634b5c,0x100634b74,[('sp',F),('w11',0xa1),('x15',0x1010a1960)],[(0x1010a2d78,8,0x1020c48b3)]);qs.append(('candidate_frame80_pointer',z3.Or(v.read('x11')!=S,cell(v,F+0x80,8)!=S)))
 return qs,counts
