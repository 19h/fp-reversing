#!/usr/bin/env python3
"""Original-instruction local BV proofs for ASCII/strtol arguments, record
output-pointer forwarding, conversion/end-pointer/end-byte guards and exact
low32 output/marker. Readable cell, frame-placement and retained-register
premises are explicit. O(source/BV DAGs + solver resources) time/space.
No native target/framework/IPC execution; host strtol is not part of proofs.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE,TABLE,FIXUPS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell
from capture_daemon_record720 import sha
def obligations():
 qs=[];counts={}
 def run(name,a,z,seeds=(),memory=()):
  m=LifetimeFlags({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('string_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 FP,S,REF,END,VALUE,OUT=z3.BitVecs('string_FP64 string_SP64 string_CF_ref64 string_end64 string_long64 string_out_pointer64',64);RET=z3.BitVec('string_conversion_return32',32);BYTE=z3.BitVec('string_end_byte8',8)
 m=run('ASCII_arguments',0x10014c644,0x10014c658,[('x29',FP),('x21',REF)]);qs.append(('all_ASCII_argument_addresses',z3.Or(m.read('x0')!=REF,m.read('x1')!=FP-0x80,m.read('x2')!=32,m.read('x3')!=0x600,m.read('x17')!=0x7208)))
 m=run('ASCII_return_gate',0x10014c65c,0x10014c67c,[('w19',0x5946),('w22',0xa9a3),('w0',RET)]);qs.append(('all_ASCII_return_words',m.read('w8')!=z3.If(RET!=0,z3.BitVecVal(0x596e,32),z3.BitVecVal(0x5946,32))))
 m=run('parser_arguments',0x10000a2d8,0x10000a2e8,[('x29',FP)]);qs.append(('all_parser_argument_addresses',z3.Or(m.read('x0')!=FP-0x80,m.read('x1')!=FP-0x90,m.read('x2')!=10,m.read('x17')!=0x887b)))
 m=run('end_pointer_gate',0x10000a2ec,0x10000a304,[('x29',FP),('w19',0),('w22',0xa9a3),('x0',VALUE)],[(FP-0x90,8,END)]);qs.append(('all_end_pointer_and_long_words',z3.Or(m.read('w8')!=z3.If(END!=0,z3.BitVecVal(0xa9d6,32),z3.BitVecVal(0xa9a3,32)),m.read('x9')!=END,m.read('x0')!=VALUE)))
 m=run('end_byte_gate',0x1000094e4,0x100009524,[('x9',END),('w19',0),('w20',0x38f8),('x0',VALUE)],[(END,1,BYTE)]);qs.append(('all_end_bytes_and_long_words',z3.Or(m.read('w9')!=z3.If(BYTE==0,z3.BitVecVal(0x1f1e,32),z3.BitVecVal(0x1f11,32)),m.read('x0')!=VALUE)))
 m=run('output_pointer_forward',0x10003b2c0,0x10003b2cc,[('sp',S)],[(S+0x48,8,S+0x10df8),(S+0x10e08,8,OUT)]);qs.append(('all_record_output_pointer_words',cell(m,S+0x18,8)!=OUT))
 slot=TABLE+0x1f11*8;target=FIXUPS[slot]['target']
 class ByteMemory(LifetimeFlags):
  def __init__(self,c):super().__init__(c);self.ram=z3.Array('string_exact_byte_memory',z3.BitVecSort(64),z3.BitVecSort(8))
  def load(self,a,n):return z3.Concat(*[z3.Select(self.ram,a+j)for j in reversed(range(n))])if n>1 else z3.Select(self.ram,a)
  def store(self,a,n,value,pc):
   value=z3.BitVecVal(value,8*n)if isinstance(value,int)else value
   for j in range(n):self.ram=z3.Store(self.ram,a+j,z3.Extract(8*j+7,8*j,value))
  def seed_memory(self,a,n,value):self.store(z3.BitVecVal(a,64)if isinstance(a,int)else a,n,value,0)
 a,z=0x100073fd8,0x100073fe8;m=ByteMemory({'spans':[{'label':'one','start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
 for reg,value in [('sp',S),('x0',VALUE),('x23',TABLE),('w8',0x1f11)]:m.seed(reg,value)
 m.seed_memory(S+0x18,8,OUT);m.seed_memory(slot,8,target);m.run('one');counts['output_and_marker']=m.count
 separate=z3.And(*[S+0x18+j!=slot+k for j in range(8)for k in range(8)],*[OUT+j!=slot+k for j in range(4)for k in range(8)])
 qs.append(('all_long_words_low32_store_and_marker',z3.And(separate,z3.Or(m.load(OUT,4)!=z3.Extract(31,0,VALUE),m.read('w24')!=0x32,m.read('x8')!=target))))
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_secondary_string_'+name+'_original.smt2');b=ROOT/('daemon_secondary_string_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_secondary_string_contracts.json','daemon_arena_lifetime_symbolic.py']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_secondary_string_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
