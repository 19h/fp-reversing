#!/usr/bin/env python3
"""Local cache gates, prospective lookup layouts and saved stop status.

O(I) DAG construction/space; solver-dependent cost. Lookup table/frame
premises are explicit and no native table or accepted record is constructed.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from lskd_values_symbolic import Lift,part,mem,cell,resize
class SelectLift(Lift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;original=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='csel':
    assert i.op_str.rsplit(',',1)[1].strip()=='eq';self.pc=i.address;self.count+=1;self.write(i.reg_name(i.operands[0].reg),z3.If(self.equal,self.read(i.reg_name(i.operands[1].reg)),self.read(i.reg_name(i.operands[2].reg))));continue
   self.c={'spans':[{'label':'instruction','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('instruction')
  self.c=original;return self

def queries(c):
 qs=[];counts={};F=0x51000000;CELL=0x52000000;G=z3.BitVec('state_context_cache64',64);C=z3.BitVec('state_context64',64);TABLE=z3.BitVec('state_table_pointer64',64);ENTRY=z3.BitVec('state_table_entry32',32);KEY=z3.BitVec('state_lookup_key32',32)
 def run(name,a,z,seeds,memory=()):
  v=SelectLift(part(c,name,a,z))
  for reg,x in seeds:v.seed(reg,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 v=run('vault_context_cache_gate',0xfffffe000a56a154,0xfffffe000a56a188,[('w23',0x72d),('x10',CELL)],[(CELL,8,G)]);qs.append(('vault_context_cache_gate',v.read('w10')!=z3.If(G==0,z3.BitVecVal(0x3f0,32),z3.BitVecVal(0x3e6,32))))
 v=run('allowed_context_cache_gate',0xfffffe000a5299e0,0xfffffe000a529a08,[('w28',0x8ac),('x10',CELL)],[(CELL,8,G)]);qs.append(('allowed_context_cache_gate',v.read('w10')!=z3.If(G==0,z3.BitVecVal(0x47b,32),z3.BitVecVal(0x475,32))))
 v=run('vault_prospective_lookup_index',0xfffffe000a5939a0,0xfffffe000a5939c4,[('w9',0x3f0),('sp',F)],[(F+40,8,C^0xe5fc6c5572d2c184),(F+48,8,TABLE)]);qs.append(('vault_prospective_lookup_index',z3.Or(v.read('w10')!=resize(C,32),v.read('w12')!=(resize(C,32)&0x3ff),cell(v,F+60,4)!=(resize(C,32)&0x3ff),v.read('x11')!=TABLE)))
 v=run('allowed_prospective_lookup_index',0xfffffe000a531148,0xfffffe000a531170,[('w28',0x8ac),('sp',F)],[(F+80,8,C^0xfc6c08b9c3804423),(F+96,8,TABLE)]);qs.append(('allowed_prospective_lookup_index',z3.Or(v.read('w11')!=resize(C,32),v.read('w13')!=(resize(C,32)&0x3ff),cell(v,F+116,4)!=(resize(C,32)&0x3ff),v.read('x12')!=TABLE)))
 v=run('vault_prospective_entry_status',0xfffffe000a5939c8,0xfffffe000a5939e0,[('w11',ENTRY),('w10',KEY)]);qs.append(('vault_prospective_entry_status',v.read('w26')!=z3.If(ENTRY==KEY,z3.BitVecVal(0x5e561849,32),z3.BitVecVal(0x5e55719c,32))))
 v=run('allowed_prospective_entry_status',0xfffffe000a531174,0xfffffe000a531190,[('w12',ENTRY),('w11',KEY),('sp',F)]);qs.append(('allowed_prospective_entry_status',cell(v,F+184,4)!=z3.If(ENTRY==KEY,z3.BitVecVal(0x5e561849,32),z3.BitVecVal(0x5e55719c,32))))
 S=z3.BitVec('saved_stop_status64',64);v=run('stop_saved_status_return',0xfffffe000a5054f8,0xfffffe000a5054fc,[('x19',S)]);qs.append(('stop_saved_status_return',v.read('x0')!=S))
 return qs,counts
