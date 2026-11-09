#!/usr/bin/env python3
"""Original class-byte/phase/matching/registration-argument source obligations.

O(I) BV DAG time/space plus30 s/query. Fixed source phases and original fixups;
no native daemon/kernel/API/PAC executes. Native publication remains unknown.
"""
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_query_fallback_symbolic import FlagLift
from lskd_values_symbolic import part,mem,cell
class ClassLift(FlagLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,int(row['start'],16)));assert len(ins)*4==len(raw);original=self.c
  for i in ins:
   self.pc=i.address
   if i.mnemonic=='adrp':self.write(i.reg_name(i.operands[0].reg),z3.BitVecVal(i.operands[1].imm&((1<<64)-1),64));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};FlagLift.run(self,'one')
  self.c=original;return self

def queries(c):
 merged={'spans':c['spans']+c['kext_constructors']+c['kext_spans']};qs=[];counts={};F=z3.BitVec('class_frame64',64);W=z3.BitVec('decoder_entry_W28',32);ST=z3.BitVec('main_port_status32',32);D=z3.BitVec('matching_return_pointer64',64)
 def run(name,a,z,seeds=(),memory=()):
  x=ClassLift(part(merged,name,a,z))
  for n,v in seeds:x.seed(n,v)
  for at,n,v in memory:mem(x,at,n,v)
  x.run(name);counts[name]=x.count;return x
 IN=z3.BitVec('outer_input64',64);v=run('saved_context_tables',0x100461c30,0x100461c38,[('sp',F),('x19',IN),('x13',0x100e99800),('x12',0x100f4e290)]);qs.append(('saved_context_tables',z3.Or(cell(v,F+0x38,8)!=IN,cell(v,F+0x40,8)!=0x100e99800,cell(v,F+0x48,8)!=0x100f4e290)))
 v=run('main_phase',0x100461c38,0x100461c40,[('w28',W)]);qs.append(('main_phase',v.read('w26')!=(W^0xc3e1)))
 v=run('main_phase_preserved',0x100461ca4,0x100461ca8,[('w26',v.read('w26')),('w8',0xc3e1)]);qs.append(('main_phase_preserved',v.read('w28')!=W))
 v=run('main_arguments',0x100461cb8,0x100461cc4,[('sp',F)]);qs.append(('main_arguments',z3.Or(v.read('x0')!=0,v.read('x1')!=F+0x7c,v.read('x17')!=0x6240)))
 v=run('main_status_gate',0x100461cc8,0x100461ce0,[('w0',ST),('w28',0x597a),('w26',0x9a9b)]);qs.append(('main_status_gate',v.read('w8')!=z3.If(ST==0,z3.BitVecVal(0x9a9b,32),z3.BitVecVal(0x9ae1,32))))
 phase=run('decoder_phase',0x10040b5e0,0x10040b5fc,[('sp',F),('w28',W)]);qs.append(('decoder_phase',z3.Or(cell(phase,F+0x28,4)!=W-0x31ac,phase.read('w26')!=W-0x1f6,phase.read('w28')!=((W-0x31ac)^0x91c8))))
 DATA,CELL=0x100fd40c0,0x1010b8cc0;encoded=bytes.fromhex(c['class_data']['encoded31_hex']);name=bytes.fromhex(c['class_data']['expected_class31_hex'])
 dec=run('class_bytes',0x10040b64c,0x10040b7d4,[('sp',F),('x9',CELL),('w26',phase.read('w26')),('w28',phase.read('w28'))],[(CELL,8,DATA)]+[(DATA+j,1,b)for j,b in enumerate(encoded)])
 got=[cell(dec,F+0x89+j,1)for j in range(31)];mask3=z3.Extract(7,0,phase.read('w26')^0x78);mask5=z3.Extract(7,0,phase.read('w28')^0xfa);expect=[z3.BitVecVal(b,8)^(mask3 if j==3 else mask5 if j==5 else z3.BitVecVal(0xfc,8))for j,b in enumerate(encoded)]
 qs.append(('class_byte_formulas',z3.Or(*[a!=b for a,b in zip(got,expect)])));same=z3.And(*[a==b for a,b in zip(got,name)]);qs.append(('class_name_unique_low_byte',z3.Xor(same,z3.Extract(7,0,W)==0x7a)));qs.append(('class_terminator',got[-1]!=0))
 qs.append(('selected_path_class_name',z3.And(W==0x597a,z3.Not(same))))
 v=run('class_matching_argument',0x10040b80c,0x10040b814,[('sp',F)]);qs.append(('class_matching_argument',z3.Or(v.read('x0')!=F+0x89,v.read('x17')!=0x83b)))
 v=run('matching_return_gate',0x10040b818,0x10040b830,[('sp',F),('x0',D)],[(F+0x28,4,0x27ce)]);qs.append(('matching_return_gate',z3.Or(v.read('x0')!=D,v.read('w8')!=z3.If(D!=0,z3.BitVecVal(0x27d5,32),z3.BitVecVal(0x27ce,32)))))
 v=run('null_matching_result',0x1004616a8,0x1004616b8,[('sp',F),('w26',0x5784)]);qs.append(('null_matching_result',z3.Or(v.read('w8')!=0x597a,cell(v,F+0x60,4)!=0x74c29fc9)))
 # Registration argument setup only. No kernel constructor/registration effect.
 THIS=z3.BitVec('metaclass_receiver64',64);SUPER=0xfffffe000cb5c060;CNAME=0xfffffe000790cc00
 for label,a,z in[('kext_C1_arguments',0xfffffe000a50a844,0xfffffe000a50a858),('kext_C2_arguments',0xfffffe000a50a988,0xfffffe000a50a99c)]:
  v=run(label,a,z,[('x0',THIS)],[(0xfffffe000847c5d8,8,SUPER)]);qs.append((label,z3.Or(v.read('x0')!=THIS,v.read('x1')!=CNAME,v.read('x2')!=SUPER,v.read('x3')!=0x88)))
 return qs,counts
