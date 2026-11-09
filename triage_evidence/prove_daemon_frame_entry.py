#!/usr/bin/env python3
"""Source-lifted frame, controller, CAS, result and cursor obligations.
O(I) bit-vector DAG construction/time/space; solver timeout 30 s/query.
CAS is one single-thread architectural compare/exchange transition; native
PAC/concurrency and unknown incoming stack contents are outside this proof.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_UXTB
from daemon_receive_tools import ROOT
from daemon_rwlock_lifecycle_symbolic import RwLift
from lskd_values_symbolic import part,mem,cell
class FrameLift(RwLift):
 def operand(self,i,o,n):
  if o.ext==ARM64_EXT_UXTB:
   assert not o.shift.type;from lskd_values_symbolic import resize
   return resize(self.read(i.reg_name(o.reg)),n)&255
  return super().operand(i,o,n)
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='casal':
    e,d,m=i.operands;er,dr=i.reg_name(e.reg),i.reg_name(d.reg);a=self.address(i,m);before=self.load(a,4);expect=self.read(er);desired=self.read(dr);self.store(a,4,z3.If(before==expect,desired,before),i.address);self.write(er,before);self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};RwLift.run(self,'one')
  self.c=old;return self
def obligations(c):
 qs=[];counts={};F,A,B=z3.BitVecs('frame_SP64 controller_A64 controller_B64',64);S=z3.BitVec('gate_state32',32);Q=z3.BitVec('gate_address64',64);P=z3.BitVec('cursor64',64)
 def run(n,a,z,seeds=(),memory=()):
  v=FrameLift(part(c,n,a,z))
  for r,x in seeds:v.seed(r,x)
  for at,size,x in memory:mem(v,at,size,x)
  v.run(n);counts[n]=v.count;return v
 v=run('frame_geometry',0x100450568,0x100450570,[('sp',F+0xb40)]);qs.append(('frame_geometry',z3.Or(v.read('sp')!=F,v.read('x29')!=F+0xbd0)))
 literal=run('cursor_literal',0x100450710,0x100450714)
 v=run('initial_cursor',0x100450724,0x100450728,[('sp',F),('x12',literal.read('x12'))]);qs.append(('initial_cursor',cell(v,F+0x5c0,8)!=16))
 v=run('caller_bank_stores',0x100450694,0x1004506ac,[('sp',F),('x0',0x100e99a00),('x15',0x100f4e390),('w11',0),('w14',0x54)],[(0x100e99a00,1,0),(0x100f4e3e4,1,z3.BitVec("unused_bank_byte8",8))]);qs.append(('caller_bank_stores',z3.Or(cell(v,F+0x378,8)!=0x100e99a00,cell(v,F+0x370,8)!=0x100f4e390)))
 v=run('controller_update',0x100450650,0x100450680,[('sp',F),('x1',0x1010c4670),('x6',0x1010b7dd8),('x12',A),('x9',0xa5cd4cf)],[(0x1010c4670,8,B)]);D=((B-A-(F+0x658))^0x73d046208eaed1a6)*0xa5cd4cf;qs.append(('controller_update',z3.Or(cell(v,0x1010b7dd8,8)!=D,cell(v,0x1010c4670,8)!=D)))
 v=run('initial_status',0x1004506c8,0x1004506d8,[('sp',F),('x12',0x1010b6360)]);qs.append(('initial_status',z3.Or(cell(v,F+0x28,8)!=0x1010b6360,cell(v,0x1010b6360,4)!=0x8b3dc651)))
 v=run('first_CAS_and_dispatch',0x10035df80,0x10035df9c,[('x7',Q),('w13',0xa94ef),('w14',0x5d96),('w15',0x8720)],[(Q,4,S)]);qs.append(('CAS_word_transition',cell(v,Q,4)!=z3.If(S==0x5d96,z3.BitVecVal(0xa94ef,32),S)));qs.append(('CAS_dispatch_index',v.read('w16')!=z3.If(S==0x5d96,z3.BitVecVal(0x8726,32),z3.BitVecVal(0x8720,32))))
 v=run('saved_controller_roots',0x10032bb6c,0x10032bb80,[('sp',F),('x6',0x1010b7dd8),('x1',0x1010c4670),('x26',0x100e99900),('x2',0x101031da0),('x7',0x1010b5de0)]);qs.append(('saved_controller_roots',z3.Or(cell(v,F+0x390,8)!=0x1010b7dd8,cell(v,F+0x398,8)!=0x1010c4670)))
 v=run('global_flag_gate',0x1003308a0,0x1003308e4,[('sp',F),('w8',0x49fa)],[(F+0x1c8,8,0x1010b6cb8),(0x1010b6cb8,4,S)]);qs.append(('global_flag_gate',z3.Or(v.read('w9')!=0x8a9b8560,v.read('w8')!=z3.If(S==0,z3.BitVecVal(0x49fa,32),z3.BitVecVal(0x49fd,32)))))
 v=run('flag_zero_marker',0x10046c748,0x10046c754,[('sp',F)],[(F+0x200,8,0x1010c5798)]);qs.append(('flag_zero_marker',cell(v,0x1010c5798,1)!=1))
 v=run('plain_gate_restore',0x10032c598,0x10032c5a0,[('x7',0x1010b5de0)]);qs.append(('plain_gate_restore',cell(v,0x1010b5de0,4)!=0x5d96))
 v=run('fill_arguments',0x100306308,0x10030631c,[('sp',F)]);qs.append(('fill_arguments',z3.Or(v.read('x0')!=F+0x6f0,v.read('x21')!=F+0x6f0,v.read('x1')!=0,v.read('x2')!=1024,v.read('x17')!=0xac7d)))
 v=run('cursor_reservation',0x100306320,0x10030633c,[('sp',F),('x21',F+0x6f0)],[(F+0x5c0,8,P)]);qs.append(('cursor_reservation',z3.Or(v.read('x10')!=P+64,cell(v,F+0x250,8)!=F+0x660+P,cell(v,F+0x6e8,8)!=F+0x6f0)))
 v=run('cursor_publication',0x10030635c,0x100306360,[('sp',F),('x10',P+64)]);qs.append(('cursor_publication',cell(v,F+0x5c0,8)!=P+64))
 return qs,counts
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_frame_entry_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for n,q in qs:
  op=ROOT/f'daemon_frame_entry_{n}_original.smt2';np=ROOT/f'daemon_frame_entry_{n}.smt2';s=z3.Solver();s.add(q);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(n,result);np.write_text(s.to_smt2());rows.append({'name':n,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 deps=['daemon_frame_entry_contracts.json','daemon_rwlock_lifecycle_symbolic.py','daemon_iokit_sync_symbolic.py','daemon_iokit_class_symbolic.py','daemon_query_fallback_symbolic.py','daemon_query_state_symbolic.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_frame_entry_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(rows),'source_lift_counts':counts}),flush=True)
if __name__=='__main__':main()
