#!/usr/bin/env python3
"""Source-lifted initialization induction, time projection and scalar codecs.
O(lifted instructions) DAG construction, 30 s per SMT query. Original
bank's exhaustive 256-input lemma qualifies the time-import composition.
No target, entropy, time query, or authentication executes.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,TABLE
from prove_daemon_frame_entry import FrameLift
from lskd_values_symbolic import part,mem,cell
C=0x55b365ae;M=0x6c078965;D=0xaa4c9a53;B=0x1010c784c
class EntropyLift(FrameLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='cset'and i.op_str.endswith(', hi'):
    self.write(i.reg_name(i.operands[0].reg),z3.If(z3.UGT(self.sleft,self.sright),z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};FrameLift.run(self,'one')
  self.c=old;return self

def obligations(c):
 F,I=z3.BitVecs('entropy_frame64 entropy_index64',64);S,H,P,A,Q,T=z3.BitVecs('entropy_seed32 entropy_high32 entropy_previous32 entropy_controller_A32 entropy_controller_B32 entropy_projection32',32);SEC,USEC,STATUS=z3.BitVecs('time_seconds_low32 time_usec32 time_status32',32);qs=[];counts={};domain=z3.And(F&15==0,z3.UGE(F,0x200000000),z3.ULE(F,(1<<64)-3041));idx=z3.Extract(31,0,I);loopdomain=z3.And(domain,z3.UGE(I,1),z3.ULE(I,623))
 def run(n,a,z,seeds=(),memory=()):
  v=EntropyLift(part(c,n,a,z))
  for name,value in seeds:v.seed(name,value)
  for at,size,value in memory:mem(v,at,size,value)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,d=domain):qs.append((n,z3.And(d,p)))
 setup=run('seed_setup',0x100409578,0x1004095b0,[('x0',z3.Concat(H,S)),('x28',B),('sp',F)],[(F+0xe8,8,0x101068588),(0x101068588,8,0x1002fbee4)])
 add('seed_store_uses_only_low_u32',cell(setup,B,4)!=S);add('seed_setup_and_first_index',z3.Or(setup.read('x8')!=1,setup.read('w9')!=C,setup.read('w12')!=C,setup.read('w13')!=0x5cd3,setup.read('w14')!=M,setup.read('w15')!=D,setup.read('x10')!=0x1002fbee4,setup.read('x17')!=0xd0a9))
 v=run('one_seed_iteration',0x1002fbee4,0x1002fbf20,[('x0',z3.Concat(H,P)),('x8',I),('w9',idx-1+C),('w12',C),('w13',0x5cd3),('w14',M),('w15',D),('x28',B)])
 expected=(P^z3.LShR(P,30))*M+idx
 add('all_u32_seed_iteration_and_carry',z3.Or(cell(v,B+(I<<2),4)!=expected,v.read('w0')!=expected),loopdomain)
 assert len(v.stores)==1 and v.stores[0]['size_bytes']==4
 add('iteration_single_word_destination',v.stores[0]['address']!=B+(I<<2),loopdomain)
 add('inductive_index_and_phase',z3.Or(v.read('x8')!=I+1,v.read('w9')!=idx+C),loopdomain)
 add('seed_independent_termination_selector',v.read('w10')!=z3.If(z3.UGT(idx,622),z3.BitVecVal(0x5ced,32),z3.BitVecVal(0x5cd3,32)),loopdomain)
 args=run('time_arguments',0x1002dc290,0x1002dc2b0,[('sp',F),('w8',624),('x19',0x1010b7dd8)],[(F+0x580,8,F+0x670)])
 add('time_pointer_and_completed_cursor',z3.Or(args.read('x0')!=F+0x680,cell(args,F+0x60c,4)!=624,args.read('w24')!=0x8a9b8560))
 controller=run('time_controller',0x1002dc2b0,0x1002dc2d4,[('x19',0x1010b7dd8),('x23',0x1010c4670)],[(0x1010b7dd8,4,A),(0x1010c4670,4,Q)])
 add('all_u32_time_controller_projection',controller.read('w8')!=((A+Q)^0xa6)*0x0a5cd4cf)
 L=0x100fc4230;R=0x101031fa0;BYTE=z3.BitVec('time_left_lookup8',8);low=z3.Extract(7,0,T)
 projection=run('time_bank_projection',0x1002dc2d4,0x1002dc308,[('sp',F),('x8',z3.ZeroExt(32,T)),('x20',TABLE)],[(F+0x368,8,L),(F+0x360,8,R),(L+z3.ZeroExt(56,low),1,BYTE),(R+z3.ZeroExt(56,BYTE^0xf3),1,low^0x43),(0x10109ff20,8,0x7c100000)])
 add('all_u32_time_import_under_exhaustive_bank_lemma',z3.Or(projection.read('x8')!=0x7c100000,projection.read('x1')!=0,projection.read('x17')!=0x9298))
 time=run('time_output_codecs',0x1002dc30c,0x1002dc354,[('sp',F),('x22',F+0x670),('w24',0x8a9b8560),('w0',STATUS)],[(F+0x680,4,SEC),(F+0x688,4,USEC),(F+0x498,8,F+0x670)])
 add('time_scalar_output_codecs',z3.Or(cell(time,F+0x678,4)!=(SEC^0x5cf7672b),cell(time,F+0x674,4)!=(USEC^0x5cf7672b)))
 add('time_status_unused_in_immediate_output_codecs',time.read('w0')!=STATUS)
 return qs,counts

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_entropy_return_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,p in qs:
  op=ROOT/f'daemon_entropy_return_{name}_original.smt2';np=ROOT/f'daemon_entropy_return_{name}.smt2';s=z3.Solver();s.add(p);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));r=str(s.check());assert r=='unsat',(name,r);np.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':r})
 witnesses=[]
 for f in [0x640000b420,0x640000b520]:
  for i in [1,623]:
   s=z3.Solver();s.add(qs[2][1].arg(0),z3.BitVec('entropy_frame64',64)==f,z3.BitVec('entropy_index64',64)==i);assert str(s.check())=='sat';witnesses.append({'frame':hex(f),'index':i,'result':'sat'})
 deps=['daemon_entropy_return_contracts.json','prove_daemon_frame_entry.py','daemon_rwlock_lifecycle_symbolic.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'source_lift_instruction_visits':sum(counts.values()),'nonempty_premise_witnesses':witnesses,'normalization_dependency':'time_bank_projection uses the source-pinned exhaustive bank lemma x XOR R[L[x] XOR F3] = 43 for all 256 input bytes; no native authentication claim.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_entropy_return_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lifts':counts,'source_lift_instruction_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
