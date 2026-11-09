#!/usr/bin/env python3
"""Source-local adapter, address-coded record and context codec obligations.
O(source instructions) expression construction; 30 s/query; fixed memory cells.
No native target, API or pointer authentication. Domain premises are explicit.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT
from daemon_global_state_lift import GlobalLift
from daemon_callback_simd import apply
from lskd_values_symbolic import resize,part,mem,cell
class CallbackLift(GlobalLift):
 def key(self,n):return 'q'+n[1:]if n[:1]in 'qvsdhb'and n[1:].isdigit()else super().key(n)
 def width(self,n):return 128 if n[:1]in 'qv'and n[1:].isdigit()else 32 if n.startswith('s')and n[1:].isdigit()else 16 if n.startswith('h')and n[1:].isdigit()else 8 if n.startswith('b')and n[1:].isdigit()else super().width(n)
 def seed(self,n,v):self.regs[self.key(n)]=resize(v,128 if self.key(n).startswith('q')else 64)
 def write(self,n,v):
  if n in ['xzr','wzr']:return
  self.regs[self.key(n)]=z3.simplify(resize(resize(v,self.width(n)),128 if self.key(n).startswith('q')else 64))
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);old=self.c;cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if apply(self,i):self.count+=1;continue
   if i.mnemonic in ['sturh','ldurh']:
    o=i.operands;a=self.address(i,o[1]);r=i.reg_name(o[0].reg)
    if i.mnemonic=='sturh':self.store(a,2,self.read(r),i.address)
    else:self.write(r,self.load(a,2))
    self.count+=1;continue
   self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};GlobalLift.run(self,'one')
  self.c=old;return self

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def obligations(c):
 qs=[];counts={};R,F,C,T,O=z3.BitVecs('callback_record64 callback_frame64 callback_state64 callback_temp64 callback_output64',64);K=z3.Extract(31,0,(R^0xeaae0ac9)*0x7398180b);L=z3.BitVec('callback_length16',16);CTL=z3.BitVec('callback_control32',32)
 def run(name,a,z,seeds=(),memory=()):
  v=CallbackLift(part(c,name,a,z))
  for n,x in seeds:v.seed(n,x)
  for at,n,x in memory:mem(v,at,n,x)
  v.run(name);counts[name]=v.count;return v
 def add(n,p,d=z3.BoolVal(True)):qs.append((n,z3.And(d,p)))
 step=run('LCG',0x100add6c0,0x100add6cc,[('x21',C)]);add('all_u64_adapter_LCG',step.read('x2')!=C*0x2ec5+1)
 reserve=16*(z3.LShR(C,60)+1);alloc=run('allocation',0x100add72c,0x100add750,[('sp',F),('x2',C),('x21',T)]);add('adapter_allocation_and_bias',z3.Or(alloc.read('sp')!=F-reserve,alloc.stores[0]['address']!=F-reserve,alloc.stores[0]['value']!=T-0xb0));add('adapter_reserve_bounds_alignment',z3.Or(z3.ULT(reserve,16),z3.UGT(reserve,256),reserve&15!=0))
 delta=run('delta',0x100add7d8,0x100add7e8,[('x20',0x70000000),('x19',0x70001000),('w21',z3.Extract(31,0,C))],[(0x70000000,4,z3.Extract(31,0,T))]);E=z3.ZeroExt(32,(z3.Extract(31,0,T-C)&65535))<<4;add('adapter_return_delta',cell(delta,0x70001000,8)!=E);add('adapter_delta_range_alignment',z3.Or(z3.UGT(E,0xffff0),E&15!=0))
 key=run('key',0x100acdb20,0x100acdb54,[('x0',R)]);add('all_u32_record_key',key.read('w8')!=K)
 aligned=R&3==0;pack=run('pack',0x1003013e8,0x100301444,[('x29',R+0xd8),('sp',F)]);add('aligned4_caller_key',pack.read('w8')!=0xb399-K,aligned);add('caller_pointer_length_control',z3.Or(cell(pack,R+8,8)!=F+0x5b4,cell(pack,R+0x10,2)!=resize(K+0x153f,16),cell(pack,R+0x14,4)!=0xb399-K),aligned)
 decode=run('decode',0x100acdb54,0x100acdb80,[('x0',R),('sp',F),('w8',K)],[(R+0x14,4,CTL-K),(R+8,8,O),(R+0x10,2,L+resize(K,16)+0x153b)]);add('all_record_control_length_gate',z3.Or(decode.read('w15')!=CTL,decode.equal!=z3.Not(z3.And(O!=0,L!=0))))
 S,I=z3.BitVecs('callback_seed32 callback_index32',32);B=z3.BitVec('callback_input_block128',128);p=c['context_payload'];const=p['vector_constants'];seeds=[('x15',0x70000000),('x11',0),('q1',z3.Concat(S,S,S,S))]
 for name,off in [('q2',12),('q3',8),('q4',4),('q5',0)]:seeds.append((name,z3.Concat(*[I+off+k for k in range(3,-1,-1)])))
 for n in ['q26','q27','q28','q29','q30','q31']:seeds.append((n,int.from_bytes(bytes.fromhex(const[n]['hex']),'little')))
 block=run('vector',0x100462848,0x1004628ac,seeds,[(0x70000000,16,B)]);expected=[]
 for j in range(16):m=resize(S^((I+j+S)*(I+j-S)),8);expected.append((z3.Extract(j*8+7,j*8,B)^m)*0x93)
 add('all_u32_vector_byte_codec',cell(block,0x70000000,16)!=z3.Concat(*reversed(expected)))
 BYTE=z3.BitVec('callback_byte8',8);m=resize(S^((I+S)*(I-S)),8);encoded=(BYTE^m)*0x93;add('all_byte_codec_inverse',((encoded*0x9b)^m)!=BYTE)
 A,B64=z3.BitVecs('callback_swap_A64 callback_swap_B64',64);u=A^B64;v=u^B64;w=u^v;add('distinct_word_XOR_swap',z3.Or(v!=A,w!=B64))
 # Remainder bound states the arithmetic property used by the original UDIV/MSUB.
 N=z3.BitVec('callback_shuffle_counter32',32);num=((S+N)^S)*0x01000193;j=z3.URem(num,N);add('shuffle_strictly_lower_index',z3.UGE(j,N),z3.And(z3.UGE(N,1),z3.ULE(N,272)))
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_callback_revisit_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,pred in qs:
  op=ROOT/f'daemon_callback_revisit_{name}_original.smt2';np=ROOT/f'daemon_callback_revisit_{name}.smt2';s=z3.Solver();s.add(pred);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(pred));result=str(s.check());print(json.dumps({'proof':name,'result':result}),flush=True);assert result=='unsat',(name,result);np.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 witnesses=[]
 for name in ['aligned4_caller_key','caller_pointer_length_control','shuffle_strictly_lower_index']:
  p=next(p for n,p in qs if n==name);s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':name,'premise':'sat','model':str(s.model())})
 deps=['daemon_callback_revisit_contracts.json','daemon_callback_simd.py','daemon_global_state_lift.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'z3_version':z3.get_version_string(),'normalization_dependencies':'No source-register replacements. Vector table and multiplier constants are fixed to source-observed values; arbitrary seed, position and input bytes. Shuffle remainder is a mathematical composition obligation; fixed original loop independently replayed.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
