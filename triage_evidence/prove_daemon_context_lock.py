#!/usr/bin/env python3
"""Source-local creator gates, descriptor fields, pointer transform and readers.
O(source instructions) expression construction/space;30 s/query. Mathematical
identities use explicit phases/alignment; reachability is independently bounded.
"""
import json,hashlib
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
import z3
from daemon_receive_tools import ROOT,POOL,qword
from prove_daemon_callback_revisit import CallbackLift
from lskd_values_symbolic import part,mem,cell,resize
M=0x8b3dc651;TABLE=0x101039ef0
class ContextLift(CallbackLift):
 def run(self,label):
  row=next(r for r in self.c['spans']if r['label']==label);old=self.c;cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='udiv':
    o=i.operands;name=i.reg_name(o[0].reg);n=self.width(name);a=self.operand(i,o[1],n);b=self.operand(i,o[2],n);self.write(name,z3.If(b==0,z3.BitVecVal(0,n),z3.UDiv(a,b)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};CallbackLift.run(self,'one')
  self.c=old;return self


def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def obligations(c):
 qs=[];counts={};R,F,G,P,X=z3.BitVecs('ctxlock_record64 ctxlock_frame64 ctxlock_global64 ctxlock_pointer64 ctxlock_word64',64);Y,K=z3.BitVecs('ctxlock_result32 ctxlock_key32',32)
 def run(n,a,z,seeds=(),memory=()):
  v=ContextLift(part(c,n,a,z))
  for reg,val in seeds:v.seed(reg,val)
  for at,nbytes,val in memory:mem(v,at,nbytes,val)
  v.run(n);counts[n]=v.count;return v
 def add(n,p,d=z3.BoolVal(True)):qs.append((n,z3.And(d,p)))
 first=run('first_gate',0x100492658,0x100492674,[('x29',R+0xd8),('w23',0),('w24',M),('w25',0x55fc)],[(R+16,4,Y)]);add('all_u32_arena_lock_result_gate',first.read('w9')!=z3.If(Y==M,z3.BitVecVal(0x55fc^0x37b4,32),z3.BitVecVal(0x55fc,32)))
 key=run('second_key',0x1003ae510,0x1003ae53c,[('x29',R+0xd8)]);add('all_u32_global_creator_key',key.read('w10')!=(resize(R,32)^0xdc40790b))
 pack=run('second_pack',0x1003ae5a0,0x1003ae5b4,[('x29',R+0xd8),('x21',G),('w10',K),('w13',0x5973a279),('w22',0x924a)]);add('second_creator_record_pack',z3.Or(cell(pack,R+8,8)!=G,cell(pack,R,4)!=0xaed7-K*0x5973a279))
 second=run('second_gate',0x1003ae60c,0x1003ae634,[('x29',R+0xd8),('w19',0x9285),('w25',0x1bcb),('w22',0x924a)],[(R+16,4,Y)]);add('all_u32_global_lock_result_gate',second.read('w9')!=z3.If(Y==M,z3.BitVecVal(0x9257,32),z3.BitVecVal(0x924a,32)))
 zero=run('descriptor_count_zero',0x10038eb08,0x10038eb0c,[('x21',G)]);add('descriptor_initial_count',z3.Or(cell(zero,G+8,4)!=0,len(zero.stores)!=1))
 arg=run('descriptor_buffer_size',0x10038eb54,0x10038eb5c);add('buffer_allocation_size_and_modifier',z3.Or(arg.read('x0')!=960,arg.read('x17')!=0x6aa4))
 ret=run('descriptor_buffer_return',0x10038eb60,0x10038eb84,[('x21',G),('x0',P),('w25',0x1bcb),('w19',0x9285)]);add('all_u64_buffer_pointer_publication',cell(ret,G+16,8)!=P);add('all_u64_buffer_null_gate',ret.read('w8')!=z3.If(P==0,z3.BitVecVal(0x9285,32),z3.BitVecVal(0x92a7,32)))
 # Source pointer publication core: two independent low32 multiply-add lanes,
 # followed by an XOR with the separately packed eight bytes at F+0x628.
 A,B,C,D=z3.BitVecs('ctxlock_lane_add64 ctxlock_lane_input64 ctxlock_lane_factor64 ctxlock_xor64',64)
 encoded=run('pointer_transform',0x1003c439c,0x1003c43b8,[('sp',F),('x19',G),('q0',z3.ZeroExt(64,A)),('q13',z3.ZeroExt(64,C))],[(F+0x630,8,B),(F+0x628,8,D)])
 lanes=[resize(z3.LShR(A,j*32),32)+resize(z3.LShR(B,j*32),32)*resize(z3.LShR(C,j*32),32)for j in range(2)];expected=D^z3.Concat(lanes[1],lanes[0]);add('all_u64_context_pointer_lane_transform',cell(encoded,G,8)!=expected)
 reader=run('candidate_buffer_field',0x100a63764,0x100a6377c,[('x21',G),('w8',Y)],[(G+16,8,P)]);add('candidate_buffer_flag_gate',reader.read('w10')!=((Y^z3.If(P==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))&1))
 lock=run('candidate_lock_field',0x10021ed7c,0x10021eda0,[('x20',G),('x29',R+0x100),('w8',Y),('w10',K)],[(G,8,P)]);add('candidate_lock_pointer_forward',cell(lock,R+8,8)!=P)

 I,J=z3.BitVecs('ctxlock_array_index64 ctxlock_logical_index64',64);A64=z3.BitVec('ctxlock_entry_sentinel64',64);B32,C32=z3.BitVecs('ctxlock_entry_word_B32 ctxlock_entry_word_C32',32)
 body=run('entry_body',0x100407458,0x100407474,[('x21',G),('x9',I),('x10',48),('x11',-0x16eaf53240),('x2',A64),('w12',B32),('w13',C32)],[(G+16,8,P)]);offset=I*48-0x16eaf53240;fields=[(0,8,0),(8,8,0),(16,8,0),(24,8,A64),(32,4,B32),(36,4,C32),(40,4,C32),(44,4,C32)];assert len(body.stores)==8
 add('all_entry_fields_and_addresses',z3.Or(*[z3.Or(e['address']!=P+offset+off,e['value']!=resize(v,n*8),e['size_bytes']!=n)for e,(off,n,v)in zip(body.stores,fields)]))
 start=0x7a3a710c;add('logical_array_offset',((start+J)*48-0x16eaf53240)!=J*48)
 advance=run('entry_advance',0x100407474,0x10040748c,[('x9',start+J),('x14',0xffffffffffff9d6e),('x19',0x6293),('x15',start+20),('w0',0x3b),('w8',0x1dd7)])
 add('bounded_array_advance_and_exit',z3.Or(advance.read('x9')!=start+J+1,advance.read('w16')!=z3.If(J==19,z3.BitVecVal(0x1dec,32),z3.BitVecVal(0x1dd7,32))),z3.ULE(J,19))
 add('array_record_extent_fits960',z3.Or(z3.UGT(J*48+48,960),z3.ULT(J*48+48,J*48)),z3.ULE(J,19))

 seal=json.loads((ROOT/'daemon_context_seal_contracts.json').read_text())['cases'][0];const=seal['vector_constants'];S,SI=z3.BitVecs('ctxlock_seal_seed32 ctxlock_seal_index32',32);DATA=z3.BitVec('ctxlock_seal_input128',128);seeds=[('x16',0x70000000),('x12',0),('q1',z3.Concat(S,S,S,S))]
 for name,off in [('q2',0),('q3',4),('q4',8),('q5',12)]:seeds.append((name,z3.Concat(*[SI+off+k for k in range(3,-1,-1)])))
 for name in ['q26','q27','q28','q29','q30','q31']:seeds.append((name,int.from_bytes(bytes.fromhex(const[name]['hex']),'little')))
 block=run('header_vector',0x1003c41ec,0x1003c4250,seeds,[(0x70000000,16,DATA)]);output=[]
 for j in range(16):output.append((z3.Extract(8*j+7,8*j,DATA)^resize(S^((SI+j+S)*(SI+j-S)),8))*0x93)
 add('all_u32_header_vector_codec',cell(block,0x70000000,16)!=z3.Concat(*reversed(output)))
 N=z3.BitVec('ctxlock_seal_word_index32',32);word=run('header_word_index',0x1003c42d4,0x1003c42e8,[('w17',S),('w12',N),('w4',0x01000193)]);expected=z3.URem(((S+N)^S)*0x01000193,N);add('header_word_remainder_and_bound',z3.Or(word.read('w0')!=expected,z3.UGE(word.read('w0'),N)),z3.And(z3.UGE(N,1),z3.ULE(N,68)))
 # Exact ABI buffer field extents; no source/native structure name is inferred.
 add('descriptor_fields_disjoint',z3.Or(*[z3.And(z3.ULT(G+a,G+b+nb),z3.ULT(G+b,G+a+na))for a,na,b,nb in [(0,8,8,4),(0,8,16,8),(8,4,16,8)]]),z3.ULE(G,(1<<64)-25))
 return qs,counts

def main():
 c=json.loads((ROOT/'daemon_context_lock_contracts.json').read_text());qs,counts=obligations(c);rows=[]
 for name,pred in qs:
  a=ROOT/f'daemon_context_lock_{name}_original.smt2';b=ROOT/f'daemon_context_lock_{name}.smt2';s=z3.Solver();s.add(pred);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(pred));result=str(s.check());print(json.dumps({'proof':name,'result':result}),flush=True);assert result=='unsat',(name,result);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':result})
 witnesses=[]
 for name,pred in qs:
  if name in ['descriptor_fields_disjoint','bounded_array_advance_and_exit','array_record_extent_fits960','header_word_remainder_and_bound']:s=z3.Solver();s.add(pred.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':name,'premise_result':'sat','model':str(s.model())})
 gates=[]
 for name,values in [('arena',[0x55fc,0x55fc^0x37b4]),('global',[0x924a,0x9257]),('buffer',[0x9285,0x92a7]),('array',[0x1dd7,0x1dec])]:
  gates.append({'name':name,'indices':[hex(i)for i in values],'slots':[hex(TABLE+i*8)for i in values],'targets':[hex(qword(TABLE+i*8))for i in values]})
 deps=['daemon_context_lock_contracts.json','daemon_context_seal_contracts.json','prove_daemon_callback_revisit.py','daemon_callback_simd.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'gate_targets':gates,'z3_version':z3.get_version_string(),'normalization_dependencies':'No register replacement. Caller phase constants are source-observed and independently replayed. Candidate-reader theorems assume the global address supplied by the separately documented conditional pool-index premise; full candidate reachability is unknown. The pointer-core theorem begins after source byte packing.','native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_lock_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
