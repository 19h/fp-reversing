#!/usr/bin/env python3
"""Source descriptor/header/link/cache/readiness and all-u32 flag obligations.
O(I) BV DAG time/space,30 s/query. Fresh mapped disjoint nonwrapping frame/
owner roles and selected incoming phase; no native allocator/PAC execution.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,IMAGE,FIXUPS,TABLE,verify_original_fixups
from prove_daemon_arena_entry import ArenaLift
from lskd_values_symbolic import part,mem,cell,resize
D=0x1010b5ef0;N=90000;M=0x5e878c613b8123ea
class StorageLift(ArenaLift):
 def load(self,a,n):
  a=z3.simplify(a);key=(a.sexpr(),n)
  if key in self.memory or z3.is_bv_value(a):return super().load(a,n)
  assert n==8;expr=z3.BitVec('unmapped_pointer_default64',64)
  for index in [0x4570,0x457c]:
   slot=TABLE+index*8;t=FIXUPS[slot]['target'];assert isinstance(t,int);self.fixup_reads.append(slot);expr=z3.If(a==slot,z3.BitVecVal(t,64),expr)
  return expr
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='csel':
    assert i.op_str.rsplit(',',1)[1].strip()=='ne';o=i.operands;n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.operand(i,o[1],n),self.operand(i,o[2],n)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};ArenaLift.run(self,'one')
  self.c=old;return self
def obligations(c):
 qs=[];counts={};F,H=z3.BitVecs('storage_frame64 storage_owner64',64);S=z3.BitVec('post_malloc_flag32',32);v=StorageLift(c);v.fixup_reads=[];v.malloc_pointer=z3.BitVec('unused_malloc_pointer64',64)
 premises=z3.And(F&15==0,H&15==0,z3.UGE(F,0x200000000),z3.UGE(H,0x200000000),z3.ULE(F,(1<<64)-1-3040),z3.ULE(H,(1<<64)-1-N),z3.Or(z3.ULE(F+3040,H),z3.ULE(H+N,F)))
 def add(n,p):qs.append((n,z3.And(premises,p)))
 def run(n,a,z):
  before=v.count;v.c=part(c,n,a,z);v.run(n);counts[n]=v.count-before
 for j in range(31):v.seed('x'+str(j),z3.BitVec('post_malloc_x'+str(j),64))
 for name,val in [('sp',F),('x0',H),('x20',TABLE),('w19',0xa2077530),('w21',0x5df88acf),('w22',0x6285a28d),('w25',0x4570),('w26',0xecbddfff),('w27',0x99cea740),('w28',0x6285a28d)]:v.seed(name,val)
 for off,val in [(0x300,D),(0x2f0,D+48),(0x1f8,0x101031da0),(0x1c8,0x1010b6cb8),(0x200,0x1010c5798),(0x390,0x1010b7dd8),(0x208,0x100e99900),(0x210,0x1010b5de0)]:mem(v,F+off,8,val)
 mem(v,0x1010b6cb8,4,S);run('allocation_return',0x10032a4ec,0x10032a5dc)
 add('descriptor_pointer_and_flags',z3.Or(cell(v,D+8,8)!=H,cell(v,D+16,4)!=0,cell(v,D+20,4)!=10,cell(v,D+32,4)!=1,cell(v,D+36,4)!=0))
 add('descriptor_signature_and_zero_fields',z3.Or(cell(v,D+40,8)!=0x1aa4071f0801765b,*[cell(v,D+k,8)!=0 for k in [48,56,64]]))
 add('head_and_end_word_relations',z3.Or(cell(v,H,8)!=M,cell(v,H+8,8)!=M+N-24,cell(v,H+N-24,8)!=M+N-24,cell(v,H+N-16,8)!=(M^(1<<63))))
 add('reciprocal_link_graph',z3.Or(cell(v,H+24,8)!=D+48,cell(v,H+32,8)!=D+48,cell(v,D+72,8)!=H,cell(v,D+80,8)!=H))
 add('source_write_bounds',z3.Or(*[z3.Not(z3.Or(z3.And(z3.UGE(e['address'],H),z3.ULE(e['address']+e['size_bytes'],H+N)),z3.And(z3.UGE(e['address'],D),z3.ULE(e['address']+e['size_bytes'],D+88))))for e in v.stores]))
 add('post_malloc_dispatch',z3.Or(v.read('x8')!=0x100331de4,v.read('x17')!=0xb9e1,v.read('x10')!=H,v.read('x0')!=H))
 footprint={'store_events':len(v.stores),'written_bytes':sum(e['size_bytes']for e in v.stores)};assert footprint=={'store_events':17,'written_bytes':120}
 run('flag_index',0x100331de4,0x100331e30);add('all_u32_flag_index',v.read('w9')!=z3.If(z3.UGT(S,1),z3.BitVecVal(0x457c,32),z3.BitVecVal(0x4570,32)))
 run('flag_target',0x100331e30,0x100331e38);add('all_u32_flag_target',z3.Or(v.read('x9')!=z3.If(z3.UGT(S,1),z3.BitVecVal(0x100332700,64),z3.BitVecVal(0x100322418,64)),v.read('x17')!=0xcfb7))
 # Instantiate the proven selected branch's actual flag fixture S=1.
 sub=lambda x:z3.simplify(z3.substitute(x,(S,z3.BitVecVal(1,32))))
 v.regs={k:sub(x)for k,x in v.regs.items()};v.memory={k:sub(x)for k,x in v.memory.items()};v.equal=sub(v.equal);v.carry=sub(v.carry);assert z3.is_true(z3.simplify(v.read('x9')==0x100322418))
 run('cache_publication',0x100322418,0x100322468);add('source_cache_pointer_publication',z3.Or(cell(v,F+0x5f8,8)!=H,cell(v,F+0x540,8)!=H));add('cache_dispatch',z3.Or(v.read('x10')!=0x10046c73c,v.read('x17')!=0x69f9))
 run('readiness_publication',0x10046c73c,0x10046c77c);add('readiness_and_next_dispatch',z3.Or(cell(v,0x1010c5798,1)!=1,v.read('x8')!=0x10032c590,v.read('x17')!=0x4ef7))
 return qs,counts,sorted(set(v.fixup_reads)),footprint
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_arena_storage_contracts.json').read_text());qs,counts,fix,footprint=obligations(c);rows=[]
 premise_file=ROOT/'daemon_arena_storage_premises.smt2';s=z3.Solver();s.add(qs[0][1].arg(0));s.add(z3.BitVec('storage_frame64',64)==0x640000b420,z3.BitVec('storage_owner64',64)==0x6500000000);assert str(s.check())=='sat';premise_file.write_text(s.to_smt2());premise_witness={'file':premise_file.name,'sha256':sha(premise_file),'result':'sat','frame':'0x640000b420','owner':'0x6500000000'}
 for n,q in qs:
  op=ROOT/f'daemon_arena_storage_{n}_original.smt2';np=ROOT/f'daemon_arena_storage_{n}.smt2';s=z3.Solver();s.add(q);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(n,result);np.write_text(s.to_smt2());rows.append({'name':n,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 deps=['daemon_arena_storage_contracts.json','prove_daemon_arena_entry.py','prove_daemon_frame_entry.py','daemon_rwlock_lifecycle_symbolic.py','daemon_iokit_sync_symbolic.py','daemon_iokit_class_symbolic.py','daemon_query_fallback_symbolic.py','daemon_query_state_symbolic.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'premise_witness':premise_witness,'source_lift_counts':counts,'post_malloc_write_footprint':footprint,'source_fixup_records':verify_original_fixups(fix),'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_storage_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(rows),'lifts':counts,'fixups':len(fix),'footprint':footprint}),flush=True)
if __name__=='__main__':main()
