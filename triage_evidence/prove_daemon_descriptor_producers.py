#!/usr/bin/env python3
"""Source-lift record,cursor,allocation,word-view and stack-probe identities.
Linear source expression construction; 30 s solver limit/query. Native incoming
state,lifetime,cache compatibility and fault-free return are separate premises.
"""
import json,hashlib
from pathlib import Path
import z3
from daemon_receive_tools import ROOT
from prove_daemon_callback_revisit import CallbackLift
from lskd_values_symbolic import part,mem,cell,resize
class ProducerLift(CallbackLift):
 def run(self,label):
  from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
  cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;row=next(r for r in self.c['spans']if r['label']==label);old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='orn':o=i.operands;name=i.reg_name(o[0].reg);n=self.width(name);self.write(name,self.operand(i,o[1],n)|~self.operand(i,o[2],n));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};CallbackLift.run(self,'one')
  self.c=old;return self
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def obligations(c,source):
 c={'spans':c['spans']+[{'label':'cache_stack_probe','start':source['stack_probe_original_function']['start'],'end':source['stack_probe_original_function']['end'],'bytes_hex':source['stack_probe_original_function']['bytes']}]};qs=[];counts={};R,F,P,C,Q,H,DATA,A,B,U=z3.BitVecs('producer_record64 producer_SP64 producer_pointer64 producer_counter64 producer_cursor64 producer_payload64 producer_data64 producer_A64 producer_B64 producer_word64',64);S,AUX,K=z3.BitVecs('producer_selector32 producer_aux32 producer_key32',32);key=(resize(R,32)^0xdc40790b)*0x5973a279
 def run(n,a,z,seeds=(),memory=()):
  v=ProducerLift(part(c,n,a,z))
  for name,x in seeds:v.seed(name,x)
  for at,nbytes,x in memory:mem(v,at,nbytes,x)
  v.run(n);counts[n]=v.count;return v
 def add(name,p,premise=z3.BoolVal(True)):qs.append((name,z3.And(premise,p)))
 caller=run('caller_record',0x10039c898,0x10039c8d4,[('x29',R+256),('x19',P)]);add('all_u32_caller_record_fields',z3.Or(cell(caller,R,4)!=(key^0x471c),cell(caller,R+8,8)!=P,cell(caller,R+20,4)!=key+0x2be18a5d))
 pre=run('entry_prekey64',0x100a59d18,0x100a59d5c,[('x0',R)]);add('all_u64_entry_prekey',pre.read('x11')!=(R^0x0efbac0edc40790b))
 multiply=run('entry_key64',0x100a59d5c,0x100a59d68,[('x11',R^0x0efbac0edc40790b)]);add('all_u64_entry_multiply_and_low32_key',z3.Or(multiply.read('x11')!=(R^0x0efbac0edc40790b)*0x5973a279,resize(multiply.read('x11'),32)!=key))
 decode=run('entry_decode',0x100a59d68,0x100a59d74,[('x0',R),('w11',K)],[(R,4,S^K),(R+8,8,P)]);add('all_record_selector_and_pointer_decode',z3.Or(decode.read('w15')!=S,decode.read('x2')!=P))
 cursor=run('entry_cursor',0x100a59d0c,0x100a59d18,[('x1',R)],[(R,8,Q)]);add('all_u64_entry_cursor_increment',cell(cursor,R,8)!=Q+160)
 nz=run('entry_nonnull',0x100a59d84,0x100a59d90,[('x2',P)]);add('all_u64_pointer_nonnull_flag',nz.read('w12')!=z3.If(P==0,z3.BitVecVal(0,32),z3.BitVecVal(1,32)))
 index=run('entry_dispatch',0x100a59ddc,0x100a59de0,[('w15',S),('w10',z3.If(P==0,z3.BitVecVal(0,32),z3.BitVecVal(44,32)))]);add('all_u32_selector_pointer_dispatch',index.read('w9')!=(S^z3.If(P==0,z3.BitVecVal(0,32),z3.BitVecVal(44,32))))
 aux=run('auxiliary_gate',0x1006583b0,0x1006583f8,[('x0',R),('w11',K),('w15',S)],[(R+20,4,AUX+K)]);expected=(S+0x4438)^z3.If(AUX<z3.BitVecVal(0xeedd0b20,32),((S+0xd3e83862)&0x2c17e9cb)-0x693d,z3.BitVecVal(0,32));add('all_u32_auxiliary_decode_and_signed_gate',z3.Or(aux.read('w8')!=AUX,aux.read('w10')!=expected));add('selected_auxiliary_first_index',aux.read('w10')!=0x8b54,z3.And(S==0x471c,AUX==0x2be18a5d))
 # This second gate is source-pinned directly; no previous record byte is replaced.
 second=run('second_aux_gate',0x100a2c7e0,0x100a2c824,[('w15',0x471c),('w8',AUX)]);add('selected_auxiliary_second_index',second.read('w11')!=z3.If(AUX<z3.BitVecVal(0x2be18a5d,32),z3.BitVecVal(0x8202,32),z3.BitVecVal(0x8200,32)))
 lcg=run('adapter_LCG',0x100abcb84,0x100abcb88,[('x16',0x2ebd),('x21',C),('x1',1)]);add('all_u64_adapter_LCG',lcg.read('x16')!=C*0x2ebd+1)
 reserve=16*(z3.LShR(U,60)+1);alloc=run('adapter_allocation',0x100abcbe4,0x100abcc08,[('x16',U),('x21',C),('sp',F)]);assert len(alloc.stores)==1;add('all_u64_adapter_cursor_and_allocation',z3.Or(alloc.read('sp')!=F-reserve,alloc.read('x20')!=F-reserve,alloc.stores[0]['address']!=F-reserve,alloc.stores[0]['value']!=C-160));add('adapter_reserve_bounds_alignment',z3.Or(z3.ULT(reserve,16),z3.UGT(reserve,256),reserve&15!=0))
 delta=run('adapter_result',0x100abcc9c,0x100abccac,[('x20',R),('x21',C),('x19',H)],[(R,4,resize(Q,32))]);D=z3.ZeroExt(48,z3.Extract(15,0,Q-C))<<4;add('all_u64_cursor_delta_low16_result',cell(delta,H,8)!=D);add('adapter_delta_range_alignment',z3.Or(z3.UGT(D,0xffff0),D&15!=0));add('null_return_cursor_composition',z3.Or(((C-160)+160)!=C,z3.ZeroExt(48,z3.Extract(15,0,((C-160)+160)-C))<<4!=0))
 null=run('null_result',0x10095f074,0x10095f078,[('x0',R),('w23',0x74c29d88)]);add('null_source_result_store',cell(null,R+16,4)!=0x74c29d88)
 pack=run('payload_pack',0x1009d0198,0x1009d02ac,[('x2',H),('x20',0x45f86ad91b5c5736),('w13',0x98)],[(H+j,1,z3.Extract(j*8+7,j*8,DATA))for j in range(8)]);BE=z3.Concat(*[z3.Extract(j*8+7,j*8,DATA)for j in range(8)]);W=BE^0x9898989898989898;add('all_eight_byte_big_endian_XOR_pack',z3.Or(pack.read('x9')!=W,pack.read('x10')!=((W<<1)&0xc7710d2b81aa5b78)))
 word=run('payload_word',0x1009d02fc,0x1009d0308,[('x9',U),('x10',(U<<1)&0xc7710d2b81aa5b78),('x6',0xe3b88695c0d52dbc),('sp',F)]);add('all_u64_payload_word_transform',cell(word,F+0x2a70,8)!=(U^0xe3b88695c0d52dbc))
 ck=run('creator_prekey',0x10097291c,0x100972948,[('x29',R+0xb0)]);add('aligned8_new_creator_prekey',ck.read('w9')!=(resize(R,32)^0xdc40790b),R&7==0)
 loc=F+0xde90;ckpack=run('creator_record',0x100972948,0x100972978,[('x29',F+0xdf40),('sp',F),('w9',resize(loc,32)^0xdc40790b),('w21',0x447c),('x26',A),('x25',B)],[(F+0x26c0,8,P)]);add('new_creator_record_control_and_destination',z3.Or(cell(ckpack,loc,4)!=0xaed7-(resize(loc,32)^0xdc40790b)*0x5973a279,cell(ckpack,loc+8,8)!=P))
 save=run('stack_probe_save',0x180587cd4,0x180587cd8,[('sp',F),('x10',A),('x11',B)]);add('all_u64_stack_probe_scratch_save',z3.Or(cell(save,F-16,8)!=A,cell(save,F-8,8)!=B,save.read('sp')!=F))
 restore=run('stack_probe_restore',0x180587d08,0x180587d0c,[('sp',F),('x10',U),('x11',H)],[(F-16,8,A),(F-8,8,B)]);add('all_u64_stack_probe_restore',z3.Or(restore.read('x10')!=A,restore.read('x11')!=B,restore.read('sp')!=F))
 return qs,counts
def main():
 c=json.loads((ROOT/'daemon_descriptor_producers_contracts.json').read_text());source=json.loads((ROOT/'daemon_descriptor_producers_source.json').read_text());qs,counts=obligations(c,source);rows=[];witnesses=[]
 for name,p in qs:
  a=ROOT/f'daemon_descriptor_producers_{name}_original.smt2';b=ROOT/f'daemon_descriptor_producers_{name}.smt2';s=z3.Solver();s.add(p);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(p));answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer})
  if name in['selected_auxiliary_first_index','aligned8_new_creator_prekey']:s=z3.Solver();s.add(p.arg(0));assert str(s.check())=='sat';witnesses.append({'proof':name,'premise_result':'sat','model':str(s.model())})
 deps=['daemon_descriptor_producers_contracts.json','daemon_descriptor_producers_source.json','prove_daemon_callback_revisit.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'nonempty_premise_witnesses':witnesses,'composition_cuts':[{'pc':'0x100a59d5c','input':'X11=R XOR0x0efbac0edc40790b','producer':'all_u64_entry_prekey'},{'pc':'0x100a59d68','input':'W11=low32 key','producer':'all_u64_entry_multiply_and_low32_key'},{'pc':'0x100972948','input':'W9=low32(R) XOR0xdc40790b under R&7==0','producer':'aligned8_new_creator_prekey'}],'z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_producers_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
