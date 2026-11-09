#!/usr/bin/env python3
"""Source-local proofs of twist phases, record40, counters and XOR consumer.
O(source instructions) BV DAG time/space;30 s per SMT query. Full path
reachability is bounded to the retained incoming states, not native runs.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,IMAGE
from prove_daemon_seed_material import LessLift
from lskd_values_symbolic import part,mem,cell
MIX=0x823819558515cfbd;COEFF=0xc7f6dca7;A=0x1010c784c
class OutLift(LessLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   if i.mnemonic=='asr':
    self.pc=i.address;o=i.operands;n=self.width(i.reg_name(o[0].reg));v=self.operand(i,o[1],n)>>(self.operand(i,o[2],n)&(n-1));self.write(i.reg_name(o[0].reg),v);self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};LessLift.run(self,'one')
  self.c=old;return self

def obligations(c):
 R,F=z3.BitVecs('out_record64 out_frame64',64);X,Y=z3.BitVecs('out_operand_A64 out_operand_B64',64);MODE,YES,NO,MASK,C=z3.BitVecs('out_mode32 out_true32 out_false32 out_mask32 out_counter32',32);K=(R^MIX)*COEFF;k=z3.Extract(31,0,K);qs=[];counts={};fd=z3.And(F&15==0,z3.UGE(F,0x6400000000),z3.ULE(F,0x640000f420));rd=z3.And(fd,R==F+0xaf8,R&7==0);aligned4=z3.And(fd,R&3==0,z3.ULE(R,(1<<64)-41))
 def run(name,start,end,seeds=(),memory=(),normalize=False):
  v=OutLift(part(c,name,start,end))
  for r,x in seeds:v.seed(r,x)
  for at,n,x in memory:mem(v,at,n,x)
  if normalize:v.overrides={(0x100444d98,'x8'):R^MIX}
  v.run(name);counts[name]=v.count;return v
 def add(name,pred,domain=rd):qs.append((name,z3.And(domain,pred)))
 pre=run('helper40_prekey',0x100444d6c,0x100444d9c,[('x0',R)]);add('helper40_prekey_identity',pre.read('x8')!=(R^MIX),z3.BoolVal(True))
 inv=pow(COEFF,-1,1<<64);add('helper40_codec_inverse',((K*inv)^MIX)!=R,z3.BoolVal(True))
 cp=run('caller40_prekey',0x10032c9fc,0x10032ca54,[('x0',R)]);add('caller40_prekey_aligned4',cp.read('x12')!=(R^MIX),aligned4)
 km=run('caller40_key',0x10032cdc8,0x10032cdd8,[('sp',F),('x12',cp.read('x12'))]);add('caller40_key_agrees',cell(km,F+0x1a0,8)!=K,aligned4)
 memory=[(R+4,4,MASK-k),(R+8,4,NO+k),(R+0xc,4,MODE^k),(R+0x10,8,X-K),(R+0x1c,4,YES^k),(R+0x20,8,Y^K)]
 leaf=run('record40_leaf',0x100444d6c,0x100444df8,[('x0',R)],memory,True);choose=z3.If(MODE&1!=0,z3.UGT(X,Y),X==Y);add('all_u64_record40_selection',cell(leaf,R,4)!=(MASK^z3.If(choose,YES,NO)));assert len(leaf.stores)==1 and leaf.stores[0]['size_bytes']==4;add('record40_single_output_store',leaf.stores[0]['address']!=R);add('record40_preserves_X0',leaf.read('x0')!=R)
 pack=run('counter_record_pack',0x10029a138,0x10029a190,[('sp',F),('x29',R+0xd8),('x21',z3.ZeroExt(32,C)),('x4',0x13ff),('w8',0x8a9b8560)],[(F+0x1a0,8,K)])
 composed=OutLift(part(c,'counter_record_body',0x100444d6c,0x100444df8));composed.memory=pack.memory.copy();composed.seed('x0',R);composed.overrides={(0x100444d98,'x8'):R^MIX};composed.run('counter_record_body');counts['counter_record_body']=composed.count;add('all_u32_counter_route',cell(composed,R,4)!=z3.If(z3.UGT(C,5119),z3.BitVecVal(0x17a0,32),z3.BitVecVal(0x17a4,32)))
 normal=run('counter_normal',0x100478558,0x100478570,[('w21',C),('w23',0x13ff)]);add('counter_normal_values',z3.Or(normal.read('w10')!=C+1,normal.read('w8')!=1,normal.read('w11')!=0xffffffff),z3.And(fd,z3.ULE(C,5119)))
 normal_tail=run('counter_normal_tail',0x100478580,0x100478584);add('counter_normal_tail_value',normal_tail.read('w12')!=1,fd)
 reset=run('counter_reset',0x1002b3d7c,0x1002b3dac,[('x21',z3.ZeroExt(32,C))]);add('counter_reset_values',z3.Or(reset.read('w10')!=0,reset.read('w8')!=1,reset.read('w11')!=0xffffffff,reset.read('w12')!=1),z3.And(fd,z3.UGT(C,5119)))
 update=run('counter_publication',0x1003505b4,0x1003505bc,[('sp',F),('w10',z3.If(z3.UGT(C,5119),z3.BitVecVal(0,32),C+1))],[(F+0x298,8,0x1010c8258)]);add('all_u32_counter_update',cell(update,0x1010c8258,4)!=z3.If(z3.UGT(C,5119),z3.BitVecVal(0,32),C+1),fd)
 OFF=z3.BitVec('out_twist_offset64',64);CUR,NEXT,FAR=z3.BitVecs('out_current32 out_next32 out_far32',32);enc=z3.If(NEXT&1==0,z3.BitVecVal(0x94fdeab5,32),z3.BitVecVal(0x0df55a6a,32));expected=FAR^z3.LShR((CUR&0x80000000)|(NEXT&0x7fffffff),1)^z3.If(NEXT&1==0,z3.BitVecVal(0,32),z3.BitVecVal(0x9908b0df,32))
 for name,start,lookup,end,dest,mems,extra,domain in [
  ('twist_first',0x10035c6d8,0x10035c6f8,0x10035c70c,A+OFF,[(A+OFF+4,4,NEXT),(A+OFF+397*4,4,FAR)],[],z3.And(fd,OFF&3==0,z3.ULE(OFF,226*4))),
  ('twist_second',0x100474038,0x100474058,0x10047406c,A+OFF+227*4,[(A+OFF+228*4,4,NEXT),(A+OFF,4,FAR)],[],z3.And(fd,OFF&3==0,z3.ULE(OFF,395*4))),
  ('twist_last',0x1003b090c,0x1003b092c,0x1003b094c,A+623*4,[(A+623*4,4,CUR),(A,4,NEXT),(A+396*4,4,FAR)],[('w8',0x8a9b8560)],fd)]:
  seeds=[('x28',A),('x8',OFF),('w9',CUR),('x3',F+0x6d8)]+extra;v=run(name+'_prefix',start,lookup,seeds,mems);addr=v.read('x10'if name=='twist_last'else'x13');add(name+'_finite_address',z3.And(addr!=F+0x6d8,addr!=F+0x6dc),domain)
  seeds=[(key,value)for key,value in v.regs.items()]+[('w15',0x94fdeab5)];post=run(name+'_post',lookup,end,seeds,[(addr,4,enc)]);add(name+'_all_u32_transition',cell(post,dest,4)!=expected,domain)
 I,RAW=z3.BitVecs('out_index32 out_raw32',32);ia=z3.ZeroExt(32,I);index=run('index_read_advance',0x10029a11c,0x10029a134,[('sp',F),('x28',A)],[(F+0x60c,4,I),(F+0x2f8,8,0x1010c67dc),(A+(ia<<2),4,RAW)]);add('index_word_and_publication',z3.Or(index.read('w19')!=RAW,cell(index,F+0x60c,4)!=I+1,cell(index,0x1010c67dc,4)!=I+1),z3.And(fd,z3.ULE(I,623)))
 H,D=z3.BitVecs('out_owner64 out_data64',64);O,OLD=z3.BitVecs('out_byte_offset32 out_old_word32',32);V=z3.BitVec('out_frame_cursor64',64);oa=z3.ZeroExt(32,O);dd=z3.And(fd,z3.UGE(H,0x6500000000),z3.ULE(H,(1<<64)-90001),z3.UGE(D,H),z3.ULE(D,H+89996),z3.UGE(D+oa,H),z3.ULE(D+oa,H+89996),z3.UGE(D+oa,D))
 body=run('temper_and_mask',0x1003505bc,0x100350628,[('sp',F),('w19',RAW),('w8',1),('w11',0xffffffff),('w12',1),('x15',0x1010c8278)],[(F+0x5c0,8,V+32),(0x1010c8278,8,D),(F+0x48c,4,O),(D+oa,4,OLD)])
 T=RAW^z3.LShR(RAW,11);T=T^((T<<7)&0x9d2c5680);T=T^((T<<15)&0xefc60000);T=T^z3.LShR(T,18);add('all_u32_tempered_buffer_xor',cell(body,D+oa,4)!=(OLD^T),dd);add('frame_reservation_released',cell(body,F+0x5c0,8)!=V,dd);assert len(body.stores)==2
 publish=run('buffer_pointer_publish',0x1002fb814,0x1002fb824,[('sp',F),('x15',0x1010c8278)],[(F+0x358,8,D)]);add('buffer_pointer_published_before_null_test',cell(publish,0x1010c8278,8)!=D,fd)
 N=z3.BitVec('out_next_byte_offset32',32);loop=run('buffer_loop_guard',0x1004093fc,0x100409440,[('sp',F),('w10',N),('w9',0x3170)]);add('all_u32_buffer512_guard',loop.read('w9')!=z3.If(z3.ULT(N,512),z3.BitVecVal(0x3170,32),z3.BitVecVal(0x3195,32)),fd);add('buffer_offset_publication',cell(loop,F+0x48c,4)!=N,fd)
 return qs,counts,inv

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_prng_output_contracts.json').read_text());qs,counts,inv=obligations(c);rows=[]
 for name,pred in qs:
  op=ROOT/f'daemon_prng_output_{name}_original.smt2';np=ROOT/f'daemon_prng_output_{name}.smt2';s=z3.Solver();s.add(pred);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(pred));result=str(s.check());assert result=='unsat',(name,result);np.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(IMAGE.read(0x10032ca54,0x374),0x10032ca54));assert len(ins)==221
 for i in ins:
  reads,writes=i.regs_access();assert not any(i.reg_name(r)in ['x12','w12']for r in writes)and i.mnemonic not in ['b','bl','braa','blraa','ret','svc']
 witnesses=[]
 lookup={name:pred for name,pred in qs}
 for name,bindings in [('all_u64_record40_selection',{'out_frame64':0x640000b420,'out_record64':0x640000bf18}),('counter_normal_values',{'out_frame64':0x640000b420,'out_counter32':5119}),('counter_reset_values',{'out_frame64':0x640000b520,'out_counter32':5120}),('twist_first_all_u32_transition',{'out_frame64':0x640000b420,'out_twist_offset64':0}),('twist_second_all_u32_transition',{'out_frame64':0x640000b520,'out_twist_offset64':1580}),('twist_last_all_u32_transition',{'out_frame64':0x640000b420}),('all_u32_tempered_buffer_xor',{'out_frame64':0x640000b420,'out_owner64':0x6500000000,'out_data64':0x6500015d6c,'out_byte_offset32':0})]:
  solver=z3.Solver();solver.add(lookup[name].arg(0))
  for var,value in bindings.items():solver.add(z3.BitVec(var,32 if var.endswith('32')else 64)==value)
  assert str(solver.check())=='sat';witnesses.append({'premise':name,'bindings':{k:hex(v)for k,v in bindings.items()},'result':'sat'})
 R=z3.BitVecVal(0x640000bf1a,64);bad=OutLift(part(c,'alignment_probe',0x10032c9fc,0x10032ca54));bad.seed('x0',R);bad.run('alignment_probe');actual=z3.simplify(bad.read('x12')).as_long();expected=z3.simplify(R^MIX).as_long();assert actual!=expected;alignment={'R':'0x640000bf1a','actual_prekey':hex(actual),'aligned4_identity':hex(expected),'outside_proof_domain':True,'native_unaligned_record_observed':False}
 deps=['daemon_prng_output_contracts.json','prove_daemon_seed_material.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'source_lift_instruction_visits':sum(counts.values()),'address_multiplier_inverse64':hex(inv),'nonempty_premise_witnesses':witnesses,'outside_alignment_counterexample':alignment,'constructor_key_liveness':{'register':'x12','start':'0x10032ca54','end':'0x10032cdc8','instructions_checked':221,'overwrites':0,'branches_or_calls':0,'bytes_sha256':hashlib.sha256(IMAGE.read(0x10032ca54,0x374)).hexdigest()},'normalization_dependency':'record40_leaf and composed counter_record_body replace prekey at0x100444D98 with helper40_prekey_identity. Twist posts use source-initialized encoded table94FDEAB5/0DF55A6A and the finite-address proofs; last phase assumes source-verified W8=8A9B8560.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_prng_output_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values()),'liveness_instructions':221,'inverse64':hex(inv)}),flush=True)
if __name__=='__main__':main()
