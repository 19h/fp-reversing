#!/usr/bin/env python3
"""Source proofs for four input codecs, less-than record and mixing update.
O(source instructions) bit-vector DAG construction,30 s per SMT query.
Caller record alignment and original storage ownership are explicit.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT
from prove_daemon_frame_entry import FrameLift
from lskd_values_symbolic import part,mem,cell
MIX=0x0179fa0fe732d262;COEFF=0xba209ef7;ENC=0x5cf7672b;STATE=0x1010c784c
class LessLift(FrameLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;o=i.operands
   if i.mnemonic in ['lsl','lsr']:
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);shift=self.operand(i,o[2],n)&(n-1);self.write(i.reg_name(o[0].reg),a<<shift if i.mnemonic=='lsl'else z3.LShR(a,shift));self.count+=1
   elif i.mnemonic=='cmn':
    n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[0],n);b=self.operand(i,o[1],n);self.carry=z3.ULT(a+b,a);self.equal=a+b==0;self.count+=1
   elif i.mnemonic=='cinc':
    assert i.op_str.endswith(', lo');n=self.width(i.reg_name(o[0].reg));a=self.operand(i,o[1],n);self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.carry),a+1,a));self.count+=1
   elif i.mnemonic=='tst':self.equal=(self.operand(i,o[0],self.width(i.reg_name(o[0].reg)))&self.operand(i,o[1],self.width(i.reg_name(o[0].reg))))==0;self.count+=1
   elif i.mnemonic=='cset'and i.op_str.rsplit(',',1)[1].strip()in ['lo','lt']:
    cc=i.op_str.rsplit(',',1)[1].strip();cond=z3.ULT(self.sleft,self.sright)if cc=='lo'else self.sleft<self.sright;self.write(i.reg_name(o[0].reg),z3.If(cond,z3.BitVecVal(1,32),z3.BitVecVal(0,32)));self.count+=1
   elif i.mnemonic=='csel':
    assert i.op_str.endswith(', ne');n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.operand(i,o[1],n),self.operand(i,o[2],n)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};FrameLift.run(self,'one')
  self.c=old;return self

def obligations(c):
 R,F,A,B=z3.BitVecs('less_record64 material_frame64 less_A64 less_B64',64);MODE,TRUE,FALSE,MASK=z3.BitVecs('less_mode32 less_true32 less_false32 less_mask32',32);K=(R^MIX)*COEFF;k=z3.Extract(31,0,K);qs=[];counts={};domain=z3.And(R&7==0,z3.ULE(R,(1<<64)-37));framedomain=z3.And(domain,F&15==0,z3.UGE(F,0x200000000),z3.ULE(F,(1<<64)-3041),R==F+0xaf8)
 def run(n,a,z,seeds=(),memory=(),normalize=False):
  v=LessLift(part(c,n,a,z))
  for name,value in seeds:v.seed(name,value)
  for at,size,value in memory:mem(v,at,size,value)
  if normalize:v.overrides={(0x100427550,'x8'):R^MIX}
  v.run(n);counts[n]=v.count;return v
 def add(n,p,d=domain):qs.append((n,z3.And(d,p)))
 helper=run('less_helper_prekey',0x100427514,0x100427554,[('x0',R)]);add('less_helper_prekey_identity',helper.read('x8')!=(R^MIX),z3.BoolVal(True))
 inv=pow(COEFF,-1,1<<64);add('less_address_codec_inverse',((K*inv)^MIX)!=R,z3.BoolVal(True))
 caller=run('less_caller_prekey',0x10032ca54,0x10032ca98,[('x0',R),('sp',F)]);add('less_caller_prekey_aligned8',cell(caller,F+0x340,8)!=(R^MIX),framedomain)
 memory=[(R,8,A-K),(R+8,4,MODE^k),(R+0x10,4,TRUE^k),(R+0x14,4,FALSE-k),(R+0x18,8,B^K),(R+0x20,4,MASK^k)]
 leaf=run('less_record_body',0x100427514,0x1004275b0,[('x0',R)],memory,True);choose=z3.If(MODE&1!=0,A<B,z3.ULT(A,B));add('all_u64_signed_unsigned_less_choice',cell(leaf,R+0xc,4)!=(MASK^z3.If(choose,TRUE,FALSE)));assert len(leaf.stores)==1 and leaf.stores[0]['size_bytes']==4
 add('less_only_result_store',leaf.stores[0]['address']!=R+0xc);add('less_preserves_record_pointer',leaf.read('x0')!=R)
 H,E2,E3,SEC,USEC=z3.BitVecs('material_upper32 material_entropy2_32 material_entropy3_32 material_seconds32 material_usec32',32)
 td=z3.And(F&15==0,z3.UGE(F,0x200000000),z3.ULE(F,(1<<64)-3041))
 time=run('time_to_material',0x1002dc30c,0x1002dc354,[('sp',F),('x22',F+0x670),('w24',0x8a9b8560)],[(F+0x680,4,SEC),(F+0x688,4,USEC),(F+0x498,8,F+0x670)])
 add('time_to_material_two_codecs',z3.Or(cell(time,F+0x678,4)!=(SEC^ENC),cell(time,F+0x674,4)!=(USEC^ENC)),td)
 second=run('second_entropy_codec',0x1002dc3a4,0x1002dc3b4,[('x0',z3.Concat(H,E2)),('w25',ENC*2),('w23',ENC),('x19',F+0x670)]);add('second_entropy_to_material_word3',cell(second,F+0x67c,4)!=(E2^ENC),td)
 third=run('third_entropy_codec',0x1002dc408,0x1002dc418,[('x0',z3.Concat(H,E3)),('w25',ENC*2),('w23',ENC),('x19',F+0x670)]);add('third_entropy_to_material_word0',cell(third,F+0x670,4)!=(E3^ENC),td)
 X=z3.BitVec('material_cursor64',64);cursor=run('cursor_low_word',0x1002dc440,0x1002dc464,[('sp',F),('x10',X)]);add('cursor_mask_is_low32_identity',cell(cursor,F+0x268,4)!=z3.Extract(31,0,X),td)
 I,J,SI,PREV,KEY=z3.BitVecs('material_index32 material_key_index32 material_state_word32 material_previous_word32 material_key_word32',32);ia=z3.ZeroExt(32,I);ja=z3.ZeroExt(32,J);mix=run('first_mixing_update',0x1002fbb00,0x1002fbb58,[('w23',I-0xe62b1fb7),('w22',J),('x28',STATE),('x19',F+0x670)],[(STATE+(ia<<2),4,SI),(STATE+(z3.ZeroExt(32,I-1)<<2),4,PREV),(F+0x670+(ja<<2),4,KEY^ENC)])
 expected=(SI^((PREV^z3.LShR(PREV,30))*0x19660d))+KEY+J;md=z3.And(td,z3.UGE(I,1),z3.ULE(I,623),z3.ULE(J,3));add('all_u32_first_mixing_update',cell(mix,STATE+(ia<<2),4)!=expected,md);assert len(mix.stores)==1 and mix.stores[0]['size_bytes']==4
 add('first_mixing_word_destination',mix.stores[0]['address']!=STATE+(ia<<2),md);add('first_mixing_phase_advance',mix.read('w23')!=I-0xe62b1fb7+1,md)
 CUR=z3.BitVec('material_arena_cursor64',64);RAW=z3.BitVec('material_encoded_word32',32);d=z3.Extract(31,0,CUR)
 prep=run('key_cursor_preparation',0x1002dc418,0x1002dc440,[('sp',F)],[(F+0x358,8,CUR)])
 add('key_cursor_preparation',z3.Or(cell(prep,F+0x280,8)!=CUR+0xde12b29d,cell(prep,F+0x270,8)!=z3.ZeroExt(32,(d+1)&0xde12b269)),td)
 adv=run('key_next_word_mutation',0x100288aa4,0x100288ad0,[('sp',F),('w8',1),('x19',F+0x670),('x24',ja)],[(F+0x270,8,cell(prep,F+0x270,8)),(F+0x280,8,cell(prep,F+0x280,8)),(F+0x670+(ja<<2),4,RAW)])
 jd=z3.And(td,z3.UGE(J,1),z3.ULE(J,3));add('all_u32_next_key_xor_cursor_plus_one',cell(adv,F+0x670+(ja<<2),4)!=(RAW^(d+1)),jd)
 wrap=run('key_wrap_mutation',0x10038ec84,0x10038eca4,[('sp',F),('x19',F+0x670),('w22',3)],[(F+0x670,4,RAW),(F+0x268,4,d)])
 add('all_u32_wrapped_key_xor_cursor',cell(wrap,F+0x670,4)!=(RAW^d),td);add('paired_key_mutations_restore_word',z3.Or((RAW^d)^d!=RAW,(RAW^(d+1))^(d+1)!=RAW),td)
 second_mix=run('second_mixing_update',0x1003068b4,0x100306904,[('w23',I-0xe62b1fb7),('x28',STATE)],[(STATE+(ia<<2),4,SI),(STATE+(z3.ZeroExt(32,I-1)<<2),4,PREV)])
 add('all_u32_second_mixing_update',cell(second_mix,STATE+(ia<<2),4)!=((SI^((PREV^z3.LShR(PREV,30))*1566083941))-I),md)
 assert len(second_mix.stores)==1 and second_mix.stores[0]['size_bytes']==4;add('second_mixing_word_destination',second_mix.stores[0]['address']!=STATE+(ia<<2),md)
 for name,start in [('first_state_wrap',0x1004694e4),('second_state_wrap',0x100396ec0)]:
  cp=run(name,start,start+8,[('x28',STATE)],[(STATE+623*4,4,RAW)]);add(name,cell(cp,STATE,4)!=RAW,td)
 forced=run('state_nonzero_force',0x1002f0eec,0x1002f0ef4,[('x28',STATE)]);add('state_word0_high_bit_force',cell(forced,STATE,4)!=0x80000000,td)
 OFFSET=z3.BitVec('twist_byte_offset64',64);S0,NEXT,FAR=z3.BitVecs('twist_current32 twist_next32 twist_far32',32);twist_domain=z3.And(td,OFFSET&3==0,z3.ULE(OFFSET,226*4))
 pre=run('twist_prefix',0x10035c6d8,0x10035c6f8,[('x28',STATE),('x8',OFFSET),('w9',S0),('x3',F+0x6d8)],[(STATE+OFFSET+4,4,NEXT),(STATE+OFFSET+397*4,4,FAR)])
 table_address=pre.read('x13');add('twist_table_has_exactly_two_candidate_addresses',z3.And(table_address!=F+0x6d8,table_address!=F+0x6dc),twist_domain)
 add('twist_table_address_is_next_word_low_bit',table_address!=F+0x6d8+(z3.ZeroExt(32,NEXT&1)<<2),twist_domain)
 encoded=z3.If(NEXT&1==0,z3.BitVecVal(0x94fdeab5,32),z3.BitVecVal(0x0df55a6a,32))
 post=run('twist_after_lookup',0x10035c6f8,0x10035c70c,[('x13',table_address),('w12',pre.read('w12')),('w11',pre.read('w11')),('w15',0x94fdeab5),('x10',STATE+OFFSET)],[(table_address,4,encoded)])
 expected_twist=FAR^z3.LShR((S0&0x80000000)|(NEXT&0x7fffffff),1)^z3.If(NEXT&1==0,z3.BitVecVal(0,32),z3.BitVecVal(0x9908b0df,32));add('all_u32_first_twist_slice',cell(post,STATE+OFFSET,4)!=expected_twist,twist_domain)
 O=z3.BitVec('material_old_frame_cursor64',64);reservation=run('frame_material_reservation',0x1002dc094,0x1002dc0b0,[('sp',F)],[(F+0x5c0,8,O)]);add('frame_material_reservation32',z3.Or(cell(reservation,F+0x580,8)!=F+0x660+O,cell(reservation,F+0x498,8)!=F+0x660+O,cell(reservation,F+0x5c0,8)!=O+32),td)
 table_setup=run('twist_table_setup',0x1002dc0b0,0x1002dc0c4,[('sp',F)]);add('twist_table_literal_source',cell(table_setup,F+0x6d8,8)!=0x0df55a6a94fdeab5,td)
 return qs,counts,inv

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_seed_material_contracts.json').read_text());qs,counts,inv=obligations(c);rows=[]
 for name,pred in qs:
  op=ROOT/f'daemon_seed_material_{name}_original.smt2';np=ROOT/f'daemon_seed_material_{name}.smt2';s=z3.Solver();s.add(pred);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(pred));result=str(s.check());assert result=='unsat',(name,result);np.write_text(s.to_smt2());rows.append({'name':name,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 witnesses=[]
 for f in [0x640000b420,0x640000b520]:
  for i,j in [(1,0),(623,3)]:
   s=z3.Solver();s.add(qs[10][1].arg(0),z3.BitVec('material_frame64',64)==f,z3.BitVec('material_index32',32)==i,z3.BitVec('material_key_index32',32)==j);assert str(s.check())=='sat';witnesses.append({'frame':hex(f),'index':i,'key_index':j,'result':'sat'})
 R,F=z3.BitVecs('less_record64 material_frame64',64);v=LessLift(part(c,'unaligned_counterexample',0x10032ca54,0x10032ca98));v.seed('x0',R);v.seed('sp',F);v.run('unaligned_counterexample');actual=cell(v,F+0x340,8);s=z3.Solver();s.add(F==0x640000b420,R==F+0xafc,actual!=(R^MIX));assert str(s.check())=='sat';model=s.model();counterexample={'R':hex(model.eval(R).as_long()),'record_alignment_bytes':4,'actual_prekey':hex(model.eval(actual).as_long()),'aligned8_identity_prekey':hex(model.eval(R^MIX).as_long()),'result':'sat','scope':'Outside the aligned8 caller proof domain; no native unaligned record observed.'}
 deps=['daemon_seed_material_contracts.json','prove_daemon_frame_entry.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'source_lift_instruction_visits':sum(counts.values()),'address_multiplier_inverse64':hex(inv),'nonempty_premise_witnesses':witnesses,'outside_alignment_counterexample':counterexample,'normalization_dependency':'less_record_body uses less_helper_prekey_identity at0x100427550; caller prekey requires record alignment8. twist_after_lookup uses twist_table_literal_source and twist_table_address_is_next_word_low_bit; those postlookup instructions are not executed by the whole-prefix replays.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_proof_pairs':len(rows),'source_lifts':counts,'inverse64':hex(inv)}),flush=True)
if __name__=='__main__':main()
