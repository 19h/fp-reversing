#!/usr/bin/env python3
"""Compact address-codec and 48-byte comparison-record source obligations.
O(I) bit-vector DAG construction/space,30 s/query. Valid aligned disjoint
records and selected caller phase; source prekey lemma normalizes helper K.
"""
import hashlib,json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT
from prove_daemon_frame_entry import FrameLift
from lskd_values_symbolic import part,mem,cell
MIX=0x4de3a292f9d49974;COEFF=0xda51a827
class CompareLift(FrameLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;old=self.c
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address;o=i.operands
   if i.mnemonic=='tst':
    n=self.width(i.reg_name(o[0].reg));self.equal=(self.operand(i,o[0],n)&self.operand(i,o[1],n))==0;self.carry=z3.BoolVal(False);self.count+=1
   elif i.mnemonic=='csel':
    cc=i.op_str.rsplit(',',1)[1].strip();assert cc=='ne';n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.If(z3.Not(self.equal),self.operand(i,o[1],n),self.operand(i,o[2],n)));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};FrameLift.run(self,'one')
  self.c=old;return self
def obligations(c):
 R,F,A,B=z3.BitVecs('comparison_record64 comparison_frame64 comparison_A64 comparison_B64',64);MODE,T,FALSE,MASK,C=z3.BitVecs('comparison_mode32 comparison_true32 comparison_false32 comparison_mask32 control_word32',32);K=(R^MIX)*COEFF;k=z3.Extract(31,0,K);qs=[];counts={};assume=z3.And(R&7==0,z3.ULE(R,(1<<64)-49))
 def run(n,a,z,seeds=(),memory=(),normalize=False):
  v=CompareLift(part(c,n,a,z))
  for name,value in seeds:v.seed(name,value)
  for at,size,value in memory:mem(v,at,size,value)
  if normalize:v.overrides={(0x10041a60c,'x8'):R^MIX}
  v.run(n);counts[n]=v.count;return v
 caller_domain=z3.And(assume,F&15==0,z3.UGE(F,0x200000000),z3.ULE(F,(1<<64)-3041),R==F+0xaf8)
 def add(n,p):qs.append((n,z3.And(caller_domain if n.startswith('caller_')or n=='all_u32_control_word_selector'else assume,p)))
 pre=run('helper_prekey',0x10041a5e0,0x10041a610,[('x0',R)]);add('helper_prekey_identity',pre.read('x8')!=(R^MIX))
 inv=pow(COEFF,-1,1<<64);add('address_codec_inverse',((K*inv)^MIX)!=R)
 caller=run('caller_prekey',0x10032c960,0x10032c9a4,[('x0',R),('sp',F)]);add('caller_prekey_identity',cell(caller,F+0x138,8)!=(R^MIX))
 key=run('caller_key_multiply',0x1002dc0d4,0x1002dc0e4,[('sp',F)],[(F+0x138,8,cell(caller,F+0x138,8))]);add('caller_key_matches_helper',key.read('x9')!=K)
 inputs=[(R,4,MODE+k),(R+8,8,A+K),(R+0x20,8,B^K),(R+0x28,4,FALSE-k),(R+0x2c,4,T^k),(R+0x14,4,MASK+k)]
 helper=run('comparison_body',0x10041a5e0,0x10041a66c,[('x0',R)],inputs,True);predicate=z3.If(MODE&1==1,z3.UGT(A,B),A==B);expected=MASK^z3.If(predicate,T,FALSE);add('all_u64_mode_comparison_and_result',cell(helper,R+0x10,4)!=expected)
 add('helper_preserves_record_pointer',helper.read('x0')!=R);assert len(helper.stores)==1 and helper.stores[0]['size_bytes']==4
 add('helper_only_result_store',helper.stores[0]['address']!=R+0x10)
 P=(0x8a9b8560+0xd75b54f6)&0xffffffff;pack=run('caller_pack',0x1002dc0d0,0x1002dc12c,[('sp',F),('x29',R+0xd8),('x0',0x1010c8258),('w8',0x8a9b8560)],[(0x1010c8258,4,C),(F+0x138,8,R^MIX)])
 add('caller_decodes_equality_zero_and_control',z3.Or(cell(pack,R,4)-k!=0,cell(pack,R+8,8)-K!=0,(cell(pack,R+0x20,8)^K)!=z3.ZeroExt(32,C)))
 add('caller_decoded_choice_fields',z3.Or(cell(pack,R+0x14,4)-k!=(P-0xd3e)&0xffffffff,cell(pack,R+0x28,4)+k!=(P+0x3e)&0xffffffff,(cell(pack,R+0x2c,4)^k)!=P))
 combined=CompareLift(part(c,'combined',0x10041a5e0,0x10041a66c));combined.memory=pack.memory.copy();combined.seed('x0',R);combined.overrides={(0x10041a60c,'x8'):R^MIX};combined.run('combined');counts['composed_helper_body']=combined.count
 add('all_u32_control_word_selector',cell(combined,R+0x10,4)!=z3.If(C==0,z3.BitVecVal(0x174e,32),z3.BitVecVal(0x178c,32)))
 return qs,counts,inv
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads((ROOT/'daemon_context_transfer_contracts.json').read_text());qs,counts,inv=obligations(c);rows=[]
 for n,q in qs:
  op=ROOT/f'daemon_context_transfer_{n}_original.smt2';np=ROOT/f'daemon_context_transfer_{n}.smt2';s=z3.Solver();s.add(q);op.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));result=str(s.check());assert result=='unsat',(n,result);np.write_text(s.to_smt2());rows.append({'name':n,'original_file':op.name,'original_sha256':sha(op),'file':np.name,'sha256':sha(np),'result':result})
 deps=['daemon_context_transfer_contracts.json','prove_daemon_frame_entry.py','daemon_rwlock_lifecycle_symbolic.py','daemon_iokit_sync_symbolic.py','daemon_iokit_class_symbolic.py','daemon_query_fallback_symbolic.py','daemon_query_state_symbolic.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'coefficient_inverse64':hex(inv),'normalization_dependency':'comparison_body and composed_helper_body replace x8 at41A60C with the independently proved helper_prekey_identity; original records and all_u64 result terms remain symbolic.','z3_version':z3.get_version_string(),'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_transfer_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(rows),'lifts':counts,'inverse64':hex(inv)}),flush=True)
if __name__=='__main__':main()
