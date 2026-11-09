#!/usr/bin/env python3
"""Original-source SHA-1 helper proofs with explicit local ABI/owner premises.
O(source DAG+solver resources) time/space; 30 s/query. Universal local word
identities plus finite complete traces are not a native caller proof.
"""
import json
from pathlib import Path
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_REG
from daemon_receive_tools import ROOT,TABLE
from recover_daemon_object_creation import sha
from prove_daemon_digest_routes import RouteLift
from lskd_values_symbolic import part,mem,cell,resize
from daemon_sha1_core_model import STATE_XOR,WORD_XOR
class CoreLift(RouteLift):
 def __init__(self,*args,data=()):super().__init__(*args);self.data_values=list(data);self.data_reads=[];self.control_reads=[];self.rewrites={};self.rewrite_queries=[]
 def write(self,n,v):
  at=(self.pc,n)
  if at in self.rewrites:
   compact=self.rewrites[at];self.rewrite_queries.append((at,resize(v,self.width(n))!=compact));v=compact
  super().write(n,v)
  if n not in ['xzr','wzr']:self.values[(self.pc,n)]=self.read(n)
 def load(self,a,n):
  k=(z3.simplify(a).sexpr(),n)
  if k in self.memory:return self.memory[k]
  if n==8:
   self.control_reads.append(a);assert len(self.control_reads)==1
   return z3.BitVec('sha1_unused_control_target64',64)
  assert self.data_values,(hex(self.pc),'unexpected source data read',a,n)
  expected_n,v=self.data_values.pop(0);assert n==expected_n;self.data_reads.append((a,n));return resize(v,8*n)
 def run(self,label):
  old=self.c;row=next(s for s in self.c['spans']if s['label']==label);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
  for i in cs.disasm(bytes.fromhex(row['bytes_hex']),int(row['start'],16)):
   self.pc=i.address
   if i.mnemonic=='extr':
    d,a,b,amount=i.operands;n=self.width(i.reg_name(d.reg));wide=z3.Concat(resize(self.read(i.reg_name(a.reg)),n),resize(self.read(i.reg_name(b.reg)),n));self.write(i.reg_name(d.reg),z3.Extract(n-1,0,z3.LShR(wide,amount.imm)));self.count+=1
   elif i.mnemonic in ['lsl','lsr','ror']and i.operands[2].type==ARM64_OP_REG:
    d,a,b=i.operands;n=self.width(i.reg_name(d.reg));v=resize(self.read(i.reg_name(a.reg)),n);shift=resize(self.read(i.reg_name(b.reg)),n)&(n-1);result=v<<shift if i.mnemonic=='lsl'else z3.LShR(v,shift)if i.mnemonic=='lsr'else z3.LShR(v,shift)|(v<<((n-shift)&(n-1)));self.write(i.reg_name(d.reg),result);self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};RouteLift.run(self,'one')
  self.c=old;return self
def terms_for(phase,S,W):
 a,b,cc,d,e=S;f=(b&cc)|(~b&d)if phase==0 else b^cc^d if phase in [1,3]else(b&cc)|(b&d)|(cc&d);return [z3.RotateLeft(a,5),f,e,W]
def generalized(name,pred):
 return z3.simplify(pred,bv_sort_ac=True),{'kind':'semantics_preserving_normalization','instantiation_verified':True}
def obligations(c,captures=None):
 F=0x6c00040000;C=0x6c00010000;B=0x6c00050000;J=z3.BitVec('sha1_helper_index32',32);S=z3.BitVecs('sha1_A32 sha1_B32 sha1_C32 sha1_D32 sha1_E32',32);W=z3.BitVec('sha1_message_word32',32);qs=[];counts={};details={}
 def add(name,pred,pre=z3.BoolVal(True)):qs.append((name,z3.And(pre,pred)))
 def seeded(name,data=()):
  abi=c['helper_ABIs'][name];a,z=int(abi['start'],16),int(abi['end'],16)-4;v=CoreLift(part(c,name,a,z),data=data)
  for reg,spec in abi['seeds'].items():
   kind=spec['kind'];value=F if kind=='frame_pointer'else C if kind=='context_pointer'else B if kind=='workspace_pointer'else TABLE if kind=='table_pointer'else J*spec['scale']+spec['base']if kind=='counter'else S[spec['word_index']]^STATE_XOR if kind=='state_word'else spec['value'];v.seed(reg,value)
  if name.startswith('round'):
   phase=int(name[-1]);ts=terms_for(phase,S,W);plan=json.loads((ROOT/'daemon_sha1_core_rewrite_plan.json').read_text())['round_rewrites'][name]
   for r in plan:
    val=sum(t for j,t in enumerate(ts)if r['subset_mask']>>j&1)*r['sign'];constant=int(r['constant'],16);val=val^constant if r['operation']=='xor'else val+constant;v.rewrites[(int(r['pc'],16),r['reg'])]=val
  v.run(name);assert not v.data_values
  if captures is not None:captures[name]=v
  counts[name]=v.count;lo,hi=abi['counter_domain'];pre=z3.And(z3.UGE(J,lo),z3.ULE(J,hi))
  for (pc,reg),q in v.rewrite_queries:add(name+'_certified_rewrite_'+hex(pc)+'_'+reg,q,pre)
  assert len(v.control_reads)==1;want=z3.If(z3.ULT(J,hi),z3.BitVecVal(int(abi['loop_slot'],16),64),z3.BitVecVal(int(abi['exit_slot'],16),64));add(name+'_original_control_address',v.control_reads[0]!=want,pre);return v,pre
 bs=z3.BitVecs('sha1_encoded_byte0 sha1_encoded_byte1 sha1_encoded_byte2 sha1_encoded_byte3',8);v,pre=seeded('input_words',[(1,b)for b in bs]);assert len(v.data_reads)==4 and len(v.stores)==1;expected=z3.Concat(*[b^0x98 for b in bs])^WORD_XOR
 add('input_words_all_u8_BE32_encoding_and_address',z3.Or(v.stores[0]['value']!=expected,v.stores[0]['address']!=B+(z3.ZeroExt(32,J)<<2),*[a!=C+z3.ZeroExt(32,J*4+j)for j,(a,n)in enumerate(v.data_reads)]),pre)
 words=z3.BitVecs('sha1_Wm3 sha1_Wm8 sha1_Wm14 sha1_Wm16',32);v,pre=seeded('schedule',[(4,w^WORD_XOR)for w in words]);assert len(v.data_reads)==4 and len(v.stores)==1
 expected=z3.RotateLeft(words[0]^words[1]^words[2]^words[3],1)^WORD_XOR
 add('schedule_all_u32_recurrence_and_four_addresses',z3.Or(v.stores[0]['value']!=expected,v.stores[0]['address']!=B+(z3.ZeroExt(32,J)<<2),*[a!=B+(z3.ZeroExt(32,J-k)<<2)for (a,n),k in zip(v.data_reads,[3,8,14,16])]),pre)
 for phase in range(4):
  name='round'+str(phase);v,pre=seeded(name,[(4,W^WORD_XOR)]);assert len(v.data_reads)==1;a,b,cc,d,e=S;f=(b&cc)|(~b&d)if phase==0 else b^cc^d if phase in [1,3]else(b&cc)|(b&d)|(cc&d);k=[0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6][phase];nxt=[z3.RotateLeft(a,5)+f+e+k+W,a,z3.RotateLeft(b,30),cc,d];bad=[v.data_reads[0][0]!=B+(z3.ZeroExt(32,J)<<2)]
  for j,regs in enumerate(c['round_output_maps'][phase]):
   for reg in regs:bad.append(resize(v.read('x'+str(reg)),32)!=(nxt[j]^STATE_XOR))
  add(name+'_all_u32_SHA1_working_transition',z3.Or(*bad),pre)
 # The feed-forward source stores C/D and updates E, then updates A/B/C/D.
 initial=z3.BitVecs('sha1_initial0 sha1_initial1 sha1_initial2 sha1_initial3 sha1_initial4',32);v=CoreLift(part(c,'feed_e',0x100908450,0x100908664))
 for r,val in [('sp',F),('x7',C),('x2',TABLE),('w0',S[2]^STATE_XOR),('w21',S[3]^STATE_XOR),('w1',S[4]^STATE_XOR),('w11',S[0]^STATE_XOR),('w19',S[1]^STATE_XOR),('w15',0x2183)]:v.seed(r,val)
 for j,x in enumerate(initial):mem(v,C+0x48+4*j,4,x^STATE_XOR)
 for r in json.loads((ROOT/'daemon_sha1_core_rewrite_plan.json').read_text())['feed_forward_rewrites']:
  value=initial[r['word_index']]if r['kind']=='initial'else S[r['word_index']];v.rewrites[(int(r['pc'],16),r['reg'])]=value+int(r['constant'],16)
 mem(v,F+0x2a70,8,C);v.run('feed_e');counts['feed_e']=v.count;assert len(v.control_reads)==1;add('feed_forward_original_control_address',v.control_reads[0]!=TABLE+8*0x2183)
 before=v.count;v.c=part(c,'feed_abcd',0x100bdf3bc,0x100bdfaf0);v.run('feed_abcd');counts['feed_abcd']=v.count-before;assert not v.data_reads and len(v.stores)==7
 if captures is not None:captures['feed_forward']=v
 for (pc,reg),q in v.rewrite_queries:add('feed_forward_certified_rewrite_'+hex(pc)+'_'+reg,q)
 for j in range(5):add('feed_forward_word'+str(j)+'_all_u32_sum_and_state_encoding',cell(v,C+0x48+4*j,4)!=((initial[j]+S[j])^STATE_XOR))
 details={'local_helper_control_addresses':7,'local_data_and_round_contracts':6,'feed_forward_words':5,'universal_word_scope':'u32 words/u8 source bytes; indices have explicit finite domains; valid separated owners and calibrated cutpoint constants required.','whole_native_caller_or_general_alias_proof':False};return qs,counts,details
def main():
 c=json.loads((ROOT/'daemon_sha1_core_contracts.json').read_text());qs,counts,details=obligations(c);rows=[]
 for name,pred in qs:
  a=ROOT/f'daemon_sha1_core_{name}_original.smt2';b=ROOT/f'daemon_sha1_core_{name}.smt2';s=z3.Solver();s.add(pred);a.write_text(s.to_smt2());g,certificate=generalized(name,pred);s=z3.Solver();s.set(timeout=30000);s.add(g);answer=str(s.check());print(json.dumps({'proof':name,'result':answer}),flush=True);assert answer=='unsat',(name,answer,str(s.model())if answer=='sat'else'');b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer,'certificate':certificate})
 deps=['daemon_sha1_core_contracts.json','daemon_sha1_core_model.py','daemon_sha1_core_rewrite_plan.json','prove_daemon_digest_routes.py','lskd_values_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'proofs':rows,'source_lift_counts':counts,'proof_scope':details,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_sha1_core_proofs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proof_pairs':len(rows),'source_lift_visits':sum(counts.values())}),flush=True)
if __name__=='__main__':main()
