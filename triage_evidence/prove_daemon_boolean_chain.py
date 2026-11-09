#!/usr/bin/env python3
"""Original local BV equations for bridge address-key decode, fixed-context
pointer gate, four-byte result channels, pair-state accumulation and shared
global updates. Readable/writable disjoint relative cells and preserved
intermediate registers are premises; no native policy or owner proof.
O(source/BV DAGs + solver resources) time/space; no native target/IPC.
"""
import json
import z3
from daemon_receive_tools import ROOT,IMAGE
from daemon_output_base_dispatch import CS
from daemon_arena_lifetime_symbolic import LifetimeFlags
from lskd_values_symbolic import mem,cell,resize
from capture_daemon_record720 import sha
class Local(LifetimeFlags):
 def run(self,label):
  span=next(s for s in self.c['spans']if s['label']==label)
  for ins in CS.disasm(bytes.fromhex(span['bytes_hex']),int(span['start'],16)):
   if ins.mnemonic=='cinc':
    assert ins.op_str=='w11, w11, ne';value=self.read('w11');self.write('w11',z3.If(self.condition('ne'),value+1,value));self.count+=1
   else:self.c={'spans':[{'label':'one','start':hex(ins.address),'bytes_hex':bytes(ins.bytes).hex()}]};super().run('one')
def obligations():
 c=json.loads((ROOT/'daemon_boolean_chain_contracts.json').read_text());qs=[];counts={}
 def run(name,a,z,seeds=(),memory=()):
  m=Local({'spans':[{'label':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()}]})
  for r,v in seeds:m.seed(r,v)
  for at,n,v in memory:mem(m,at,n,v)
  m.negative,m.equal,m.carry,m.overflow=[z3.Bool('bool_chain_'+name+'_'+f)for f in ['N','Z','C','V']];m.run(name);counts[name]=m.count;return m
 R,S,PTR=z3.BitVecs('bool_chain_record64 bool_chain_SP64 bool_chain_state_pointer64',64);INPUT,RAW,PHASE,KEY=z3.BitVecs('bool_chain_key_input32 bool_chain_raw32 bool_chain_phase32 bool_chain_key32',32);m=run('bridge_key_input',0x100458824,0x10045884c,[('x19',R)]);qs.append(('all_bridge_record_key_inputs',m.read('w10')!=(z3.Extract(31,0,R)^0x7cf28be0)))
 m=run('bridge_decode',0x10045884c,0x100458860,[('w10',INPUT),('x0',R)],[(R+0xc,4,RAW)]);qs.append(('all_bridge_key_and_raw_words',m.read('w10')!=(RAW^(INPUT*0x83918153))));qs.append(('all_caller_bridge_codec_words',(((PHASE+0xd64d96e8)^KEY)^KEY)!=(PHASE+0xd64d96e8)))
 TAG=z3.BitVec('bool_chain_decoded_tag32',32);m=run('pointer_gate',0x100458860,0x100458888,[('x0',R),('sp',S),('w10',TAG)],[(R+0x10,8,PTR)]);scale=run('pointer_scale',0x1004588c0,0x1004588d0,[('w26',m.read('w26')),('w11',m.read('w11'))]);joined=run('pointer_join',0x1004588e0,0x1004588e4,[('w11',scale.read('w11')),('w10',TAG)]);status=run('pointer_early_status',0x1004588f4,0x1004588fc);expected=TAG|z3.If(PTR!=0,((TAG+0xd3bf43e3)&0x7defcbea)+0xae503c68,z3.BitVecVal(0,32));qs.append(('all_pointer_words_local_index',z3.Or(m.read('x14')!=PTR,joined.read('w9')!=expected,status.read('w8')!=0x74c29d88,z3.And(TAG==0xb3d4,joined.read('w9')!=z3.If(PTR!=0,z3.BitVecVal(0xb3de,32),z3.BitVecVal(0xb3d4,32))))))
 mc,fc,ml,fl=z3.BitVecs('bool_chain_CoreML_marker8 bool_chain_CoreML_flag8 bool_chain_Classic_marker8 bool_chain_Classic_flag8',8);OLD=z3.BitVec('bool_chain_old_state32',32);HIGH=z3.BitVec('bool_chain_phase_upper24',24);STATE=S+0x6bbc;m=run('pair_state',0x1003455e8,0x100345638,[('sp',S),('w20',mc),('w25',fc)],[(S+0x20,4,z3.Concat(HIGH,z3.BitVecVal(0xd4,8))),(S+0x58,1,ml),(S+0x27,1,fl),(S+0x18,8,STATE),(STATE,4,OLD)]);core=z3.And(mc!=0x5b,fc!=0);classic=z3.And(ml!=0x5b,fl!=0);expected=OLD|z3.If(core,z3.BitVecVal(1,32),z3.BitVecVal(0,32))|z3.If(classic,z3.BitVecVal(2,32),z3.BitVecVal(0,32));qs.append(('all_marker_flag_and_old_state_words',cell(m,STATE,4)!=expected))
 m=run('saved_phase',0x1003452d8,0x1003452e8,[('sp',S),('w26',0x51afc3a2)]);qs.append(('all_bridge_frames_saved_phase',cell(m,S+0x20,4)!=0xb3d4))
 v=run('zero_status',0x100345664,0x10034566c);m=run('status_store',0x1003fdcfc,0x1003fdd00,[('x19',R),('w8',v.read('w8'))]);STATUS=z3.BitVec('bool_chain_returned_raw_status32',32);load=run('caller_status',0x1007f7a88,0x1007f7a8c,[('x19',R-0xcb8)],[(R+8,4,STATUS)]);qs.append(('all_bridge_records_status_channel',z3.Or(cell(m,R+8,4)!=0x8b3dc651,load.read('w6')!=STATUS)))
 phase=run('caller_zero_phase',0x1008017b8,0x1008017d0,[('w8',0x48cd)]);gate=run('caller_zero_compare',0x1008017ec,0x100801808,[('w21',phase.read('w21')),('w6',STATUS)]);qs.append(('all_caller_status_words_zero_gate',gate.read('w9')!=z3.If(STATUS==0x8b3dc651,z3.BitVecVal(0xc2b8,32),z3.BitVecVal(0,32))))
 A,B=z3.BitVecs('bool_chain_old_global_A64 bool_chain_old_global_B64',64);m=run('shared_globals',0x1004587e4,0x100458824,[('sp',S),('x10',A),('x11',B),('x22',0xa5cd4cf),('x23',0x1010b7d88),('x27',0x1010c4670)]);d=B-A-(S+0x48);qs.append(('all_global_and_frame_words',z3.Or(cell(m,0x1010b7d88,8)!=d*0xa5cd4cf+0x673e3a80075f02c6,cell(m,0x1010c4670,8)!=((d^0x73d046208eaed1a6)*0xa5cd4cf))))
 path=c['Classic_token_copy'];call=path['call'];SRC,DST=[int(x,16)for x in call['arguments8'][:2]];payload=z3.BitVec('bool_chain_Classic_token256',256);data={SRC+k:z3.Extract(8*k+7,8*k,payload)for k in range(32)};bad=[]
 class Copy(LifetimeFlags):
  def load(self,a,n):
   a=z3.simplify(a);assert z3.is_bv_value(a);at=a.as_long();return z3.Concat(*[data[at+k]for k in reversed(range(n))])if n>1 else data[at]
  def store(self,a,n,v,pc):
   a=z3.simplify(a);assert z3.is_bv_value(a);at=a.as_long();v=resize(v,8*n)
   for k in range(n):data[at+k]=z3.Extract(8*k+7,8*k,v)
 m=Copy({'spans':[]});m.seed('x0',SRC);m.seed('x1',DST);m.seed('x2',32);m.seed('x30',int(call['pc'],16)+4);m.seed('sp',int(call['SP'],16));m.negative,m.equal,m.carry,m.overflow=[z3.Bool('bool_chain_copy_'+f)for f in ['N','Z','C','V']];body=path['body']
 for k,row in enumerate(body):
  pc=int(row['pc'],16);ins=next(CS.disasm(bytes.fromhex(row['bytes_hex']),pc))
  if ins.mnemonic=='ret':continue
  if ins.mnemonic=='b'or ins.mnemonic.startswith('b.')or ins.mnemonic in ['cbz','cbnz']:
   if ins.mnemonic=='b':condition=z3.BoolVal(True);target=ins.operands[0].imm
   elif ins.mnemonic.startswith('b.'):condition=m.condition(ins.mnemonic[2:]);target=ins.operands[0].imm
   else:condition=m.read(ins.reg_name(ins.operands[0].reg))==0;target=ins.operands[1].imm;condition=z3.Not(condition)if ins.mnemonic=='cbnz'else condition
   bad.append(z3.If(condition,z3.BitVecVal(target,64),z3.BitVecVal(pc+4,64))!=int(body[k+1]['pc'],16));continue
  m.c={'spans':[{'label':'one','start':hex(pc),'bytes_hex':row['bytes_hex']}]};m.run('one')
 qs.append(('all_256_Classic_copy_bits',z3.Or(*bad,*[data[DST+k]!=z3.Extract(8*k+7,8*k,payload)for k in range(32)])));counts['Classic_copy']=len(body)
 return qs,counts
if __name__=='__main__':
 qs,counts=obligations();rows=[]
 for name,q in qs:
  a=ROOT/('daemon_boolean_chain_'+name+'_original.smt2');b=ROOT/('daemon_boolean_chain_'+name+'.smt2');s=z3.Solver();s.add(q);a.write_text(s.to_smt2());s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(q));answer=str(s.check());assert answer=='unsat',(name,answer);b.write_text(s.to_smt2());rows.append({'name':name,'original_file':a.name,'original_sha256':sha(a),'file':b.name,'sha256':sha(b),'result':answer});print(name,answer,flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['daemon_boolean_chain_contracts.json','daemon_arena_lifetime_symbolic.py','daemon_secondary_result_proofs.json']},'proofs':rows,'source_lift_counts':counts,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_boolean_chain_proofs.json').write_text(json.dumps(out,indent=2)+'\n')
