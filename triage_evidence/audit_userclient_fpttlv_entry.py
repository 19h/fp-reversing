#!/usr/bin/env python3
"""Independent continuous replay, phase/byte oracles and original-word proofs.
O(C*(V+E+M)+I+256R+query DAG) time/space; SMT limited to 30 s/query.
"""
import json
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import Lift as OriginalLift,resize,mem,cell
from audit_userclient_entry_execution import cut,proof
from replay_userclient_fpttlv_entry import Replay,PRIVATE
import recover_userclient_fpttlv_entry as R

class Lift(OriginalLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(raw,int(row['start'],16)));assert len(ins)*4==len(raw)
  for i in ins:
   self.pc=i.address
   if i.mnemonic=='cmn':
    n=self.width(i.reg_name(i.operands[0].reg));a=self.operand(i,i.operands[0],n);b=self.operand(i,i.operands[1],n);self.carry=z3.ULT(a+b,a);self.count+=1
   elif i.mnemonic=='cset'and i.op_str.rsplit(',',1)[1].strip()in['hs','lo']:
    cond=i.op_str.rsplit(',',1)[1].strip();carry=self.carry if hasattr(self,'carry')else z3.UGE(self.cmp_left,self.cmp_right);self.write(i.reg_name(i.operands[0].reg),z3.If(carry if cond=='hs'else z3.Not(carry),resize(1,32),resize(0,32)));self.count+=1
   else:
    self.c={'spans':[{'label':'word','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('word')
  return self

def obligations(e):
 out=[];H,C,S,c=z3.BitVecs('FE_object64 FE_typed64 FE_workspace64 FE_cursor64',64);N=z3.BitVec('FE_length32',32)
 def lift(a,z):return Lift(cut(e,'one',(a,z))[0])
 v=lift(0xfffffe000a636428,0xfffffe000a636448)
 for reg,val in [('x0',H),('x2',C),('w19',0x4a2),('w20',0x68e)]:v.seed(reg,val)
 v.run('one');out.append(proof('third_result_retention_and_nullable_index',v,z3.Or(cell(v,C+0xb0,8)!=H,v.read('w8')!=z3.If(H==0,resize(0x693,32),resize(0x68e,32)))))
 v=lift(0xfffffe000a6366b0,0xfffffe000a6366cc);v.seed('x0',H);v.seed('w30',0x4a2);v.run('one');out.append(proof('source_zeroes_both_object_words',v,z3.Or(cell(v,H,8)!=0,cell(v,H+8,8)!=0),[H!=0,z3.ULE(H,resize(2**64-17,64))]))
 v=lift(0xfffffe000a660af8,0xfffffe000a660b20)
 for reg,val in [('x4',S),('w10',0xc89),('w30',0x31ae0066)]:v.seed(reg,val)
 mem(v,S+0xa10,8,c);mem(v,S+0xb5c,4,N^0x31ae0066);v.run('one');out.append(proof('unsigned_cursor_length_dispatch',v,v.read('w10')!=z3.If(z3.UGE(c,z3.ZeroExt(32,N)),resize(0xcd0,32),resize(0xc89,32))))
 v=lift(0xfffffe000a660c84,0xfffffe000a660d54)
 for reg,val in [('x8',c),('x9',z3.ZeroExt(32,N^0x31ae0066)),('w11',0x6a2)]:v.seed(reg,val)
 v.run('one');out.append(proof('ten_byte_header_fit_dispatch',v,v.read('w9')!=z3.If(z3.UGE(z3.ZeroExt(32,N)-c,resize(10,64)),resize(0x6bb,32),resize(0x6a2,32)),[z3.ULT(c,z3.ZeroExt(32,N))]))
 v=lift(0xfffffe000a660d88,0xfffffe000a660dcc);v.seed('x8',c);v.run('one');out.append(proof('first_header_byte_offset',v,v.read('x9')!=c+6))
 v=lift(0xfffffe000a660b68,0xfffffe000a660b74);v.seed('x2',C);mem(v,C+0xb0,8,H);mem(v,C+0x170,8,C+0x418);v.run('one');out.append(proof('empty_result_publication_alias',v,cell(v,C+0x418,8)!=H))
 return out

def prefix(r,parent):
 j=r['input']['parent_case_index']
 if j is None:return False
 p=parent['cases'][j]
 for key in ['entry_PC','entry_SP','entry_registers31','entry_NZCV','entry_Q_registers32','frame_base_SP','extra_initial_globals','probe_entries']:assert r[key]==p[key]
 for key in ['source_visits','source_frames']:assert r[key][:1162]==p[key]
 for key in ['source_reads','source_writes','logical_edges','API_models']:assert [q for q in r[key]if q['source_visit_index']<1162]==p[key]
 for key in ['SP','registers31','NZCV']:assert r['source_frames'][1162][key]==p['boundary'][key]
 return True

def oracle(r,v):
 h=r['input']['FPTTLV_result_fixture'];I,A,Q=r['input']['inputs8'][:3];n=A&0xffffffff;s=PRIVATE+0x8000;c=PRIVATE+0xc000;f=int(r['frame_base_SP'],16)
 def val(a,z):assert all(j in v.known for j in range(a,a+z));return int.from_bytes(v.at(a,z),'little')
 assert len(r['API_models'])==3 and r['model_memory_writes']==0 and not r['native_target_executed']
 assert val(c+0xb0,8)==h and val(f+0x9ec,4)==0xce515bb2
 assert [val(f+o,8)for o in [0x8f8,0x878,0x738]]==[I,A,Q]
 assert val(s+0xa10,8)==0 and val(s+0xb5c,4)==(n^0x31ae0066)and val(c+0x98,8)==I
 assert not any(j in v.known for j in range(s+0x20,s+0x24))
 assert not any(q['pc']=='0xfffffe000a660dcc'for q in r['source_reads'])
 object_mask=bytes.fromhex(r['earlier_FPTTLV_object']['known_mask_hex']);status=None;cleanup=None
 if not h:
  assert not any(object_mask)and r['unknown_read']is None and r['boundary']['pc']=='0xfffffe000a641cf8'and len(r['source_visits'])==1479
  assert r['unexecuted_call']['target']=='0xfffffe000c4ba60c'and int(r['unexecuted_call']['arguments8'][0],16)==n and val(c+0x418,8)==0
  assert not any(j in v.known for j in range(s+0xc94,s+0xc98));kind='NULL_object_to_staging_request'
 else:
  assert sum(object_mask)==16 and val(h,8)==val(h+8,8)==0
  if n<10:
   status=val(s+0xc94,4);cleanup=c+(0x418 if n==0 else 0x3d0)
   assert status==(0x31ae0066 if n==0 else 0xce515bb8)and val(cleanup,8)==h
   assert r['boundary']['pc']=='0xfffffe000a6605c4'and r['unknown_read']is None and r['unexecuted_call']['target']=='0xfffffe000c4ba368'
   assert r['unexecuted_call']['arguments8'][:2]==['0xfffffe000847bde0',hex(h)]and int(r['boundary']['registers31'][19],16)==cleanup
   assert val(c+0x418,8)==(h if n==0 else 0)and len(r['source_visits'])==(1720 if n==0 else 1548)
   kind='empty_to_typed_retirement'if n==0 else 'short_header_to_typed_retirement'
  else:
   assert len(r['source_visits'])==1464 and r['boundary']['pc']=='0xfffffe000a660dcc'and r['unexecuted_call']is None and val(c+0x418,8)==0
   q=r['unknown_read'];at=(I+6)&((1<<64)-1);assert int(q.get('address',q.get('snapshot',{}).get('address')),16)==at
   assert r['boundary']['kind']==('before_unbacked_value_load'if I==(1<<64)-1 else 'before_undefined_private_value_load')
   assert not any(j in v.known for j in range(s+0xc94,s+0xc98));kind='before_original_input_header_byte'
 return {'kind':kind,'source_visits':len(r['source_visits']),'object_defined_bytes':sum(object_mask),'raw_parser_status32':status,'cleanup_cell':hex(cleanup)if cleanup is not None else None,'input_bytes_read':0,'marker_defined_bytes':0,'all_checks_pass':True}

def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));k=Kernel();assert e['source']==R.source(k,e['cases']);parent=json.loads(read(ROOT/'userclient_entry_execution_checks.json'));totals=Counter();rows=[];matched=0
 for r in e['cases']:
  v=Replay(k,r);totals.update(v.run());matched+=prefix(r,parent);rows.append(oracle(r,v))
 assert matched==72 and Counter(r['kind']for r in rows)=={'NULL_object_to_staging_request':36,'empty_to_typed_retirement':6,'short_header_to_typed_retirement':12,'before_original_input_header_byte':30}
 from probe_userclient_fpttlv_entry import Entry,cases
 case=next(c for c in cases()if c['FPTTLV_result_fixture']and c['inputs8'][1]==0);negatives=[]
 for pc,want in [(0xfffffe000a6366c8,0xfffffe000a662c14),(0xfffffe000a636428,0xfffffe000a660b68)]:
  mutation={'pc':pc};b=Entry(case,mutation);r=b.run();v=Replay(k,r,mutation);counts=v.run();assert r['boundary']['kind']=='before_undefined_private_value_load'and r['boundary']['pc']==hex(want)
  try:oracle(r,v)
  except AssertionError:rejected=True
  else:rejected=False
  assert rejected;negatives.append({'mutated_PC':hex(pc),'original_word_hex':k.read(pc,4).hex(),'replacement_word_hex':'1f2003d5','boundary':r['boundary'],'unknown_load':r['unknown_read'],'independent_checks':counts,'normal_oracle_rejected':True})
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/'replay_userclient_fpttlv_entry.py'),'dependencies':e['dependencies'],'source_sha256':e['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':e['scope'],'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'matched_parent_prefixes':matched,'cases':rows,'source_proofs':obligations(e),'negative_source_controls':negatives,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps({'independent':a['independent_totals'],'queries':len(a['source_proofs']),'lifted':sum(p['lifted_instruction_instances']for p in a['source_proofs']),'controls':len(a['negative_source_controls'])}),flush=True)
