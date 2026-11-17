#!/usr/bin/env python3
"""Independent integer replay, byte-origin oracles and fresh source obligations.
O(C*(V+E+M)+I+256R+query DAG) work/space; SMT cost separate, 30 s/query.
No native target or IDB execution. Negative controls alter private source only.
"""
import json
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,IMAGE,TABLE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
from lskd_values_symbolic import Lift,resize,mem,cell
from replay_userclient_entry_execution import Replay,PRIVATE
import recover_userclient_entry_execution as R

def cut(e,label,*ranges):
 parts=[]
 for a,z in ranges:
  s=next(s for s in e['source']['spans'] if int(s['start'],16)<=a<z<=int(s['end_exclusive'],16));b=bytes.fromhex(s['bytes_hex']);start=int(s['start'],16);parts.append(b[a-start:z-start])
 # Ranges in each multi-part proof are separate instruction records, preserving PCs.
 return [{'spans':[{'label':label,'start':hex(a),'bytes_hex':b.hex()}]} for (a,z),b in zip(ranges,parts)]
def proof(name,v,bad,premises=()):
 s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat;s.add(bad);query=s.to_smt2();assert s.check()==z3.unsat,name
 return {'name':name,'lifted_instruction_instances':v.count,'premises_nonvacuous':True,'result':'unsat','query':query}
def obligations(e):
 out=[];I,A,Q,F,W,C,S=z3.BitVecs('UE_input64 UE_size64 UE_third64 UE_frame64 UE_workspace64 UE_typed64 UE_source64',64)
 v=Lift(cut(e,'one',(0xfffffe000a635584,0xfffffe000a63559c))[0]);v.seed('x20',I);v.run('one');out.append(proof('nullable_input_dispatch_index',v,v.read('w8')!=z3.If(I==0,resize(0xc26,32),resize(0xc2c,32))))
 v=Lift(cut(e,'one',(0xfffffe000a635244,0xfffffe000a635258))[0]);v.seed('sp',F+0x1070)
 for reg,val in [('x0',I),('x1',A),('x2',Q)]:v.seed(reg,val)
 v.run('one');out.append(proof('post_probe_frame_and_exact_three_arguments',v,z3.Or(v.read('sp')!=F,cell(v,F+0x8f8,8)!=I,cell(v,F+0x878,8)!=A,cell(v,F+0x738,8)!=Q)))
 for name,base,reg,off,n,p1,p2 in [('workspace_order_operands',W,'x24',0xe40,0x4000,0xfffffe000a635478,0xfffffe000a6354bc),('typed_order_operands',C,'x23',0x800,0x1000,0xfffffe000a6354e0,0xfffffe000a635514)]:
  parts=cut(e,'one',(p1,p1+4),(p2,p2+4));v=Lift(parts[0]);v.seed(reg,base);v.run('one');v.c=parts[1];v.run('one');out.append(proof(name,v,z3.Or(v.read('x0')!=base+off,v.read('x1')!=base+n,z3.Not(z3.ULE(v.read('x0'),v.read('x1')))),[z3.ULE(base,resize(2**64-1-n,64))]))
 v=Lift(cut(e,'one',(0xfffffe000a6355ec,0xfffffe000a63561c))[0]);v.seed('sp',F);mem(v,F+0x878,8,A);v.run('one');out.append(proof('low32_size_encoded_channel',v,v.read('w1')!=(z3.Extract(31,0,A)^0x31ae0066)))
 v=Lift(cut(e,'one',(0xfffffe000a635950,0xfffffe000a635960))[0])
 for reg,val in [('sp',F),('x2',C),('x4',S),('x17',C+0x418),('x20',I),('w1',z3.Extract(31,0,A)^0x31ae0066),('w3',0x886a1ca3)]:v.seed(reg,val)
 v.run('one');v.c=cut(e,'one',(0xfffffe000a636344,0xfffffe000a63635c))[0];v.run('one')
 extents=[(F,0x10f0),(C,0x1000),(S,0x4000)];owned=[]
 for j,(a,n) in enumerate(extents):
  owned.extend([a!=0,z3.ULE(a,resize(2**64-1-n,64))])
  for b,m in extents[j+1:]:owned.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
 out.append(proof('source_pointer_and_extent_clones',v,z3.Or(cell(v,C+0x170,8)!=C+0x418,cell(v,C+0x98,8)!=I,cell(v,S+0xb5c,4)!=(z3.Extract(31,0,A)^0x31ae0066)),owned))
 return out
def known_ranges(s):
 mask=bytes.fromhex(s['known_mask_hex']);b=bytes.fromhex(s['bytes_hex']);rows=[];j=0
 while j<len(mask):
  if not mask[j]:j+=1;continue
  start=j
  while j<len(mask)and mask[j]:j+=1
  rows.append({'offset':start,'size_bytes':j-start,'bytes_hex':b[start:j].hex()})
 return rows
def oracle(r,replay):
 args=r['input']['inputs8'];nonnull=args[0]!=0;f=int(r['frame_base_SP'],16);s=PRIVATE+0x8000;c=PRIVATE+0xc000;n=args[1]&0xffffffff
 assert f==int(r['entry_SP'],16)-0x10f0
 def val(a,n):return int.from_bytes(replay.at(a,n),'little')
 assert [val(f+o,8) for o in [0x8f8,0x878,0x738]]==args[:3]
 assert len(r['API_models'])==2 and len(r['probe_entries'])==1 and r['probe_entries'][0]['probe_size_bytes']==0x1070
 assert r['unknown_read']is None and r['boundary']['kind']=='before_unmodeled_call'
 assert r['boundary']['pc']==('0xfffffe000a636404' if nonnull else '0xfffffe000a666260')
 assert r['unexecuted_call']['target']==('0xfffffe000c4ba154' if nonnull else '0xfffffe000c4ba368')
 assert r['unexecuted_call']['arguments8'][0]==('0xfffffe000847bb60' if nonnull else '0xfffffe000847ba60')
 if not nonnull:assert r['unexecuted_call']['arguments8'][1]==hex(c)
 assert sum(bytes.fromhex(r['workspace']['known_mask_hex']))==(45 if nonnull else 8)
 assert sum(bytes.fromhex(r['typed_region']['known_mask_hex']))==(80 if nonnull else 24)
 assert not any(a in replay.known for a in range(s+0x20,s+0x24))
 assert not any(int(x['address'],16)<PRIVATE+0x3000 and int(x['address'],16)+x['size_bytes']>PRIVATE+0x2000 for x in r['source_reads'])
 before={x['pc']:r['source_frames'][x['source_visit_index']] for x in r['logical_edges'] if x['kind']=='blraa'}
 assert before['0xfffffe000a6354dc']['registers31'][:2]==[hex(s+0xe40),hex(s+0x4000)]
 assert before['0xfffffe000a635534']['registers31'][:2]==[hex(c+0x800),hex(c+0x1000)]
 if nonnull:
  for a,want,nbytes in [(c+0x170,c+0x418,8),(c+0x98,args[0],8),(s+0xb5c,n^0x31ae0066,4),(s+0xc8,n^0x31ae0066,4),(f+0x524,n^0x31ae0066,4)]:assert val(a,nbytes)==want
  for off,want in [(0x658,0x10),(0x490,0x14),(0x628,0x26)]:assert val(f+off,8)==s+want
  assert len(r['source_visits'])==1162 and r['source_frames'][-1]['registers31'][12]=='0x5c'and r['source_frames'][-1]['registers31'][15]=='0x32'
 else:assert len(r['source_visits'])==297
 return {'nonnull':nonnull,'source_visits':len(r['source_visits']),'workspace_known_bytes':45 if nonnull else 8,'typed_known_bytes':80 if nonnull else 24,'workspace_defined_ranges':known_ranges(r['workspace']),'typed_defined_ranges':known_ranges(r['typed_region']),'marker_defined_bytes':0,'input_bytes_read':0,'all_checks_pass':True}
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));k=Kernel();assert e['source']==R.source(k)
 totals=Counter();rows=[]
 for r in e['cases']:
  v=Replay(k,r);totals.update(v.run());rows.append(oracle(r,v))
 # Verify preserved entry arguments through the actual source prologue and probe.
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;pcs=[]
 for a,z in [(0xfffffe000a635208,0xfffffe000a63524c),(0xfffffe000a5a1cc4,0xfffffe000a5a1cf8)]:
  for i in dec.disasm(k.read(a,z-a),a):
   _,written=i.regs_access();assert not {i.reg_name(j) for j in written}&{'x0','w0','x1','w1','x2','w2'};pcs.append(hex(i.address))
 negatives=[]
 from probe_userclient_entry_execution import Entry,cases
 case=list(cases())[2]
 for pc,want in [(0xfffffe000a635950,0xfffffe000a636344),(0xfffffe000a63595c,0xfffffe000a636350)]:
  mutation={'pc':pc};b=Entry(case,mutation);r=b.run();v=Replay(k,r,mutation);counts=v.run();assert r['boundary']['kind']=='before_undefined_private_value_load'and r['boundary']['pc']==hex(want)
  try:oracle(r,v)
  except AssertionError:rejected=True
  else:rejected=False
  assert rejected;negatives.append({'mutated_PC':hex(pc),'original_word_hex':k.read(pc,4).hex(),'replacement_word_hex':'1f2003d5','boundary':r['boundary'],'unknown_load':r['unknown_read'],'independent_checks':counts,'normal_oracle_rejected':True})
 source_proofs=obligations(e)
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/'replay_userclient_entry_execution.py'),'dependencies':e['dependencies'],'source_sha256':e['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':e['scope'],'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'cases':rows,'prologue_argument_preservation_PCs':pcs,'source_proofs':source_proofs,'negative_source_controls':negatives,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps({'independent':a['independent_totals'],'queries':len(a['source_proofs']),'controls':len(a['negative_source_controls'])}),flush=True)
