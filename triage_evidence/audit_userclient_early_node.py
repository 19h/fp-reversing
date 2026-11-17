#!/usr/bin/env python3
"""Independent node-byte epochs, finite source continuation and local SMT proofs.
O(C*(V+E+M)+I+256+query DAG) work/space; SMT bounded at 30 s/query.
"""
import json
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_userclient_early_header import Lift as BaseLift
from audit_userclient_entry_execution import cut,proof
from lskd_values_symbolic import resize,mem,cell
from replay_userclient_early_node import Replay,PRIVATE
import recover_userclient_early_node as R
class Lift(BaseLift):
 def run(self,label):
  row=next(s for s in self.c['spans']if s['label']==label);raw=bytes.fromhex(row['bytes_hex']);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ii=list(cs.disasm(raw,int(row['start'],16)));assert len(ii)*4==len(raw)
  for i in ii:
   self.pc=i.address;o=i.operands
   if i.mnemonic=='csel':
    n=self.width(i.reg_name(o[0].reg));self.write(i.reg_name(o[0].reg),z3.If(self.condition(i.op_str.rsplit(',',1)[1].strip()),self.operand(i,o[1],n),self.operand(i,o[2],n)));self.count+=1
   elif i.mnemonic=='adrp':self.write(i.reg_name(o[0].reg),resize(o[1].imm,64));self.count+=1
   else:self.c={'spans':[{'label':'word','start':hex(i.address),'bytes_hex':bytes(i.bytes).hex()}]};super().run('word')
  return self
def obligations(e):
 out=[];J,C,S,F,D,Z=z3.BitVecs('EN_node64 EN_context64 EN_workspace64 EN_frame64 EN_descriptor64 EN_zone64',64);L,A=z3.BitVecs('EN_length32 EN_allocator_flags32',32);N=z3.BitVec('EN_data_request64',64)
 def lift(a,z):return Lift(cut(e,'one',(a,z))[0])
 def seeds(v,items):
  for reg,val in items:v.seed(reg,val)
 v=lift(0xfffffe000a661670,0xfffffe000a661690);seeds(v,[('x0',J),('x10',C),('w23',0x886a1ca3),('w26',0x871),('w25',0x886a1ca3),('w20',0xaaa)]);v.run('one');out.append(proof('result_retention_and_nullable_dispatch_index',v,z3.Or(cell(v,C+0x58,8)!=J,v.read('w8')!=z3.If(J==0,resize(0xb09,32),resize(0xaaa,32)))))
 v=lift(0xfffffe000a6616ec,0xfffffe000a6616f0);v.seed('x0',J);v.run('one');out.append(proof('source_zeroes_first_sixteen_node_bytes',v,z3.Or(cell(v,J,8)!=0,cell(v,J+8,8)!=0)))
 v=lift(0xfffffe000a6616f0,0xfffffe000a661794);seeds(v,[('w24',L^0x31ae0066),('x25',0x886a1ca3),('sp',F)]);mem(v,F+0xa08,8,S);v.run('one');out.append(proof('encoded_body_extent_channel64',v,cell(v,S+0xca8,8)!=z3.ZeroExt(32,L)+0x622f763938943e93))
 v=lift(0xfffffe000a661794,0xfffffe000a6617fc);seeds(v,[('w24',L^0x31ae0066),('w26',0x871),('x22',J)]);v.run('one');out.append(proof('node_total_extent_and_data_request',v,z3.Or(cell(v,J+0x10,4)!=L+10,v.read('x0')!=z3.ZeroExt(32,L+10)),[z3.ULE(L,resize(0xfffffff5,32))]))
 v=lift(0xfffffe000c4ba158,0xfffffe000c4ba16c);v.seed('x0',D);mem(v,D+0x28,4,A);v.run('one');out.append(proof('typed_wrapper_flags_selection',v,v.read('w1')!=z3.If(A&0x10==0,resize(0x8004,32),resize(4,32))))
 v=lift(0xfffffe000bcfeb98,0xfffffe000bcfeba8);seeds(v,[('x0',D),('w1',A)]);mem(v,D,8,Z);v.run('one');out.append(proof('external_type_wrapper_masks_incoming_flags',v,z3.Or(v.read('w10')!=(A&7),v.read('w9')!=0xd1000,v.read('x8')!=Z)))
 for name,a,z,expected in [('zone_statistics_flags',0xfffffe000bcfebc4,0xfffffe000bcfebcc,0xd1000|(A&7)),('zone_context_flags',0xfffffe000bcfebd4,0xfffffe000bcfebdc,0xd1040+(A&7)),('heap_fallback_flags',0xfffffe000bcfec18,0xfffffe000bcfec20,0xd1000|(A&7))]:
  v=lift(a,z);seeds(v,[('w10',A&7),('w9',0xd1000),('x8',Z)]);v.run('one');out.append(proof(name,v,v.read('w2')!=expected))
 v=lift(0xfffffe000c4ba620,0xfffffe000c4ba638);v.seed('x19',N);v.run('one');out.append(proof('data_wrapper_first_backend_arguments',v,z3.Or(v.read('x0')!=0xfffffe0007f8bfb0,v.read('x1')!=N,v.read('w2')!=0x31000,v.read('x3')!=0)))
 return out
def prefix(r,parent):
 p=parent['cases'][r['input']['node_parent_case_index']];n=len(p['source_visits']);assert p['boundary']['pc']=='0xfffffe000a661664'
 for key in ['entry_PC','entry_SP','entry_registers31','entry_NZCV','entry_Q_registers32','frame_base_SP','extra_initial_globals','probe_entries']:assert r[key]==p[key]
 for key in ['source_visits','source_frames']:assert r[key][:n]==p[key]
 for key in ['source_reads','source_writes','logical_edges','API_models']:assert[q for q in r[key]if q['source_visit_index']<n]==p[key]
 for key in ['SP','registers31','NZCV']:assert r['source_frames'][n][key]==p['boundary'][key]
 return n
def oracle(r,v,parent):
 c=r['input'];j=c['node_result_fixture'];s=PRIVATE+0x8000;t=PRIVATE+0xc000;h=PRIVATE+0xe000;node=PRIVATE+0xe100;l=c['wire_length32'];i=c['inputs8'][0];p=parent['cases'][c['node_parent_case_index']]
 def val(a,n):assert all(a+k in v.known for k in range(n));return int.from_bytes(v.at(a,n),'little')
 assert len(r['API_models'])==4 and r['model_memory_writes']==0 and val(t+0x58,8)==j
 assert val(h,8)==val(h+8,8)==0 and val(t+0x20,8)==h and val(s+0xa10,8)==10+l
 data=bytes.fromhex(c['input_fixture_hex']);d=c['wire_tag32'];u=c['wire_type16'];scalar32=int.from_bytes(data[10:14],'big')if c['profile']=='u32_payload'else 0;scalar64=int.from_bytes(data[10:18],'big')if c['profile'].startswith('u64_payload')else 0
 for a,n,want in [(t+0x260,8,0xfffffe000a661ba0),(s+0x1d0,4,d^0x31ae0066),(s+0x1b2,2,u^0xa2e3),(s+0x94,4,l^0x31ae0066),(s+0x110,4,scalar32^0x31ae0066),(s+0xad0,8,scalar64^0x8f98c6acce5848ca),(t+0x168,8,i+10 if c['profile'].startswith('blob')else 0)]:assert val(a,n)==want
 assert not any(a in v.known for a in range(s+0x20,s+0x24))
 reads=[q for q in r['source_reads']if i<=int(q['address'],16)<i+64];oldreads=[q for q in p['source_reads']if i<=int(q['address'],16)<i+64];assert reads==oldreads
 if j:
  assert r['unknown_read']is None and r['boundary']['kind']=='before_unmodeled_call'and r['boundary']['pc']=='0xfffffe000a661848'
  assert r['unexecuted_call']['target']=='0xfffffe000c4ba60c'and int(r['unexecuted_call']['arguments8'][0],16)==10+l
  assert val(node,8)==val(node+8,8)==0 and val(node+0x10,4)==10+l and val(s+0xca8,8)==0x622f763938943e93+l
  assert sum(a in v.known for a in range(node,node+32))==20 and not any(a in v.known for a in range(node+20,node+32))
 else:
  assert r['boundary']['kind']=='before_unbacked_value_load'and r['boundary']['pc']=='0xfffffe000a664098'and r['unknown_read']['address']=='0x18'and r['unknown_read']['size_bytes']==8
  assert int(r['boundary']['registers31'][22],16)==0 and int(r['boundary']['registers31'][23],16)==0xce515bb2
  assert not any(a in v.known for a in range(node,node+32))and r.get('unexecuted_call')is None
 return {'profile':c['profile'],'node_result_fixture':hex(j),'source_visits':len(r['source_visits']),'node_defined_bytes':20 if j else 0,'node_unknown_bytes':12 if j else 32,'input_bytes_read':len(reads),'data_request_size_bytes':10+l if j else None,'unbacked_load_executed':False,'native_failure_inferred':False,'marker_defined_bytes':0,'all_checks_pass':True}
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));k=Kernel();assert e['source']==R.source(k,e['cases']);parent=json.loads(read(ROOT/'userclient_early_header_checks.json'));totals=Counter();rows=[];matched=0
 for r in e['cases']:
  v=Replay(k,r);totals.update(v.run());prefix(r,parent);matched+=1;rows.append(oracle(r,v,parent))
 assert matched==60 and sum(q['node_defined_bytes']==20 for q in rows)==30
 from probe_userclient_early_node import Entry,cases
 negatives=[]
 for pc,result in [(0xfffffe000a661670,0),(0xfffffe000a6617f8,PRIVATE+0xe100)]:
  c=next(c for c in cases()if c['profile']=='blob_tag_one'and c['node_result_fixture']==result);mutation={'pc':pc};r=Entry(c,mutation).run();v=Replay(k,r,mutation);counts=v.run()
  try:oracle(r,v,parent)
  except AssertionError:rejected=True
  else:rejected=False
  assert rejected;negatives.append({'mutated_PC':hex(pc),'original_word_hex':k.read(pc,4).hex(),'replacement_word_hex':'1f2003d5','boundary':r['boundary'],'independent_checks':counts,'normal_oracle_rejected':True,'undefined_or_unbacked_load_executed':False})
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/'replay_userclient_early_node.py'),'dependencies':e['dependencies'],'source_sha256':e['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':e['scope'],'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'matched_parent_prefixes':matched,'cases':rows,'source_proofs':obligations(e),'negative_source_controls':negatives,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps({'independent':a['independent_totals'],'queries':len(a['source_proofs']),'lifted':sum(q['lifted_instruction_instances']for q in a['source_proofs']),'controls':len(a['negative_source_controls'])}),flush=True)
