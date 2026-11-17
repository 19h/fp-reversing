#!/usr/bin/env python3
"""Independent data-return epochs and conditional shared-writer fan-in proofs.
O(C*(V+E+M)+I+512+query DAG) work/space; SMT 30 s/query limit.
"""
import json
from collections import Counter
import z3
from kext_port_tools import ROOT,TABLE
from kernel_native_reader import Kernel
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_userclient_early_node import Lift
from audit_userclient_entry_execution import cut,proof
from lskd_values_symbolic import resize,mem,cell
from replay_userclient_early_data import Replay,PRIVATE
import recover_userclient_early_data as R
def obligations(e):
 out=[];J,Z,F,C,S,A=z3.BitVecs('ED_node64 ED_data64 ED_frame64 ED_context64 ED_workspace64 ED_return64',64);D=z3.BitVec('ED_tag32',32)
 def lift(a,z):return Lift(cut(e,'one',(a,z))[0])
 def seeds(v,items):
  for reg,val in items:v.seed(reg,val)
 def separated(extents):
  p=[]
  for j,(a,n)in enumerate(extents):
   p.extend([a!=0,z3.ULE(a,resize(2**64-1-n,64))])
   for b,m in extents[j+1:]:p.append(z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a)))
  return p
 v=lift(0xfffffe000a66184c,0xfffffe000a661864);seeds(v,[('x0',Z),('x22',J),('w26',0x871)]);v.run('one');out.append(proof('data_result_retention_and_nullable_dispatch',v,z3.Or(cell(v,J+0x18,8)!=Z,v.read('w8')!=z3.If(Z==0,resize(0x871,32),resize(0x87c,32))),separated([(J,32)])))
 v=lift(0xfffffe000a661884,0xfffffe000a6618b8);seeds(v,[('w26',0x871),('x22',J),('w19',D^0x31ae0066),('sp',F)]);v.run('one');v.c=cut(e,'one',(0xfffffe000a6618bc,0xfffffe000a6618e8))[0];mem(v,F+0xa08,8,S);mem(v,F+0xa28,8,C);v.run('one');out.append(proof('early_shared_writer_handoff',v,z3.Or(v.read('x16')!=J+0x18,v.read('w23')!=(D^0x2502309f),v.read('w8')!=0x543,v.read('x0')!=0x02e859d27e491464,v.read('w1')!=0x31ae0066,v.read('x3')!=S,v.read('x11')!=C,v.read('w14')!=0x7795e642,v.read('w25')!=0x886a1ca3,v.read('x17')!=0xdfc5)))
 v=lift(0xfffffe000a664078,0xfffffe000a6640b0);seeds(v,[('w25',0x886a1ca3),('w28',0x7795e642),('x22',J)]);mem(v,J+0x18,8,Z);v.run('one');out.append(proof('common_data_retirement_selection',v,z3.Or(v.read('w19')!=0x63d,v.read('w8')!=z3.If(Z==0,resize(0xa71,32),resize(0xa94,32)))))
 for name,off,a in R.RETURN_STORES:
  v=lift(a,a+12);seeds(v,[('sp',F),('x0',A)]);mem(v,F+0xa28,8,C);mem(v,F+0xa60,8,TABLE);v.run('one');out.append(proof('conditional_call_return_store_'+name,v,cell(v,C+off,8)!=A,separated([(F,0x10f0),(C,0x1000)])))
 nodes=z3.BitVecs('ED_node_768 ED_node_458 ED_node_140 ED_node_6b8 ED_node_58',64);M1,M2,M3,E,V=z3.BitVecs('ED_meta_d30 ED_meta_e28 ED_meta_df8 ED_early_extent ED_early_scalar',32);UL,UE=z3.BitVecs('ED_later_type16 ED_early_type16',16);IN=z3.BitVec('ED_incoming_buffer_cell64',64)
 v=lift(0xfffffe000a654ad8,0xfffffe000a654b8c);seeds(v,[('sp',F),('x3',S),('x11',C),('w14',0x7795e642),('w25',0x886a1ca3),('w1',0x31ae0066),('x16',IN)])
 for off,value in zip([0x768,0x458,0x140,0x6b8,0x58],nodes):mem(v,C+off,8,value)
 for off,value in [(0xd30,M1),(0xe28,M2),(0xdf8,M3),(0x94,E),(0x110,V)]:mem(v,S+off,4,value)
 mem(v,S+0xb90,2,UL);mem(v,S+0x1b2,2,UE);v.run('one')
 bad=[v.read('x9')!=nodes[0]+0x18,v.read('x13')!=nodes[1]+0x18,v.read('x15')!=nodes[2]+0x18,v.read('x10')!=nodes[3]+0x18,v.read('x22')!=nodes[4],v.read('x8')!=nodes[4]+0x18,v.read('x16')!=IN,cell(v,F+0x50,8)!=nodes[3],cell(v,F+0x9e0,4)!=(M1^0x14ac30f9),cell(v,F+0x9d0,4)!=(M3^0x14ac30f9),cell(v,F+0x480,4)!=(V^0x14ac30f9),v.read('w7')!=(M2^0x14ac30f9),v.read('w6')!=(E^0x14ac30f9),z3.Extract(7,0,v.read('w19'))!=(z3.Extract(15,8,UL)^0x36),z3.Extract(7,0,v.read('w30'))!=(z3.Extract(7,0,UL)^0x5e),z3.Extract(7,0,v.read('w11'))!=(z3.Extract(15,8,UE)^0xa2),z3.Extract(7,0,v.read('w3'))!=(z3.Extract(7,0,UE)^0xe3),v.read('w17')!=0x439]
 out.append(proof('conditional_five_node_seven_metadata_writer_setup',v,z3.Or(*bad),separated([(F,0x10f0),(C,0x1000),(S,0x4000)])))
 return out
def prefix(r,parent):
 p=parent['cases'][r['input']['data_parent_case_index']];n=len(p['source_visits']);assert p['boundary']['pc']=='0xfffffe000a661848'
 for key in ['entry_PC','entry_SP','entry_registers31','entry_NZCV','entry_Q_registers32','frame_base_SP','extra_initial_globals','probe_entries']:assert r[key]==p[key]
 for key in ['source_visits','source_frames']:assert r[key][:n]==p[key]
 for key in ['source_reads','source_writes','logical_edges','API_models']:assert[q for q in r[key]if q['source_visit_index']<n]==p[key]
 for key in ['SP','registers31','NZCV']:assert r['source_frames'][n][key]==p['boundary'][key]
 return n
def oracle(r,v,parent):
 c=r['input'];p=parent['cases'][c['data_parent_case_index']];n=len(p['source_visits']);z=c['data_result_fixture'];j=PRIVATE+0xe100;d=PRIVATE+0xe200;s=PRIVATE+0x8000;t=PRIVATE+0xc000
 def val(a,n):assert all(a+k in v.known for k in range(n));return int.from_bytes(v.at(a,n),'little')
 assert len(r['API_models'])==5 and r['model_memory_writes']==0 and val(j+0x18,8)==z and val(j+0x10,4)==10+c['wire_length32']
 assert val(j,8)==val(j+8,8)==0 and sum(a in v.known for a in range(j,j+32))==28 and not any(a in v.known for a in range(j+20,j+24))
 assert not any(a in v.known for a in range(d,d+64))and not any(a in v.known for a in range(s+0x20,s+0x24))
 new=[q for q in r['source_writes']if q['source_visit_index']>=n];assert len(new)==1 and new[0]['pc']=='0xfffffe000a66184c'and new[0]['address']==hex(j+0x18)and new[0]['size_bytes']==8
 for key in ['frame','workspace','typed_region','earlier_FPTTLV_object','declared_input']:assert r[key]==p[key]
 i=c['inputs8'][0];assert[q for q in r['source_reads']if i<=int(q['address'],16)<i+64]==[q for q in p['source_reads']if i<=int(q['address'],16)<i+64]
 known=0
 for q in r['writer_input_cells']:
  wanted=(q['root'],q['offset'])in [('C','0x58'),('S','0x94'),('S','0x110'),('S','0x1b2')];mask=bytes.fromhex(q['known_mask_hex']);assert mask==bytes([int(wanted)])*q['size_bytes'];known+=sum(mask)
 assert known==18
 if z:
  assert r['boundary']['kind']=='before_undefined_private_value_load'and r['boundary']['pc']=='0xfffffe000a654ae4'and r.get('unexecuted_call')is None
  assert r['unknown_read']['snapshot']['address']==hex(t+0x768)and r['unknown_read']['snapshot']['known_mask_hex']=='00'*8
  ix=next(n for n,q in enumerate(r['source_visits'])if q['pc']=='0xfffffe000a6618e8');g=[int(x,16)for x in r['source_frames'][ix]['registers31']]
  for reg,want in [(0,0x02e859d27e491464),(1,0x31ae0066),(3,s),(11,t),(16,j+0x18),(17,0xdfc5),(23,c['wire_tag32']^0x2502309f),(25,0x886a1ca3)]:assert g[reg]==want
  assert any(q['pc']=='0xfffffe000a6618e8'and q['target']=='0xfffffe000a654ad4'and q['modifier64']=='0xdfc5'for q in r['logical_edges'])
 else:
  assert r['unknown_read']is None and r['boundary']['kind']=='before_unmodeled_call'and r['boundary']['pc']=='0xfffffe000a6641e4'
  assert r['unexecuted_call']['target']=='0xfffffe000c4ba368'and r['unexecuted_call']['arguments8'][:2]==['0xfffffe000847bfa0',hex(j)]
 return {'profile':c['profile'],'data_result_fixture':hex(z),'source_visits':len(r['source_visits']),'node_defined_bytes':28,'node_unknown_padding_bytes':4,'data_defined_bytes':0,'writer_required_cells':12,'writer_required_bytes':64,'writer_required_defined_bytes':known,'writer_required_unknown_bytes':64-known,'writer_request_selected':bool(z),'typed_node_retirement_requested':not z,'undefined_value_consumed':False,'native_failure_inferred':False,'marker_defined_bytes':0,'all_checks_pass':True}
def audit(e=None):
 e=e if e is not None else json.loads(read(ROOT/(R.P+'_checks.json')));k=Kernel();assert e['source']==R.source(k,e['cases']);parent=json.loads(read(ROOT/'userclient_early_node_checks.json'));totals=Counter();rows=[];matched=0
 for r in e['cases']:
  v=Replay(k,r);totals.update(v.run());prefix(r,parent);matched+=1;rows.append(oracle(r,v,parent))
 assert matched==60 and sum(q['writer_request_selected']for q in rows)==30
 from probe_userclient_early_data import Entry,cases
 negatives=[]
 for pc,result in [(0xfffffe000a66184c,0),(0xfffffe000a661888,PRIVATE+0xe200)]:
  c=next(c for c in cases()if c['profile']=='blob_tag_one'and c['data_result_fixture']==result);mutation={'pc':pc};r=Entry(c,mutation).run();v=Replay(k,r,mutation);counts=v.run()
  try:oracle(r,v,parent)
  except AssertionError:rejected=True
  else:rejected=False
  assert rejected;negatives.append({'mutated_PC':hex(pc),'original_word_hex':k.read(pc,4).hex(),'replacement_word_hex':'1f2003d5','boundary':r['boundary'],'independent_checks':counts,'normal_oracle_rejected':True,'undefined_or_unbacked_load_executed':False})
 return {'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'replay_sha256':sha(ROOT/'replay_userclient_early_data.py'),'dependencies':e['dependencies'],'source_sha256':e['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':e['scope'],'verified_counts':e['verified_counts'],'independent_totals':dict(totals),'matched_parent_prefixes':matched,'cases':rows,'source_proofs':obligations(e),'negative_source_controls':negatives,'all_checks_pass':True,**{n:False for n in R.FALSE}}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps({'independent':a['independent_totals'],'queries':len(a['source_proofs']),'lifted':sum(q['lifted_instruction_instances']for q in a['source_proofs']),'controls':len(a['negative_source_controls'])}),flush=True)
