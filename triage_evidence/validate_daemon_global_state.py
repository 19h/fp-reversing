#!/usr/bin/env python3
"""Independent source/SMT/section/codec checks across sealed and isolated A64 data.
O(artifact bytes+cases+source bytes+SMT queries) time, O(largest artifact) space.
No native target/API/PAC or IDB mutation executes.
"""
import hashlib,json,struct
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,verify_original_fixups,selected
from replay_daemon_global_state import compact,Isolated,KD,KOFF,KA,KM

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and not q['full_goal_complete']
 for name,h in q.get('dependencies',{}).items():assert sha(ROOT/name)==h,(n,name)
 if 'source_sha256'in q:assert sha(SOURCE)==q['source_sha256']
 return q

def main():
 c=checked('daemon_global_state_contracts.json','recover_daemon_global_state.py');p=checked('daemon_global_state_observations.json','probe_daemon_global_state.py');q=checked('daemon_global_state_proofs.json','prove_daemon_global_state.py');replays=checked('daemon_global_state_replays.json','replay_daemon_global_state.py');counts={};assert not c['live_IDB_available']and c['live_IDB_rows_matched']==0
 for name in ['daemon_global_state_live_ida.json','daemon_global_state_ida_retry.json']:
  error=read(name);assert error['isError']and 'matching authenticated bridge worker is unavailable'in error['content'][0]['text']
 counts['unavailable_IDA_probes']=2
 for span in c['spans']:
  a=int(span['start'],16);raw=bytes.fromhex(span['bytes_hex']);assert IMAGE.read(a,len(raw))==raw and hashlib.sha256(raw).hexdigest()==span['sha256']
 counts['original_source_spans']=len(c['spans']);assert counts['original_source_spans']==14
 assert verify_original_fixups([int(r['address'],16)for r in c['source_fixups']['records']])==c['source_fixups'];counts['original_fixups_verified']=len(c['source_fixups']['records'])
 for b in c['bank_rules']:
  assert selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),base=int(b['slot'],16)-int(b['index'],16)*8,bias=int(b['bias'],16))==b
 counts['bank_inputs_checked']=512
 for proof in q['proofs']:
  for filekey,hashkey in [('original_file','original_sha256'),('file','sha256')]:
   path=ROOT/proof[filekey];assert sha(path)==proof[hashkey];s=z3.Solver();s.set(timeout=30000);s.from_file(str(path));assert str(s.check())=='unsat',proof['name']
 assert len(q['nonempty_premise_witnesses'])==3 and all(v['premise_result']=='sat'for v in q['nonempty_premise_witnesses']);counts['nonempty_premise_witnesses']=3
 counts['source_proof_pairs_unsat']=len(q['proofs']);counts['SMT_queries_unsat']=2*len(q['proofs']);assert counts['source_proof_pairs_unsat']==16
 section=c['text_section'];off=int(section['header_file_offset'],16);raw=IMAGE.data[off:off+80];assert raw.hex()==section['header_bytes_hex'];name,segment=struct.unpack_from('<16s16s',raw);addr,size=struct.unpack_from('<QQ',raw,32);assert (name.rstrip(b'\0'),segment.rstrip(b'\0'),addr,size)==(b'__text',b'__TEXT',0x100001058,0xe297a8)
 assert int.from_bytes(IMAGE.read(0x1010b70d8,8),'little')==KD and int.from_bytes(IMAGE.read(0x1010b83a0,8),'little')==KOFF
 expected=c['current_image_window'];assert expected['offset_mask']=='0xe21000'and expected['window_length_bytes']==32768 and expected['floor_log2']==23 and expected['span_delta']=='0x7f8000'and expected['selected_Q_bits']==[12,17,21,22,23]and len(expected['possible_offsets_hex'])==32
 old=read('daemon_buffer_consumer_profiles.json');rows=[];observed_offsets=set()
 def event(case,pc,kind='write'):
  hits=[e for e in case['consumer_events']if e['pc']==hex(pc)and e['kind']==kind];assert len(hits)==1;return hits[0]
 for case in old['cases']:
  P=int.from_bytes(bytes.fromhex(event(case,0x10031ed5c)['after_hex']),'little');S=int.from_bytes(bytes.fromhex(event(case,0x1003875b8)['after_hex']),'little');qe=event(case,0x1002475bc);Q=int.from_bytes(bytes.fromhex(qe['after_hex']),'little');assert S==size and P==addr and qe['address']==hex(int(case['boundary']['SP'],16)+0x358)and qe['size_bytes']==8
  assert event(case,0x10031ed48,'read')['address']=='0x100000080'and event(case,0x10031ed50,'read')['address']=='0x1000000d0'and event(case,0x10031ed60,'read')['address']=='0x1000000d8'
  d=compact(S,P,Q);assert d['containment_applicable']and d['containment']and d['offset']==(Q&0xe21000)
  for pc,address,field in [(0x1003f1850,0x1010b70d8,'encoded_span'),(0x1003f18f8,0x1010b83a0,'encoded_offset'),(0x1003f19dc,0x1010ca2a8,'encoded_address'),(0x1003f19f8,0x1010c6800,'encoded_mask')]:
   e=event(case,pc);assert int(e['address'],16)==address and e['size_bytes']==8 and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==d[field]
  for a in range(0x1003f1390,0x1003f19fc,4):assert case['source_pool'][hex(a)]['bytes_hex']==IMAGE.read(a,4).hex()and case['source_PC_counts'][hex(a)]==1
  observed_offsets.add(d['offset']);rows.append({'prior_case_index':case['prior_case_index'],'values_name':case['values']['name'],'P':hex(P),'S':hex(S),'Q':hex(Q),'decoded':{k:hex(v)if isinstance(v,int)and not isinstance(v,bool)and k!='floor_log2'else v for k,v in d.items()}})
 counts['sealed_full_continuations_checked']=len(rows);counts['source_window_block_visits_checked']=411*len(rows);counts['sealed_publication_values_checked']=4*len(rows);counts['distinct_observed_offsets']=len(observed_offsets)
 observations={r['pc']:r for r in p['observations']};assert p['full_continuation_matches_sealed_case']and len(observations)==22
 assert int(observations['0x1003f1390']['registers31'][9],16)==0x8a9b8560 and int(observations['0x1003f176c']['registers31'][14],16)==23 and int(observations['0x1003f17b0']['registers31'][14],16)==0x7f8000
 counts['full_source_observation_checkpoints']=len(observations);current=next(r for r in rows if r['prior_case_index']==17 and r['values_name']=='reference');assert int(observations['0x1002475bc']['registers31'][8],16)==int(current['Q'],16)
 assert replays['all_checks_pass'];pairs={};valid=0;invalid=0
 for row in replays['cases']:
  inp=row['inputs'];d=compact(*(int(inp[k],16)for k in ['S','P','Q']));normalized={k:hex(v)if isinstance(v,int)and not isinstance(v,bool)and k!='floor_log2'else v for k,v in d.items()};assert normalized==row['expected']and row['source_visits']==411 and row['all_checks_pass']and len(row['writes'])==4
  if d['containment_applicable']:valid+=1;assert d['containment']
  else:invalid+=1
  if row['class']=='current_image_offset':pairs.setdefault(d['offset'],[]).append(row['writes'])
 assert len(pairs)==32 and all(len(v)==2 and v[0]==v[1]for v in pairs.values())
 assert set(replays['used_fixups'])=={r['address']for r in c['source_fixups']['records']}
 counts.update(replays['verified_counts']);counts['containment_applicable_cases']=valid;counts['outside_containment_domain_cases']=invalid
 fresh=Isolated().one(int(current['S'],16),int(current['P'],16),int(current['Q'],16),0x1234);assert fresh['all_checks_pass'];counts['fresh_isolated_A64_cases']=1
 deps=['daemon_global_state_contracts.json','daemon_global_state_observations.json','daemon_global_state_proofs.json','daemon_global_state_replays.json','daemon_buffer_consumer_profiles.json','daemon_global_state_lift.py','replay_daemon_global_state.py','daemon_global_state_ida_retry.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':counts,'source_lift_counts':q['source_lift_counts'],'sealed_decoded_interfaces':rows,'distinct_observed_offsets_hex':[hex(x)for x in sorted(observed_offsets)],'live_IDB_verification_available':False,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_global_state_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':counts}),flush=True)
if __name__=='__main__':main()
