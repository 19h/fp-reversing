#!/usr/bin/env python3
"""Independent source/SMT/journal/compact-state checks and one fresh A64 replay.
O(artifact bytes+cases*130*624+solver queries) time, O(largest trace) space.
No target import, native PAC or live IDB change executes.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,verify_original_fixups,selected
from replay_daemon_prng_output import twist,temper
from replay_daemon_seed_material import compact
from probe_daemon_buffer_consumer import Consumer,INPUTS,unpack

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def check(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and not q['full_goal_complete']
 for name,h in q.get('dependencies',{}).items():assert sha(ROOT/name)==h,(n,name)
 if 'source_sha256'in q:assert sha(SOURCE)==q['source_sha256']
 return q
def decode_call(call):
 R=int(call['X0'],16);before=call['packet_before'];after=call['packet_after'];b=bytes.fromhex(before['physical_bytes_hex']);a=bytes.fromhex(after['physical_bytes_hex']);known=bytes.fromhex(before['known_mask_hex']);u=lambda off,n:int.from_bytes(b[off:off+n],'little');m32=(1<<32)-1;m64=(1<<64)-1
 assert call['returned']and before['unknown_bits_are_not_definitions']and after['unknown_bits_are_not_definitions']
 if call['target']=='0x10041a5e0':
  fields=[(0,4),(8,8),(20,4),(32,8),(40,4),(44,4)];K=((R^0x4de3a292f9d49974)*0xda51a827)&m64;k=K&m32;d={'mode':(u(0,4)-k)&m32,'A':(u(8,8)-K)&m64,'B':u(32,8)^K,'mask':(u(20,4)-k)&m32,'true':u(44,4)^k,'false':(u(40,4)+k)&m32};choose=(d['A']>d['B'])if d['mode']&1 else d['A']==d['B'];off=16
 elif call['target']=='0x100427514':
  fields=[(0,8),(8,4),(16,4),(20,4),(24,8),(32,4)];K=((R^0x0179fa0fe732d262)*0xba209ef7)&m64;k=K&m32;d={'mode':u(8,4)^k,'A':(u(0,8)+K)&m64,'B':u(24,8)^K,'mask':u(32,4)^k,'true':u(16,4)^k,'false':(u(20,4)+k)&m32};signed=lambda v:v-(1<<64)if v>>63 else v;choose=(signed(d['A'])<signed(d['B']))if d['mode']&1 else d['A']<d['B'];off=12
 else:raise AssertionError(call['target'])
 assert all(all(known[at:at+n])for at,n in fields);out=int.from_bytes(a[off:off+4],'little');assert out==(d['mask']^(d['true']if choose else d['false']));assert all(b[j]==a[j]for j in range(64)if not off<=j<off+4)
 return {'pc':call['pc'],'target':call['target'],**{k:hex(v)for k,v in d.items()},'output':hex(out),'choose':choose}

def main():
 c=check('daemon_buffer_consumer_contracts.json','recover_daemon_buffer_consumer.py');p=check('daemon_buffer_consumer_profiles.json','probe_daemon_buffer_consumer.py');q=check('daemon_buffer_consumer_proofs.json','prove_daemon_buffer_consumer.py');isolated=check('daemon_buffer_normalization_replays.json','replay_daemon_buffer_normalization.py')
 counts=Counter();assert len(c['spans'])==13
 for span in c['spans']:
  a=int(span['start'],16);raw=bytes.fromhex(span['bytes_hex']);assert IMAGE.read(a,len(raw))==raw and hashlib.sha256(raw).hexdigest()==span['sha256'];counts['original_source_spans']+=1
 assert verify_original_fixups([int(r['address'],16)for r in c['source_fixups']['records']])==c['source_fixups'];counts['original_fixups_verified']=len(c['source_fixups']['records'])
 for b in c['bank_rules']:
  actual=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),base=int(b['slot'],16)-int(b['index'],16)*8,bias=int(b['bias'],16));assert actual==b;counts['bank_inputs_checked']+=256
 for proof in q['proofs']:
  for filekey,hashkey in [('original_file','original_sha256'),('file','sha256')]:
   path=ROOT/proof[filekey];assert sha(path)==proof[hashkey];solver=z3.Solver();solver.set(timeout=30000);solver.from_file(str(path));assert str(solver.check())=='unsat',proof['name'];counts['SMT_queries_unsat']+=1
  counts['source_proof_pairs_unsat']+=1
 for diagnostic in q['solver_diagnostics']:assert sha(ROOT/diagnostic['retained_query_file'])==diagnostic['retained_query_sha256']and diagnostic['result']=='unknown'
 cases=p['cases'];assert len(cases)==8 and {(v['prior_case_index'],v['values']['name'])for v in cases}=={(i,n)for i in [0,1,16,17]for n in ['zero','reference']};decoded=[];global_writes=[];all_pool={}
 for case in cases:
  assert case['complete_words_checked']==128 and len(case['new_word_certificates'])==126 and case['new_API_summaries']==0
  state,_=compact(case['values'],int(case['prefix_certificate']['cursor_source_pointer'],16));buffer=bytearray.fromhex(case['initial_unmasked_buffer_bytes_hex']);certificates=case['prefix_checkpoints']+case['new_word_certificates'];assert len(certificates)==128
  for j,certificate in enumerate(certificates):
   state=twist(state);state_raw=b''.join(v.to_bytes(4,'little')for v in state);assert hashlib.sha256(state_raw).hexdigest()==certificate['state_sha256'];word=temper(state[j]);old=int.from_bytes(buffer[4*j:4*j+4],'little');buffer[4*j:4*j+4]=(old^word).to_bytes(4,'little')
   if j>=2:assert certificate['word_index']==j and int(certificate['old_u32'],16)==old and int(certificate['tempered_u32'],16)==word and hashlib.sha256(buffer).hexdigest()==certificate['buffer_sha256']
   counts['complete_twists_checked']+=1;counts['mask_words_checked']+=1
  assert buffer.hex()==case['exit_snapshot']['buffer_bytes_hex']and case['exit_snapshot']['global_index']==case['exit_snapshot']['global_counter']==128
  D=int(case['exit_snapshot']['buffer_address'],16);events=case['consumer_events'];normal=[e for e in events if e['kind']=='write'and 0x100315488<=int(e['pc'],16)<0x100315648];assert len(normal)==16
  immutable=bytes(buffer)
  for j,e in enumerate(normal):
   offset=j*16;old=int.from_bytes(buffer[offset:offset+4],'little');lookup=8*((old>>1)&31);table=int.from_bytes(buffer[lookup:lookup+4],'little');expected=old|((~table<<16)&0xffffffff);assert int(e['address'],16)==D+offset and e['before_hex']==buffer[offset:offset+4].hex()and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==expected
   assert expected==(old|((~int.from_bytes(immutable[lookup:lookup+4],'little')<<16)&0xffffffff));buffer[offset:offset+4]=expected.to_bytes(4,'little');counts['normalization_word_updates_checked']+=1
  assert buffer.hex()==case['final_buffer_bytes_hex']
  for address,pc,value,n in [(0x1010c8268,0x100315478,D,8),(0x1010c67d4,0x100315484,255,4)]:
   rows=[e for e in events if e['kind']=='write'and int(e['address'],16)==address];assert len(rows)==1 and int(rows[0]['pc'],16)==pc and rows[0]['size_bytes']==n and int.from_bytes(bytes.fromhex(rows[0]['after_hex']),'little')==value
  # Independently reconstruct the two further 624-word state passes from the
  # retained post-exit byte journal. Their result destinations remain separate.
  writes=[e for e in events if e['kind']=='write'and 0x1010c784c<=int(e['address'],16)<0x1010c784c+2496];assert len(writes)==1248
  for phase in range(2):
   expected=twist(state);actual=state.copy()
   for j,e in enumerate(writes[phase*624:(phase+1)*624]):
    assert int(e['address'],16)==0x1010c784c+4*j and e['size_bytes']==4 and int.from_bytes(bytes.fromhex(e['before_hex']),'little')==actual[j];actual[j]=int.from_bytes(bytes.fromhex(e['after_hex']),'little')
   assert actual==expected;state=actual;counts['post_exit_twists_checked']+=1
  for address in [0x1010c67dc,0x1010c8258]:
   rows=[e for e in events if e['kind']=='write'and int(e['address'],16)==address];assert [int.from_bytes(bytes.fromhex(e['after_hex']),'little')for e in rows]==[129,130]
  calls=[decode_call(call)for call in case['consumer_calls']];assert [(v['pc'],v['output'])for v in calls]==[('0x100315734','0x16f4'),('0x100349b3c','0x169b'),('0x1003c23a0','0x16f0'),('0x1003cbe04','0x1783')];decoded.append({'prior_case_index':case['prior_case_index'],'values_name':case['values']['name'],'calls':calls});counts['decoded_comparison_calls']+=len(calls)
  for address,row in case['source_pool'].items():
   assert IMAGE.read(int(address,16),4).hex()==row['bytes_hex'];all_pool[address]=row
  assert sum(case['source_PC_counts'].values())==case['dynamic_counts']['source_visits']
  for address,n in case['source_PC_counts'].items():assert address in case['source_pool'];counts['original_dynamic_opcode_bytes_checked']+=4*n
  assert case['boundary']['kind']=='unknown_or_unowned_memory_read'and case['boundary']['pc']=='0x1003ecb98'and case['boundary']['address']==hex(int(case['boundary']['SP'],16)+0x4a0)and case['boundary']['instruction_effects_not_used'];counts['unknown_read_frontiers_retained']+=1
  global_writes.append({'prior_case_index':case['prior_case_index'],'values_name':case['values']['name'],'writes':[e for e in events if e['kind']=='write'and int(e['address'],16)<0x6400000000 and not 0x1010c784c<=int(e['address'],16)<0x1010c784c+2496]})
 counts['full_prefix_A64_runs']=8;counts['new_symbolic_API_models']=0;counts['source_pool_unique_instructions']=len(all_pool);counts['live_IDB_rows_matched']=c['live_IDB_rows_matched'];counts['unique_live_IDB_rows_matched']=c['unique_live_IDB_rows_matched']
 assert isolated['all_checks_pass']and isolated['verified_counts']['cases']==1096
 pairs=set()
 for row in isolated['cases']:
  assert row['all_checks_pass']and row['idempotent']and len(row['passes'])==2 and row['passes'][0]['output_sha256']==row['passes'][1]['output_sha256']
  for phase in row['passes']:assert phase['source_visits']==112 and phase['read_events']==32 and phase['write_events']==16
  if row['forced_destination_selector']:
   forced=row['forced_destination_selector'];j=forced['destination_index'];k=forced['selector'];assert row['passes'][0]['selected_table_words'][j]=={'destination_word':4*j,'table_word':2*k};pairs.add((row['alignment_offset_bytes'],j,k))
 assert len(pairs)==1024;counts['isolated_A64_cases']=1096;counts['isolated_A64_passes']=2192;counts['forced_destination_selector_pairs']=len(pairs)
 # Fresh complete prefix plus continuation, using independent seed/state and
 # journal checks above rather than assigning backing bytes as source values.
 names=['daemon_arena_storage_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_seed_material_profiles.json','daemon_prng_output_profiles.json'];base,prior,entropy,material,output=[read(n)for n in names];index=17;pick=lambda data:unpack(next(v for v in data['cases']if v['prior_case_index']==index));cfg=next(v for v in INPUTS if v['name']=='reference');fresh=Consumer(base['cases'][index]['input'],pick(prior),pick(entropy),pick(material),pick(output),cfg,3).run_consumer();fresh['prior_case_index']=index;reference=next(v for v in cases if v['prior_case_index']==index and v['values']['name']=='reference');assert fresh==reference;counts['fresh_full_A64_runs']=1
 deps=['daemon_buffer_consumer_contracts.json','daemon_buffer_consumer_profiles.json','daemon_buffer_consumer_proofs.json','daemon_buffer_normalization_replays.json','probe_daemon_buffer_consumer.py','replay_daemon_prng_output.py','replay_daemon_seed_material.py','prove_daemon_buffer_consumer.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'dynamic_A64_totals':{k:sum(v['dynamic_counts'][k]for v in cases)for k in cases[0]['dynamic_counts']},'prefix_A64_totals':{k:sum(v['prefix_verified_counts'][k]for v in cases)for k in cases[0]['prefix_verified_counts']},'decoded_calls':decoded,'post_exit_global_writes':global_writes,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_buffer_consumer_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
