#!/usr/bin/env python3
"""Independent caller/root-premise/record/source/proof and composed checks.
O(B+C*(V+E)+K*(V+E+JF)+text+I+256R) time,O(largest JSON+K*(V+E)) space,
plus30 s/query. Frozen epoch/status-record auditors reused; no native target.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,FIXUPS,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from recover_daemon_iokit_callers import census
from daemon_iokit_callers_symbolic import queries
from probe_daemon_iokit_callers import Caller,cases,SITES,P
from validate_daemon_iokit_sync import audit
from validate_daemon_iokit_errors import records
FRESH={0,2,8,16,17,19,25,33,34,35,37,39}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def record_epochs(r,counts):
 data={};prov={};events={};caps={}
 def put(a,b,p):
  for at,v in enumerate(b,a):data[at]=v;prov[at]=p
 for e in r['initial_private_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),3)
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append((int(e['address'],16),bytes.fromhex(e['after_hex']),1))
 for m in r['API_models']+r['IOKit_models']+r['prefix_models']+r['sync_models']:
  for e in m['modeled_writes']:events.setdefault(m['source_visit_index'],[]).append((int(e['address'],16),bytes.fromhex(e['bytes_hex']),2))
 for key in ['init_call','init_return']:caps.setdefault(r[key]['source_visit_index'],[]).append(r[key]['record'])
 caps.setdefault(r['init_entry']['source_visit_index'],[]).append(r['init_input_before'])
 for ix,v in enumerate(r['source_visits']):
  for s in caps.get(ix,[]):
   a=int(s['address'],16);n=s['size_bytes'];assert bytes(data.get(j,0xa5)for j in range(a,a+n)).hex()==s['bytes_hex']and bytes(int(j in data)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex'];counts['caller_record_capture_epochs_checked']+=1
  for a,b,p in events.get(ix,[]):
   if P<=a<a+len(b)<=P+0x10000:put(a,b,p)
def main():
 c,p,proof,sync=map(read,['daemon_iokit_callers_contracts.json','daemon_iokit_callers_profiles.json','daemon_iokit_callers_proofs.json','daemon_iokit_sync_contracts.json']);counts=Counter();matrix=Counter();replays=[]
 for obj,name in [(c,'recover_daemon_iokit_callers.py'),(p,'probe_daemon_iokit_callers.py'),(proof,'prove_daemon_iokit_callers.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert census()==c['census'];counts['exact_literal_candidates']=len(c['census']['candidates'])
 for s in c['spans']+c['census']['candidates']:assert native(s['label'],int(s['start'],16),int(s['end'],16))=={k:s[k]for k in ['label','start','end','bytes_hex','sha256','instructions']};counts['original_bounded_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[k]==b[k]for k in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(e['address'],16)for e in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 collisions=[{'address':hex(a),'fixup':r}for a,r in FIXUPS.items()if 'div=0x0A74 'in r['line']];assert collisions==c['discriminator_collision_slots']and len(collisions)==4;counts['same_discriminator_distinct_target_slots']=4
 for r in c['caller_continuation_routes']:
  a=TABLE+int(r['index'],16)*8;assert hex(a)==r['slot']and FIXUPS[a]==r['fixup']and IMAGE.read(a,8).hex()==r['original_word_hex']and hex(FIXUPS[a]['target'])==r['target'];counts['caller_continuation_routes_verified']+=1
 live=read('daemon_iokit_callers_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);counts['live_IDB_source_rows_matched']+=1;counts['live_IDB_instruction_bytes_matched']+=len(bytes.fromhex(i['bytes']))
 xrefs=read('daemon_iokit_callers_live_xrefs.json');assert xrefs['idb_node']=='6b117c693e3b'and not xrefs['idb_mutated']and '0x1010a0520'in xrefs['tool_text']and '0x1004601d0'in xrefs['tool_text'];counts['live_xref_inputs_preserved']=4
 qs,lifts=queries(c,sync);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs']);done=set()
 for (name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat'and set(row['depends_on'])<=done;done.add(name);op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 prior=read('daemon_iokit_errors_profiles.json')['composed_cases'];prior_sync=read('daemon_iokit_sync_profiles.json')['cases'];cs=list(cases());assert len(cs)==len(p['cases'])==40
 for j,(case,r)in enumerate(zip(cs,p['cases'])):
  assert case==r['input'];audit(r,counts);records(r,counts);record_epochs(r,counts);counts['composed_cases_audited']+=1;counts['source_visits']+=len(r['source_visits']);s=SITES[case['caller']];call,entry,ret=r['init_call'],r['init_entry'],r['init_return'];R=int(r['caller_record']['address'],16)
  assert not r['native_target_executed']and not r['full_goal_complete']and call['target']=='0x1004601d0'and call['modifier16']=='0xa74'and call['pc']==hex(s['call'])and int(call['registers31'][0],16)==R and R==int(r['caller_FP'],16)-0x98
  assert call['record']==r['init_input_before']and call['record']['known_mask_hex']=='01'*4+'00'*4 and call['record']['provenance_hex']=='01'*4+'00'*4;counts['unknown_caller_result_cells_preserved_before_init']+=1
  raw=bytes.fromhex(r['caller_record']['bytes_hex']);initial=int.from_bytes(raw[:4],'little');key=(((R&0xffffffff)^0x966e5812)*0x592e2f77)&0xffffffff;assert(initial-key)&0xffffffff==0x5784 and r['caller_record']['known_mask_hex']=='01'*8 and r['caller_record']['provenance_hex']=='01'*8
  assert ret['SP']==call['SP']==r['caller_SP']and ret['registers31'][19:30]==call['registers31'][19:30]and ret['record']==r['caller_record'];counts['callee_integer_ABI_returns']+=1
  old=prior[case['prior_error_index']]if 'prior_error_index'in case else prior_sync[case['prior_sync_direct_index']];at,z=entry['source_visit_index'],ret['source_visit_index'];assert r['source_visits'][at:z]==[{**v,'source_visit_index':v['source_visit_index']+at}for v in old['source_visits']];assert[{**e,'source_visit_index':e['source_visit_index']-at}for e in r['source_edges']if at<=e['source_visit_index']<z]==old['source_edges'];counts['embedded_original_callee_sequences']+=1
  assert r['outer_result_word']==old['outer_result_word']and r['state_cache']==old['state_cache']
  for group,argc in [('prefix_models',{'main_port':2,'matching_dictionary':1}),('IOKit_models',{'matching_services':3,'iterator_next':1,'service_open':4,'service_release':1,'iterator_release':1})]:
   assert len(r[group])==len(old[group])
   for a,b in zip(r[group],old[group]):assert a['pc']==b['pc']and a['binding']==b['binding']and a['registers8'][:argc[a['name']]]==b['registers8'][:argc[b['name']]]and a['modeled_writes']==b['modeled_writes']and a.get('returned_value',a.get('returned_u32'))==b.get('returned_value',b.get('returned_u32'))
  assert len(r['API_models'])==len(old['API_models'])
  for a,b in zip(r['API_models'],old['API_models']):assert a['registers8'][:6]==b['registers8'][:6]and a['modeled_writes']==b['modeled_writes']and a['status32_fixture']==b['status32_fixture']
  result=int.from_bytes(raw[4:],'little');ok=result==0x8b3dc651;expected={'313':(0x10040dba0,0x100624b74),'AF':(0x100b12828,0x100b01974)}[case['caller']][0 if ok else 1];assert r['boundary']['pc']==hex(expected)and ret['record']['bytes_hex'][8:]==r['outer_result_word']['bytes_hex'];matrix[case['caller']+('_zero_result'if ok else'_nonzero_result')]+=1
  if 'prior_sync_direct_index'in case:assert ok and any(m['status32_fixture']!='0x0'for m in r['API_models']);counts['metadata_error_cases_retaining_zero_result_gate']+=1
  if j in FRESH:
   f=Caller(case);fresh=f.run();del f;assert fresh==r;counts['fresh_replayed_cases']+=1;replays.append({'index':j,'profile_sha256':hashlib.sha256(json.dumps(fresh,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
  if j%16==0:print(json.dumps({'cases_audited':j+1}),flush=True)
 deps={n:sha(ROOT/n)for n in ['daemon_iokit_callers_contracts.json','daemon_iokit_callers_profiles.json','daemon_iokit_callers_proofs.json','daemon_iokit_callers_symbolic.py','probe_daemon_iokit_callers.py','daemon_iokit_errors_profiles.json','daemon_iokit_sync_profiles.json','validate_daemon_iokit_sync.py','validate_daemon_iokit_errors.py']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'case_matrix':dict(matrix),'fresh_replays':replays,'all_checks_pass':True,'upstream_context_producers_proved':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_callers_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'case_matrix':dict(matrix)}),flush=True)
if __name__=='__main__':main()
