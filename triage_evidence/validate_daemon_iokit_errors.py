#!/usr/bin/env python3
"""Fresh error/status/source/proof checks with independent byte/record epochs.
O(B+C*(V+E)+K*(V+E+JF)+I+256R) time,O(largest JSON+K*(V+E)) space,
plus30 s/query. Frozen full epoch auditor reused; new record epochs audited
separately. No native target, IOKit, Mach, pthread or IDB mutation.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from daemon_iokit_errors_symbolic import queries
from probe_daemon_iokit_errors import Errors,Isolated,composed_cases,isolated_cases,STATUS,P
from validate_daemon_iokit_sync import audit
CFRESH={0,1,2,3,14,46,68,91,92,93,120,135,150,180,220,223}
IFRESH={s&0xffffffff for s in [0,1,99,100,-49999,-49998,-42001,-42000]}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def normalized(s):
 t=s if s<0x80000000 else s-(1<<32)
 return -42600-t if 1<=t<=99 else t if -49998<=t<=-42001 else -42600
def word(s):return (normalized(s)&0xffffffff)^0x8b3dc651
def records(r,counts):
 data={};prov={};events={};captures={}
 def put(a,b,p):
  for at,v in enumerate(b,a):data[at]=v;prov[at]=p
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert all(j in data for j in range(a,a+n))and bytes(data[j]for j in range(a,a+n)).hex()==s['bytes_hex']and s['known_mask_hex']=='01'*n and bytes(prov[j]for j in range(a,a+n)).hex()==s['provenance_hex'];counts['status_record_snapshots_checked']+=1
 for e in r['initial_private_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),3)
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append((int(e['address'],16),bytes.fromhex(e['after_hex']),1))
 for m in r['API_models']+r['IOKit_models']+r['prefix_models']+r['sync_models']:
  for e in m['modeled_writes']:events.setdefault(m['source_visit_index'],[]).append((int(e['address'],16),bytes.fromhex(e['bytes_hex']),2))
 for e in r['status_calls']:captures.setdefault(e['source_visit_index'],[]).append(e['record'])
 for e in r['status_returns']:captures.setdefault(e['source_visit_index'],[]).append(e['result'])
 for ix,v in enumerate(r['source_visits']):
  for s in captures.get(ix,[]):snapshot(s)
  for a,b,p in events.get(ix,[]):
   if P<=a<a+len(b)<=P+0x10000:put(a,b,p)
 if r['isolated']:snapshot(r['status_input_record']);snapshot(r['status_output_word'])
def main():
 c,p,proof=map(read,['daemon_iokit_errors_contracts.json','daemon_iokit_errors_profiles.json','daemon_iokit_errors_proofs.json']);counts=Counter();matrix=Counter();replays=[]
 for obj,name in [(c,'recover_daemon_iokit_errors.py'),(p,'probe_daemon_iokit_errors.py'),(proof,'prove_daemon_iokit_errors.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[k]==b[k]for k in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(e['address'],16)for e in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents'];counts['retained_prior_sources_verified']+=1
 live=read('daemon_iokit_errors_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);counts['live_IDB_source_rows_matched']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs'])
 for (name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 prior=read('daemon_iokit_sync_profiles.json')['cases'];inputs=list(composed_cases());iso=list(isolated_cases());assert len(inputs)==len(p['composed_cases'])==224 and len(iso)==len(p['isolated_cases'])==748
 for group,cs,cls in [('composed',inputs,Errors),('isolated',iso,Isolated)]:
  for j,(case,r)in enumerate(zip(cs,p[group+'_cases'])):
   assert case==r['input'];audit(r,counts);records(r,counts);counts[group+'_cases_audited']+=1;counts[group+'_source_visits']+=len(r['source_visits']);assert not r['native_target_executed']and not r['full_goal_complete']
   fresh=j in CFRESH if group=='composed'else case['isolated_status']in IFRESH
   if fresh:
    f=cls(case);now=f.run();del f;assert now==r;counts[group+'_fresh_replays']+=1;replays.append({'group':group,'index':j,'profile_sha256':hashlib.sha256(json.dumps(now,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
   if group=='isolated':
    s=case['isolated_status'];got=struct.unpack('<I',bytes.fromhex(r['status_output_word']['bytes_hex']))[0];assert got==word(s)and r['status_output_word']['provenance_hex']=='01'*4 and not r['API_models']and not r['IOKit_models']and not r['prefix_models']and not r['sync_models'];assert r['boundary']['SP']==r['status_entry_SP']and r['boundary']['registers31'][19:30]==r['status_entry_registers31'][19:30];matrix['isolated_positive'if 1<=s<=99 else'isolated_passthrough'if normalized(s)==(s if s<0x80000000 else s-(1<<32))else'isolated_default']+=1
    if s==0:counts['isolated_zero_status_not_native_reachable_claims']+=1
   else:
    assert r['outer_returned']and not r['callback_pending']and r['boundary']['SP']==r['entry_SP']and r['boundary']['registers31'][19:30]==r['entry_registers31'][19:30];assert r['outer_input_record']['bytes_hex'][8:]==r['outer_result_word']['bytes_hex']and r['outer_input_record']['provenance_hex']=='03'*4+'01'*4;counts['outer_result_publications_and_ABI_returns']+=1
    if 'prior_sync_index'in case:
     old=prior[case['prior_sync_index']];n=len(old['source_visits'])
     for field in ['source_visits','source_reads','source_writes','source_edges']:assert [e for e in r[field]if e['source_visit_index']<n]==old[field],field
     for field in ['API_models','IOKit_models','prefix_models','sync_models']:assert [e for e in r[field]if e['source_visit_index']<n]==old[field],field
     counts['prior_source_and_epoch_prefixes_retained']+=1
     if not old['outer_returned']:counts['former_error_frontiers_closed']+=1
     else:assert not r['status_calls']and r['outer_result_word']==old['outer_result_word'];counts['prior_return_controls_retained']+=1
    assert len(r['status_calls'])==len(r['status_returns'])<=1
    for call,ret in zip(r['status_calls'],r['status_returns']):
     origin=call['origin'];s=case['prefix']['main_status']if origin=='main_port'else case['IO']['matching_status'if origin=='matching_services'else'open_status'];assert s!=0 and call['target']==hex(STATUS)and ret['SP']==call['caller_SP'];record=call['record'];raw=bytes.fromhex(record['bytes_hex']);dest,value,control=struct.unpack('<QII',raw);R=int(record['address'],16);k=(((R&0xffffffff)^0x8515cfbd)*0xc7f6dca7)&0xffffffff;assert record['provenance_hex']=='01'*16 and dest==int(r['frame_SP'],16)+0x60 and(value+k)&0xffffffff==s^0x8b3dc651 and(control-k)&0xffffffff==0x952a;assert ret['result']['bytes_hex']==r['outer_result_word']['bytes_hex']==struct.pack('<I',word(s)).hex();matrix[origin+'_error_returns']+=1;counts['source_status_adapter_returns']+=1
     names=[m['name']for m in r['IOKit_models']];assert names==([]if origin=='main_port'else['matching_services']if origin=='matching_services'else['matching_services','iterator_next','service_open','service_release','iterator_release']);assert not r['API_models'];counts['error_path_release_sequences_checked']+=1
   if j%64==0:print(json.dumps({'group':group,'cases_audited':j+1}),flush=True)
 deps={n:sha(ROOT/n)for n in ['probe_daemon_iokit_errors.py','daemon_iokit_errors_contracts.json','daemon_iokit_errors_profiles.json','daemon_iokit_errors_proofs.json','daemon_iokit_errors_symbolic.py','validate_daemon_iokit_sync.py','daemon_iokit_sync_profiles.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'case_matrix':dict(matrix),'fresh_replays':replays,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_errors_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'case_matrix':dict(matrix)}),flush=True)
if __name__=='__main__':main()
