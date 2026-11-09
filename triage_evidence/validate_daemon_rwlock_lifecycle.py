#!/usr/bin/env python3
"""Independent creator/heap/cell/record/status/state and primary-source checks.
O(B+C*(V+E)+K*(V+E+JF)+text+I+256R+SDK bytes) time,
O(largest JSON+K*(V+E)) space plus30 s/query. No native target or SDK code runs.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_rwlock_lifecycle import census,sdk_check
from resolve_kernel_collection_interfaces import macho
from daemon_rwlock_lifecycle_symbolic import queries
from probe_daemon_rwlock_lifecycle import Lifecycle,cases,PRIMARY,SECOND,STATE,P,HELPER
from validate_daemon_iokit_sync import audit
FRESH={0,8,48,56,96,100,160,200,240,280,288,289}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def status(cfg):
 if not cfg['malloc_nonnull']:return 0x74c29d85
 return {0:0x8b3dc651,12:0x74c29d85,16:0x74c29d82}.get(cfg['init_status'],0x74c29d83)
def extra(r,counts):
 data={};prov={};events={};caps={}
 def put(a,b,p):
  for at,v in enumerate(b,a):data[at]=v;prov[at]=p
 for e in r['initial_private_fixtures']+r['initial_image_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),3)
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append((int(e['address'],16),bytes.fromhex(e['after_hex']),1))
 for e in r['creator_calls']+r['creator_returns']:caps.setdefault(e['source_visit_index'],[]).append(e['record'])
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert bytes(data.get(j,0xa5)for j in range(a,a+n)).hex()==s['bytes_hex']and bytes(int(j in data)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex'];counts['creator_record_and_heap_snapshots_checked']+=1
 for ix,v in enumerate(r['source_visits']):
  for s in caps.get(ix,[]):snapshot(s)
  for a,b,p in events.get(ix,[]):put(a,b,p)
 for s in r['heap_snapshots']+[r['creator_record']]:snapshot(s)
 for a,key in [(PRIMARY,'primary_value'),(SECOND,'secondary_value')]:assert hex(int.from_bytes(bytes(data[a+j]for j in range(8)),'little'))==r[key];counts['cell_publication_epochs_checked']+=1
def main():
 c,p,proof=map(read,['daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_profiles.json','daemon_rwlock_lifecycle_proofs.json']);counts=Counter();matrix=Counter();replays=[]
 for obj,name in [(c,'recover_daemon_rwlock_lifecycle.py'),(p,'probe_daemon_rwlock_lifecycle.py'),(proof,'prove_daemon_rwlock_lifecycle.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 assert census()==c['census'];counts['primary_bias_literal_matches']=len(c['census']['MOVK64_lsl16_high16_matches']['0x858b']);counts['fallback_high16_literal_matches']=len(c['census']['MOVK64_lsl16_high16_matches']['0xc81b']);assert not c['census']['ADRP_primary_page_matches']
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[k]==b[k]for k in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(e['address'],16)for e in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for b in c['lifecycle_bindings']:assert binding(int(b['slot'],16))==b;counts['original_import_bindings_checked']+=1
 m=macho(IMAGE.data,0,'daemon');assert all(s in m['sections']and s['flags']&255==1 for s in c['cell_sections']);counts['zerofill_cell_sections_checked']=2
 assert sdk_check()==c['SDK'];counts['SDK_compile_exit_zero']=1;counts['SDK_static_initializer_bytes_equal']=200
 live=read('daemon_rwlock_lifecycle_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);counts['live_IDB_source_rows_matched']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs'])
 for (name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 cs=list(cases());assert len(cs)==len(p['cases'])==290
 for j,(case,r)in enumerate(zip(cs,p['cases'])):
  assert case==r['input'];audit(r,counts);extra(r,counts);counts['cases_audited']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['native_target_executed']and not r['full_goal_complete'];raw=bytes.fromhex(r['creator_record']['bytes_hex']);R=int(r['creator_record']['address'],16);k=(((R&0xffffffff)^0xdc40790b)*0x5973a279)&0xffffffff;assert(int.from_bytes(raw[:4],'little')+k)&0xffffffff==0xaed7 and r['creator_record']['known_mask_hex'][8:16]=='00'*4
  if case['isolated']:
   assert not r['lifecycle_models']and not r['creator_calls']and raw[16:20]==struct.pack('<I',0x74c29d88)and r['boundary']['SP']==r['caller_SP']and r['boundary']['registers31'][19:30]==r['entry_registers31'][19:30];counts['null_cell_creator_returns']+=1
  else:
   counts['paired_caller_cases']+=1;assert len(r['creator_calls'])==len(r['creator_returns'])==2
   for step,(call,ret,addr)in enumerate(zip(r['creator_calls'],r['creator_returns'],[PRIMARY,SECOND])):
    assert call['SP']==ret['SP']==r['caller_SP']and int.from_bytes(bytes.fromhex(call['record']['bytes_hex'])[8:16],'little')==addr;got=int.from_bytes(bytes.fromhex(ret['record']['bytes_hex'])[16:20],'little');assert got==status(case['steps'][step]);counts['creator_returns_checked']+=1
    loads=[e for e in r['source_reads']if e['source_visit_index']==call['source_visit_index']-3];assert len(loads)==1 and loads[0]['address']=='0x1010a0558'and loads[0]['original_fixup']['target']==HELPER;counts['creator_target_load_epochs_checked']+=1
   first,second=[status(cfg)for cfg in case['steps']];assert raw[16:20]==struct.pack('<I',second);a=r['creator_returns'][0]['source_visit_index'];z=r['creator_calls'][1]['source_visit_index'];assert not any(int(e['address'],16)<R+20 and int(e['address'],16)+e['size_bytes']>R+16 for e in r['source_reads']if a<=e['source_visit_index']<z);counts['first_result_unread_windows_checked']+=1
   ok=second==0x8b3dc651;state=9 if ok else case['initial_state'];assert r['state_cache']['bytes_hex'][:2]==f'{state:02x}';sw=[e for e in r['source_writes']if int(e['address'],16)==STATE];assert len(sw)==int(ok)and all(e['pc']=='0x1001f1ff8'for e in sw);counts['source_state09_publications']+=int(ok)
   for step,key in [(0,'primary_value'),(1,'secondary_value')]:
    good=status(case['steps'][step])==0x8b3dc651;expected=P+(0x2000 if step==0 else 0x3000)if good else case['old_cell'];assert int(r[key],16)==expected;counts['source_lock_pointer_publications']+=int(good)
   if first!=0x8b3dc651 and ok:counts['first_failure_second_success_state09_cases']+=1
   if first==0x8b3dc651 and not ok:counts['first_success_second_failure_state_retained_cases']+=1
   matrix[('first_ok'if first==0x8b3dc651 else'first_error')+('_second_ok'if ok else'_second_error')]+=1
   for step,cfg in enumerate(case['steps']):
    models=[m for m in r['lifecycle_models']if m['step']==step];assert [m['name']for m in models]==(['malloc','rwlock_init']if cfg['malloc_nonnull']else['malloc'])
    for model in models:
     assert not model['modeled_writes']and not model['native_target_executed']and model['import_guest_target']=='0x7c100000';counts[model['name']+'_models_checked']+=1
     pc,slot,target=('0x100193850','0x10109ff58','libSystem/_malloc')if model['name']=='malloc'else('0x100130fc0','0x1010a0dd0','libSystem/_pthread_rwlock_init');loads=[e for e in r['source_reads']if e['source_visit_index']==model['source_visit_index']-3];assert len(loads)==1 and loads[0]['pc']==pc and loads[0]['address']==slot and loads[0]['original_fixup']['target']==target and model['binding']==binding(int(slot,16));counts['API_binding_load_epochs_checked']+=1
    h=r['heap_snapshots'][step];assert h['known_mask_hex']==('01'*8+'00'*192 if cfg['malloc_nonnull']else'00'*200)and h['provenance_hex']==h['known_mask_hex'];counts['opaque_heap_unknown_extents_checked']+=1
    if cfg['malloc_nonnull']:assert h['bytes_hex'][:16]=='00'*8
  if j in FRESH:
   f=Lifecycle(case);fresh=f.run();del f;assert fresh==r;counts['fresh_replayed_cases']+=1;replays.append({'index':j,'profile_sha256':hashlib.sha256(json.dumps(fresh,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
  if j%64==0:print(json.dumps({'cases_audited':j+1}),flush=True)
 deps={n:sha(ROOT/n)for n in ['daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_profiles.json','daemon_rwlock_lifecycle_proofs.json','daemon_rwlock_lifecycle_symbolic.py','probe_daemon_rwlock_lifecycle.py','validate_daemon_iokit_sync.py']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'case_matrix':dict(matrix),'fresh_replays':replays,'all_checks_pass':True,'native_target_executed':False,'native_lock_initialization_proved':False,'full_goal_complete':False};(ROOT/'daemon_rwlock_lifecycle_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'case_matrix':dict(matrix)}),flush=True)
if __name__=='__main__':main()
