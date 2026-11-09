#!/usr/bin/env python3
"""Fresh discovery/query/release replays with independent byte and handle lineage.

O(B+C*(V+E+J*F)+I+256R+SDK bytes) time,O(B+C*(V+E)+I+F+4096J)
space plus30 s/query. Native objects,rights,lifetime and transport unknown.
"""
import hashlib,json,struct,gc,subprocess
from collections import Counter
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_iokit_objects import sdk_check
from probe_daemon_iokit_objects import Objects,cases,P,TASK,GUARD,API,IMPS,STATE,CALLS
from daemon_iokit_objects_symbolic import queries

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def audit(r,counts):
 data={};known=set();prov={};events={};F=int(r['frame_SP'],16)
 def put(a,b,p):
  for at,v in enumerate(b,a):data[at]=v;known.add(at);prov[at]=p
 for e in r['initial_private_fixtures']+r['initial_image_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),3)
 def original(a,n):
  if P<=a<a+n<=P+0x10000:return bytes([0xa5])*n
  b=bytearray(IMAGE.read(a,n))
  for at in range(a&~7,a+n,8):
   if at in FIXUPS:
    t=FIXUPS[at]['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;raw=struct.pack('<Q',v)
    for j in range(max(a,at),min(a+n,at+8)):b[j-a]=raw[j-at]
  return bytes(b)
 def get(a,n):
  b=original(a,n);return bytes(data.get(j,b[j-a])for j in range(a,a+n))
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert get(a,n).hex()==s['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex']
 for field,kind in[('source_reads','read'),('source_writes','write')]:
  for e in r[field]:events.setdefault(e['source_visit_index'],[]).append((kind,e))
 models={m['source_visit_index']:m for m in r['API_models']+r['IOKit_models']};assert len(models)==len(r['API_models'])+len(r['IOKit_models'])
 for ix,v in enumerate(r['source_visits']):
  assert ix==v['source_visit_index']and IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_instruction_byte_checks']+=4
  if v['pc']=='0x100011674':snapshot(r['fallback_input_record']);counts['fallback_input_unknown_result_checks']+=1
  for kind,e in events.get(ix,[]):
   a=int(e['address'],16);n=e['size_bytes'];assert e['pc']==v['pc']
   if kind=='read':
    assert get(a,n).hex()==e['bytes_hex'],('read epoch',e)
    if P<=a<a+n<=P+0x10000:assert all(j in known for j in range(a,a+n))
    if 'original_fixup'in e:assert FIXUPS[a]==e['original_fixup']
    counts['source_read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n;put(a,b,1);counts['source_write_epochs']+=1
  if ix in models:
   m=models[ix];assert not events.get(ix)
   if 'selector'in m:assert get(F+0x70,8)==struct.pack('<Q',4);counts['query_capacity_resets']+=1
   for e in m['modeled_writes']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),2);counts['API_write_epochs']+=1
 for name in['query_words','iterator_cell','connection_saved_pointer','returned_size','query_state_record','fallback_record','fallback_access_record']:
  if r[name]is not None:snapshot(r[name])
 s=r['state_cache'];assert get(STATE,24).hex()==s['bytes_hex']and bytes(prov.get(j,0)for j in range(STATE,STATE+24)).hex()==s['provenance_mask_hex']
 if r['boundary']['pc']=='0x100383b00':assert all(j not in known for j in range(F+0x50,F+0x58));counts['common_cleanup_unknown_pointer_frontiers']+=1
 counts['independent_byte_reconstructed_cases']+=1

def embedded_prefix(r,old,counts):
 at=r['query_entry']['source_visit_index'];n=len(old['source_visits']);assert r['query_entry']['pc']=='0x100364398'
 for field in['source_visits','source_reads','source_writes','source_edges']:
  rows=[dict(e)for e in r[field]if at<=e['source_visit_index']<at+n]
  for e in rows:e['source_visit_index']-=at
  assert rows==old[field],field
 fix=[{'address':e['address'],'original_fixup':e['original_fixup']}for e in r['source_reads']if at<=e['source_visit_index']<at+n and 'original_fixup'in e];assert fix==old['source_fixup_reads']
 for which,(now,prev)in enumerate(zip(r['API_models'],old['API_models'])):
  expected=json.loads(json.dumps(prev));expected['source_visit_index']+=at
  if which==0:expected['registers8'][6:]=['0xf000000000006666','0xf000000000007777']
  assert now==expected
 for field in['query_state_record','record_before_helper','fallback_record','fallback_input_record','fallback_access_record','helper_returned','fallback_returned']:assert r[field]==old[field],field
 assert r['state_cache']['bytes_hex']==old['state_cache']['bytes_hex'];mask=bytearray.fromhex(old['state_cache']['provenance_mask_hex']);mask[4:8]=b'\2'*4;assert r['state_cache']['provenance_mask_hex']==mask.hex()
 a,b=bytes.fromhex(r['query_words']['bytes_hex']),bytes.fromhex(old['query_words']['bytes_hex']);assert a[:4]==b[:4]and a[8:]==b[8:];counts['embedded_query_prefixes_with_declared_unused_register_adjustment']+=1

def main():
 c,p,proof=map(read,['daemon_iokit_objects_contracts.json','daemon_iokit_objects_profiles.json','daemon_iokit_objects_proofs.json']);prior=read('daemon_query_fallback_profiles.json');counts=Counter();matrix=Counter();roles=Counter()
 for obj,name in[(c,'recover_daemon_iokit_objects.py'),(p,'probe_daemon_iokit_objects.py'),(proof,'prove_daemon_iokit_objects.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),0);assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup'];counts['direct_dispatch_slots_verified']+=1
 for b in c['bindings']:assert binding(int(b['slot'],16))==b;counts['original_binding_decodes']+=1
 task=next(b for b in c['bindings']if b['symbol']=='_mach_task_self_');assert not task['authenticated']and task['total_addend']==0x7bf13863 and(task['total_addend']+int(c['task_bind_source_bias64'],16))&((1<<64)-1)==0;counts['ordinary_data_bind_addend_cancellations']+=1
 assert sdk_check()==c['SDK']and c['SDK']['exit_code']==0;counts['SDK_syntax_checks']+=1;counts['SDK_width_assertions']=8;counts['SDK_function_signature_checks']=4
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents'];counts['retained_prior_sources_verified']+=1
 live=read('daemon_iokit_objects_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated'];lc=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);lc+=1
 assert lc==len(c['live_IDB_source_rows_matched'])==179;counts['live_IDB_source_rows_matched']=lc
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs'])==19
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 inputs=list(cases());assert len(inputs)==632 and[r['input']for r in p['cases']]==inputs;rows=[]
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Objects(case);r=f.run();del f;assert r==retained;audit(r,counts)
  if j<564:embedded_prefix(r,prior['cases'][j],counts)
  rows.append(r);counts['fresh_cases']+=1;counts['original_instruction_visits']+=len(r['source_visits']);F=int(r['frame_SP'],16);i=case['IO'];success=i['matching_status']==0;service=success and i['service']!=0;opened=service and i['open_status']==0;expected=['matching_services']+(['iterator_next']if success else[])+(['service_open','service_release']if service else[])+(['iterator_release']if success and(not service or opened)else[]);assert [m['name']for m in r['IOKit_models']]==expected
  if not success:assert r['boundary']['pc']=='0x100318cc0'and r['iterator_cell']['known_mask_hex']=='00000000';counts['matching_error_frontiers']+=1
  elif service and not opened:assert r['boundary']['pc']=='0x1004bdb24';counts['open_error_frontiers_after_service_release']+=1
  else:assert r['boundary']['pc']=='0x100383b00'
  assert not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete'];matrix[r['boundary']['pc']]+=1
  for m in r['IOKit_models']:
   name=m['name'];roles[name]+=1;pc=int(m['pc'],16);slot=CALLS[pc][1];assert m['binding']==binding(slot)and not m['native_target_executed'];params=[int(v,16)for v in m['registers8']]
   if name=='matching_services':assert params[:3]==[i['main_port'],P+0x3000,F+0x68]and len(m['modeled_writes'])==int(success)
   elif name=='iterator_next':assert params[0]==i['iterator']and int(m['returned_u32'],16)==i['service']
   elif name=='service_open':assert params[:4]==[i['service'],i['task_port'],0,STATE+4]and len(m['modeled_writes'])==int(opened)
   elif name=='service_release':assert params[0]==i['service']and int(m['returned_u32'],16)==i['release_statuses'][0]
   else:assert params[0]==i['iterator']and int(m['returned_u32'],16)==i['release_statuses'][1]
  if success:
   s=r['iterator_cell'];assert s['bytes_hex']==struct.pack('<I',i['iterator']).hex()and s['provenance_hex']=='02020202';counts['API_produced_iterator_cells_preserved']+=1
  if opened:
   assert len(r['API_models'])==2 and r['helper_returned']and r['query_entry']is not None;assert r['state_cache']['provenance_mask_hex'][8:16]=='02020202'and bytes.fromhex(r['state_cache']['bytes_hex'])[4:8]==struct.pack('<I',0x5804);counts['connection_outputs_consumed_by_queries']+=1;counts['metadata_API_models_retained']+=2
   for m in r['API_models']:assert [int(x,16)for x in m['registers8'][:6]]==[0x5804,m['selector'],0,0,F+(0x64 if m['selector']==22 else 0x6c),F+0x70]
   assert r['query_words']['provenance_hex'][8:16]=='02020202'
  else:assert not r['API_models']and r['query_entry']is None and not r['helper_returned']
  if i['matching_status']==0 and i['iterator']==0:assert expected==['matching_services','iterator_next','iterator_release']and i['service']==0;counts['successful_null_iterator_controls']+=1
  if i['main_port']>>31:counts['high_bit_handle_controls']+=1
  if j%32==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==632 and counts['original_instruction_visits']==443392 and counts['connection_outputs_consumed_by_queries']==568 and counts['matching_error_frontiers']==32 and counts['open_error_frontiers_after_service_release']==12 and counts['common_cleanup_unknown_pointer_frontiers']==588 and counts['successful_null_iterator_controls']==4
 assert dict(roles)=={'matching_services':632,'iterator_next':600,'service_open':580,'service_release':580,'iterator_release':588}
 deps={n:sha(ROOT/n)for n in['daemon_iokit_objects_contracts.json','daemon_iokit_objects_profiles.json','daemon_iokit_objects_proofs.json','daemon_iokit_objects_symbolic.py','probe_daemon_iokit_objects.py','recover_daemon_iokit_objects.py','probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_query_fallback_profiles.json','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_iokit_objects_live_ida.json','daemon_iokit_objects_sdk.c']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_objects_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'frontier_counts':dict(matrix),'IOKit_model_role_counts':dict(roles),'fresh_replays_sha256':sha(ROOT/'daemon_iokit_objects_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False};(ROOT/'daemon_iokit_objects_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts,'IOKit_role_counts':dict(roles)}),flush=True)
if __name__=='__main__':main()
