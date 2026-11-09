#!/usr/bin/env python3
"""Independent source-byte/epoch audit plus bounded fresh model replays.
O(B+C*(V+E)+K*(V+E+JF)+I+256R) time,O(largest profile JSON+F+K*(V+E)) space,
plus30 s/query. No native target, synchronization, PAC or IDB mutation.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_iokit_sync import sdk_check
from resolve_kernel_collection_interfaces import macho
from daemon_iokit_sync_symbolic import queries
from probe_daemon_iokit_sync import Sync,cases,PRIMARY,FALLBACK,ONCE,CALLBACK,OUTER_RETURN,SYNC_IMPS,P,TASK,GUARD,API,IMPS,NEW_IMPS,STATE,NAME
FRESH=[0,4,512,520,560,600,632,636,640,660]+list(range(664,684))
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
  if P<=a<a+n<=P+0x10000 or PRIMARY&~4095<=a<a+n<=(PRIMARY&~4095)+4096:return bytes([0xa5])*n
  b=bytearray(IMAGE.read(a,n))
  for at in range(a&~7,a+n,8):
   if at in FIXUPS:
    t=FIXUPS[at]['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else SYNC_IMPS[t]if t in SYNC_IMPS else NEW_IMPS[t]if t in NEW_IMPS else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;raw=struct.pack('<Q',v)
    for j in range(max(a,at),min(a+n,at+8)):b[j-a]=raw[j-at]
  return bytes(b)
 def get(a,n):
  b=original(a,n);return bytes(data.get(j,b[j-a])for j in range(a,a+n))
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert get(a,n).hex()==s['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex'],('snapshot',hex(a))
 for field,kind in [('source_reads','read'),('source_writes','write')]:
  for e in r[field]:events.setdefault(e['source_visit_index'],[]).append((kind,e))
 models={m['source_visit_index']:m for m in r['API_models']+r['IOKit_models']+r['prefix_models']+r['sync_models']};assert len(models)==sum(len(r[k])for k in ['API_models','IOKit_models','prefix_models','sync_models'])
 for ix,v in enumerate(r['source_visits']):
  assert ix==v['source_visit_index']and IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_instruction_bytes_checked']+=4
  timed={'0x100011674':['fallback_record','fallback_input_record'],'0x100011678':['fallback_access_record'],'0x1003c3ae8':['record_before_helper'],'0x10040b814':['class_call_snapshot']}
  for field in timed.get(v['pc'],[]):
   if r[field]is not None:snapshot(r[field]);counts['capture_epoch_snapshots_checked']+=1
  for kind,e in events.get(ix,[]):
   a=int(e['address'],16);n=e['size_bytes'];assert e['pc']==v['pc']
   if kind=='read':
    assert get(a,n).hex()==e['bytes_hex'],('read epoch',e)
    if P<=a<a+n<=P+0x10000 or PRIMARY&~4095<=a<a+n<=(PRIMARY&~4095)+4096:assert all(j in known for j in range(a,a+n))
    if 'original_fixup'in e:assert FIXUPS[a]==e['original_fixup']
    counts['source_read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n;put(a,b,1);counts['source_write_epochs']+=1
  if ix in models:
   m=models[ix];assert not events.get(ix)
   for e in m['modeled_writes']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),2);counts['API_write_epochs']+=1
 for name in ['class_buffer','main_port_cell','saved_input_and_tables','query_words','iterator_cell','connection_saved_pointer','returned_size','query_state_record','saved_primary_cell_pointer','outer_result_word','outer_input_record']:
  if r[name]is not None:snapshot(r[name])
 s=r['state_cache'];assert get(STATE,24).hex()==s['bytes_hex']and bytes(prov.get(j,0)for j in range(STATE,STATE+24)).hex()==s['provenance_mask_hex'];counts['independent_byte_reconstructed_cases']+=1
def main():
 c,p,proof=map(read,['daemon_iokit_sync_contracts.json','daemon_iokit_sync_profiles.json','daemon_iokit_sync_proofs.json']);counts=Counter();matrix=Counter()
 for obj,name in [(c,'recover_daemon_iokit_sync.py'),(p,'probe_daemon_iokit_sync.py'),(proof,'prove_daemon_iokit_sync.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for b in c['bindings']:assert binding(int(b['slot'],16))==b;counts['original_binding_decodes']+=1
 assert sdk_check()==c['SDK'];counts['SDK_syntax_checks']=1;counts['SDK_function_signature_checks']=3;counts['SDK_width_assertions']=2
 m=macho(IMAGE.data,0,'fairplayd');assert c['primary_segment']in m['segments']and c['primary_section']in m['sections'];s=c['primary_segment'];assert PRIMARY>=s['address']+s['file_size']and PRIMARY<s['address']+s['vm_size']and c['primary_section']['flags']&255==1;counts['zerofill_cell_extent_checks']=1
 live=read('daemon_iokit_sync_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);counts['live_IDB_source_rows_matched']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs'])
 for (name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 cs=list(cases());assert len(cs)==len(p['cases'])==684 and [r['input']for r in p['cases']]==cs
 prior=read('daemon_iokit_class_profiles.json')['composed_cases'];replayed=[]
 for j,r in enumerate(p['cases']):
  audit(r,counts);counts['generated_cases']+=1;counts['source_instruction_visits']+=len(r['source_visits']);matrix[r['boundary']['kind']]+=1;sync=r['input']['sync'];chosen=sync['primary']or sync['fallback'];ret=r['outer_returned'];F=int(r['frame_SP'],16)
  if j in FRESH:
   f=Sync(cs[j]);now=f.run();del f;assert now==r;counts['fresh_replayed_cases']+=1;replayed.append({'index':j,'profile_sha256':hashlib.sha256(json.dumps(now,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'boundary':now['boundary']})
  assert not r['callback_pending']and not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete']
  expected=['acquire_once']+(['write_lock']if chosen else[])+(['cleanup_once']+(['unlock']if chosen else[])if ret else[]);assert [x['name']for x in r['sync_models']]==expected
  once=[x for x in r['sync_models']if x['name'].endswith('once')]
  assert [x['callback_invoked']for x in once]==[not sync['once_completed']]+([False]if ret else[])
  for x in r['sync_models']:
   assert x['returned_u32']=='0x0'and not x['modeled_writes']and not x['native_target_executed'];counts[x['name']+'_models']+=1
   if x['name'].endswith('once'):assert [int(v,16)for v in x['registers8'][:2]]==[ONCE,CALLBACK]
   else:assert int(x['registers8'][0],16)==chosen
   if x.get('callback_invoked'):
    counts['source_callback_invocations']+=1;a,z=x['callback_source_visit_begin'],x['callback_source_visit_end'];assert r['source_visits'][a]['pc']==hex(CALLBACK);writes=[e for e in r['source_writes']if a<=e['source_visit_index']<z];assert not any(int(e['address'],16)in [PRIMARY,FALLBACK]for e in writes);assert sum(e['pc']=='0x10040ecfc'for e in writes)==sum(e['pc']=='0x10040ed00'for e in writes)==1
  assert r['saved_primary_cell_pointer']['bytes_hex']==struct.pack('<Q',PRIMARY).hex()and r['saved_primary_cell_pointer']['provenance_hex']=='01'*8
  if ret:
   assert r['boundary']['pc']==hex(OUTER_RETURN)and r['boundary']['SP']==r['entry_SP']and r['boundary']['registers31'][19:30]==r['entry_registers31'][19:30]
   assert r['outer_input_record']['bytes_hex'][8:]==r['outer_result_word']['bytes_hex']and r['outer_input_record']['provenance_hex']=='03'*4+'01'*4;counts['outer_result_publications_and_ABI_returns']+=1
  if j<664:
   old=prior[j];at=r['class_entry']['source_visit_index'];assert r['source_visits'][at:at+len(old['source_visits'])]==[{**v,'source_visit_index':v['source_visit_index']+at}for v in old['source_visits']];counts['embedded_original_class_source_sequences']+=1
   for group,argc in [('prefix_models',{'main_port':2,'matching_dictionary':1}),('IOKit_models',{'matching_services':3,'iterator_next':1,'service_open':4,'service_release':1,'iterator_release':1})]:
    assert len(r[group])==len(old[group])
    for a,b in zip(r[group],old[group]):assert a['pc']==b['pc']and a['binding']==b['binding']and a['registers8'][:argc[a['name']]]==b['registers8'][:argc[b['name']]]and a['modeled_writes']==b['modeled_writes']and a.get('returned_u32',a.get('returned_value'))==b.get('returned_u32',b.get('returned_value'))
   assert len(r['API_models'])==len(old['API_models'])
   for a,b in zip(r['API_models'],old['API_models']):assert a['registers8'][:6]==b['registers8'][:6]and a['modeled_writes']==b['modeled_writes']and a['status32_fixture']==b['status32_fixture']
   for name in ['record_before_helper','fallback_access_record','state_cache']:assert r[name]==old[name],name
   if r['fallback_input_record']is not None:assert r['fallback_input_record']['bytes_hex'][:32]==old['fallback_input_record']['bytes_hex'][:32]
  if j%64==0:print(json.dumps({'cases_audited':j+1}),flush=True)
 deps={n:sha(ROOT/n)for n in ['daemon_iokit_sync_contracts.json','daemon_iokit_sync_profiles.json','daemon_iokit_sync_proofs.json','daemon_iokit_sync_symbolic.py','probe_daemon_iokit_sync.py','daemon_iokit_class_profiles.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'frontier_matrix':dict(matrix),'fresh_replays':replayed,'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_sync_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'counts':dict(counts),'frontier_matrix':dict(matrix)}),flush=True)
if __name__=='__main__':main()
