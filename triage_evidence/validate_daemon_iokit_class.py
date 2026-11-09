#!/usr/bin/env python3
"""Fresh class/source/byte/SDK/kext association checks;no native API or registry.
O(B+C*(V+E+J*F)+I+256R+KC+SDK bytes) time,
O(B+C*(V+E)+I+F+4096J+KC) space plus30 s/query.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_iokit_class import sdk_check
from probe_daemon_iokit_class import Matching,cases,decoder_cases,NAME,P,TASK,GUARD,API,IMPS,NEW_IMPS,STATE,DICT
from daemon_iokit_class_symbolic import queries
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from kext_port_tools import SOURCE as KSOURCE,IMAGE as KIMAGE

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
    t=FIXUPS[at]['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else NEW_IMPS[t]if t in NEW_IMPS else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;raw=struct.pack('<Q',v)
    for j in range(max(a,at),min(a+n,at+8)):b[j-a]=raw[j-at]
  return bytes(b)
 def get(a,n):
  b=original(a,n);return bytes(data.get(j,b[j-a])for j in range(a,a+n))
 def snapshot(s):
  a=int(s['address'],16);n=s['size_bytes'];assert get(a,n).hex()==s['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex']
 for field,kind in[('source_reads','read'),('source_writes','write')]:
  for e in r[field]:events.setdefault(e['source_visit_index'],[]).append((kind,e))
 models={m['source_visit_index']:m for m in r['API_models']+r['IOKit_models']+r['prefix_models']};assert len(models)==len(r['API_models'])+len(r['IOKit_models'])+len(r['prefix_models'])
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
 for name in['class_buffer','class_call_snapshot','main_port_cell','saved_input_and_tables','query_words','iterator_cell','connection_saved_pointer','returned_size','query_state_record','fallback_record','fallback_access_record']:
  if r[name]is not None:snapshot(r[name])
 s=r['state_cache'];assert get(STATE,24).hex()==s['bytes_hex']and bytes(prov.get(j,0)for j in range(STATE,STATE+24)).hex()==s['provenance_mask_hex']
 if r['boundary']['pc']=='0x100383b00':assert all(j not in known for j in range(F+0x50,F+0x58));counts['common_cleanup_unknown_pointer_frontiers']+=1
 counts['independent_byte_reconstructed_cases']+=1

def embedded(r,old,counts):
 at=r['objects_entry']['source_visit_index'];assert at==198;n=len(old['source_visits'])
 for field in['source_visits','source_reads','source_writes','source_edges']:
  rows=[dict(e)for e in r[field]if at<=e['source_visit_index']<at+n]
  for e in rows:e['source_visit_index']-=at
  assert rows==old[field],field
 fix=[{'address':e['address'],'original_fixup':e['original_fixup']}for e in r['source_reads']if at<=e['source_visit_index']<at+n and 'original_fixup'in e];assert fix==old['source_fixup_reads']
 for group in['IOKit_models','API_models']:
  assert len(r[group])==len(old[group])
  for which,(now,prev)in enumerate(zip(r[group],old[group])):
   exp=json.loads(json.dumps(prev));exp['source_visit_index']+=at
   if group=='IOKit_models'and which==0:exp['registers8'][3:]=[hex(0xf000000000000000+j*0x1111)for j in range(3,8)]
   assert now==exp
 for field in['iterator_cell','query_words','query_state_record','record_before_helper','fallback_record','fallback_input_record','fallback_access_record','state_cache','helper_returned','fallback_returned']:assert r[field]==old[field],field
 counts['embedded_object_prefixes_with_declared_unused_register_adjustments']+=1

def main():
 c,p,proof=map(read,['daemon_iokit_class_contracts.json','daemon_iokit_class_profiles.json','daemon_iokit_class_proofs.json']);prior=read('daemon_iokit_objects_profiles.json');counts=Counter();matrix=Counter()
 for obj,name in[(c,'recover_daemon_iokit_class.py'),(p,'probe_daemon_iokit_class.py'),(proof,'prove_daemon_iokit_class.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_daemon_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup'];counts['direct_dispatch_slots_verified']+=1
 for b in c['bindings']:assert binding(int(b['slot'],16))==b;counts['original_binding_decodes']+=1
 assert sdk_check()==c['SDK'];counts['SDK_syntax_checks']=1;counts['SDK_width_assertions']=3;counts['SDK_function_signature_checks']=2
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents'];counts['retained_prior_sources_verified']+=1
 data=c['class_data'];assert data['pointer_cell']=='0x1010b8cc0'and data['source_address']=='0x100fd40c0'and FIXUPS[0x1010b8cc0]['target']==0x100fd40c0 and IMAGE.read(0x1010b8cc0,8).hex()==data['raw_word_hex'];raw=IMAGE.read(0x100fd40c0,31);assert raw.hex()==data['encoded31_hex']and bytes(x^0xfc for x in raw)==NAME and data['expected_class31_hex']==NAME.hex();counts['original_class_pointer_rebases']=1
 live=read('daemon_iokit_class_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated'];n=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);n+=1
 assert n==len(c['live_IDB_source_rows_matched'])==208;counts['live_IDB_source_rows_matched']=n
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and sha(KSOURCE)==c['kext_sha256'];e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for f in c['kext_constructors']:assert function(k,e,int(f['start'],16))==f;counts['kext_metaclass_constructors_verified']+=1
 for s in c['kext_spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[key]==s[key]for key in now);counts['kext_import_stub_spans_verified']+=1
 for ptr in c['kext_pointers']:assert pointer(k,int(ptr['slot'],16))==ptr;counts['kext_pointer_bindings_verified']+=1
 assert k.symbols([int(a,16)for a in c['exact_kext_symbols']])==c['exact_kext_symbols'];assert k.read(0xfffffe000790cc00,31)==KIMAGE.read(0xfffffe000790cc00,31)==NAME;counts['daemon_kext_class_name_equalities']=1
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==15 and lifts==proof['source_lift_counts']and sum(lifts.values())==141
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 groups={}
 for label,inputs,retained in[('composed',list(cases()),p['composed_cases']),('decoder',list(decoder_cases()),p['decoder_cases'])]:
  assert len(inputs)==len(retained)==(664 if label=='composed'else 512)and[r['input']for r in retained]==inputs;rows=[]
  for j,(case,old)in enumerate(zip(inputs,retained)):
   f=Matching(case);r=f.run();del f;assert r==old;audit(r,counts);rows.append(r);counts[label+'_fresh_cases']+=1;counts[label+'_instruction_visits']+=len(r['source_visits']);F=int(r['frame_SP'],16);assert not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete'];out=bytes.fromhex(r['class_buffer']['bytes_hex'])
   if label=='decoder':
    W=case['decoder_W28'];v=bytearray(x^0xfc for x in raw);v[3]=raw[3]^(((W-0x1f6)^0x78)&255);v[5]=raw[5]^((((W-0x31ac)^0x91c8)^0xfa)&255);assert out==bytes(v)and r['class_buffer']['known_mask_hex']=='01'*31 and r['class_buffer']['provenance_hex']=='01'*31 and r['boundary']['pc']=='0x10040b7d4'and not r['prefix_models']and not r['IOKit_models']and not r['API_models'];assert(out==NAME)==((W&255)==0x7a)
    if out==NAME:counts['exact_decoder_class_controls']+=1
   else:
    if j<632:embedded(r,prior['cases'][j],counts)
    prefix=case['prefix'];ok=prefix['main_status']==0;models=r['prefix_models'];assert[m['name']for m in models]==(['main_port','matching_dictionary']if ok else['main_port']);m=models[0];assert m['binding']==binding(0x1010a0988)and[int(x,16)for x in m['registers8'][:2]]==[0,F+0x7c]and int(m['returned_value'],16)==prefix['main_status']and len(m['modeled_writes'])==int(ok);counts['main_port_API_models']+=1
    if ok:
     assert r['main_port_cell']['bytes_hex']==struct.pack('<I',case['IO']['main_port']).hex()and r['main_port_cell']['provenance_hex']=='02020202';counts['API_produced_main_ports_preserved']+=1
     assert out==NAME and r['class_buffer']['provenance_hex']=='01'*31 and r['class_call_snapshot']==r['class_buffer'];counts['exact_class_matching_calls']+=1;m=models[1];assert m['binding']==binding(0x1010a0c28)and int(m['registers8'][0],16)==F+0x89 and int(m['returned_value'],16)==(DICT if prefix['matching_nonnull']else 0)
     ptrreads=[e for e in r['source_reads']if e['pc']in['0x10040b64c','0x10040b74c']];assert len(ptrreads)==2 and all(e['address']=='0x1010b8cc0'and e['bytes_hex']=='c040fd0001000000'for e in ptrreads);counts['class_data_pointer_epoch_checks']+=2
     assert r['saved_input_and_tables']['bytes_hex']==struct.pack('<3Q',P+0x2000,0x100e99800,0x100f4e290).hex()and r['saved_input_and_tables']['provenance_hex']=='01'*24
     if prefix['matching_nonnull']:
      assert r['objects_entry']is not None and r['objects_entry']['source_visit_index']==198 and r['IOKit_models'][0]['name']=='matching_services'and r['IOKit_models'][0]['registers8'][1]==hex(DICT);counts['matching_dictionary_forwardings']+=1
     else:assert r['objects_entry']is None and not r['IOKit_models']and not r['API_models']and r['boundary']['pc']=='0x100383b00';counts['null_dictionary_cleanup_paths']+=1
    else:assert r['boundary']['pc']=='0x10062fb74'and r['class_buffer']['known_mask_hex']=='00'*31 and r['main_port_cell']['known_mask_hex']=='00000000'and not r['IOKit_models']and not r['API_models'];counts['main_port_error_frontiers']+=1
    matrix[r['boundary']['pc']]+=1;counts['metadata_API_models_retained']+=len(r['API_models']);counts['IOKit_object_models_retained']+=len(r['IOKit_models'])
   if j%32==0:gc.collect();print(json.dumps({'kind':label,'fresh_cases_completed':j+1}),flush=True)
  groups[label+'_cases']=rows
 assert counts['composed_fresh_cases']==664 and counts['decoder_fresh_cases']==512 and counts['composed_instruction_visits']==573640 and counts['decoder_instruction_visits']==64000 and counts['matching_dictionary_forwardings']==636 and counts['null_dictionary_cleanup_paths']==4 and counts['main_port_error_frontiers']==24 and counts['exact_decoder_class_controls']==2
 assert dict(matrix)=={'0x100383b00':596,'0x1004bdb24':12,'0x100318cc0':32,'0x10062fb74':24}and counts['main_port_API_models']==664 and counts['exact_class_matching_calls']==640 and counts['API_produced_main_ports_preserved']==640 and counts['metadata_API_models_retained']==1144 and counts['IOKit_object_models_retained']==3000
 deps={n:sha(ROOT/n)for n in['daemon_iokit_class_contracts.json','daemon_iokit_class_profiles.json','daemon_iokit_class_proofs.json','daemon_iokit_class_symbolic.py','probe_daemon_iokit_class.py','recover_daemon_iokit_class.py','probe_daemon_iokit_objects.py','daemon_iokit_objects_profiles.json','daemon_iokit_class_live_ida.json','daemon_iokit_class_sdk.c','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','kernel_native_reader.py','recover_carrier_control.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','kext_port_tools.py']};obj={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,**groups,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_class_replays.json').write_text(json.dumps(obj,indent=2)+'\n')
 obj={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'composed_frontier_counts':dict(matrix),'fresh_replays_sha256':sha(ROOT/'daemon_iokit_class_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_service_publication_proved':False,'full_goal_complete':False};(ROOT/'daemon_iokit_class_checks.json').write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
