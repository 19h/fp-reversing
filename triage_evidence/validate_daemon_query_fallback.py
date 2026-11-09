#!/usr/bin/env python3
"""Fresh fallback replays with independent source/byte/ABI/threshold checks.

O(B+C*(V+E+J*F)+I+256R) time,O(B+C*(V+E)+I+F+4096J) space,
plus30 s/query. All native IOKit/Mach/PAC and lifetime effects remain unknown.
"""
import gc,hashlib,json,struct
from collections import Counter,defaultdict
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from daemon_query_fallback_symbolic import queries
from probe_daemon_query_fallback import Fallback,cases
from validate_daemon_query_state import audit
U64=(1<<64)-1;STATE=0x1010b6380

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def prefix(r,old,counts):
 n=len(old['source_visits']);assert r['input']==old['input']and r['source_visits'][:n]==old['source_visits']and r['API_models']==old['API_models']
 for field in['source_reads','source_writes','source_edges']:
  assert[e for e in r[field]if e['source_visit_index']<n]==old[field],field
 assert r['source_fixup_reads'][:len(old['source_fixup_reads'])]==old['source_fixup_reads']
 for field in['initial_private_fixtures','initial_image_fixtures','source_entry_register_adjustments','preceding_query_boundary','helper_call','query_words','returned_size','query_state_record','record_before_helper','fallback_record']:assert r[field]==old[field],field
 if old['helper_returned']:assert r['state_cache']==old['state_cache']and r['boundary']==old['boundary']
 else:assert r['cache_before_fallback']['bytes_hex']==old['state_cache']['bytes_hex']
 counts['exact_preceding_prefixes']+=1

def main():
 c,p,proof=map(read,['daemon_query_fallback_contracts.json','daemon_query_fallback_profiles.json','daemon_query_fallback_proofs.json']);prior=read('daemon_query_state_profiles.json');counts=Counter();markers=Counter();edgecounts=Counter()
 for obj,name in[(c,'recover_daemon_query_fallback.py'),(p,'probe_daemon_query_fallback.py'),(proof,'prove_daemon_query_fallback.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex']and b['source_byte_input']==0x3a;counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup'];counts['direct_dispatch_slots_verified']+=1
 for row in c['retained_prior_sources']:
  pth=Path(row['path']);assert sha(pth)==row['sha256']and pth.read_text()==row['contents'];counts['retained_prior_sources_verified']+=1
 live=read('daemon_query_fallback_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated'];lc=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);lc+=1
 assert lc==len(c['live_IDB_source_rows_matched'])==162;counts['live_IDB_source_rows_matched']=lc
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs'])==16
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 inputs=list(cases());assert len(inputs)==564 and[r['input']for r in p['cases']]==inputs;rows=[];pairs=defaultdict(list)
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Fallback(case);r=f.run();del f;assert r==retained;audit(r,counts)
  if j<264:prefix(r,prior['cases'][j],counts)
  rows.append(r);counts['fresh_cases']+=1;counts['original_instruction_visits']+=len(r['source_visits']);F=int(r['frame_SP'],16);good=[s==0 and z==4 for s,z in case['responses']];V,C=[case['words'][n]if good[n]else 0 for n in range(2)];threshold=(V>>16)>=0x2e1e
  assert r['helper_returned']and r['boundary']['pc']=='0x100483ca8'and r['boundary']['kind']=='before_uninitialized_saved_iterator_read'and not r['unexecuted_calls']and not r['native_target_executed']and not r['full_goal_complete'];counts['normal_returns_before_unknown_iterator']+=1
  assert r['uninitialized_read_boundary']['snapshot']['known_mask_hex']=='00000000';assert int(r['uninitialized_read_boundary']['snapshot']['address'],16)==F+0x68;assert r['state_before_final_marker']is not None and bytes.fromhex(r['state_before_final_marker']['bytes_hex'])[0]==9
  cache=bytes.fromhex(r['state_cache']['bytes_hex']);assert cache[0]==10 and cache[4:8]==struct.pack('<I',0x5804);assert struct.unpack('<3I',cache[8:20])==((V>>24)+0xbfd3da4,((V>>16)&255)+0xe62359a,((V>>8)&255)+0xda54c41)
  expected=(C^0xc49697f0)if C else(0xc49697f8 if threshold else 0xc49697f0);assert struct.unpack('<I',cache[20:24])[0]==expected;counts['final_encoded_cache_checks']+=1
  assert len(r['API_models'])==2 and all(not m['native_target_executed']for m in r['API_models']);counts['API_models_retained']+=2
  bits=[e for e in r['source_writes']if e['pc']=='0x100015280'];assert len(bits)==int(C==0 and threshold)
  if bits:assert bits[0]['address']=='0x1010b6394'and bits[0]['after_hex']=='f89796c4';counts['version_qualified_capability_bit_stores']+=1
  if C:
   assert not r['fallback_calls']and not r['fallback_returned']and r['fallback_input_record']is None and r['fallback_access_record']is None;counts['nonzero_capabilities_skip_fallback']+=1
  else:
   counts['completed_zero_capability_fallbacks']+=1;call,=r['fallback_calls'];assert call['pc']=='0x100011674'and call['target']=='0x10043bd18'and call['modifier16']=='0xb61a'and call['target_executed_in_private_guest']and not call['native_target_executed']and r['fallback_returned'];Q=F-0x60+0x14;assert int(call['registers8'][0],16)==Q
   before,after=r['fallback_input_record'],r['fallback_access_record'];assert before['address']==after['address']==hex(Q)and before['size_bytes']==after['size_bytes']==20 and before['known_mask_hex']=='01'*16+'00'*4 and after['known_mask_hex']=='01'*20 and after['provenance_hex']=='01'*20
   raw,done=bytes.fromhex(before['bytes_hex']),bytes.fromhex(after['bytes_hex']);assert done[:16]==raw[:16]and raw[16:]==b'\xa5'*4
   marker=0x3a9c01d9 if not threshold else 0x3a9c01da if (V>>16)==0x2e1e and ((V>>8)&255)==0 else 0x3a9c01db;assert int.from_bytes(done[16:],'little')==marker;markers[hex(marker)]+=1;counts['record_result_publications']+=1
   stores=[e for e in r['source_writes']if e['pc']=='0x1001a88f8'];assert len(stores)==1 and stores[0]['address']==hex(Q+16)and stores[0]['size_bytes']==4 and stores[0]['after_hex']==done[16:].hex()
   record_reads=[e for e in r['source_reads']if call['source_visit_index']<e['source_visit_index']<stores[0]['source_visit_index']and Q<=int(e['address'],16)<Q+20];assert[(e['pc'],int(e['address'],16),e['size_bytes'])for e in record_reads]==[('0x10043bdb0',Q+8,4)]
   readmarker,=[e for e in r['source_reads']if e['pc']=='0x100011678'];assert readmarker['address']==hex(Q+16)and readmarker['bytes_hex']==done[16:].hex()and readmarker['source_visit_index']>stores[0]['source_visit_index'];counts['caller_result_alias_checks']+=1
   A=next(e for e in r['source_reads']if e['pc']=='0x10043bd20');B=next(e for e in r['source_reads']if e['pc']=='0x10043bd28');a,b=[int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')for e in[A,B]];L=F-0x70;D=((b-a)&U64)^((L+8)^0x73d046208eaed1a6);value=(D*0xa5cd4cf)&U64
   for pc,addr in[('0x10043bd58','0x1010b6918'),('0x10043bd5c','0x1010c4670')]:
    s,=[e for e in r['source_writes']if e['pc']==pc];assert s['address']==addr and s['size_bytes']==8 and int.from_bytes(bytes.fromhex(s['after_hex']),'little')==value;counts['fallback_controller_store_checks']+=1
   for edge in r['source_edges']:
    if edge['pc']in['0x10043be88','0x1002578ac','0x10036c6c0','0x10034f598','0x100275bc0']:edgecounts[edge['pc']+'->'+edge['target']]+=1
  if j>=264:pairs[(V>>8,case['placement'])].append(r)
  if j%32==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 for group in pairs.values():
  assert len(group)==2;a,b=group
  for field in['query_state_record','fallback_access_record','state_cache']:assert a[field]==b[field]
  counts['low_version_byte_independence_pairs']+=1
 assert counts['fresh_cases']==564 and counts['original_instruction_visits']==324496 and counts['completed_zero_capability_fallbacks']==532 and counts['nonzero_capabilities_skip_fallback']==32 and counts['version_qualified_capability_bit_stores']==156 and dict(markers)=={'0x3a9c01d9':376,'0x3a9c01da':4,'0x3a9c01db':152}and counts['low_version_byte_independence_pairs']==150
 deps={n:sha(ROOT/n)for n in['daemon_query_fallback_contracts.json','daemon_query_fallback_profiles.json','daemon_query_fallback_proofs.json','daemon_query_fallback_symbolic.py','probe_daemon_query_fallback.py','recover_daemon_query_fallback.py','probe_daemon_query_state.py','validate_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_query_state_profiles.json','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_query_fallback_live_ida.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'fallback_marker_counts':dict(markers),'decision_edge_counts':dict(edgecounts),'fresh_replays_sha256':sha(ROOT/'daemon_query_fallback_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts,'marker_counts':dict(markers),'decision_edges':dict(edgecounts)}),flush=True)
if __name__=='__main__':main()
