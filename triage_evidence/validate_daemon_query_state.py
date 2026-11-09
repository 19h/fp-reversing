#!/usr/bin/env python3
"""Fresh source replays, independent byte epochs, algebra and prior-prefix audit.

O(B+C*(V+E+J*F)+I+256R) time,O(B+C*(V+E)+I+F+4096J) space,
plus SMT cost30 s/query. Native/API/PAC execution is outside this model.
"""
import gc,hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_query_state import SPANS,RULES,DIRECT
from probe_daemon_query_state import FullState,full_cases,STATE,GUARD,GUARD_VALUE
from probe_daemon_iokit_census import P,LIMIT,API
from daemon_query_state_symbolic import queries
U32=(1<<32)-1;U64=(1<<64)-1
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def audit(r,counts):
 data={};known=set();provenance={};events={};F=int(r['frame_SP'],16)
 def put(a,b,p):
  for at,v in enumerate(b,a):data[at]=v;known.add(at);provenance[at]=p
 for e in r['initial_private_fixtures']+r['initial_image_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),3)
 def original(a,n):
  if P<=a<a+n<=LIMIT:return bytes([0xa5])*n
  b=bytearray(IMAGE.read(a,n))
  for at in range(a&~7,a+n,8):
   if at in FIXUPS:
    t=FIXUPS[at]['target'];v=GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else t if isinstance(t,int)else 0x7c100000;raw=struct.pack('<Q',v)
    for j in range(max(a,at),min(a+n,at+8)):b[j-a]=raw[j-at]
  return bytes(b)
 def get(a,n):
  orig=original(a,n);return bytes(data.get(j,orig[j-a])for j in range(a,a+n))
 for field,kind in[('source_reads','read'),('source_writes','write')]:
  for e in r[field]:events.setdefault(e['source_visit_index'],[]).append((kind,e))
 models={m['source_visit_index']:m for m in r['API_models']}
 for ix,v in enumerate(r['source_visits']):
  assert ix==v['source_visit_index']and IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_instruction_byte_checks']+=4
  for kind,e in events.get(ix,[]):
   a=int(e['address'],16);n=e['size_bytes'];assert e['pc']==v['pc']
   if kind=='read':
    assert get(a,n).hex()==e['bytes_hex'],('read epoch',e)
    if P<=a<a+n<=LIMIT:assert all(j in known for j in range(a,a+n))
    if 'original_fixup'in e:assert e['original_fixup']==FIXUPS[a]
    counts['source_read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n;put(a,b,1);counts['source_write_epochs']+=1
  if ix in models:
   m=models[ix];assert not events.get(ix)and get(F+0x70,8)==struct.pack('<Q',4);counts['source_capacity_resets']+=1
   for e in m['modeled_writes']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),2);counts['API_write_epochs']+=1
 for name in['query_words','returned_size','query_state_record','fallback_record']:
  s=r[name]
  if s is None:continue
  a=int(s['address'],16);n=s['size_bytes'];assert get(a,n).hex()==s['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(provenance.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex']
 s=r['state_cache'];assert get(STATE,24).hex()==s['bytes_hex']and bytes(provenance.get(j,0)for j in range(STATE,STATE+24)).hex()==s['provenance_mask_hex']
 assert not any(j in known for j in range(F+0x68,F+0x6c));counts['independent_byte_reconstructed_cases']+=1
 # The source helper touches only five record words and preserves their bytes.
 assert r['record_before_helper']==r['query_state_record']
 def at_write(pc):return[e for e in r['source_writes']if e['pc']==hex(pc)]
 helper_ix=r['helper_call']['source_visit_index'];assert helper_ix<len(r['source_visits'])and r['source_visits'][helper_ix]['pc']=='0x1003c3ae8'
 record_stores=[e for e in r['source_writes']if e['pc']in['0x1003c3a58','0x1003c3a7c','0x1003c3a90']];assert len(record_stores)==5 and sum(e['size_bytes']for e in record_stores)==20 and all(e['source_visit_index']<helper_ix for e in record_stores)
 assert not any(int(e['address'],16)<F+0xbc and F+0xa8<int(e['address'],16)+e['size_bytes']for e in r['source_writes']if e['source_visit_index']>helper_ix)
 Aread=next(e for e in r['source_reads']if e['pc']=='0x100013b58');Bread=next(e for e in r['source_reads']if e['pc']=='0x100013bbc');A=int.from_bytes(bytes.fromhex(Aread['bytes_hex']),'little');B=int.from_bytes(bytes.fromhex(Bread['bytes_hex']),'little');H=F-0x60;D=(B-A-H-8)&U64;T=0x73d046208eaed1a6;M=0xa5cd4cf
 for pc,addr,expect in[(0x100013bec,0x1010b9028,((D*M)^T)&U64),(0x100013bf0,0x1010c4670,((D^T)*M)&U64)]:
  e,=at_write(pc);assert int(e['address'],16)==addr and e['size_bytes']==8 and int.from_bytes(bytes.fromhex(e['after_hex']),'little')==expect;counts['source_controller_update_checks']+=1
 counts['record_preservation_checks']+=1

def prefix(r,old,counts):
 n=len(old['source_visits']);assert r['source_visits'][:n]==old['source_visits']and r['API_models']==old['API_models']and r['query_words']==old['query_words']and r['returned_size']==old['returned_size'];F=int(r['frame_SP'],16)
 for field in['source_writes','source_edges','source_fixup_reads']:
  new=[e for e in r[field]if e.get('source_visit_index',0)<n]if field!='source_fixup_reads'else r[field][:len(old[field])]
  assert new==old[field],field
 newreads=[e for e in r['source_reads']if e['source_visit_index']<n];assert len(newreads)==len(old['source_reads'])
 for new,prev in zip(newreads,old['source_reads']):
  expected=dict(prev);at=int(prev['address'],16)
  if at==F+8:expected['bytes_hex']=struct.pack('<Q',STATE+4).hex()
  if at==P+0x4000:expected['address']=hex(STATE+4)
  assert new==expected,('declared alias prefix',new,expected)
 a=r['preceding_query_boundary'];b=old['boundary'];assert a['pc']==b['pc']and a['SP']==b['SP']
 for j,(x,y)in enumerate(zip(a['registers31'],b['registers31'])):
  if j in[28,29]:assert int(x,16)==(0x101031ea0 if j==28 else F+0x120)
  else:assert x==y,(j,x,y)
 counts['preceding_query_prefixes_with_declared_alias_adjustments']+=1

def main():
 c,p,proof=map(read,['daemon_query_state_contracts.json','daemon_query_state_profiles.json','daemon_query_state_proofs.json']);prior=read('daemon_iokit_census_profiles.json');counts=Counter();matrix=Counter()
 for obj,name in[(c,'recover_daemon_query_state.py'),(p,'probe_daemon_query_state.py'),(proof,'prove_daemon_query_state.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records'])
 for field,at in[('stack_guard_binding',0x1010b1e18),('release_binding',0x1010a0240)]:assert binding(at)==c[field];counts['independent_bind_checks']+=1
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup'];counts['direct_dispatch_slots_verified']+=1
 live=read('daemon_query_state_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated'];lc=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:assert IMAGE.read(int(i['address'],16),len(bytes.fromhex(i['bytes'])))==bytes.fromhex(i['bytes']);lc+=1
 assert lc==len(c['live_IDB_source_rows_matched'])==78;counts['live_IDB_source_rows_matched']=lc
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and len(qs)==len(proof['proofs'])==11
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 inputs=list(full_cases());assert len(inputs)==264 and[r['input']for r in p['cases']]==inputs;rows=[]
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=FullState(case);r=f.run();del f;assert r==retained;audit(r,counts)
  if j<256:prefix(r,prior['cases'][j],counts)
  rows.append(r);counts['fresh_cases']+=1;counts['original_instruction_visits']+=len(r['source_visits']);F=int(r['frame_SP'],16);R=F+0xa8
  good=[s==0 and z==4 for s,z in case['responses']];V,C=[case['words'][n]if good[n]else 0 for n in range(2)];K=(((R&U32)^0xc6d66014)*0x6b86592f)&U32;b3,b2,b1=V>>24,(V>>16)&255,(V>>8)&255
  words=[(0x2757-K)&U32,(K+b2+0xe62359a)&U32,((C^0xc49697f0)-K)&U32,(K+b3+0xbfd3da4)&U32,(K+b1+0xda54c41)&U32];assert bytes.fromhex(r['query_state_record']['bytes_hex'])==struct.pack('<5I',*words);counts['packed_record_checks']+=1
  cache=bytes.fromhex(r['state_cache']['bytes_hex']);assert struct.unpack('<4I',cache[8:])==(b3+0xbfd3da4,b2+0xe62359a,b1+0xda54c41,C^0xc49697f0)and cache[4:8]==struct.pack('<I',0x5804);counts['encoded_cache_checks']+=1
  assert len(r['API_models'])==2 and all(not m['native_target_executed']for m in r['API_models']);counts['API_models_retained']+=2;assert not r['native_target_executed']and not r['full_goal_complete']
  assert r['helper_call']['target']=='0x100013ac0'and r['helper_call']['modifier16']=='0xf08f'and r['helper_call']['target_executed']
  if C:
   assert r['helper_returned']and r['boundary']['pc']=='0x100483ca8'and r['boundary']['kind']=='before_uninitialized_saved_iterator_read'and not r['unexecuted_calls']and cache[0]==10
   u=r['uninitialized_read_boundary']['snapshot'];assert int(u['address'],16)==F+0x68 and u['size_bytes']==4 and u['known_mask_hex']=='00000000';assert r['fallback_record']is None;counts['normal_returns_before_unknown_iterator']+=1
  else:
   assert not r['helper_returned']and r['boundary']['pc']=='0x100011674'and r['boundary']['kind']=='before_zero_capability_fallback_call'and r['uninitialized_read_boundary']is None and cache[0]==9
   call,=r['unexecuted_calls'];assert call['target']=='0x10043bd18'and call['modifier16']=='0xb61a'and not call['target_executed'];Q=F-0x60+0x14;KF=(((Q&U32)^0x8515cfbd)*0xc7f6dca7)&U32;expected=[(KF+0x50ebc19f)&U32,KF^0x7b3d5095,(0x6d25-KF)&U32,KF^0x0862cc88];assert bytes.fromhex(r['fallback_record']['bytes_hex'])==struct.pack('<4I',*expected)and int(call['registers8'][0],16)==Q;counts['zero_capability_fallback_frontiers']+=1
  matrix[str((good[1],C!=0,r['helper_returned']))]+=1
  if j%32==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 # Accepted response versions differing only in byte0 have identical encodings.
 for placement in[0,0x100]:
  a,b=[r for r in rows[256:]if r['input']['placement']==placement and r['input']['words'][0]in[0x12345678,0x123456ff]];assert a['query_state_record']==b['query_state_record']and a['state_cache']==b['state_cache'];counts['low_version_byte_independence_pairs']+=1
 assert counts['normal_returns_before_unknown_iterator']==32 and counts['zero_capability_fallback_frontiers']==232 and counts['original_instruction_visits']==111616
 deps={n:sha(ROOT/n)for n in['daemon_query_state_contracts.json','daemon_query_state_profiles.json','daemon_query_state_proofs.json','daemon_query_state_symbolic.py','probe_daemon_query_state.py','recover_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_iokit_census_profiles.json','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_query_state_live_ida.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_query_state_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'query_capability_return_matrix':dict(matrix),'fresh_replays_sha256':sha(ROOT/'daemon_query_state_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False};(ROOT/'daemon_query_state_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
