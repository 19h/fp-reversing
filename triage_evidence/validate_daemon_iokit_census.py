#!/usr/bin/env python3
"""Independent source/census/fixup/proof checks and fresh query22/23 byte epochs.

O(B+C*(V+E+J*F)+I+256R) time,O(B+C*(V+E)+I+F+J*4096) space,
plus solver cost30 s/query;J is demand pages,F fixup records. Native ports,
IOKit/query providers, hardware PAC and full entry reachability remain unknown.
"""
import hashlib,json,struct,gc
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native,text_section
from probe_daemon_iokit_census import Queries,cases,P,LIMIT,API
from daemon_iokit_census_symbolic import queries
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from kext_port_tools import SOURCE as KSOURCE

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def audit(r,counts):
 state={};known=set();prov={};events={};models={m['source_visit_index']:m for m in r['API_models']};F=int(r['frame_SP'],16)
 for e in r['initial_private_fixtures']:
  a=int(e['address'],16)
  for j,b in enumerate(bytes.fromhex(e['bytes_hex']),a):state[j]=b;known.add(j);prov[j]=3
 def at(a,n):
  if P<=a<a+n<=LIMIT:return bytes(state.get(j,0xa5)for j in range(a,a+n))
  if n==8 and a in FIXUPS:
   t=FIXUPS[a]['target'];v=API if t=='IOKit/_IOConnectCallStructMethod'else t if isinstance(t,int)else 0x7c100000;return struct.pack('<Q',v)
  return IMAGE.read(a,n)
 for field,kind in[('source_reads','read'),('source_writes','write')]:
  for e in r[field]:events.setdefault(e['source_visit_index'],[]).append((kind,e))
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_instruction_byte_checks']+=4
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert at(a,n).hex()==e['bytes_hex']
    if P<=a<a+n<=LIMIT:assert all(j in known for j in range(a,a+n))
    if 'original_fixup'in e:assert FIXUPS[a]==e['original_fixup']
    counts['source_read_epochs']+=1
   else:
    assert P<=a<a+n<=LIMIT;b=bytes.fromhex(e['after_hex']);assert len(b)==n
    for j,byte in enumerate(b,a):state[j]=byte;known.add(j);prov[j]=1
    counts['source_write_epochs']+=1
  if ix in models:
   m=models[ix];assert not events.get(ix)and at(F+0x70,8)==struct.pack('<Q',4);counts['source_capacity_reset_before_API']+=1
   for e in m['modeled_writes']:
    a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);assert P<=a<a+len(b)<=LIMIT
    for j,byte in enumerate(b,a):state[j]=byte;known.add(j);prov[j]=2
    counts['API_write_epochs']+=1
 for field in['query_words','returned_size']:
  s=r[field];a=int(s['address'],16);n=s['size_bytes'];assert at(a,n).hex()==s['bytes_hex']and bytes(int(j in known)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex']
 counts['independent_byte_reconstructed_cases']+=1

def main():
 c=read('daemon_iokit_census_contracts.json');p=read('daemon_iokit_census_profiles.json');proof=read('daemon_iokit_census_proofs.json');counts=Counter();matrix=Counter()
 for obj,name in[(c,'recover_daemon_iokit_census.py'),(p,'probe_daemon_iokit_census.py'),(proof,'prove_daemon_iokit_census.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_daemon_source_spans']+=1
 a,n=text_section();raw=IMAGE.read(a,n);pcs=[]
 for off in range(0,n-4,4):
  if struct.unpack_from('<II',raw,off)==(0xd28f4d91,0xd73f0911):pcs.append(hex(a+off+4))
 cc=c['census'];assert hashlib.sha256(raw).hexdigest()==cc['text_sha256']and pcs==[r['call_PC']for r in cc['candidates']]and len(pcs)==24;counts['independent_whole_text_four_byte_units']=n//4;counts['exact_syntactic_candidates']=24
 for row in cc['candidates']:
  now=native('candidate',int(row['start'],16),int(row['end'],16));assert all(now[k]==row[k]for k in now)and not row['target_proved_by_modifier'];counts['bounded_candidate_source_windows']+=1
 counts['windows_preparing_21_22_23_or_26']=sum(r['literal_W1_candidate']in['0x15','0x16','0x17','0x1a']for r in cc['candidates']);assert counts['windows_preparing_21_22_23_or_26']==12 and not any(r['literal_W1_candidate']=='0x12'for r in cc['candidates'])
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),TABLE,0);assert all(now[k]==b[k]for k in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_inputs_checked']+=256
 assert binding(0x1010a0640)==c['API_binding']and verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_dispatch_and_root_fixups']=len(c['original_fixup_records']['records']);assert len(c['modifier_collision_pointers'])==4;counts['same_modifier_original_pointer_slots']=4
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and sha(KSOURCE)==c['kext_sha256'];entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for s in c['kext_spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);counts['original_kext_source_spans']+=1
 for q in c['kext_query_contracts']:
  for n in['descriptor_pointer','method_pointer','provider_slot']:assert pointer(k,int(q[n]['slot'],16))==q[n]
  assert function(k,entry,int(q['provider_slot']['target'],16))==q['provider_stub'];record=int(q['descriptor_pointer']['target'],16);assert k.read(record,48).hex()==q['descriptor_original48_hex'];counts['kext_query_routes_verified']+=1
 assert k.symbols([int(a,16)for a in c['exact_kext_symbols']])==c['exact_kext_symbols']
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==13 and lifts==proof['source_lift_counts']
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 inputs=list(cases());assert len(inputs)==256 and[r['input']for r in p['cases']]==inputs;rows=[]
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Queries(case);r=f.run();del f;assert r==retained;rows.append(r);audit(r,counts);counts['fresh_cases']+=1;counts['original_instruction_visits']+=len(r['source_visits']);assert not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete']and[r['API_models'][n]['selector']for n in range(2)]==[22,23]
  good=[s==0 and z==4 for s,z in case['responses']];matrix[str(tuple(good))]+=1;F=int(r['frame_SP'],16);values=[case['words'][n]if good[n]else 0 for n in range(2)];raw=bytes.fromhex(r['query_words']['bytes_hex']);known=bytes.fromhex(r['query_words']['known_mask_hex']);prov=bytes.fromhex(r['query_words']['provenance_hex']);assert raw[:4]==struct.pack('<I',values[0])and raw[8:]==struct.pack('<I',values[1])and raw[4:8]==b'\xa5'*4 and known==b'\1'*4+bytes(4)+b'\1'*4 and prov[:4]==bytes([2 if good[0]else 1])*4 and prov[8:]==bytes([2 if good[1]else 1])*4;counts['unknown_gap_preserved_cases']+=1
  assert int(r['boundary']['registers31'][8],16)==values[1]and int(r['boundary']['registers31'][20],16)==0x4ef4 and r['boundary']['SP']==r['frame_SP']and r['boundary']['pc']=='0x1003c39b0';counts['joint_query_consumer_frontiers']+=1
  for which,m in enumerate(r['API_models']):
   assert not m['native_target_executed']and m['binding']==c['API_binding']and[int(x,16)for x in m['registers8'][:6]]==[0x5804,22+which,0,0,F+(0x64 if which==0 else 0x6c),F+0x70];counts['API_response_models_checked']+=1
   s,z=case['responses'][which];assert int(m['status32_fixture'],16)==s and int(m['returned_size64_fixture'],16)==z and len(m['modeled_writes'])==(2 if good[which]else 1)
   clears=[e for e in r['source_writes']if e['pc']==('0x10062875c'if which==0 else'0x1004d6c00')];assert len(clears)==(0 if good[which]else 1)
   if good[which]:counts['successful_status_size_query_responses']+=1
   else:counts['source_failure_output_clears']+=1
   if z==0x100000004:assert not good[which];counts['high_word_size_mismatch_responses']+=1
  if not good[0]:counts['second_queries_after_first_query_rejection']+=1
  if j%32==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==256 and counts['original_instruction_visits']==34464 and counts['API_response_models_checked']==512 and counts['source_failure_output_clears']==448 and counts['high_word_size_mismatch_responses']==128 and counts['second_queries_after_first_query_rejection']==224
 deps={n:sha(ROOT/n)for n in['daemon_iokit_census_contracts.json','daemon_iokit_census_profiles.json','daemon_iokit_census_proofs.json','daemon_iokit_census_symbolic.py','probe_daemon_iokit_census.py','recover_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_iokit_census_live_ida.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_replays.json').write_text(json.dumps(out,indent=2)+'\n');out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'independent_query_acceptance_matrix':dict(matrix),'fresh_replays_sha256':sha(ROOT/'daemon_iokit_census_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_port_identity_proved':False,'actual_selector18_caller_established':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
