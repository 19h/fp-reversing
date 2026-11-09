#!/usr/bin/env python3
"""Independent source/owner/representation/model/readback checks. Rebuild every
source obligation, solve both persisted forms, verify old arbitrary-word cases,
and replay two new compositions. O(artifact bytes+events+SMT+fresh visits) time;
O(largest trace+RAM) space. No native API, daemon, kernel or IDB mutation.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from replay_daemon_descriptor_producers import unpack
from replay_daemon_registry_lookup import RegistryReplay
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_context_lock import ida_output
from daemon_seed_material_symbolic import decode
from prove_daemon_registry_lookup import obligations

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 if'source_sha256'in r:assert r['source_sha256']==sha(SOURCE)
 return r
def main():
 s=checked('daemon_registry_lookup_source.json','capture_daemon_registry_lookup.py');p=checked('daemon_registry_lookup_profiles.json','probe_daemon_registry_lookup.py');ph=checked('daemon_registry_lookup_payloads.json','probe_daemon_registry_lookup_payloads.py');c=checked('daemon_registry_lookup_contracts.json','recover_daemon_registry_lookup.py');proofs=checked('daemon_registry_lookup_proofs.json','prove_daemon_registry_lookup.py');r1=checked('daemon_registry_lookup_replays.json','replay_daemon_registry_lookup.py');r2=checked('daemon_registry_lookup_payload_replays.json','replay_daemon_registry_lookup_payloads.py');counts=Counter();APIs=Counter();boundaries=Counter();writes=Counter();totalA64=Counter();P=0x6800000000;KEY=P+0x10000;PAY=P+0x18000;OBJ=P+0x20000;ENC64=0xe3b88695c0d52dbc
 assert c['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for row in c['source_spans']:
  a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(a,len(b))==b and hashlib.sha256(b).hexdigest()==row['sha256'];assert[(hex(i.address),i.mnemonic,i.op_str)for i in CS.disasm(b,a)]==[(i['pc'],i['mnemonic'],i['operands'])for i in row['instructions']];counts['source_spans_checked']+=1
 raw=IMAGE.read(int(s['text_address'],16),s['text_size_bytes']);assert hashlib.sha256(raw).hexdigest()==s['text_sha256']
 for off,row in s['literal_LDR_Xn_SP_census'].items():
  want=0xf94003e0|((int(off,16)//8)<<10);expected=[hex(int(s['text_address'],16)+j*4)for j,(w,)in enumerate(struct.iter_unpack('<I',raw))if w&0xffffffe0==want];assert expected==[x['start']for x in row['matches']];counts['bounded_frame_slot_census_matches']+=len(expected)
  for x in row['matches']:assert IMAGE.read(int(x['start'],16),len(bytes.fromhex(x['bytes_hex']))).hex()==x['bytes_hex']
 assert[len(s['literal_LDR_Xn_SP_census'][hex(off)]['matches'])for off in[0x26d0,0x24a8,0x26b0]]==[11,13,28];assert len(s['direct_ADRP_page_census']['matches'])==227 and all(r['next_mnemonic']=='add'and r['next_operands'].endswith('#0x800')for r in s['direct_ADRP_page_census']['matches']);counts['bounded_ADRP_page_candidates_checked']=227
 for name,rows in s['bias_MOVN_MOVK_census']['matches'].items():
  assert len(rows)==1
  for x in rows:assert IMAGE.read(int(x['start'],16),len(bytes.fromhex(x['bytes_hex']))).hex()==x['bytes_hex'];counts['bias_construction_candidates_checked']+=1
 a=s['saved_annotation_search'];assert sha(Path(a['path']))==a['sha256']and a['entries']==4920 and a['exact_target_matches']==[];counts['saved_annotation_entries_checked']=4920
 for b in c['banks_exhaustive256']:
  left=IMAGE.read(int(b['left'],16),256);right=IMAGE.read(int(b['right'],16),256);assert all(j^right[left[j]^int(b['key'],16)]==int(b['constant'],16)for j in range(256));assert qword(int(b['slot'],16))==b['target'];counts['exhaustive_bank_input_cases']+=256
 assert verify_used_fixups({int(x['address'],16)for x in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records'])
 for d in c['dispatch_slots']:assert hex(qword(int(d['slot'],16)))==d['target'];counts['dispatch_slots_checked']+=1
 for row in proofs['proofs']:
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/row[fk];assert sha(f)==row[hk];solver=z3.Solver();solver.set(timeout=30000);solver.from_file(str(f));assert str(solver.check())=='unsat',row['name'];counts['SMT_file_queries_unsat']+=1
 rebuilt,lifts=obligations(s);assert lifts==proofs['source_lift_counts']and[n for n,pred in rebuilt]==[r['name']for r in proofs['proofs']]
 for n,pred in rebuilt:
  solver=z3.Solver();solver.set(timeout=30000);solver.add(pred);assert str(solver.check())=='unsat',n;counts['rebuilt_source_obligations_unsat']+=1
 counts['source_lift_visits']=sum(lifts.values());assert len(proofs['nonempty_premise_witnesses'])==3
 prior=json.loads((ROOT/'daemon_mode471c_lifecycle_profiles.json').read_text())
 for row in prior['cases']:
  t=unpack(row);F=int(t['initial_SP'],16);a=next(e['value']for st in t['steps']if st['pc']=='0x1009d0304'for e in st['events']if e['kind']=='write');b=next(e['value']for st in t['steps']if st['pc']=='0x100975790'for e in st['events']if e['kind']=='write');solver=z3.Solver();solver.set(timeout=30000);solver.add((decode(a,F)^ENC64)!=decode(b,F));assert str(solver.check())=='unsat';counts['prior_symbolic_representation_relations_unsat']+=1
 for dataset in[p,ph]:
  for row in dataset['cases']:
   cfg=row['configuration'];t=unpack(row);F=int(t['initial_SP'],16);U=cfg['input_word'];N=len(cfg['records']);M=len(cfg['payload_keys']);assert not t['callback_pending']and t['definitions']==[];counts['continuous_cases_checked']+=1;counts['continuation_source_visits']=counts['continuation_source_visits']+len(t['steps']);counts['private_byte_origins_retained']+=len(t['origins']);counts['API_byte_origins_retained']+=len(t['API_origins']);assert all(0x6b00000000<=F+x['offset']<0x6b00100000 for x in t['API_origins'])
   assert next(x['bytes_hex']for x in row['prefix']['initial_private_fixtures']if x['address']=='0x6800001000')==(U^0x9898989898989898).to_bytes(8,'big').hex()
   expect={'0x1009d0304':U^ENC64,'0x100975790':U}
   for pc,value in expect.items():assert next(e['value']for st in t['steps']if st['pc']==pc for e in st['events']if e['kind']=='write')=={'hex':value.to_bytes(8,'little').hex()};counts['new_word_representation_values_checked']+=1
   taghit=next((j for j,k in enumerate(cfg['records'])if k['tag32']==U&0xffffffff),None);keyreads=[int(e['address'],16)for st in t['steps']if st['pc']=='0x100bb01f0'for e in st['events']if e['kind']=='read'];assert keyreads==[KEY+16*j+8 for j in range(N if taghit is None else taghit+1)];counts['outer_scan_read_sequences_checked']+=1
   payloadhit=None
   if taghit is not None:payloadhit=next((j for j,key in enumerate(cfg['payload_keys'])if key==cfg['records'][taghit]['key64']),None)
   payloadreads=[int(e['address'],16)for st in t['steps']if st['pc']=='0x10095e950'for e in st['events']if e['kind']=='read'];expected=[]if taghit is None else[PAY+32*j for j in range(M if payloadhit is None else payloadhit+1)];assert payloadreads==expected;counts['inner_scan_read_sequences_checked']+=1
   selected=[int.from_bytes(bytes.fromhex(e['value']['hex']),'little')for st in t['steps']if st['pc']=='0x100b328c8'for e in st['events']if e['kind']=='write'];assert selected==([]if payloadhit is None else[payloadhit]);counts['selected_index_sequences_checked']+=1
   for st in t['steps']:
    pc=int(st['pc'],16);assert IMAGE.read(pc,4).hex()==st['bytes_hex'];counts['source_opcodes_checked']+=1
    for e in st['events']:
     a=int(e['address'],16);n=e['size_bytes']
     if KEY<=a<KEY+0x1000:assert KEY<=a<a+n<=KEY+16*N;counts['key_owner_effects_checked']+=1
     if PAY<=a<PAY+0x1000:assert M>0 and PAY<=a<a+n<=PAY+32*M;counts['payload_owner_effects_checked']+=1
     if OBJ<=a<OBJ+0x1000:assert cfg.get('object_header32')is not None and OBJ<=a<a+n<=OBJ+872;counts['object_owner_effects_checked']+=1
     if e['kind']=='write'and(KEY<=a<KEY+0x1000 or PAY<=a<PAY+0x1000 or OBJ<=a<OBJ+0x1000):writes[hex(a)]+=1
   link_reads=[e['value']for st in t['steps']if st['pc']=='0x100a264dc'for e in st['events']if e['kind']=='read'];head_writes=[e['value']for st in t['steps']if st['pc']=='0x100a264e0'for e in st['events']if e['kind']=='write'];assert head_writes==link_reads
   if cfg.get('object_header32')==0x8b3dc651:assert len(head_writes)==1;counts['head_link_replacements_checked']+=1
   else:assert head_writes==[]
   boundary=t['boundary'];boundaries[boundary['pc']]+=1;names=[x['name']for x in t['api_models']];APIs.update(names);assert names.count('pthread_rwlock_wrlock')==1 and names.count('malloc')==names.count('pthread_rwlock_init')==0
   if boundary['pc']=='0x10039c998':
    assert int(boundary['SP'],16)==int(row['prefix']['entry_SP'],16)and names.count('pthread_rwlock_unlock')==names.count('free')==1 and names.count('pthread_once')==2;assert t['retired_owners']==[{'address':'0x6800001000','size_bytes':8}];result=[e['value']for st in t['steps']if st['pc']=='0x10095f074'for e in st['events']];assert result==[{'hex':'009fc274'}];counts['returning_paths_checked']+=1
   else:assert names==['pthread_once','pthread_rwlock_wrlock']and t['retired_owners']==[]and 'unknown flags'in boundary['reason'];counts['partial_object_paths_checked']+=1
   assert boundary['kind']=='before_unresolved_source_effect'
 for r in[r1,r2]:
  assert r['all_checks_pass']
  subtotal=Counter()
  for row in r['cases']:assert row['all_checks_pass'];subtotal.update(row['verified_counts']);counts['independent_A64_replays']+=1
  assert dict(subtotal)==r['verified_totals'];totalA64.update(subtotal)
 for row in[p['cases'][38],ph['cases'][3]]:assert RegistryReplay(row,3).run()['all_checks_pass'];counts['fresh_composed_replays']+=1
 for name in['daemon_registry_lookup_live_ida.json','daemon_registry_lookup_more_ida.json','daemon_registry_lookup_unlink_ida.json']:
  data=json.loads((ROOT/name).read_text());assert not data['isError']
  for row in ida_output(data)['results']:
   b=bytes.fromhex(row['bytes']);assert IMAGE.read(int(row['address'],16),len(b))==b;counts['live_IDB_ranges_checked']+=1;counts['live_IDB_raw_bytes_checked']+=len(b)
   for i in row['instructions']:raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;counts['live_IDB_display_rows_checked']+=1;counts['live_IDB_partial_macro_rows']+=len(raw)<i.get('size',len(raw));counts['live_IDB_undecoded_byte_rows']+='size'not in i
 refs=json.loads((ROOT/'daemon_registry_lookup_ida_refs.json').read_text());assert not refs['isError']and ida_output(refs)['header']['candidates_scanned']==0;counts['IDB_direct_xref_queries_checked']=1
 assert len(p['cases'])==54 and len(ph['cases'])==10 and len(proofs['proofs'])==21;assert dict(boundaries)=={'0x10039c998':44,'0x100c744c4':14,'0x100b31cf0':2,'0x100c70cac':2,'0x100a2ae30':2};assert dict(writes)=={'0x6800018010':4};counts['distinct_continuation_retired_opcodes']=c['distinct_continuation_retired_opcodes'];counts['distinct_continuation_inspected_opcodes']=c['distinct_continuation_inspected_opcodes']
 deps=['daemon_registry_lookup_source.json','daemon_registry_lookup_profiles.json','daemon_registry_lookup_payloads.json','daemon_registry_lookup_contracts.json','daemon_registry_lookup_proofs.json','daemon_registry_lookup_replays.json','daemon_registry_lookup_payload_replays.json','replay_daemon_registry_lookup.py','prove_daemon_registry_lookup.py','daemon_mode471c_lifecycle_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'verified_counts':dict(counts),'API_counts':dict(APIs),'boundary_counts':dict(boundaries),'registry_owner_source_writes':dict(writes),'independent_A64_totals':dict(totalA64),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_registry_lookup_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'API_counts':dict(APIs),'boundaries':dict(boundaries)}),flush=True)
if __name__=='__main__':main()
