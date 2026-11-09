#!/usr/bin/env python3
"""Independent byte/knownness/owner/ABI/epoch/link/flag and source proof checks.
O(artifact bytes+C*(visits+events+N)) time,O(largest JSON+N+events) space;
30 s/query. No target/native operation executes.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from prove_daemon_arena_storage import obligations,M
from probe_daemon_arena_storage import Storage,cases,D,N,P
from probe_daemon_arena_entry import READS
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def audit(r,counts):
 H=int(r['heap_snapshot']['address'],16);F=int(r['frame_SP'],16);data={};prov={};backing={};events={};snaps={};timeline=[]
 def put(a,b,p):
  for j,x in enumerate(b,a):data[j]=x;prov[j]=p
 for x in r['initial_private_fixtures']+r['initial_image_fixtures']:put(int(x['address'],16),bytes.fromhex(x['bytes_hex']),3)
 for x in r['unknown_backing_storage']:
  for j,b in enumerate(bytes.fromhex(x['bytes_hex']),int(x['address'],16)):assert j not in data;backing[j]=b
 def get(a,n,dead=False):
  if H<=a<H+((N+4095)&~4095):assert a+n<=H+N and all(j in data for j in range(a,a+n));return bytes(data[j]for j in range(a,a+n))
  if P<=a<a+n<=P+0x10000:
   assert all((j not in data and j in backing)if dead else j in data for j in range(a,a+n));return bytes(data.get(j,backing.get(j,0xa5))for j in range(a,a+n))
  b=bytearray(IMAGE.read(a,n))
  for at in range(a&~7,a+n,8):
   if at in FIXUPS:
    t=FIXUPS[at]['target'];raw=struct.pack('<Q',t if isinstance(t,int)else 0x7c100000)
    for j in range(max(a,at),min(a+n,at+8)):b[j-a]=raw[j-at]
  return bytes(data.get(j,b[j-a])for j in range(a,a+n))
 for field,k in [('source_reads','read'),('source_writes','write')]:
  for x in r[field]:events.setdefault(x['source_visit_index'],[]).append((k,x))
 for x in r['frame_snapshots']:snaps.setdefault(x['pc'],[]).append(x['frame'])
 for ix,v in enumerate(r['source_visits']):
  assert ix==v['source_visit_index']and IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_visits']+=1
  for kind,e in events.get(ix,[]):
   a=int(e['address'],16);n=e['size_bytes'];assert e['pc']==v['pc']
   if kind=='read':
    dead=int(e['pc'],16)in READS;assert get(a,n,dead).hex()==e['bytes_hex']
    if dead:assert a==F+READS[int(e['pc'],16)]and e['known_mask_hex']=='00'*8;counts['dead_load_epochs_checked']+=1
    if H<=a<H+N:counts['source_heap_reads']+=1
    counts['source_read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if H<=a<H+((N+4095)&~4095):assert a+n<=H+N
    if e['pc']in ['0x10032a520','0x100322440','0x100322444','0x10046c750']:
     timeline.append({'pc':e['pc'],'source_visit_index':ix,'address':hex(a),'gate_word32':hex(int.from_bytes(get(0x1010b5de0,4),'little')),'known_heap_bytes_before':sum(j in data for j in range(H,H+N))})
    put(a,b,1);counts['source_write_epochs']+=1
  if v['pc']in snaps:
   s=snaps[v['pc']].pop(0);a=int(s['address'],16);n=s['size_bytes'];assert bytes(data.get(j,backing.get(j,0xa5))for j in range(a,a+n)).hex()==s['bytes_hex']and bytes(int(j in data)for j in range(a,a+n)).hex()==s['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==s['provenance_hex'];counts['frame_snapshots_reconstructed']+=1
 h=r['heap_snapshot'];raw=zlib.decompress(base64.b64decode(h['bytes_zlib_base64']));known=zlib.decompress(base64.b64decode(h['known_mask_zlib_base64']));pr=zlib.decompress(base64.b64decode(h['provenance_mask_zlib_base64']));assert len(raw)==len(known)==len(pr)==N
 assert raw==bytes(data.get(j,h['initial_backing_byte'])for j in range(H,H+N))and known==bytes(int(j in data)for j in range(H,H+N))and pr==bytes(prov.get(j,0)for j in range(H,H+N));assert sum(known)==h['known_byte_count']==48 and h['unknown_byte_count']==89952;counts['heap_bytes_reconstructed']+=N;counts['heap_known_bytes_checked']+=48
 expected=set(range(16))|set(range(24,40))|set(range(N-24,N-8));assert {j for j,x in enumerate(known)if x}==expected
 descriptor=r['descriptor'];assert get(D,88).hex()==descriptor['bytes_hex'];mask=bytes(prov.get(j,0)==1 for j in range(D,D+88));assert mask.hex()==descriptor['source_written_mask_hex']and sum(mask)==80 and mask[24:32]==bytes(8);counts['descriptor_source_bytes_checked']+=80
 q=lambda a:int.from_bytes(get(a,8),'little')
 for a,value in [(D+8,H),(D+72,H),(D+80,H),(H+24,D+48),(H+32,D+48),(H,M),(H+8,M+N-24),(H+N-24,M+N-24),(H+N-16,M^(1<<63))]:assert q(a)==value;counts['pointer_and_marker_fields_checked']+=1
 for s,pc in zip(r['cached_arena_words_at_boundary'],['0x100322440','0x100322444']):
  a=int(s['address'],16);assert get(a,8).hex()==s['bytes_hex']==struct.pack('<Q',H).hex()and s['known_mask_hex']==s['provenance_hex']=='01'*8;ws=[e for e in r['source_writes']if e['address']==hex(a)];assert ws[-1]['pc']==pc;counts['source_cached_owner_fields_checked']+=1
 assert [t['pc']for t in timeline]==['0x10032a520','0x100322440','0x100322444','0x10046c750']and [t['known_heap_bytes_before']for t in timeline]==[0,48,48,48]and all(t['gate_word32']=='0xa94ef'for t in timeline);counts['publication_order_timelines_checked']+=1
 assert r['readiness_hex']==get(0x1010c5798,1).hex()=='01'and r['boundary']['pc']=='0x1003ecb8c';counts['cases_byte_reconstructed']+=1;return timeline
def main():
 c,p,q=map(read,['daemon_arena_storage_contracts.json','daemon_arena_storage_profiles.json','daemon_arena_storage_proofs.json']);counts=Counter();timelines=[]
 for obj,n in [(c,'recover_daemon_arena_storage.py'),(p,'probe_daemon_arena_storage.py'),(q,'prove_daemon_arena_storage.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 assert verify_original_fixups([int(x['address'],16)for x in c['source_fixup_records']['records']])==c['source_fixup_records'];counts['original_fixups_verified']=len(c['source_fixup_records']['records'])
 live=read('daemon_arena_storage_live_ida.json');assert live['target']=='6b117c693e3b'and not live['idb_mutated']
 for row in live['instructions']:assert IMAGE.read(int(row['address'],16),len(bytes.fromhex(row['bytes'])))==bytes.fromhex(row['bytes']);counts['live_IDB_source_rows_matched']+=1
 qs,lifts,fix,footprint=obligations(c);assert lifts==q['source_lift_counts']and footprint==q['post_malloc_write_footprint']and verify_original_fixups(fix)==q['source_fixup_records']
 pw=q['premise_witness'];assert sha(ROOT/pw['file'])==pw['sha256'];s=z3.Solver();s.add(*z3.parse_smt2_string((ROOT/pw['file']).read_text()));assert str(s.check())==pw['result']=='sat';counts['premise_sat_witnesses']=1
 for(n,pred),row in zip(qs,q['proofs']):
  assert n==row['name']and row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256'];orig=z3.parse_smt2_string((ROOT/row['original_file']).read_text());assert len(orig)==1
  for form in [pred,*orig,*z3.parse_smt2_string((ROOT/row['file']).read_text()),z3.Xor(pred,orig[0])]:
   s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(form));assert str(s.check())=='unsat',n
  counts['source_proof_pairs_unsat']+=1
 old=read('daemon_arena_entry_profiles.json');cs=list(cases());assert len(cs)==len(p['cases'])==64
 for j,(cfg,r)in enumerate(zip(cs,p['cases'])):
  assert cfg==r['input']and not r['native_allocator_executed']and not r['native_target_executed'];timeline=audit(r,counts);timelines.append({'case':j,'events':timeline});base={k:v for k,v in cfg.items()if k not in ['heap_placement','heap_backing_byte']};prior=next(x for x in old['cases']if x['input']==base);K=len(prior['source_visits']);assert K==375 and r['source_visits'][:K]==prior['source_visits']and r['source_reads'][:len(prior['source_reads'])]==prior['source_reads']and r['source_writes'][:len(prior['source_writes'])]==prior['source_writes'];counts['prior_prefixes_preserved']+=1
  assert len(r['allocation_models'])==1;m=r['allocation_models'][0];assert m['binding']==binding(0x10109ff58)and m['registers8'][0]=='0x15f90'and m['known_owner_bytes_at_return']==0 and not m['modeled_writes']and not m['native_target_executed']and m['preserved_before']==m['preserved_after'];counts['malloc_return_and_preserved_ABI_checked']+=1
  es=[e for e in r['source_reads']if e['source_visit_index']==m['source_visit_index']-4];assert len(es)==1 and es[0]['pc']=='0x10032a4d8'and es[0]['address']=='0x10109ff58'and es[0]['original_fixup']['target']=='libSystem/_malloc';counts['allocator_binding_load_epochs_checked']+=1
  if j in [0,1,2,7,16,31,48,63]:assert Storage(cfg).run()==r;counts['fresh_replayed_cases']+=1
  counts['cases_checked']+=1
 assert counts['source_heap_reads']==0
 deps=['daemon_arena_storage_contracts.json','daemon_arena_storage_profiles.json','daemon_arena_storage_proofs.json','daemon_arena_storage_live_ida.json','probe_daemon_arena_storage.py','prove_daemon_arena_storage.py','daemon_arena_entry_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'publication_timelines':timelines,'source_lift_counts':lifts,'post_malloc_write_footprint':footprint,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_storage_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
