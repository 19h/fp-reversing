#!/usr/bin/env python3
"""Independent unknown-bit, epoch, liveness, prefix, ABI and source proof audit.
O(artifact bytes+visits+events+256) time,O(largest JSON+events) space;
30 s/solver query. No target import/native operations execute.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_arena_entry import liveness
from recover_daemon_iokit_census import native
from prove_daemon_arena_entry import obligations
from probe_daemon_arena_entry import ArenaEntry,cases,P,READS
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def audit(r,counts):
 data={};prov={};backing={};events={};snaps={}
 def put(a,b,p):
  for j,x in enumerate(b,a):data[j]=x;prov[j]=p
 for x in r['initial_private_fixtures']+r['initial_image_fixtures']:put(int(x['address'],16),bytes.fromhex(x['bytes_hex']),3)
 for x in r['unknown_backing_storage']:
  a=int(x['address'],16);assert x['known_mask_hex']=='00'*8
  for j,b in enumerate(bytes.fromhex(x['bytes_hex']),a):assert j not in data;backing[j]=b
 def get(a,n,dead=False):
  if P<=a<a+n<=P+0x10000:
   if dead:assert all(j not in data and j in backing for j in range(a,a+n))
   else:assert all(j in data for j in range(a,a+n)),('unproven read',hex(a),n)
   return bytes(data.get(j,backing.get(j,0xa5))for j in range(a,a+n))
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
    if dead:assert a==int(r['frame_SP'],16)+READS[int(e['pc'],16)]and n==8 and e['known_mask_hex']=='00'*8;counts['dead_load_epochs_checked']+=1
    if 'original_fixup'in e:assert FIXUPS[a]==e['original_fixup']
    counts['source_read_epochs']+=1
   else:assert len(bytes.fromhex(e['after_hex']))==n;put(a,bytes.fromhex(e['after_hex']),1);counts['source_write_epochs']+=1
  if v['pc']in snaps:
   ss=snaps[v['pc']].pop(0);a=int(ss['address'],16);n=ss['size_bytes'];assert bytes(data.get(j,backing.get(j,0xa5))for j in range(a,a+n)).hex()==ss['bytes_hex']and bytes(int(j in data)for j in range(a,a+n)).hex()==ss['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==ss['provenance_hex'];counts['frame_snapshots_reconstructed']+=1
 for s in r['dead_words_at_boundary']:
  a=int(s['address'],16);assert get(a,8,True).hex()==s['bytes_hex']and s['known_mask_hex']==s['provenance_hex']=='00'*8;counts['unknown_words_preserved']+=1
 assert get(0x1010b5ef0,8).hex()==r['descriptor_prefix8_hex']=='00'*8
 counts['cases_byte_reconstructed']+=1
def main():
 c,p,q=map(read,['daemon_arena_entry_contracts.json','daemon_arena_entry_profiles.json','daemon_arena_entry_proofs.json']);counts=Counter()
 for obj,n in [(c,'recover_daemon_arena_entry.py'),(p,'probe_daemon_arena_entry.py'),(q,'prove_daemon_arena_entry.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==q['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 assert liveness()==c['liveness'];counts['source_liveness_certificates']=len(c['liveness']);counts['liveness_instruction_checks']=sum(len(r['instructions'])for r in c['liveness'])
 b=c['malloc_bank'];now=selected(*[int(b[k],16)for k in ['left','right','key','additive','base','bias']]);assert all(now[k]==b[k]for k in now);counts['bank_inputs_checked']=256
 assert c['allocator_binding']==binding(0x10109ff58);assert verify_original_fixups([int(x['address'],16)for x in q['original_fixup_records']['records']])==q['original_fixup_records'];counts['original_fixups_verified']=len(q['original_fixup_records']['records'])
 live=read('daemon_arena_entry_live_ida.json');assert live['target']=='6b117c693e3b'and not live['idb_mutated']
 for row in live['instructions']:assert IMAGE.read(int(row['address'],16),len(bytes.fromhex(row['bytes'])))==bytes.fromhex(row['bytes']);counts['live_IDB_source_rows_matched']+=1
 qs,lifts,fix=obligations(c);assert lifts==q['source_lift_counts']and len(qs)==len(q['proofs'])
 for(n,pred),row in zip(qs,q['proofs']):
  assert n==row['name']and row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256'];orig=z3.parse_smt2_string((ROOT/row['original_file']).read_text());assert len(orig)==1
  for form in [pred,*orig,*z3.parse_smt2_string((ROOT/row['file']).read_text()),z3.Xor(pred,orig[0])]:
   s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(form));assert str(s.check())=='unsat',n
  counts['source_proof_pairs_unsat']+=1
 old=read('daemon_frame_entry_profiles.json');groups={};fresh=[];cs=list(cases());assert len(cs)==len(p['cases'])==32
 for j,(cfg,r)in enumerate(zip(cs,p['cases'])):
  assert cfg==r['input']and not r['allocator_executed']and not r['native_target_executed']and r['stop_reason']=='before_first_arena_malloc';audit(r,counts);assert r['boundary']['pc']=='0x10032a4e8'and int(r['boundary']['registers31'][0],16)==90000 and r['allocator_binding']==binding(0x10109ff58)
  base={k:v for k,v in cfg.items()if k!='unknown_words'};prior=next(x for x in old['cases']if x['input']==base);N=len(prior['source_visits']);assert N==287 and r['source_visits'][:N]==prior['source_visits']and r['source_reads'][:len(prior['source_reads'])]==prior['source_reads']and r['source_writes'][:len(prior['source_writes'])]==prior['source_writes'];counts['prior_prefixes_preserved']+=1
  for pc,slot,target,div in [('0x1003b5770',0x101086d58,0x1003c24b8,0x6587),('0x1003c24d8',0x101085358,0x10032a464,0xb9e1),('0x10032a4d8',0x10109ff58,'libSystem/_malloc',0x6aa4)]:
   es=[e for e in r['source_reads']if e['pc']==pc];assert len(es)==1 and es[0]['address']==hex(slot)and es[0]['original_fixup']['target']==target;counts['target_load_epochs_checked']+=1
  key=json.dumps(base,sort_keys=True);observed={'registers31':r['boundary']['registers31'],'SP':r['boundary']['SP'],'edges':r['source_edges'],'writes':r['source_writes']};assert key not in groups or groups[key]==observed;groups[key]=observed
  if j in [0,1,3,4,7,16,23,31]:assert ArenaEntry(cfg).run()==r;counts['fresh_replayed_cases']+=1;fresh.append(j)
  counts['cases_checked']+=1
 counts['unknown_pattern_equivalence_groups']=len(groups);assert len(groups)==8
 deps=['daemon_arena_entry_contracts.json','daemon_arena_entry_profiles.json','daemon_arena_entry_proofs.json','daemon_arena_entry_live_ida.json','probe_daemon_arena_entry.py','prove_daemon_arena_entry.py','recover_daemon_arena_entry.py','daemon_frame_entry_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replay_indices':fresh,'all_checks_pass':True,'native_target_executed':False,'allocator_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_entry_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts)}),flush=True)
if __name__=='__main__':main()
