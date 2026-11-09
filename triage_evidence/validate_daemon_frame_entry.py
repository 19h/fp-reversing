#!/usr/bin/env python3
"""Independent byte/epoch/frame/CAS/fill/fixture-correction and proof checks.
O(artifact bytes+V+events+replay visits+256R) time,O(largest JSON+events) space;
30 s/solver query. No native target operations or historical producer rerun.
"""
import hashlib,json,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from probe_daemon_frame_entry import FrameEntry,Fill,CorrectedPair,cases,P
from prove_daemon_frame_entry import obligations
from validate_daemon_iokit_sync import audit as pair_audit
from validate_daemon_rwlock_lifecycle import extra,status
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def audit(r,counts):
 data={};prov={};events={};snapshots={}
 def put(a,b,p):
  for j,v in enumerate(b,a):data[j]=v;prov[j]=p
 for e in r.get('initial_private_fixtures',[])+r.get('initial_image_fixtures',[]):put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),3)
 def get(a,n):
  if P<=a<a+n<=P+0x10000:assert all(j in data for j in range(a,a+n)),('unknown private read',hex(a),n);return bytes(data[j]for j in range(a,a+n))
  b=bytearray(IMAGE.read(a,n))
  for at in range(a&~7,a+n,8):
   if at in FIXUPS:
    t=FIXUPS[at]['target'];value=t if isinstance(t,int)else 0x7c100000;raw=struct.pack('<Q',value)
    for j in range(max(a,at),min(a+n,at+8)):b[j-a]=raw[j-at]
  return bytes(data.get(j,b[j-a])for j in range(a,a+n))
 for field,k in [('source_reads','read'),('source_writes','write')]:
  for e in r[field]:events.setdefault(e['source_visit_index'],[]).append((k,e))
 for s in r.get('frame_snapshots',[]):snapshots.setdefault(s['pc'],[]).append(s)
 for ix,v in enumerate(r['source_visits']):
  assert ix==v['source_visit_index']and IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_instruction_bytes_checked']+=4
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':assert get(a,n).hex()==e['bytes_hex'];counts['source_read_epochs']+=1
   else:assert len(bytes.fromhex(e['after_hex']))==n;put(a,bytes.fromhex(e['after_hex']),1);counts['source_write_epochs']+=1
  if v['pc']in snapshots:
   ss=snapshots[v['pc']].pop(0)['frame'];a=int(ss['address'],16);n=ss['size_bytes'];assert bytes(data.get(j,0xa5)for j in range(a,a+n)).hex()==ss['bytes_hex']and bytes(int(j in data)for j in range(a,a+n)).hex()==ss['known_mask_hex']and bytes(prov.get(j,0)for j in range(a,a+n)).hex()==ss['provenance_hex'];counts['frame_snapshots_reconstructed']+=1
 counts['independent_byte_reconstructed_cases']+=1
def main():
 c,p,q=map(read,['daemon_frame_entry_contracts.json','daemon_frame_entry_profiles.json','daemon_frame_entry_proofs.json']);counts=Counter();boundaries=Counter()
 for obj,n in [(c,'recover_daemon_frame_entry.py'),(p,'probe_daemon_frame_entry.py'),(q,'prove_daemon_frame_entry.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s;counts['original_source_spans']+=1
 for b in c['bank_rules']:
  now=selected(*[int(b[k],16)for k in ['left','right','key','additive','base','bias']]);assert all(now[k]==b[k]for k in now);counts['bank_inputs_checked']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records'];counts['original_fixups_verified']=len(c['original_fixup_records']['records']);counts['live_IDB_source_rows_matched']=len(c['live_IDB_source_rows_matched'])
 qs,lifts=obligations(c);assert lifts==q['source_lift_counts']and len(qs)==len(q['proofs'])
 for(n,pred),row in zip(qs,q['proofs']):
  assert n==row['name']and row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
  original=z3.parse_smt2_string((ROOT/row['original_file']).read_text());assert len(original)==1
  for formula in [pred,*original,*z3.parse_smt2_string((ROOT/row['file']).read_text()),z3.Xor(pred,original[0])]:
   s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(formula));assert str(s.check())=='unsat',n
  counts['source_proof_pairs_unsat']+=1
 assert len(p['cases'])==96
 for ix,(cfg,r)in enumerate(zip(cases(),p['cases'])):
  assert cfg==r['input'];audit(r,counts);counts['entry_cases']+=1;counts['entry_source_visits']+=len(r['source_visits']);F=int(r['frame_SP'],16);E=int(r['entry_SP'],16);assert E-F==3040 and r['boundary']['SP']==hex(F)
  initial=r['frame_snapshots'][0]['frame'];raw=bytes.fromhex(initial['bytes_hex']);assert int.from_bytes(raw[0x5c0:0x5c8],'little')==16 and int.from_bytes(raw[0xb28:0xb30],'little')==cfg['guard'];assert int(r['boundary']['registers31'][29],16)==F+0xbd0
  for off,j in [(0xb80,28),(0xb88,27),(0xb90,26),(0xb98,25),(0xba0,24),(0xba8,23),(0xbb0,22),(0xbb8,21),(0xbc0,20),(0xbc8,19),(0xbd0,29),(0xbd8,30)]:assert int.from_bytes(raw[off:off+8],'little')==int(r['entry_registers31'][j],16);counts['GPR_saved_slots']+=1
  for off,j in [(0xb40,15),(0xb48,14),(0xb50,13),(0xb58,12),(0xb60,11),(0xb68,10),(0xb70,9),(0xb78,8)]:assert int.from_bytes(raw[off:off+8],'little')==int(r['entry_Q_registers32'][j],16)&((1<<64)-1);counts['SIMD_saved_low64_slots']+=1
  D=((cfg['B']-cfg['A']-(F+0x658))^0x73d046208eaed1a6)*0xa5cd4cf&((1<<64)-1)
  for pc in ['0x100450678','0x10045067c']:w=next(w for w in r['source_writes']if w['pc']==pc);assert int.from_bytes(bytes.fromhex(w['after_hex']),'little')==D;counts['controller_publications']+=1
  for a in r['atomic_visits']:
   before=int.from_bytes(bytes.fromhex(a['before32']),'little');expected=int(a['expected32'],16);desired=int(a['desired32'],16);assert int(a['returned_expected_register32'],16)==before and int.from_bytes(bytes.fromhex(a['after32']),'little')==(desired if before==expected else before);counts['single_thread_CAS_transitions']+=1
  if cfg['gate']!=0x5d96:assert r['stop_reason']=='before_retry_after_failed_CAS'and r['source_edges'][-1]['target']=='0x10035df48';counts['failed_CAS_retry_cases']+=1
  boundaries[r['boundary']['pc']]+=1
  if ix in [0,1,2,3,12,48,49,50]:assert FrameEntry(cfg).run()==r;counts['fresh_entry_replays']+=1
 assert len(p['fill_cases'])==272
 for ix,r in enumerate(p['fill_cases']):
  cfg=r['input'];a=int(r['destination'],16);n=cfg['length'];assert r['bytes_hex']==bytes([cfg['byte']]*n).hex()and sum(w['size_bytes']for w in r['source_writes'])==n and not r['source_reads']
  for w in r['source_writes']:assert a<=int(w['address'],16)<int(w['address'],16)+w['size_bytes']<=a+n
  for v in r['source_visits']:assert IMAGE.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['fill_source_visits']+=1
  if n==1024 and cfg['alignment']==0 and cfg['byte']==0:assert int(r['result_X0'],16)==a+n;counts['aligned_zero_1024_cases']+=1
  if ix in [0,1,32,33,34,271]:assert Fill(cfg).run()==r;counts['fresh_fill_replays']+=1
  counts['fill_cases']+=1
 for r in p['corrected_pair_cases']:
  pair_audit(r,counts);extra(r,counts);C=int(r['caller_SP'],16);assert int(r['caller_FP'],16)==C+0xbd0 and int(r['creator_record']['address'],16)==C+0xaf8
  reads=[e for e in r['source_reads']if e['address']==hex(C+0x390)];assert reads and all(int.from_bytes(bytes.fromhex(e['bytes_hex']),'little')==0x1010b7dd8 for e in reads)
  for j,key in enumerate(['primary_value','secondary_value']):assert int(r[key],16)==(P+0x2000+0x1000*j if r['input']['steps'][j]['init_status']==0 else r['input']['old_cell'])
  assert r['state_cache']['bytes_hex'][:2]==('09'if r['input']['steps'][1]['init_status']==0 else f"{r['input']['initial_state']:02x}")
  assert CorrectedPair(r['input']).run()==r;counts['corrected_pair_cases_and_fresh_replays']+=1
 assert len(c['historical_startup_readback'])==3
 expected={0x28:0x1010b6360,0x348:0x100f4e190,0x350:0x100e99700,0x360:0x101031fa0,0x368:0x100fc4230,0x370:0x100f4e390,0x378:0x100e99a00,0x390:0x1010b7dd8,0x398:0x1010c4670,0x5c0:16}
 for h in c['historical_startup_readback']:
  assert h['startup_returned']and 'zero-filled'in h['stack_initialization'];fields=h['events'][0]['fields'];assert {int(e['offset_bytes'],16):int(e['value64'],16)for e in fields}==expected
  assert h['events'][1]['before64']=='0x10'and h['events'][1]['after64']=='0x50';counts['historical_source_field_epochs_checked']+=len(fields);counts['historical_startup_cases_read_back']+=1
 deps=['daemon_frame_entry_contracts.json','daemon_frame_entry_profiles.json','daemon_frame_entry_proofs.json','probe_daemon_frame_entry.py','prove_daemon_frame_entry.py','validate_daemon_iokit_sync.py','validate_daemon_rwlock_lifecycle.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'entry_boundaries':dict(boundaries),'source_lift_counts':lifts,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_frame_entry_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'entry_boundaries':dict(boundaries)}),flush=True)
if __name__=='__main__':main()
