#!/usr/bin/env python3
"""Independently validate source, slots, models, epochs, outcomes and solver files.
Replays two fresh source compositions. O(artifact bytes+events+SMT+fresh visits)
time, O(largest trace+RAM) space. No native daemon/kernel/API/IDA executes.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,qword,CS
from replay_daemon_descriptor_producers import unpack
from replay_daemon_mode471c_lifecycle import LifecycleReplay,SPECS
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_seed_material_symbolic import decode

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def checked(n,g):
 r=json.loads((ROOT/n).read_text());assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 if 'source_sha256'in r:assert r['source_sha256']==sha(SOURCE)
 return r

def main():
 p=checked('daemon_mode471c_lifecycle_profiles.json','probe_daemon_mode471c_lifecycle.py');c=checked('daemon_mode471c_lifecycle_contracts.json','recover_daemon_mode471c_lifecycle.py');proofs=checked('daemon_mode471c_lifecycle_proofs.json','prove_daemon_mode471c_lifecycle.py');a64=checked('daemon_mode471c_lifecycle_replays.json','replay_daemon_mode471c_lifecycle.py');counts=Counter();sourcehash=sha(SOURCE);assert sourcehash=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:
  b=bytes.fromhex(s['bytes_hex']);assert IMAGE.read(int(s['start'],16),len(b))==b and hashlib.sha256(b).hexdigest()==s['sha256'];assert[(hex(i.address),i.mnemonic,i.op_str)for i in CS.disasm(b,int(s['start'],16))]==[(i['pc'],i['mnemonic'],i['operands'])for i in s['instructions']];counts['source_spans_checked']+=1
 for b in c['banks_exhaustive256']:
  l=IMAGE.read(int(b['left'],16),256);r=IMAGE.read(int(b['right'],16),256);assert all(j^r[l[j]^int(b['key'],16)]==int(b['constant'],16)for j in range(256));t=qword(int(b['slot'],16));assert t==b['target']if isinstance(t,str)else hex((t+int(b['bias'],16))&((1<<64)-1))==b['target'];counts['exhaustive_bank_input_cases']+=256
 assert verify_used_fixups({int(r['address'],16)for r in c['original_fixups']['records']})==c['original_fixups'];counts['original_fixups_checked']=len(c['original_fixups']['records'])
 for s in c['selectors']:assert hex(qword(int(s['slot'],16)))==s['target'];counts['dispatch_slots_checked']+=1
 for s in c['source_derived_initial_roots']:assert hex((qword(int(s['pool_slot'],16))+int(s['bias'],16))&((1<<64)-1))==s['value'];counts['source_derived_root_values_checked']+=1
 for row in proofs['proofs']:
  for fk,hk in [('original_file','original_sha256'),('file','sha256')]:
   f=ROOT/row[fk];assert sha(f)==row[hk];s=z3.Solver();s.set(timeout=30000);s.from_file(str(f));assert str(s.check())=='unsat',row['name'];counts['SMT_queries_unsat']+=1
 from prove_daemon_mode471c_lifecycle import obligations
 rebuilt,lifts=obligations(c);assert [n for n,pred in rebuilt]==[r['name']for r in proofs['proofs']]and lifts==proofs['source_lift_counts']
 for n,pred in rebuilt:
  solver=z3.Solver();solver.set(timeout=30000);solver.add(pred);assert str(solver.check())=='unsat',n;counts['freshly_rebuilt_source_obligations_unsat']+=1
 counts['source_proof_pairs']=len(proofs['proofs']);counts['source_lift_visits']=sum(proofs['source_lift_counts'].values());assert len(proofs['nonempty_premise_witnesses'])==1
 expected_creator={0:0x8b3dc651,12:0x74c29d85,16:0x74c29d82,22:0x74c29d83,0xffffffff:0x74c29d83};pool={};used_calls=Counter();callbackcases=0
 for index,r in enumerate(p['cases']):
  t=unpack(r);cfg=r['configuration'];F=int(t['initial_SP'],16);R=F+0xde90;api=t['api_models'];names=[x['name']for x in api];nonnull=bool(cfg['old_cell']);success=nonnull or(cfg['outcomes'][0]['malloc_nonnull']and cfg['outcomes'][0]['init_status']==0);assert not t['callback_pending']and t['definitions']==[]
  if nonnull:assert cfg['outcomes']==[]and not any(n in names for n in ['malloc','pthread_rwlock_init']);counts['preexisting_lock_cases']+=1
  else:
   o=cfg['outcomes'][0];assert names[0]=='malloc'and names.count('malloc')==1 and names.count('pthread_rwlock_init')==int(o['malloc_nonnull']);counts['creation_cases']+=1
  assert names.count('pthread_rwlock_wrlock')==names.count('pthread_rwlock_unlock')==int(success);assert names.count('pthread_once')==2*int(success);assert names.count('free')==1 and names[-1]=='free';assert len(api)==r['api_calls']
  expected_callbacks=int(success and not cfg['once_completed']);assert sum(bool(x.get('callback_invoked'))for x in api)==expected_callbacks;callbackcases+=expected_callbacks
  assert len(t['borrowed_owners'])==int(nonnull)and len(t['allocated_owners'])==(0 if nonnull else int(cfg['outcomes'][0]['malloc_nonnull']));assert t['retired_owners']==[{'address':'0x6800001000','size_bytes':8}]
  assert t['boundary']['pc']=='0x10039c998'and t['boundary']['kind']=='before_unresolved_source_effect'and 'unknown-dependent read address'in t['boundary']['reason'];assert int(t['boundary']['SP'],16)==int(r['prefix']['entry_SP'],16)
  assert all(0x6b00000000<=F+x['offset']<0x6b00100000 for x in t['API_origins']);assert len({x['offset']for x in t['API_origins']})==len(t['API_origins'])
  counts['arbitrary_API_byte_origins']+=len(t['API_origins']);counts['retained_private_byte_origins']+=len(t['origins']);counts['source_continuation_visits']+=len(t['steps']);assert r['source_visits']==len(t['steps']);pool.update({pc:s['bytes_hex']for pc,s in t['source_pool'].items()})
  writes={};latestL=None;result=[];creator_results=[];mode_epoch=False;preserved_D=None;input_reads_after_free=0;freed=False
  for st in t['steps']:
   pc=int(st['pc'],16);assert IMAGE.read(pc,4).hex()==st['bytes_hex'];counts['source_opcodes_checked']+=1
   for e in st['events']:
    a=int(e['address'],16);n=e['size_bytes']
    if freed and e['kind']=='read':assert not(a<0x6800001008 and 0x6800001000<a+n)
    if e['kind']=='read'and a==0x1010c67c0:latestL=int.from_bytes(bytes.fromhex(e['value']['hex']),'little')
    if e['kind']=='write':writes[(a,n)]=e['value']
   if pc==0x100975790:preserved_D=next(e['value']for e in st['events']if e['kind']=='write')
   if pc==0x100972914:
    e=next(e for e in st['events']if e['kind']=='write');assert e['address']==hex(F+0x2a70)and e['size_bytes']==4 and e['value']=={'hex':'1c470000'};mode_epoch=True;counts['source_mode_overwrite_epochs_checked']+=1
   if pc==0x1009729f0:assert mode_epoch and next(e['value']for e in st['events']if e['kind']=='read')=={'hex':'1c470000'};counts['post_creator_phase_reads_checked']+=1
   if pc==0x1009729dc:creator_results.append(int.from_bytes(bytes.fromhex(st['events'][0]['value']['hex']),'little'))
   if pc==0x100933cd0:
    key=(((R&0xffffffff)^0x987eac8a)*0x316f29c1)&0xffffffff;raw=int.from_bytes(bytes.fromhex(writes[(R,4)]['hex']),'little');ptr=int.from_bytes(bytes.fromhex(writes[(R+8,8)]['hex']),'little');assert raw^key==0x593d and ptr==latestL!=0;counts['acquire_records_checked']+=1
   if pc==0x100a2051c:
    key=(((R&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff;raw=int.from_bytes(bytes.fromhex(writes[(R+8,4)]['hex']),'little');ptr=int.from_bytes(bytes.fromhex(writes[(R,8)]['hex']),'little');assert(raw+key)&0xffffffff==0xa293 and ptr==latestL!=0;counts['cleanup_records_checked']+=1
   if pc==0x100b353b4:
    value=next(e['value']for e in st['events']if e['kind']=='read');q=z3.Solver();q.set(timeout=30000);q.add(decode(value,F)!=decode(preserved_D,F));assert str(q.check())=='unsat';counts['opaque_word_preservation_reads_checked']+=1
   if pc==0x100b353c8:assert st['events'][0]['address']=='0x1010c67d0'and st['events'][0]['value']=={'hex':'00000000'}
   if pc==0x10095f074:result.extend(e for e in st['events']if e['kind']=='write')
   if pc==0x10039c988:freed=True
  assert len(result)==1 and result[0]['value']=={'hex':'009fc274'}and freed
  if not nonnull:
   o=cfg['outcomes'][0];assert creator_results==[expected_creator[o['init_status']]if o['malloc_nonnull']else 0x74c29d85]
  else:assert creator_results==[]
  publications=[e for st in t['steps']for e in st['events']if e['kind']=='write'and e['address']=='0x1010c67c0'];assert len(publications)==int(success and not nonnull)
  for m in api:
   pc=int(m['pc'],16);assert m['name']==SPECS[pc][0]and m['binding']==c['imported_APIs'][hex(pc)]['binding'];assert not m['native_target_executed'];used_calls[m['name']]+=1
  counts['lifecycle_cases_checked']+=1;counts['zero_field_body_results_checked']+=1;counts['terminal_unknown_pointer_boundaries']+=1
 assert len(p['cases'])==28 and len(a64['cases'])==112 and a64['all_checks_pass'];totals=Counter()
 for row in a64['cases']:assert row['all_checks_pass'];totals.update(row['verified_counts'])
 assert dict(totals)==a64['verified_totals'];counts['independent_A64_replays']=len(a64['cases']);counts['callback_executing_source_cases']=callbackcases;counts['distinct_continuation_inspected_opcodes']=len(pool)
 for i in [2,27]:assert LifecycleReplay(p['cases'][i],3).run()['all_checks_pass'];counts['fresh_composed_replays']+=1
 for h in c['sdk_compile']['headers']:assert sha(Path(h['path']))==h['sha256'];counts['SDK_headers_rehashed']+=1
 assert c['sdk_compile']['exit_code']==0 and not c['sdk_compile']['native_program_executed'];trace=c['annotated_trace'];assert sha(Path(trace['path']))==trace['sha256'];prior=json.loads((ROOT/trace['prior_audit']).read_text());assert prior['trace_sha256']==trace['sha256']and prior['raw_svc_records']==27 and prior['matched_sends']==22;counts['supplied_annotated_trace_rehashed']=1
 live=json.loads((ROOT/'daemon_mode471c_lifecycle_live_ida.json').read_text());assert live['isError']is True and c['fresh_IDB_bytes_verified']==0
 deps=['daemon_mode471c_lifecycle_profiles.json','daemon_mode471c_lifecycle_contracts.json','daemon_mode471c_lifecycle_proofs.json','daemon_mode471c_lifecycle_replays.json','replay_daemon_mode471c_lifecycle.py','prove_daemon_mode471c_lifecycle.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sourcehash,'verified_counts':dict(counts),'API_counts':dict(used_calls),'independent_A64_totals':a64['verified_totals'],'fresh_IDB_bytes_verified':0,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False,'all_checks_pass':True};(ROOT/'daemon_mode471c_lifecycle_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'API_counts':dict(used_calls)}),flush=True)
if __name__=='__main__':main()
