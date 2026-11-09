#!/usr/bin/env python3
"""Audit constant/copy certificates, independent A64 effects and compact ABI.
O(artifact bytes+V+events+proof DAG) time,O(largest trace) space;30 s/query.
No entropy API, native target or hardware authentication executes.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,selected,verify_original_fixups
from daemon_import_bindings import binding
from replay_daemon_context_transfer import unpack,Replay
from probe_daemon_arena_storage import Storage
from prove_daemon_context_transfer import obligations
from recover_daemon_iokit_census import native
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
OFFSETS={0x5a8,0x448,0x4b8,0x4a0,0x468,0x4a8,0x3f8,0x510,0x458,0x530,0x528,0x480,0x4c0,0x588}
PRESERVED={0x4a0,0x468,0x4a8,0x480,0x4c0,0x588}
def main():
 c,p,r,q=map(read,['daemon_context_transfer_contracts.json','daemon_context_transfer_profiles.json','daemon_context_transfer_replays.json','daemon_context_transfer_proofs.json']);counts=Counter();replay_totals=Counter();summaries=[]
 for obj,n in [(c,'recover_daemon_context_transfer.py'),(p,'probe_daemon_context_transfer.py'),(r,'replay_daemon_context_transfer.py'),(q,'prove_daemon_context_transfer.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,dep
 assert sha(SOURCE)==p['source_sha256']==r['source_sha256']==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for span in c['spans']:assert native(span['label'],int(span['start'],16),int(span['end'],16))==span;counts['original_source_spans']+=1
 for row in p['instruction_pool']:assert IMAGE.read(int(row['pc'],16),4).hex()==row['bytes_hex'];counts['original_instruction_pool_rows']+=1
 for row in c['bank_rules']:
  now=selected(int(row['left'],16),int(row['right'],16),int(row['key'],16),int(row['additive'],16),TABLE,int(row['bias'],16));assert now==row;counts['exhaustive_bank_inputs']+=256
 assert verify_original_fixups([int(x['address'],16)for x in c['source_fixup_records']['records']])==c['source_fixup_records'];counts['original_fixups_verified']=len(c['source_fixup_records']['records'])
 assert c['entropy_binding']==binding(int(c['bank_rules'][1]['slot'],16))and c['entropy_binding']['symbol']=='_arc4random'
 for n in ['daemon_context_transfer_live_ida.json','daemon_context_entropy_live_ida.json']:
  live=read(n);assert live['target']=='6b117c693e3b'and not live['idb_mutated']
  for x in live['instructions']:assert IMAGE.read(int(x['address'],16),len(bytes.fromhex(x['bytes'])))==bytes.fromhex(x['bytes']);counts['live_IDB_source_rows_matched']+=1
 header=c['SDK_header'];assert sha(Path(header['path']))==header['sha256']and header['declarations']==[{'line':287,'text':'uint32_t arc4random(void);'}];counts['SDK_entropy_signature_checked']=1
 qs,lifts,inv=obligations(c);assert lifts==q['source_lift_counts']and len(qs)==len(q['proofs'])and hex(inv)==q['coefficient_inverse64']
 for(n,pred),row in zip(qs,q['proofs']):
  assert n==row['name']and row['result']=='unsat'and sha(ROOT/row['original_file'])==row['original_sha256']and sha(ROOT/row['file'])==row['sha256'];orig=z3.parse_smt2_string((ROOT/row['original_file']).read_text());assert len(orig)==1
  for formula in [pred,*orig,*z3.parse_smt2_string((ROOT/row['file']).read_text()),z3.Xor(pred,orig[0])]:
   s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(formula));assert str(s.check())=='unsat',n
  counts['source_proof_pairs_unsat']+=1
 # Independently verify that the normalized record domain is nonempty.
 witness=z3.Solver();R=z3.BitVec('comparison_record64',64);witness.add(qs[0][1].arg(0),R==0x640000bf18);assert str(witness.check())=='sat';counts['premise_nonempty_witnesses']=1
 base=read('daemon_arena_storage_profiles.json');assert len(p['cases'])==4 and len(r['cases'])==16
 for context in p['cases']:
  trace=unpack(context);F=int(context['frame_SP'],16);origins={o['offset']for o in trace['origins']};expected={off+j for off in OFFSETS for j in range(8)};assert origins==expected and context['symbolic_unknown_bytes']==112
  counts['symbolic_input_bytes']+=112;counts['symbolic_contexts']+=1;counts['symbolic_source_visits']+=len(trace['steps']);assert len(trace['steps'])==context['steps'];assert trace['boundary']['pc']=='0x100409574'and trace['boundary']['target']=='0x7c100000'and all('hex'in x for x in trace['boundary']['registers31'])
  known_fields=set();preserved_fields=set()
  for field in trace['final_source_fields']:
   off=int(field['offset_bytes'],16);v=field['final_value']
   if'hex'in v:known_fields.add(off)
   else:assert v['terms']==[{'origin':off+j}for j in range(8)];preserved_fields.add(off)
  assert preserved_fields==PRESERVED and known_fields==OFFSETS-PRESERVED;counts['source_defined_final_fields']+=len(known_fields);counts['unknown_identity_fields_preserved']+=len(preserved_fields)
  for step in trace['steps']:
   assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];counts['source_bytes_checked']+=4
   for event in step['events']:
    shape=event['value'];a=int(event['address'],16);n=event['size_bytes']
    if'terms'in shape:
     assert len(shape['terms'])==n and all(isinstance(t,int)and 0<=t<256 or isinstance(t,dict)and t['origin']in origins for t in shape['terms'])
     if event['kind']=='write':assert 0x6400000000<=a<a+n<=0x6400010000;counts['unknown_private_copy_events']+=1
    else:assert len(bytes.fromhex(shape['hex']))==n
   for shape in step['registers_after'].values():
    if'terms'in shape:assert all(isinstance(t,int)or t['origin']in origins for t in shape['terms'])
  assert context['loader_zero_reads']==[{'pc':'0x1002dc0d0','address':'0x1010c8258','size_bytes':4}];counts['fresh_image_zero_read_contexts']+=1
  index=context['prior_case_index'];cfg=base['cases'][index]['input'];assert Storage(cfg).run()==base['cases'][index];counts['fresh_prefix_replays']+=1
  reps=[x for x in r['cases']if x['prior_case_index']==index];assert len(reps)==4 and {x['pattern']for x in reps}=={0,1,2,3}
  for rep in reps:
   assert rep['input']==cfg and not rep['native_target_executed']and rep['boundary']==trace['boundary'];replay_totals.update(rep['verified_counts']);counts['independent_A64_replays']+=1
  fresh=Replay(cfg,trace,3).run_forward();fresh['prior_case_index']=index;assert fresh==next(x for x in reps if x['pattern']==3);counts['fresh_transfer_replays']+=1
  summaries.append({'case':index,'steps':len(trace['steps']),'source_defined_fields':[hex(x)for x in sorted(known_fields)],'unknown_preserved_fields':[hex(x)for x in sorted(preserved_fields)],'scalar_four_byte_writes':context['scalar_four_byte_writes'],'scalar_buffer_writes':context['scalar_buffer_writes']})
 deps=['daemon_context_transfer_contracts.json','daemon_context_transfer_profiles.json','daemon_context_transfer_replays.json','daemon_context_transfer_proofs.json','daemon_context_transfer_symbolic.py','prove_daemon_context_transfer.py','replay_daemon_context_transfer.py','daemon_arena_storage_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(replay_totals),'source_lift_counts':lifts,'context_summaries':summaries,'all_checks_pass':True,'native_entropy_executed':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_context_transfer_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'independent_A64_totals':dict(replay_totals)}),flush=True)
if __name__=='__main__':main()
