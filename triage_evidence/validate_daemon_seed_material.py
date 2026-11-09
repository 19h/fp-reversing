#!/usr/bin/env python3
"""Audit seed material, comparison ABI, compact state, frontier and failure.
O(artifact bytes+source visits+byte effects+SSA) time,O(largest journal)
space;30 s per solver query. Four fresh full A64 replays, no native calls.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_seed_material import summarize
from replay_daemon_seed_material import MaterialReplay,unpack,INPUTS
from prove_daemon_seed_material import obligations,LessLift,MIX
from lskd_values_symbolic import part,cell

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,p,r,q,f=map(read,['daemon_seed_material_contracts.json','daemon_seed_material_profiles.json','daemon_seed_material_replays.json','daemon_seed_material_proofs.json','daemon_seed_material_failure.json']);counts=Counter();totals=Counter();increment=Counter();summaries=[]
 for obj,n in [(c,'recover_daemon_seed_material.py'),(p,'probe_daemon_seed_material.py'),(r,'replay_daemon_seed_material.py'),(q,'prove_daemon_seed_material.py'),(f,'probe_daemon_seed_material_failure.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,(n,dep)
 assert c['source_sha256']==p['source_sha256']==r['source_sha256']==f['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for span in c['spans']:assert native(span['label'],int(span['start'],16),int(span['end'],16))==span;counts['original_source_spans']+=1
 fix=c['source_fixup_records'];assert verify_original_fixups([int(x['address'],16)for x in fix['records']])==fix;counts['original_fixups_verified']=len(fix['records'])
 for b in c['bank_rules']:assert selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),TABLE,int(b['bias'],16))==b;counts['exhaustive_bank_inputs']+=256
 assert binding(0x1010a0050)==c['entropy_binding']and c['entropy_binding']['symbol']=='_arc4random';coverage={}
 for name in ['daemon_seed_material_live_ida.json','daemon_seed_mixing_live_ida.json','daemon_seed_table_setup_live_ida.json']:
  obj=read(name);assert obj['target']=='6b117c693e3b'and not obj['idb_mutated']
  for row in obj['instructions']:
   a=int(row['address'],16);raw=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(raw))==raw
   for j,b in enumerate(raw,a):assert j not in coverage or coverage[j]==b;coverage[j]=b
   counts['live_IDB_source_rows_matched']+=1
 for row in p['instruction_pool']:
  a=int(row['pc'],16);raw=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(a,4)==raw;counts['original_path_pool_instructions']+=1
  if all(a+j in coverage for j in range(4)):assert bytes(coverage[a+j]for j in range(4))==raw;counts['path_pool_instructions_live_IDB_covered']+=1
 doc=c['SDK_time_documentation'];path=Path(doc['path']);assert sha(path)==doc['sha256'];lines=path.read_text().splitlines()
 for item in doc['return_clauses']:assert lines[item['line']-1]==item['text'];counts['SDK_return_clauses_checked']+=1
 qs,lifts,inv=obligations(c);assert len(qs)==27 and lifts==q['source_lift_counts']and sum(lifts.values())==209 and hex(inv)==q['address_multiplier_inverse64']
 for(name,pred),item in zip(qs,q['proofs']):
  assert name==item['name']and item['result']=='unsat'
  for kind in ['original_file','file']:
   assert sha(ROOT/item[kind])==item['original_sha256'if kind=='original_file'else'sha256'];forms=z3.parse_smt2_string((ROOT/item[kind]).read_text());assert len(forms)==1
   for formula in [forms[0],z3.Xor(forms[0],pred)]:solver=z3.Solver();solver.set(timeout=30000);solver.add(z3.simplify(formula));assert str(solver.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 for w in q['nonempty_premise_witnesses']:
  solver=z3.Solver();solver.add(qs[10][1].arg(0),z3.BitVec('material_frame64',64)==int(w['frame'],16),z3.BitVec('material_index32',32)==w['index'],z3.BitVec('material_key_index32',32)==w['key_index']);assert str(solver.check())==w['result']=='sat';counts['nonempty_premise_witnesses']+=1
 ce=q['outside_alignment_counterexample'];assert ce['result']=='sat'and ce['record_alignment_bytes']==4 and int(ce['R'],16)&7==4 and ce['actual_prekey']!=ce['aligned8_identity_prekey'];R=int(ce['R'],16);F=0x640000b420;v=LessLift(part(c,'alignment_counterexample',0x10032ca54,0x10032ca98));v.seed('x0',R);v.seed('sp',F);v.run('alignment_counterexample');assert hex(z3.simplify(cell(v,F+0x340,8)).as_long())==ce['actual_prekey']and hex(R^MIX)==ce['aligned8_identity_prekey'];counts['outside_domain_alignment_counterexamples']=1
 prior=read('daemon_context_transfer_profiles.json');ent=read('daemon_entropy_return_profiles.json');oldreps=read('daemon_entropy_return_replays.json');base=read('daemon_arena_storage_profiles.json');assert len(p['cases'])==4 and len(r['cases'])==24 and len(f['cases'])==4
 for context in p['cases']:
  index=context['prior_case_index'];t=unpack(context);F=int(context['frame_SP'],16);H=int(context['heap_base'],16);prefix=unpack(next(x for x in prior['cases']if x['prior_case_index']==index));entropy=unpack(next(x for x in ent['cases']if x['prior_case_index']==index));assert len(t['steps'])==259584 and len(t['definitions'])==10185 and not context['completed_to_call_boundary']and t['boundary']['pc']=='0x10035c6f8'and t['boundary']['unsupported_frontier'].startswith("('unknown-dependent read address'");counts['symbolic_contexts']+=1;counts['symbolic_source_visits']+=len(t['steps']);counts['SSA_definitions_checked']+=len(t['definitions']);assert len(t['origins'])==112;counts['old_unknown_bytes_preserved']+=112
  seen=set()
  for d in t['definitions']:
   assert d['name']=='value_'+str(len(seen))
   for name,bits in d['expression']['symbols']:assert name in seen or name.startswith(('api_','incoming_'))
   seen.add(d['name'])
  exact=summarize(context,prefix,entropy,base['cases'][index]);assert exact==next(x for x in c['source_phase_contexts']if x['prior_case_index']==index);counts['recovered_context_summaries_matched']+=1;assert exact['new_symbolic_input_bytes']==0 and not exact['fresh_tail_materializations']and exact['cached_source_state_tail_reads']==context['loader_zero_reads'].__len__()==524;counts['cached_source_state_tail_reads']+=524
  state_writes=[(s['pc'],e)for s in t['steps']for e in s['events']if e['kind']=='write'and 0x1010c784c<=int(e['address'],16)<0x1010c820c];assert len(state_writes)==1250
  for pc,indices in [('0x1002fbb50',list(range(1,624))+[1]),('0x1003068fc',list(range(2,624))+[1])]:assert [int(e['address'],16)for site,e in state_writes if site==pc]==[0x1010c784c+i*4 for i in indices]
  counts['state_word_writes_checked']+=len(state_writes);assert sum(v['calls']for v in exact['leaf_callers'].values())==1871 and all(v['kind']=='less36'for v in exact['leaf_callers'].values());counts['less_record_calls_decoded']+=1871
  expected_effects=Counter(source_visits=len(t['steps']))
  for step in t['steps']:
   assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];counts['original_new_visit_bytes_checked']+=4;expected_effects['register_effects_checked']+=len(step['registers_after']);expected_effects['NZCV_effects_checked']+=int('NZCV_after'in step)
   for e in step['events']:
    expected_effects['read_bytes_checked'if e['kind']=='read'else'write_bytes_checked']+=e['size_bytes']
    if e['kind']=='write':expected_effects['source_write_effects_checked']+=1
  reps=[x for x in r['cases']if x['prior_case_index']==index];assert len(reps)==(7 if index in [0,17]else 5)
  for rep in reps:
   assert not rep['native_target_executed']and not rep['native_entropy_or_time_executed']and len(rep['API_models'])==4 and rep['time_output']['padding_stays_unknown']and rep['time_output']['known_mask_hex']=='01'*12+'00'*4 and rep['material_record']['all_four_encoded_words_restored']
   for model in rep['API_models']:assert model['preserved_before']==model['preserved_after']
   old=next(x for x in oldreps['cases']if x['prior_case_index']==index and x['pattern']==rep['pattern']);diff=Counter(rep['verified_counts']);diff.subtract(old['verified_counts']);assert +diff==expected_effects;totals.update(rep['verified_counts']);increment.update(diff);counts['independent_A64_replays']+=1
  fresh=MaterialReplay(base['cases'][index]['input'],prefix,entropy,t,INPUTS[3],3).run_material();fresh['prior_case_index']=index;assert fresh==next(x for x in reps if x['values']['name']=='reference'and x['pattern']==3);counts['fresh_full_A64_replays']+=1
  if index in [0,17]:
   same=[x['mixed_state']['sha256']for x in reps if x['values']['name']in ['reference','status_sensitivity','seconds_high_sensitivity']and x['pattern']==3];assert len(same)==3 and len(set(same))==1;counts['status_high_seconds_sensitivity_groups']+=1
  failed=next(x for x in f['cases']if x['prior_case_index']==index);assert failed['frontier']['pc']=='0x1002dc318'and not failed['API_model']['events']and failed['time_output_source_defined_bytes']==0 and len(failed['new_unknown_byte_origins'])==4 and len(failed['steps'])==3
  for rep in failed['isolated_A64_replays']:assert rep['source_defined_input_bytes']==0 and not rep['memory_writes']and len(rep['source_visits'])==3 and rep['status_after']=='0xffffffff';counts['isolated_failure_reader_A64_replays']+=1
  counts['conditional_no_output_failure_contexts']+=1
 hashes=[x['mixed_state']['sha256']for x in r['cases']if x['values']['name']=='reference'and x['pattern']==3];assert len(hashes)==len(set(hashes))==4;counts['distinct_representation_state_hashes']=4
 deps=['daemon_seed_material_contracts.json','daemon_seed_material_profiles.json','daemon_seed_material_replays.json','daemon_seed_material_proofs.json','daemon_seed_material_failure.json','recover_daemon_seed_material.py','prove_daemon_seed_material.py','replay_daemon_seed_material.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'new_increment_A64_totals':dict(increment),'source_lift_counts':lifts,'all_checks_pass':True,'native_failure_observed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'new_increment_A64_totals':dict(increment)}),flush=True)
if __name__=='__main__':main()
