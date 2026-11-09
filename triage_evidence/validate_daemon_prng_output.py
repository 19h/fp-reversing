#!/usr/bin/env python3
"""Independent audit of finite reads, full-prefix A64, scalar ABI and counters.
O(artifact bytes+events+SSA expansions) time,O(largest journal) space;
2 s finite-range/30 s source-query bounds. No target imports/PAC execute.
"""
import hashlib,json
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from daemon_prng_output_symbolic import Output
from daemon_seed_material_symbolic import decode
from prove_daemon_prng_output import obligations,OutLift,MIX
from lskd_values_symbolic import part
from replay_daemon_prng_output import OutputReplay,unpack,INPUTS

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def unsat(pred,ms=30000):
 s=z3.Solver();s.set(timeout=ms);s.add(z3.simplify(pred));assert str(s.check())=='unsat'
def main():
 c,p,r,q=map(read,['daemon_prng_output_contracts.json','daemon_prng_output_profiles.json','daemon_prng_output_replays.json','daemon_prng_output_proofs.json']);counts=Counter();totals=Counter();increment=Counter()
 for obj,name in [(c,'recover_daemon_prng_output.py'),(p,'probe_daemon_prng_output.py'),(r,'replay_daemon_prng_output.py'),(q,'prove_daemon_prng_output.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,(name,dep)
 assert c['source_sha256']==p['source_sha256']==r['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for span in c['spans']:assert native(span['label'],int(span['start'],16),int(span['end'],16))==span;counts['original_source_spans']+=1
 fx=c['source_fixup_records'];assert verify_original_fixups([int(x['address'],16)for x in fx['records']])==fx;counts['original_fixups_verified']=len(fx['records'])
 for b in c['bank_rules']:assert selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),TABLE,int(b['bias'],16))==b;counts['exhaustive_bank_inputs']+=256
 coverage={}
 for name in ['daemon_prng_output_live_ida.json','daemon_prng_twist_live_ida.json']:
  live=read(name);assert live['target']=='6b117c693e3b'and not live['idb_mutated']
  for row in live['instructions']:
   a=int(row['address'],16);raw=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(raw))==raw
   for j,b in enumerate(raw,a):assert j not in coverage or coverage[j]==b;coverage[j]=b
   counts['live_IDB_rows_matched']+=1
 for row in p['instruction_pool']:
  a=int(row['pc'],16);raw=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(a,4)==raw;counts['original_path_pool_rows']+=1
  if all(a+j in coverage for j in range(4)):assert bytes(coverage[a+j]for j in range(4))==raw;counts['path_pool_rows_live_IDB_covered']+=1
 qs,lifts,inv=obligations(c);assert len(qs)==24 and lifts==q['source_lift_counts']and sum(lifts.values())==247 and hex(inv)==q['address_multiplier_inverse64']
 for(name,pred),item in zip(qs,q['proofs']):
  assert name==item['name']and item['result']=='unsat'
  for kind in ['original_file','file']:
   assert sha(ROOT/item[kind])==item['original_sha256'if kind=='original_file'else'sha256'];forms=z3.parse_smt2_string((ROOT/item[kind]).read_text());assert len(forms)==1;unsat(forms[0]);unsat(z3.Xor(forms[0],pred))
  counts['source_proof_pairs_unsat']+=1
 byname={name:pred for name,pred in qs}
 for w in q['nonempty_premise_witnesses']:
  s=z3.Solver();s.add(byname[w['premise']].arg(0))
  for name,value in w['bindings'].items():s.add(z3.BitVec(name,32 if name.endswith('32')else 64)==int(value,16))
  assert str(s.check())==w['result']=='sat';counts['nonempty_premise_witnesses']+=1
 ce=q['outside_alignment_counterexample'];v=OutLift(part(c,'alignment_probe',0x10032c9fc,0x10032ca54));R=int(ce['R'],16);v.seed('x0',R);v.run('alignment_probe');assert hex(z3.simplify(v.read('x12')).as_long())==ce['actual_prekey']and hex(R^MIX)==ce['aligned4_identity']and R&3==2;counts['outside_domain_alignment_probes']=1
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;live=q['constructor_key_liveness'];raw=IMAGE.read(int(live['start'],16),int(live['end'],16)-int(live['start'],16));assert hashlib.sha256(raw).hexdigest()==live['bytes_sha256'];ins=list(cs.disasm(raw,int(live['start'],16)));assert len(ins)==221
 for i in ins:
  reads,writes=i.regs_access();assert not any(i.reg_name(x)in ['x12','w12']for x in writes)and i.mnemonic not in ['b','bl','braa','blraa','ret','svc'];counts['constructor_key_liveness_instructions']+=1
 prior=read('daemon_context_transfer_profiles.json');entropy=read('daemon_entropy_return_profiles.json');material=read('daemon_seed_material_profiles.json');base=read('daemon_arena_storage_profiles.json');oldreps=read('daemon_seed_material_replays.json');assert len(p['cases'])==4 and len(r['cases'])==8
 for ctx in p['cases']:
  index=ctx['prior_case_index'];t=unpack(ctx);F=int(ctx['frame_SP'],16);assert ctx['reached_checkpoint']and len(t['steps'])==ctx['steps']==26666 and len(t['lookups'])==1248 and len(t['origins'])==112 and not t['proof_rejections'];assert t['boundary']['pc']=='0x100350628'and t['boundary']['kind']=='two_prng_heap_updates_complete';counts['symbolic_contexts']+=1;counts['symbolic_source_visits']+=len(t['steps']);counts['SSA_definitions_checked']+=len(t['definitions'])
  seen=set()
  for node in t['definitions']:
   assert node['name']=='value_'+str(len(seen))
   for name,bits in node['expression']['symbols']:assert name in seen or name.startswith(('api_','incoming_'))
   seen.add(node['name'])
  scratch=object.__new__(Output);scratch.F=F;scratch.definitions=t['definitions'];expected=Counter(source_visits=len(t['steps']))
  for step in t['steps']:
   assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];counts['original_visit_bytes_checked']+=4;expected['register_effects_checked']+=len(step['registers_after']);expected['NZCV_effects_checked']+=int('NZCV_after'in step)
   for e in step['events']:
    expected['read_bytes_checked'if e['kind']=='read'else'write_bytes_checked']+=e['size_bytes']
    if e['kind']=='write':expected['source_write_effects_checked']+=1
  assert Counter(x['pc']for x in t['lookups'])=={'0x10035c6f8':454,'0x100474058':792,'0x1003b092c':2}
  for look in t['lookups']:
   original=decode(look['original_address'],F);expanded=original
   for recorded_names in look['expansions']:
    expanded,names=scratch.expand_once(expanded);assert sorted(names)==sorted(recorded_names)
   recorded=decode(look['expanded_address'],F);unsat(expanded!=recorded,2000);lo,hi=[int(x,16)for x in look['candidate_addresses']];assert(lo,hi)==(F+0x6d8,F+0x6dc);unsat(z3.And(expanded!=lo,expanded!=hi),2000);assert look['candidate_values_u32']==['0x94fdeab5','0xdf55a6a']and look['range_counterexample_result']=='unsat'
   step=t['steps'][look['source_visit_index']];assert step['pc']==look['pc'];event=next(e for e in step['events']if'address_expression'in e);unsat(decode(event['address_expression'],F)!=original);wanted=z3.If(expanded==lo,z3.BitVecVal(0x94fdeab5,32),z3.BitVecVal(0x0df55a6a,32));unsat(decode(event['value'],F)!=wanted);counts['finite_read_certificates_checked']+=1
  summary=next(x for x in c['contexts']if x['prior_case_index']==index);assert summary['second_word_nonzero_path_visits']==1 and summary['state_words_written']==1248 and summary['new_API_calls']==0 and summary['helper_call_sites']=={'0x10029a1e0':2,'0x1002dc178':1};counts['nonzero_seed_guard_paths_checked']+=1
  reps=[x for x in r['cases']if x['prior_case_index']==index];assert {(x['values']['name'],x['pattern'])for x in reps}=={('zero',0),('reference',3)}
  for rep in reps:
   assert not rep['native_target_executed']and rep['API_models_count']==4 and rep['finite_reads_checked']==1248 and len(rep['checkpoints'])==2
   old=next(x for x in oldreps['cases']if x['prior_case_index']==index and x['values']['name']==rep['values']['name']and x['pattern']==rep['pattern']);assert rep['prefix_verified_counts']==old['verified_counts'];assert Counter(rep['new_verified_counts'])==expected;totals.update(rep['verified_counts']);increment.update(rep['new_verified_counts']);counts['independent_full_A64_replays']+=1
  if index in [0,17]:
   args=[base['cases'][index]['input'],unpack(next(x for x in prior['cases']if x['prior_case_index']==index)),unpack(next(x for x in entropy['cases']if x['prior_case_index']==index)),unpack(next(x for x in material['cases']if x['prior_case_index']==index)),t,INPUTS[3],3];fresh=OutputReplay(*args).run_output();fresh['prior_case_index']=index;assert fresh==next(x for x in reps if x['values']['name']=='reference');counts['fresh_full_A64_replays']+=1
 deps=['daemon_prng_output_contracts.json','daemon_prng_output_profiles.json','daemon_prng_output_replays.json','daemon_prng_output_proofs.json','daemon_prng_output_symbolic.py','daemon_prng_output_runner.py','replay_daemon_prng_output.py','prove_daemon_prng_output.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{name:sha(ROOT/name)for name in deps},'verified_counts':dict(counts),'source_lift_counts':lifts,'independent_A64_totals':dict(totals),'new_increment_A64_totals':dict(increment),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_prng_output_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'new_increment_A64_totals':dict(increment)}),flush=True)
if __name__=='__main__':main()
