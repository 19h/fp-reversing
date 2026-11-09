#!/usr/bin/env python3
"""Independent source, SSA, replay, proof, SDK and output-unknownness audit.
O(artifact bytes+visits+effects+SSA DAG) time,O(largest trace) space; solver
30 s per query. Four fresh A64 replays; no target import/IDB mutation.
"""
import hashlib,json,subprocess
from pathlib import Path
from collections import Counter
import z3
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,CS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from replay_daemon_entropy_return import EntropyReplay,unpack,SEEDS,ARRAY
from prove_daemon_entropy_return import obligations

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c,p,r,q=map(read,['daemon_entropy_return_contracts.json','daemon_entropy_return_profiles.json','daemon_entropy_return_replays.json','daemon_entropy_return_proofs.json']);counts=Counter();totals=Counter();increment=Counter()
 for obj,n in [(c,'recover_daemon_entropy_return.py'),(p,'probe_daemon_entropy_return.py'),(r,'replay_daemon_entropy_return.py'),(q,'prove_daemon_entropy_return.py')]:
  assert obj['generator_sha256']==sha(ROOT/n)and not obj['full_goal_complete']
  for dep,h in obj['dependencies'].items():assert sha(ROOT/dep)==h,(n,dep)
 assert c['source_sha256']==p['source_sha256']==r['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for span in c['spans']:assert native(span['label'],int(span['start'],16),int(span['end'],16))==span;counts['original_source_spans']+=1
 fix=c['source_fixup_records'];assert verify_original_fixups([int(x['address'],16)for x in fix['records']])==fix;counts['original_fixups_verified']=len(fix['records'])
 assert selected(0x100fc4230,0x101031fa0,0xf3,0xcbc3,TABLE,0)==c['time_bank']and binding(0x10109ff20)==c['time_binding'];counts['bank_inputs_exhaustive']=256
 livebytes={}
 for n in ['daemon_entropy_return_live_ida.json','daemon_entropy_iteration_live_ida.json','daemon_time_consumers_live_ida.json']:
  live=read(n);assert live['target']=='6b117c693e3b'and not live['idb_mutated']
  for row in live['instructions']:
   a=int(row['address'],16);raw=bytes.fromhex(row['bytes']);assert IMAGE.read(a,len(raw))==raw
   for j,b in enumerate(raw,a):assert j not in livebytes or livebytes[j]==b;livebytes[j]=b
   counts['live_IDB_rows_matched']+=1
 for row in p['instruction_pool']:
  a=int(row['pc'],16);raw=bytes.fromhex(row['bytes_hex']);assert IMAGE.read(a,4)==raw and bytes(livebytes[a+j]for j in range(4))==raw;counts['original_pool_instructions_IDB_covered']+=1
 for h in c['SDK_headers']:
  path=Path(h['path']);assert sha(path)==h['sha256'];lines=path.read_text().splitlines()
  for d in h['declarations']:assert lines[d['line']-1].strip()==d['text'];counts['SDK_source_declarations_matched']+=1
  counts['SDK_headers_checked']+=1
 sc=c['SDK_compile'];run=subprocess.run(sc['command'],capture_output=True,text=True);assert run.returncode==sc['exit_code']==0 and run.stdout==sc['stdout']and run.stderr==sc['stderr'];counts['fresh_SDK_compile_checks']=1
 qs,lifts=obligations(c);assert lifts==q['source_lift_counts']and sum(lifts.values())==77 and len(qs)==11
 for(name,pred),row in zip(qs,q['proofs']):
  assert name==row['name']and row['result']=='unsat'
  for k in ['original_file','file']:
   assert sha(ROOT/row[k])==row['original_sha256'if k=='original_file'else'sha256'];forms=z3.parse_smt2_string((ROOT/row[k]).read_text());assert len(forms)==1
   for f in [*forms,z3.Xor(pred,forms[0])]:s=z3.Solver();s.set(timeout=30000);s.add(z3.simplify(f));assert str(s.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 for w in q['nonempty_premise_witnesses']:
  s=z3.Solver();s.add(qs[2][1].arg(0),z3.BitVec('entropy_frame64',64)==int(w['frame'],16),z3.BitVec('entropy_index64',64)==w['index']);assert str(s.check())==w['result']=='sat';counts['nonempty_premise_witnesses']+=1
 prior=read('daemon_context_transfer_profiles.json');old_replays=read('daemon_context_transfer_replays.json');base=read('daemon_arena_storage_profiles.json');assert len(p['cases'])==4 and len(r['cases'])==48
 for context in p['cases']:
  index=context['prior_case_index'];t=unpack(context);prefix=unpack(next(x for x in prior['cases']if x['prior_case_index']==index));F=int(context['frame_SP'],16);assert len(t['steps'])==context['steps']==11259 and len(t['definitions'])==2501 and len(t['writes'])==625 and t['boundary']['pc']=='0x1002dc308'and t['boundary']['target']=='0x7c100000'and not context['loader_zero_reads'];counts['symbolic_contexts']+=1;counts['symbolic_source_visits']+=len(t['steps']);counts['SSA_definitions_checked']+=len(t['definitions'])
  seen=set()
  for d in t['definitions']:
   assert d['name']=='value_'+str(len(seen))and d['bits']in [32,64,128]
   for name,bits in d['expression']['symbols']:assert name in seen or name.startswith(('api_','incoming_'))
   seen.add(d['name'])
  # Exact induction structure: 15 setup, 623 identical 18-instruction
  # iterations, 30 pre-call instructions. Path targets cannot read entropy.
  pcs=[int(s['pc'],16)for s in t['steps']];expected=list(range(0x100409578,0x1004095b4,4))+list(range(0x1002fbee4,0x1002fbf2c,4))*623+list(range(0x1002dc290,0x1002dc308,4));assert pcs==expected
  writes=t['writes'];assert [int(w['address'],16)for w in writes[:-1]]==list(range(ARRAY,ARRAY+2496,4))and all(w['size_bytes']==4 for w in writes)and writes[-1]['address']==hex(F+0x60c)and writes[-1]['value']=={'hex':'70020000'};counts['state_word_writes_checked']+=624
  expected_effects=Counter(source_visits=11259)
  for step in t['steps']:
   assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex'];counts['original_new_visit_bytes_checked']+=4
   expected_effects['register_effects_checked']+=len(step['registers_after']);expected_effects['NZCV_effects_checked']+=int('NZCV_after'in step)
   for e in step['events']:
    expected_effects['read_bytes_checked'if e['kind']=='read'else'write_bytes_checked']+=e['size_bytes']
    if e['kind']=='write':expected_effects['source_write_effects_checked']+=1
  reps=[rep for rep in r['cases']if rep['prior_case_index']==index];assert len(reps)==12 and {(x['entropy_model']['return_u32'],x['pattern'])for x in reps}=={(hex(seed),pat)for seed in SEEDS for pat in [0,3]}
  for rep in reps:
   assert not rep['native_entropy_executed']and not rep['native_time_executed']and rep['entropy_model']['argument_count']==0 and rep['entropy_model']['preserved_before']==rep['entropy_model']['preserved_after']and rep['state_array']['words']==624 and rep['state_array']['size_bytes']==2496 and rep['time_arguments']=={'timeval_pointer':hex(F+0x680),'timezone_pointer':'0x0'}
   old=next(x for x in old_replays['cases']if x['prior_case_index']==index and x['pattern']==rep['pattern']);diff=Counter(rep['verified_counts']);diff.subtract(old['verified_counts']);assert +diff==expected_effects;totals.update(rep['verified_counts']);increment.update(diff);counts['independent_A64_replays']+=1
  # Recheck one full source prefix and new continuation in every context.
  fresh=EntropyReplay(base['cases'][index]['input'],prefix,t,0xffffffff,3).run_entropy();fresh['prior_case_index']=index;assert fresh==next(x for x in reps if x['entropy_model']['return_u32']=='0xffffffff'and x['pattern']==3);counts['fresh_A64_replays']=counts.get('fresh_A64_replays',0)+1
  cs=next(x for x in c['contexts']if x['prior_case_index']==index);assert cs['precall_output_source_defined_bytes']==0 and cs['precall_output_size_bytes']==16 and cs['timeval_address']==hex(F+0x680);counts['unknown_timeval_contexts_checked']+=1
 # Immediate post-time continuation reads two output words before the next
 # external call and never consumes X0/W0 (the integer return status).
 decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);decoder.detail=True;ins=list(decoder.disasm(IMAGE.read(0x1002dc30c,0x94),0x1002dc30c));assert len(ins)==37
 for i in ins:
  reads,writes=i.regs_access();assert not any(i.reg_name(reg)in ['x0','w0']for reg in reads+writes)and i.mnemonic not in ['braa','blraa','b','bl','ret','svc'];counts['post_time_status_liveness_instructions']+=1
 deps=['daemon_entropy_return_contracts.json','daemon_entropy_return_profiles.json','daemon_entropy_return_replays.json','daemon_entropy_return_proofs.json','replay_daemon_entropy_return.py','prove_daemon_entropy_return.py','daemon_entropy_return_symbolic.py','daemon_entropy_return_restore.py','daemon_context_transfer_replays.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'new_increment_A64_totals':dict(increment),'source_lift_counts':lifts,'all_checks_pass':True,'native_entropy_executed':False,'native_time_executed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_entropy_return_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'independent_A64_totals':dict(totals),'new_increment_A64_totals':dict(increment)}),flush=True)
if __name__=='__main__':main()
