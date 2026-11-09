#!/usr/bin/env python3
"""Seal bounded object-slot ABI delivery with source/proof/preservation readback.

O(pinned bytes+I+256R) time and O(largest JSON) space plus solver cost30 s/query.
No target or IDB mutation executes; local fixtures never establish parent entry.
"""
import hashlib,json,re
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_objects_symbolic import queries
BASE=ROOT.parent;BASELINE_SHA='d0b479dd961ffd5e7285904fbd2e3c9e2a3609ab5e272d3a17bb1d8a15546082'
EXPECTED={'bounded_source_spans':16,'original_dispatch_slots':12,'vector_root_bank_input_checks':512,'independently_decoded_load_pairs':2,'source_proof_pairs_unsat':16,'fresh_local_fixture_cases':4096,'source_instruction_visits':65536,'source_instruction_byte_checks':262144,'source_u64_read_epochs':8192,'source_frame_zero_write_epochs':4096,'preceding_source_acquire_call_readbacks':38}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_objects_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_objects_prior_manifest.json');assert len(baseline['files'])==2030
 c=read('lskd_objects_contracts.json');checks=read('lskd_objects_checks.json');proof=read('lskd_objects_proofs.json');preserve=read('lskd_objects_preservation.json');state=read('lskd_state_contracts.json')
 for obj,name in[(c,'recover_lskd_objects.py'),(checks,'validate_lskd_objects.py'),(proof,'prove_lskd_objects.py'),(preserve,'validate_lskd_objects_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'lskd_objects_replays.json')==checks['fresh_replays_sha256']
 for flag in['accepted_context_fixture_supplied','positive_parent_path_executed','native_target_executed','external_IPC_emission_proved']:assert not checks[flag]
 assert checks['model_memory_writes']==0
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']and k.read(0xfffffe000ccc78d0,8).hex()==c['vector_root']['original8_hex']=='0000000000000000'
 assert c['indexed_vector_extent_bytes']==8192 and not c['vector_allocation_extent_proved']and not c['vector_root']['native_runtime_pointer_known']and not c['writer_candidates']['table_alias_or_reaching_definition_established']
 for row in c['dispatch_slots']:
  p=row['pointer'];assert pointer(k,int(p['slot'],16))==p and p['authenticated']and int(p['slot'],16)==0xfffffe000846c420+8*int(row['index32'],16)
 qs,lifts=queries(c,state);assert len(qs)==len(proof['proofs'])==16 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==115
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=read('lskd_objects_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_lskd_objects.py')and fresh['dependencies']==checks['dependencies']and len(fresh['cases'])==4096 and not fresh['full_goal_complete']
 coverage={}
 for r in fresh['cases']:
  assert r['model_memory_writes']==0 and not r['complete_handler_executed']and not r['native_reachability_proved']and r['fixture_vector_unchanged_by_source'];key=(r['provider'],r['null_slot']);coverage.setdefault(key,set()).add(r['index10'])
 assert len(coverage)==4 and all(v==set(range(1024))for v in coverage.values());del fresh
 for d in checks['independent_load_decodings']:
  a,b=int(d['root_load_PC'],16),int(d['slot_load_PC'],16);w,v=int.from_bytes(k.read(a,4),'little'),int.from_bytes(k.read(b,4),'little');assert hex(w)==d['root_load_word']and hex(v)==d['slot_load_word']
  assert(w&0xffc00000)==0xf9400000 and(w&31)==10 and(w>>5)&31==10 and((w>>10)&0xfff)==0
  assert(v&0xffe00c00)==0xf8600800 and(v&31)==12 and(v>>5)&31==10 and(v>>16)&31==13 and(v>>13)&7==3 and(v>>12)&1==1 and(v>>30)&3==3
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==2030 and preserve['unchanged_prior_artifacts']==2024
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_objects_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'lskd_objects_source_identity.json',ROOT/'lskd_objects_quality_gates.json'],(name,target);links+=1
 report=(BASE/'lskd_objects_report.md').read_text()
 for term in['OR11','QG7','unknown','4096','65536','8192','2030','2024','Mach','0xfffffe000ccc78d0','0xfffffe000ccc78a8','0xfffffe000ccc7b08','positive parent','writer']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'vector_root':c['vector_root'],'dispatch_slots':c['dispatch_slots'],'independent_load_decodings':checks['independent_load_decodings'],'indexed_vector_extent_bytes':8192,'native_vector_allocation_extent_known':False,'writer_candidates':c['writer_candidates'],'positive_parent_path_executed':False,'accepted_context_fixture_supplied':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_objects_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','OR1-OR11 list dependencies and falsification probes.','Positive retry/index/vector/null contracts and writer anchors covered; full objective remains active.','Exact byte widths/extents, source counts and reproduction.','First-pass/retry state, local/native execution, indexed/allocation extents, raw-slot representation and writer aliases separated.','Original source/chains,16 source proof pairs,4096 fresh isolated layout cases,38 prior call readbacks and independent load-word decoding.','Impact-labeled continuation table.'];outputs=['lskd_objects_contracts.json','lskd_objects_profiles.json','lskd_objects_replays.json','lskd_objects_checks.json','lskd_objects_proofs.json','lskd_objects_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':2030,'unchanged_prior_artifacts':2024,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_objects_source_identity.json'),'model_memory_writes':0,'accepted_context_fixture_supplied':False,'positive_parent_path_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_objects_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_isolated_cases':4096,'source_proof_pairs':16,'prior_artifacts_checked':2030,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
