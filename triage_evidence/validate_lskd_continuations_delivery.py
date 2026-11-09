#!/usr/bin/env python3
"""Scoped continuation delivery gates, original API/cache provenance and hashes.

O(total pinned bytes+C*(V+E)+I+256R) time, O(largest source/JSON) retained
space plus solver-dependent checking (30 s/query). No native target executes.
"""
import hashlib,json,re,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from lskd_continuations_symbolic import queries
BASE=ROOT.parent;BASELINE_SHA='a46385e686ab80cbe33dcdd4dc6fceb3c631ec031fe59791c677fb873e1e2dca'
EXPECTED={'bounded_source_spans': 38, 'additional_controller_cells': 5, 'exhaustive_bank_rules': 6, 'bank_byte_input_checks': 1536, 'original_lock_API_bindings': 3, 'source_proof_pairs_unsat': 20, 'fresh_cases': 355, 'source_visits': 1113798, 'source_byte_checks': 4455192, 'source_write_epochs': 114977, 'read_epochs': 224051, 'discarded_probe_read_epochs': 355, 'byte_reconstructed_cases': 355, 'preceding_complete_prefixes_equal': 343, 'FP64_contexts_preserved': 355, 'register_only_models': 1912, 'original_authenticated_edges': 797, 'original_continuation_calls': 195, 'context_record_roundtrips': 48, 'source_bounds_argument_pairs': 48, 'GP_and_SP_helper_returns': 159, 'source_context_zero_helper_errors': 24, 'continued_cases': 85, 'continued_context_error_wrapper_returns': 36, 'source_acquisition_records': 61, 'lock_records_preserved': 87, 'cached_RW_read_epochs': 99, 'unexecuted_unknown_private_read_boundaries': 24, 'source_release_records': 25, 'allowed_scalar_record_roundtrips': 24, 'source_cached_free_records': 13, 'source_stop_zeroed_candidate_publications': 13, 'additional_presence_fixture_prefixes_equal': 12, 'unexecuted_RW_write_calls': 12}

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_continuations_prior_manifest.json')==BASELINE_SHA;baseline=read('lskd_continuations_prior_manifest.json');assert len(baseline['files'])==1891
 c=read('lskd_continuations_contracts.json');p=read('lskd_continuations_profiles.json');fresh=read('lskd_continuations_replays.json');checks=read('lskd_continuations_checks.json');proof=read('lskd_continuations_proofs.json');preserve=read('lskd_continuations_preservation.json');prior=read('lskd_readback_contracts.json')
 for obj,name in[(c,'recover_lskd_continuations.py'),(p,'probe_lskd_continuations.py'),(fresh,'validate_lskd_continuations.py'),(checks,'validate_lskd_continuations.py'),(proof,'prove_lskd_continuations.py'),(preserve,'validate_lskd_continuations_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass']and checks['verified_counts']==EXPECTED;assert sha(ROOT/'lskd_continuations_replays.json')==checks['fresh_replays_sha256']and p['cases']==fresh['cases'];assert len(fresh['cases'])==355;del p
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 assert len(c['spans'])==38 and k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']+checks['additional_bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 roots=[b for b in c['bank_rules']+checks['additional_bank_rules']if b['target']=='0xfffffe000ccc78a8'];assert len(roots)==3 and len({r['slot']for r in roots})==1 and roots[0]['slot']=='0xfffffe0008471818'
 for d in c['additional_mutable_globals']:assert k.read(int(d['address'],16),8).hex()==d['original8_hex']
 assert k.read(0xfffffe000ccc78a8,8).hex()==c['cached_RW_cell']['original8_hex']=='0000000000000000'and not c['cached_RW_cell']['runtime_value_known']and not c['cached_RW_cell']['native_creation_lineage_known']
 aliases=[]
 for delta in c['pointer_alias_search_deltas']:
  target=0xfffffe000ccc78a8+delta
  for va,off,n in IMAGE.segments:
   data=IMAGE.data[off:off+n];needle=struct.pack('<Q',target);at=data.find(needle)
   while at>=0:aliases.append({'bias_from_cell':delta,'pointer':pointer(k,va+at)});at=data.find(needle,at+1)
 assert aliases==c['bounded_pointer_aliases']and len(aliases)==3
 for ptr in c['lock_control_slots']+checks['original_authenticated_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 native_entries=set();api_names={}
 for a in c['lock_apis']:
  for s in[a['wrapper'],a['stub']]:
   now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);native_entries.add(s['start'])
  b=a['binding'];assert pointer(k,int(b['slot'],16))==b and b['authenticated']and b['diversity']=='0x0'and(int(b['word'],16)>>48)&1;assert k.symbols([int(b['target'],16)])[b['target']]==a['exact_target_symbols'];native_entries.add(b['target']);api_names[a['label']]=[s['name']for s in a['exact_target_symbols']]
 assert api_names=={'write':['_IORWLockWrite','_lck_rw_lock_exclusive'],'unlock':['_IORWLockUnlock','_lck_rw_done'],'free':['_IORWLockFree']}
 qs,lifts=queries(c,prior);assert lifts==proof['source_lift_counts']and sum(lifts.values())==286 and len(qs)==20
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 groups=Counter();status_codes=Counter();publications=[];helper_return_counts=Counter()
 for r in fresh['cases']:
  case=r['input'];entry=r['continuation_entry'];assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64']
  for flag in['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','external_IPC_emission_proved','full_goal_complete','native_object_free_executed','native_complete_business_handler_executed','native_synchronization_executed']:assert not r[flag],flag
  assert not any(x['pc']in native_entries or x['pc']=='0xfffffe000a5793bc'for x in r['source_visits'])
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled']
  for x in r['continuation_returns']:helper_return_counts[x['target']]+=1
  if entry is None:continue
  if case.get('entity_fixture'):
   groups['nonnull_cache_RW_boundary']+=1;assert r['boundary']['pc']=='0xfffffe000a543fd4'and r['boundary']['registers31'][0]=='0x630000e000';assert not r['source_execution_wrapper_returned'];assert r['continuation_calls'][-1]['target']=='0xfffffe000a508d94'
  elif case['operation32']==0x1b5a:
   groups['stop_zero_cache_success']+=1;assert r['source_stop_local_success_executed']and r['source_execution_wrapper_returned']and r['source_continued_inner_dispatcher_returned'];pub=r['response_publication'];assert pub is not None and pub['pc']=='0xfffffe000a522e44'and pub['candidate']['bytes_hex']==bytes(160).hex();assert r['boundary']['registers31'][0]=='0x0'and bytes.fromhex(r['workspace']['bytes_hex'])[48:52]==struct.pack('<I',0x5e561849);publications.append(pub)
   assert [x['target']for x in r['continuation_calls']]==['0xfffffe000a54e220','0xfffffe000a551f38','0xfffffe000a5529a8']
  elif case.get('provider')in['vault','allowed']and case['context64']:
   groups[case['provider']+'_unknown_read']+=1;assert not r['source_execution_wrapper_returned']and r['unexecuted_unknown_private_read']is not None
  else:
   label=case['provider'];groups[label+'_error_wrapper']+=1;raw=0x5e561848 if label=='avd'else 0x5e55719c;status=(raw-0x5e561849)&0xffffffff;assert int(r['boundary']['registers31'][0],16)==status and bytes.fromhex(r['workspace']['bytes_hex'])[48:52]==struct.pack('<I',raw);status_codes[hex(raw)+' -> '+hex(status)]+=1;assert r['source_execution_wrapper_returned']and r['source_continued_inner_dispatcher_returned']
 assert dict(groups)=={'vault_error_wrapper':12,'vault_unknown_read':12,'avd_error_wrapper':12,'allowed_error_wrapper':12,'allowed_unknown_read':12,'stop_zero_cache_success':13,'nonnull_cache_RW_boundary':12};assert sum(helper_return_counts.values())==159 and len(publications)==13
 assert status_codes==Counter({'0x5e55719c -> 0xffff5953':24,'0x5e561848 -> 0xffffffff':12})
 calls=(BASE/'com.apple.driver.FairPlayIOKit_calls.txt').read_text()
 for text in['_kernel_iorw_lock_write -> _IORWLockWrite','_kernel_iorw_lock_unlock -> _IORWLockUnlock','_kernel_iorw_lock_free -> _IORWLockFree']:assert text in calls
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1891 and preserve['unchanged_prior_artifacts']==1885
 for row in baseline['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert path.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['lskd_continuations_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path in[ROOT/'lskd_continuations_quality_gates.json',ROOT/'lskd_continuations_source_identity.json'],(name,target);links+=1
 report=(BASE/'lskd_continuations_report.md').read_text()
 for term in['CT12','QG7','1113798','4455192','286','1912','355','343','1536','unknown','0xfffffe000ccc78a8','0xfffffe000ccceab8','0xfffffe000a57eef8','0xfffffe000a57282c','0xFFFF5953','0xFFFFFFFF','1891','1885','zero','returning','Mach','substitutions']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'cached_RW_cell':c['cached_RW_cell'],'cached_cell_roots':roots,'bounded_pointer_aliases':aliases,'lock_apis':c['lock_apis'],'original_authenticated_slots':checks['original_authenticated_slots'],'continuation_groups':dict(groups),'raw_to_wrapper_status_counts':dict(status_codes),'helper_return_counts':dict(helper_return_counts),'source_stop_publications':len(publications),'source_free_clear_PC':'0xfffffe000a5793bc','source_free_clear_executed':False,'native_synchronization_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_continuations_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual technical interface analysis.','CT1-CT12 specify source phases, checked key composition, cache/runtime state, returning-free and unknown-read premises.','Five helper contexts, records, locking touch points, local outputs and explicit frontiers covered; broad goal remains incomplete.','Fixed-width arithmetic, exact byte offsets/counts, source formulas and complexity explicit.','Raw errors, phases, file/runtime cache contents, local/Mach publication, guarded reads and native effects separated.','Original bytes/names/chains,355 fresh byte-audited cases,343+12 exact prefixes,20 re-lifted proof pairs and six exhaustive banks.','Impact-labeled continuation table.'];outputs=['lskd_continuations_contracts.json','lskd_continuations_profiles.json','lskd_continuations_replays.json','lskd_continuations_checks.json','lskd_continuations_proofs.json','lskd_continuations_preservation.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':1891,'unchanged_prior_artifacts':1885,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'continuation_groups':dict(groups),'raw_to_wrapper_status_counts':dict(status_codes),'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_continuations_source_identity.json'),'model_memory_writes':0,'native_synchronization_executed':False,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_continuations_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_quality_gates_pass':True,'fresh_cases':355,'source_proof_pairs':20,'stop_publications':13,'prior_artifacts_checked':1891,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
