#!/usr/bin/env python3
"""Original-source identity, frozen baseline and scoped values delivery gates.

O(total pinned bytes + source words + links) time; O(largest source/JSON)
space. No native target, handler/API/heap/IPC execution or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='aeebeceff611db22c1afc9578efdf9d73f6fc4ca49a434e10cec0cc8846fd7d8'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
EXPECTED={'compiler_envelopes': 9, 'static_query_caller': 1, 'new_source_spans': 25, 'exhaustive_rules': 106, 'bank_byte_inputs': 27136, 'source_derived_proofs_unsat': 14, 'fresh_cases': 343, 'source_visits': 922309, 'source_byte_checks': 3689236, 'source_write_epochs': 101314, 'read_epochs': 184777, 'discarded_probe_read_epochs': 343, 'byte_reconstructed_cases': 343, 'preceding_complete_prefix_equal_cases': 271, 'original_continuation_table_edges': 1489, 'register_only_models': 1670, 'FP64_contexts_preserved': 343, 'discarded_original_stack_probes': 343, 'source_caller_lineages': 156, 'source_constructed_packet_bytes': 3420, 'aligned_source_constructor_records': 156, 'GP_and_SP_bridge_contexts_preserved': 285, 'source_BE64_output_stores': 120, 'source_BE64_payload_byte_reads': 960, 'common_value_bridge_returns': 212, 'prepared_next_record_calls': 120, 'original_continuation_import_edges': 13, 'source_query_candidate_publications': 13, 'query_source_u32_append_bytes': 52, 'source_zero_displacement_returns': 166, 'source_execution_wrapper_returns': 166, 'source_prepared_free_calls': 485, 'span_value_bridge_returns': 73, 'source_error_wrapper_returns': 153, 'explicit_stream_fixture_cases': 187, 'common_failure_output_words_unchanged': 92, 'prepared_41byte_random_calls': 12}
LIFTS={'common_lookup_status_gate': 6, 'common_pointer_length_gate': 9, 'big_endian_value64': 55, 'common_raw_status_store': 1, 'span_status_normalization': 5, 'query_append_key': 15, 'u32_append_decoder_key': 15, 'query_append_record_pack': 12, 'query_payload_decoder': 95, 'query_inner_record_pack': 70, 'query_inner_selector': 2, 'query_append_raw_status': 2, 'query_initializer_status_gate': 11, 'query_inner_status_forward': 2, 'source_candidate_publication': 3, 'span_shape_and_auxiliary_field': 19, 'span_random_call_arguments': 2}
def main():
 assert sha(ROOT/'lskd_values_prior_manifest.json')==BASELINE_SHA;old=read('lskd_values_prior_manifest.json');assert len(old['files'])==1791
 c=read('lskd_values_contracts.json');p=read('lskd_values_profiles.json');proof=read('lskd_values_proofs.json');checks=read('lskd_values_checks.json');fresh=read('lskd_values_replays.json');preserve=read('lskd_values_preservation.json');handlers=read('lskd_handlers_contracts.json')
 for obj,name in [(c,'recover_lskd_values.py'),(p,'probe_lskd_values.py'),(proof,'prove_lskd_values.py'),(checks,'validate_lskd_values.py'),(fresh,'validate_lskd_values.py'),(preserve,'validate_lskd_values_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_values_replays.json')==checks['fresh_replays_sha256']and fresh['cases']==p['cases'];assert checks['verified_counts']==EXPECTED and checks['source_lift_counts']==proof['source_lift_counts']==LIFTS and sum(LIFTS.values())==324 and len(proof['proofs'])==14
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 assert checks['boundary_coverage']=={'before_next_record_helper':120,'before_random_call':13,'before_stop_helper':13,'wrapper_returned_to_provider':24,'selected_operation_leaf':19,'execution_wrapper_return':142,'before_span_random_call':12}and len(checks['next_handoff_coverage'])==5
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE,selected
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']+[c['query_caller_static']]:assert function(k,e,int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for b in c['bank_rules']+checks['additional_bank_rules']:
  l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']and k.symbols([0xfffffe000ccc2ce0])==checks['global_rng_exact_symbols']
 for ptr in checks['original_continuation_slots']+checks['original_import_slots']+checks['global_rng_pointer_roots']+[handlers['random_import_binding']]:assert pointer(k,int(ptr['slot'],16))==ptr
 assert len(checks['additional_bank_rules'])==2 and checks['additional_bank_rules'][0]['target']=='0xfffffe000a508d6c'and checks['additional_bank_rules'][1]['target']=='0xfffffe000ccc2ce0'and int(checks['additional_bank_rules'][1]['bias'],16)&((1<<64)-1)==((1<<64)-12)
 pubs=[];aligned=[];randoms=[]
 for r in fresh['cases']:
  for flag in ['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','stop_helper_executed','external_IPC_emission_proved','full_goal_complete']:assert not r[flag]
  assert not any(v['pc']in ['0xfffffe000a508d6c','0xfffffe000a69f394','0xfffffe000be57d68','0xfffffe000a54e220',*[h['target']for h in c['handoffs']]]for v in r['source_visits'])
  for model in r['models']:assert not model['target_executed']and not model['memory_effects_modeled']
  for call in r['source_calls']:
   if call['kind']=='constructor_record':aligned.append(int(call['record']['address'],16));assert aligned[-1]&15==8
  if r['response_publication']is not None:assert r['positive_publication_executed']and r['source_query_success_executed'];pubs.append(r['response_publication'])
  if r['next_record_handoff']is not None and r['next_record_handoff']['kind']=='random_41_call':randoms.append(r['next_record_handoff'])
 assert len(aligned)==156 and len(pubs)==13 and len(randoms)==12
 assert '_kernel_read_random -> _read_random'in(BASE/'com.apple.driver.FairPlayIOKit_calls.txt').read_text()
 identity={'scope':'Common64 consumption, record-status channels, source query append/publication/return, caller handoffs and37-byte span to unexecuted41-byte RNG request. Native effects/remaining helpers/IPC remain unknown.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in ['start','end','sha256']}for f in c['functions']],'static_query_caller':{n:c['query_caller_static'][n]for n in ['start','end','sha256']},'source_spans':[{n:s[n]for n in ['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'handoffs':c['handoffs'],'original_continuation_slots':checks['original_continuation_slots'],'original_import_slots':checks['original_import_slots'],'global_rng_pointer_roots':checks['global_rng_pointer_roots'],'global_rng_exact_symbols':checks['global_rng_exact_symbols'],'additional_bank_rules':checks['additional_bank_rules'],'random_import_binding':handlers['random_import_binding'],'private_source_publication_cases':13,'private_publication_pc':'0xfffffe000a522e44','query_packet8_hex':'0065000413180000','query_source_zero_displacement_returns':13,'prepared_global_rng_cases':12,'global_rng_destination':'0xfffffe000ccc2ce0','global_rng_requested_size_bytes':41,'source_span_required_size_bytes':37,'contracts_sha256':sha(ROOT/'lskd_values_contracts.json'),'aligned_source_constructor_records':156,'allocator_free_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'native_publication_proved':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_values_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1791 and preserve['unchanged_prior_artifacts']==1785
 for row in old['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert path.stat().st_size==row['size_bytes']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in ['lskd_values_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_values_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_values_report.md').read_text()
 for term in ['LV12','QG7','343','922309','3689236','324','3420','27136','unknown','0xfffffe000a522e44','0xfffffe000a5296e4','0xfffffe000ccc2ce0','WZR','37','41','0x13180000','cleanup','epoch','D*E']:assert term in report,term
 evidence=['Factual original-source interface analysis.','LV1-LV12 specify dependencies and falsification probes, including source phases/shared-key composition, distinct cells, conditional publication and unexecuted cleanup/native effects.','Value/status contracts, caller handoffs, query append/publication and37-byte RNG preparation covered; remaining helper/native/IPC interfaces and broad goal remain incomplete.','Fixed widths, byte epochs/extents, counts, arithmetic and implementation-sensitive complexity explicit.','Raw/normalized and record/register status, pointer/copy, publication/Mach emission, static/finite/solver and conditional/native claims separated.','Primary bytes/exact names/chains,343 fresh cases,271 exact preceding prefixes and fourteen re-lifted original/normalized source proof pairs.','Impact-labeled bounded continuation table.'];outputs=['lskd_values_contracts.json','lskd_values_profiles.json','lskd_values_replays.json','lskd_values_checks.json','lskd_values_proofs.json','lskd_values_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':LIFTS,'prior_artifacts_checked':1791,'unchanged_prior_artifacts':1785,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_values_source_identity.json'),'private_source_publication_cases':13,'allocator_free_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'native_publication_proved':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_values_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':343,'proofs_unsat':14,'private_publications':13,'prior_artifacts_checked':1791,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
