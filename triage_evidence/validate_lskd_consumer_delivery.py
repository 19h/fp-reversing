#!/usr/bin/env python3
"""Original-source identity, frozen baseline and scoped consumer delivery gates.

O(total pinned bytes + source words + links) time; O(largest source/JSON)
space. No native target, handler/API/heap/IPC execution or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='9b1dea6dee2fe6c2cbe71cf96d7e84b28c7c77666701aad08d10ba7ca24de0ad'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
EXPECTED={'compiler_envelopes': 9, 'new_source_spans': 42, 'additional_original_callers': 4, 'bounded_direct_execution_callers': 8, 'exhaustive_rules': 82, 'bank_byte_inputs': 20992, 'classifier_original_edges': 28, 'source_fixed_frame_nodes': 14, 'preparation_root_slot': 1, 'source_derived_proofs_unsat': 19, 'fresh_cases': 175, 'source_visits': 497160, 'source_byte_checks': 1988640, 'source_write_epochs': 56151, 'read_epochs': 93741, 'discarded_probe_read_epochs': 175, 'byte_reconstructed_cases': 175, 'FP64_contexts_preserved': 175, 'original_stack_probe_calls': 175, 'auxiliary_storage_untouched_cases': 175, 'original_response_clear_bytes': 28000, 'register_only_models': 669, 'prior_provider_source_lineages': 96, 'source_constructed_packet_bytes': 2928, 'aligned_source_constructor_records': 144, 'source_top_header_bytes': 9100, 'source_operation_word_lineages': 175, 'source_preparation_pointer_cells': 4900, 'shared_frame_preparation_contexts': 175, 'source_classifier_edges': 653, 'classifier_frame_write_epochs': 5966, 'additional_caller_source_lineages': 48, 'additional_span_source_packets': 12, 'standalone_operation_fixtures': 31, 'default_error_preparations': 19}
LIFTS={'arithmetic_root': 18, 'arithmetic_right': 16, 'arithmetic_left': 8, 'arithmetic_upper': 16, 'arithmetic_middle': 13, 'arithmetic_lower': 21, 'arithmetic_scalar_split': 11, 'arithmetic_start_test': 11, 'arithmetic_stop_test': 13, 'arithmetic_span_test': 9, 'arithmetic_upper_split': 13, 'arithmetic_avd_split': 16, 'arithmetic_legacy_split': 19, 'arithmetic_last_test': 8, 'shared_frame_preparation': 49, 'source_operation_reload': 8, 'default_status_0': 2, 'default_status_1': 2, 'default_status_2': 2}
def main():
 assert sha(ROOT/'lskd_consumer_prior_manifest.json')==BASELINE_SHA;old=read('lskd_consumer_prior_manifest.json');assert len(old['files'])==1667
 c=read('lskd_consumer_contracts.json');p=read('lskd_consumer_profiles.json');proof=read('lskd_consumer_proofs.json');checks=read('lskd_consumer_checks.json');fresh=read('lskd_consumer_replays.json');preserve=read('lskd_consumer_preservation.json')
 for obj,name in [(c,'recover_lskd_consumer.py'),(p,'probe_lskd_consumer.py'),(proof,'prove_lskd_consumer.py'),(checks,'validate_lskd_consumer.py'),(fresh,'validate_lskd_consumer.py'),(preserve,'validate_lskd_consumer_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_consumer_replays.json')==checks['fresh_replays_sha256']and fresh['cases']==p['cases']
 assert checks['verified_counts']==EXPECTED and checks['source_lift_counts']==proof['source_lift_counts']==LIFTS and sum(LIFTS.values())==255 and len(proof['proofs'])==19
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 assert len(checks['edge_coverage'])==28 and all(checks['edge_coverage'].values())and len(checks['leaf_coverage'])==13 and len(checks['direct_caller_coverage'])==8
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for row in c['additional_callers']:
  a=int(row['start'],16);assert function(k,e,a)==row['function']and k.symbols([a])[hex(a)]==row['symbols']
 edges=[]
 for n in c['nodes']:
  for row in n['edges']:
   ptr=row['original_pointer'];assert pointer(k,int(ptr['slot'],16))==ptr and ptr['authenticated']and ptr['diversity']==n['modifier16'];edges.append(ptr)
 root=pointer(k,int(c['table_address'],16)+8*0x3b5);assert root['slot']=='0xfffffe000846e1c8'and root['target']==c['nodes'][0]['start']=='0xfffffe000a52dd2c'and root['authenticated']and root['diversity']=='0xa7e8'
 leafs={*c['leaf_map'].values(),c['default_leaf']};records=[]
 for r in fresh['cases']:
  for flag in ['native_API_executed','native_heap_executed','native_request_execution_executed','selected_operation_callee_executed','native_business_operation_executed','positive_publication_executed','external_IPC_emission_proved','undefined_private_value_reads','full_goal_complete']:assert not r[flag]
  assert r['operation_selection_executed_in_private_guest']and r['boundary']['pc']in leafs and r['boundary']['kind']=='selected_operation_leaf';assert not any(v['pc']in leafs for v in r['source_visits'])
  for model in r['models']:assert not model['target_executed']and not model['memory_effects_modeled']
  for call in r['source_calls']:
   if call['kind']=='constructor_record':records.append(int(call['record']['address'],16));assert records[-1]&15==8
 assert len(records)==144
 identity={'scope':'Complete conditional operation selector, source caller construction and epoch-specific shared-frame preparation; operation fragments remain unexecuted.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in ['start','end','sha256']}for f in c['functions']],'source_spans':[{n:s[n]for n in ['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'additional_caller_symbols':{r['start']:r['symbols']for r in c['additional_callers']},'original_selector_edges':edges,'original_preparation_root_slot':root,'selected_operation_map':c['leaf_map'],'default_fragment':c['default_leaf'],'bounded_reference_census':checks['bounded_reference_census'],'aligned_source_constructor_records':144,'contracts_sha256':sha(ROOT/'lskd_consumer_contracts.json'),'allocator_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'selected_operation_callee_executed':False,'positive_publication_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_consumer_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1667 and preserve['unchanged_prior_artifacts']==1661
 for row in old['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert path.stat().st_size==row['size_bytes']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in ['lskd_consumer_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_consumer_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_consumer_report.md').read_text()
 for term in ['LC10','QG7','175','497160','1988640','255','4900','2928','unknown','0x1b5d..0x1b66','0xfffffe000a59c048','0xfffffe000846e1c8','WZR','conditional','epoch']:assert term in report,term
 evidence=['Factual original-source interface analysis.','LC1-LC10 list dependencies and falsification probes, including entry context, finite caller arguments and inherited alignment.','Complete conditional selector domain, eight source callers and preparer interfaces; handler semantics/native behavior/transport and broad goal remain incomplete.','u32/signed32/u64 widths, byte epochs/extents, counts and algorithmic bounds explicit.','Selection/acceptance, source/model, pointed-to bytes/pointer representation, epoch/aggregate and conditional/native claims distinguished.','Primary bytes/exact names/chains, 175 fresh replays and nineteen source-derived original/normalized proof pairs rechecked.','Impact-labeled bounded continuation table.']
 outputs=['lskd_consumer_contracts.json','lskd_consumer_profiles.json','lskd_consumer_replays.json','lskd_consumer_checks.json','lskd_consumer_proofs.json','lskd_consumer_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':LIFTS,'prior_artifacts_checked':1667,'unchanged_prior_artifacts':1661,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_consumer_source_identity.json'),'allocator_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'selected_operation_callee_executed':False,'positive_publication_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_consumer_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':175,'proofs_unsat':19,'prior_artifacts_checked':1667,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
