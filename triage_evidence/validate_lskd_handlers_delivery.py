#!/usr/bin/env python3
"""Original-source identity, frozen baseline and scoped handlers delivery gates.

O(total pinned bytes + source words + links) time; O(largest source/JSON)
space. No native target, handler/API/heap/IPC execution or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='8c8e8a836e00d36e189125f7678939183c421572fa28812f98536dd423651461'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
EXPECTED={'compiler_envelopes': 11, 'new_source_spans': 27, 'random_import_binding': 1, 'exhaustive_rules': 103, 'bank_byte_inputs': 26368, 'new_bank_pointer_roots': 4, 'source_derived_proofs_unsat': 25, 'fresh_cases': 271, 'source_visits': 720474, 'source_byte_checks': 2881896, 'source_write_epochs': 82169, 'read_epochs': 136067, 'discarded_probe_read_epochs': 271, 'byte_reconstructed_cases': 271, 'register_only_models': 957, 'FP64_contexts_preserved': 271, 'discarded_original_stack_probes': 271, 'preceding_source_prefix_equal_cases': 144, 'source_constructed_packet_bytes': 2928, 'source_caller_lineages': 144, 'aligned_source_constructor_records': 144, 'source_top_header_bytes': 14092, 'original_handler_branch_edges': 1851, 'original_handler_call_edges': 439, 'source_wire_header_byte_reads': 1008, 'field_search_returns': 213, 'scalar_record_lineages': 152, 'prepared_random_calls': 13, 'prepared_stop_helper_calls': 13, 'query_response_initializations': 13, 'span_record_lineages': 61, 'explicit_stream_fixture_cases': 127, 'unchanged_default_boundaries': 19}
LIFTS={'encoder_0x1b5b': 42, 'query_abstracted_encoder': 42, 'query_initializer_fields': 29, 'encoder_0x1b5c': 35, 'encoder_0x1b67': 29, 'encoder_0x1b68': 47, 'encoder_0x1b69': 26, 'encoder_0x1b6a': 53, 'encoder_0x1b6b': 34, 'encoder_0x1b6c': 29, 'encoder_0x1b6d': 40, 'encoder_0x1b6e': 30, 'scalar_key1': 13, 'scalar_key2': 14, 'scalar_decoder_and_pack': 45, 'span_key1': 6, 'span_key2': 7, 'span_decoder_and_pack': 35, 'generic_key32': 15, 'generic_decoder_key': 18, 'generic_output_clear': 4, 'wire_header_and_compare': 58, 'nonmatch_advance': 10, 'matching_output_stores': 4, 'raw_status_store': 1, 'random_call_arguments': 2}
def main():
 assert sha(ROOT/'lskd_handlers_prior_manifest.json')==BASELINE_SHA;old=read('lskd_handlers_prior_manifest.json');assert len(old['files'])==1723
 c=read('lskd_handlers_contracts.json');p=read('lskd_handlers_profiles.json');proof=read('lskd_handlers_proofs.json');checks=read('lskd_handlers_checks.json');fresh=read('lskd_handlers_replays.json');preserve=read('lskd_handlers_preservation.json');request=read('lskd_request_contracts.json')
 for obj,name in [(c,'recover_lskd_handlers.py'),(p,'probe_lskd_handlers.py'),(proof,'prove_lskd_handlers.py'),(checks,'validate_lskd_handlers.py'),(fresh,'validate_lskd_handlers.py'),(preserve,'validate_lskd_handlers_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_handlers_replays.json')==checks['fresh_replays_sha256']and fresh['cases']==p['cases'];assert checks['verified_counts']==EXPECTED and checks['source_lift_counts']==proof['source_lift_counts']==LIFTS and sum(LIFTS.values())==668 and len(proof['proofs'])==25
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 assert checks['boundary_coverage']=={'field_search_return':213,'before_random_call':13,'before_stop_helper':13,'response_initializer_return':13,'selected_operation_leaf':19}and checks['lookup_outcomes']=={'found':180,'not_found':33}and len(checks['operation_coverage'])==12
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE,selected
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for b in c['bank_rules']:
  l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']and k.symbols([int(a,16)for a in c['random_exact_symbols']])==c['random_exact_symbols']
 for ptr in c['original_bank_pointer_roots']+checks['original_dynamic_handler_slots']+[c['random_import_binding']]:assert pointer(k,int(ptr['slot'],16))==ptr
 random=c['random_import_binding'];assert random['slot']=='0xfffffe000847c4f8'and random['target']=='0xfffffe000be57d68'and random['authenticated']and random['diversity']=='0x0'and(int(random['word'],16)>>48)&1
 ret=next(s for s in request['spans']if s['label']=='init_return');now=span(k,int(ret['start'],16),int(ret['end'],16));assert all(now[n]==ret[n]for n in now);assert any(i['ea']=='0xfffffe000a5323cc'and i['operands']=='w10, [x19, #0xc]'for i in ret['instructions'])
 aligned=[]
 for r in fresh['cases']:
  for flag in ['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','positive_publication_executed','external_IPC_emission_proved','complete_business_handler_executed','random_backend_executed','stop_helper_executed','full_goal_complete']:assert not r[flag]
  assert not any(v['pc']in ['0xfffffe000a508d6c','0xfffffe000a69f394',random['target'],'0xfffffe000a54e220','0xfffffe000a522e44']for v in r['source_visits'])
  for model in r['models']:assert not model['target_executed']and not model['memory_effects_modeled']
  for call in r['source_calls']:
   if call['kind']=='constructor_record':aligned.append(int(call['record']['address'],16));assert aligned[-1]&15==8
 assert len(aligned)==144
 identity={'scope':'Twelve original handler prefixes, common/span records, compact lookup returns, response initialization and exact kernel random binding; complete handlers/transport/native behavior remain unknown.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in ['start','end','sha256']}for f in c['functions']],'source_spans':[{n:s[n]for n in ['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'random_exact_symbols':c['random_exact_symbols'],'random_import_binding':random,'random_address_diversity':True,'original_dynamic_handler_slots':checks['original_dynamic_handler_slots'],'initializer_status_store':{'pc':'0xfffffe000a5323cc','record_offset_bytes':12,'source_span':ret,'observed_return_X0':8},'generic_status_store':{'pc':'0xfffffe000a50f098','record_offset_bytes':0},'handler_map':c['handlers'],'contracts_sha256':sha(ROOT/'lskd_handlers_contracts.json'),'aligned_source_constructor_records':144,'allocator_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'complete_business_handler_executed':False,'positive_publication_executed':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_handlers_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1723 and preserve['unchanged_prior_artifacts']==1717
 for row in old['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert path.stat().st_size==row['size_bytes']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in ['lskd_handlers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_handlers_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_handlers_report.md').read_text()
 for term in ['LH12','QG7','271','720474','2881896','668','2928','26368','1008','unknown','0xfffffe000a5323cc','0xfffffe000847c4f8','0xfffffe000be57d68','WZR','0x28','epoch','X0 equals8','malformed']:assert term in report,term
 evidence=['Factual original-source interface analysis.','LH1-LH12 list dependencies and falsification probes, including source phases, R=B+0x28 alias, key composition and valid-stream premises.','Twelve prefixes, lookup/access ABIs, response initialization and random binding covered; complete handlers/native validity/transport and broad goal remain incomplete.','Fixed widths, byte epochs/extents, modular cursor/tag arithmetic, counts and algorithmic bounds explicit.','Source/model, lookup/whole handler, record/register status, epoch/type and pointer/copy separated; initializer status+0x0c and X0=8 verified.','Primary bytes/exact names/chains, 271 fresh replays, 144 exact preceding prefixes and twenty-five original/normalized source-derived proof pairs.','Impact-labeled bounded continuation table.'];outputs=['lskd_handlers_contracts.json','lskd_handlers_profiles.json','lskd_handlers_replays.json','lskd_handlers_checks.json','lskd_handlers_proofs.json','lskd_handlers_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':LIFTS,'prior_artifacts_checked':1723,'unchanged_prior_artifacts':1717,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_handlers_source_identity.json'),'allocator_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'complete_business_handler_executed':False,'positive_publication_executed':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_handlers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':271,'proofs_unsat':25,'prior_artifacts_checked':1723,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
