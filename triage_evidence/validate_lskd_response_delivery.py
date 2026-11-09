#!/usr/bin/env python3
"""Field/source identity, baseline preservation and scoped delivery gates.

O(total pinned bytes + links + source words) time, O(largest source/JSON)
space. No native target, heap, synchronization, crypto, IPC or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='47b7449a772a04393e85ef5e8ca53196ea8a72ee82e7e823ed37a26118177c47'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'lskd_response_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);assert len(old['files'])==1626;c=read('lskd_response_contracts.json');p=read('lskd_response_profiles.json');proof=read('lskd_response_proofs.json');checks=read('lskd_response_checks.json');fresh=read('lskd_response_replays.json');preserve=read('lskd_response_preservation.json')
 for obj,name in[(c,'recover_lskd_response.py'),(p,'probe_lskd_response.py'),(proof,'prove_lskd_response.py'),(checks,'validate_lskd_response.py'),(fresh,'validate_lskd_response.py'),(preserve,'validate_lskd_response_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_response_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases']
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 expected={'compiler_envelopes': 8, 'new_source_spans': 18, 'original_stack_helpers': 2, 'exhaustive_rules': 82, 'bank_byte_inputs': 20992, 'new_bank_pointer_roots': 10, 'typed_views': 2, 'dispatch_slots': 12, 'source_derived_proofs_unsat': 12, 'fresh_cases': 288, 'source_visits': 725748, 'source_byte_checks': 2902992, 'source_write_epochs': 72804, 'read_epochs': 140100, 'byte_reconstructed_cases': 288, 'FP64_contexts_preserved': 288, 'original_stack_probe_calls': 192, 'auxiliary_storage_untouched_cases': 288, 'register_only_models': 1392, 'response_allocation_models': 288, 'provider_source_request_lineages': 192, 'provider_packet_bytes_preserved': 5568, 'source_top_header_bytes': 15552, 'null_response_allocation_returns': 96, 'source_outer_error_returns': 144, 'source_prepared_free_calls': 336, 'discarded_probe_read_epochs': 192, 'original_response_clear_bytes': 30720, 'source_record_compositions': 192, 'source_local_seed_adjustments': 192, 'request_header_reads': 180, 'metadata_getter_records': 180, 'request_operation_copies': 144, 'metadata_success_boundaries': 144, 'bad_header_returns': 36, 'source_zero_displacement_returns': 48, 'null_request_returns': 12}
 lifts={'allocation_gate': 8, 'encoder_key': 12, 'decoder_key': 11, 'record_pack': 28, 'inner_decode': 9, 'getter_record': 19, 'getter_decoder_key': 13, 'word_copy': 2, 'header_gate': 12, 'probe_madd': 4, 'probe_size': 3, 'delta': 4, 'delta_init': 2, 'delta_add': 3, 'result_gate': 12, 'publication_store': 3};assert checks['verified_counts']==expected and checks['source_lift_counts']==proof['source_lift_counts']==lifts and sum(lifts.values())==145 and len(proof['proofs'])==12
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
  assert pointer(k,int(b['slot'],16))==b['original_pointer'];l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for f in c['stack_helpers']:assert function(k,e,int(f['start'],16))==f
 assert pointer(k,int(c['stack_binding']['slot'],16))==c['stack_binding']
 for v in c['typed_views']:assert k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and pointer(k,int(v['name_pointer']['slot'],16))==v['name_pointer'];assert v['name']=='site.LSKDDispatchStream'and v['metadata_size32']==160 and v['metadata_flags32']==100 and v['initial_runtime_links16_hex']=='00'*16
 assert c['typed_views'][0]['bytes64_hex']==c['typed_views'][1]['bytes64_hex']==read('lskd_request_contracts.json')['typed_view']['bytes64_hex']
 for row in c['dispatch_slots']:assert pointer(k,int(row['original_pointer']['slot'],16))==row['original_pointer']
 rows=fresh['cases'];assert len(rows)==288;records=[]
 for row in rows:
  assert not row['native_API_executed']and not row['native_heap_executed']and not row['native_request_execution_executed']and not row['business_request_operation_executed']and not row['positive_publication_executed']and not row['external_IPC_emission_proved']and not row['undefined_private_value_reads']
  for m in row['models']:assert not m['target_executed']and not m['memory_effects_modeled']
  for call in row['source_calls']:
   if call['kind']=='constructor_record':records.append(int(call['record']['address'],16));assert records[-1]&15==8
  assert not any(0xfffffe000a59bf78<=int(v['pc'],16)<0xfffffe000a59bf84 or 0xfffffe000a522e38<=int(v['pc'],16)<0xfffffe000a522e5c or int(v['pc'],16)in[0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]for v in row['source_visits'])
 assert len(records)==192
 pub=next(v for v in c['spans']if v['label']=='conditional_publish');assert any(i['ea']=='0xfffffe000a522e44'and i['mnemonic']=='str'and i['operands']=='x9, [x8]'for i in pub['instructions'])
 identity={'scope':'Prospective response staging, request container metadata, original error cleanup and conditional publication; business state and positive publication unexecuted.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'typed_views':c['typed_views'],'dispatch_slots':c['dispatch_slots'],'original_stack_helpers':c['stack_helpers'],'original_stack_binding':c['stack_binding'],'metadata_read_sites':{'header':'0xfffffe000a56b454','operation':'0xfffffe000a53533c','word_output':'0xfffffe000a535340'},'conditional_publication':{'source_span':pub,'frame_premise':'Required SP and frame-cell values survive the actual processing return/displacement; current local proof does not establish that native success.','executed':False},'aligned_provider_constructor_records':192,'contracts_sha256':sha(ROOT/'lskd_response_contracts.json'),'allocator_free_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'native_request_execution_executed':False,'business_request_operation_executed':False,'positive_publication_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_response_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1620
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['lskd_response_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_response_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_response_report.md').read_text()
 for term in['RS11','QG7','288','725748','2902992','145','30720','192','5568','unknown','0xffff5964','0xffff5966','site.LSKDDispatchStream','0xfffffe000a522e44','0xfffffe000a56b454','WZR','conditional','positive']:assert term in report,term
 evidence=['Factual source/interface analysis.','RS1-RS11 specify dependencies and falsification probes, including inherited construction and publication-frame premises.','Response staging, metadata/error paths, stack context and conditional publication covered; native validity/business success/transport and broad objective remain incomplete.','Fixed widths, byte epochs, source/frame/probe sizes, displacement arithmetic, counts and complexity explicit.','Container/packet header, metadata/operation acceptance, model/source, unknown probe/value reads and conditional/native publication separated.','Primary bytes/slots, 288 fresh cases, twelve original/normalized source-derived proof pairs and actual constructor alignments.','Impact-labeled bounded continuation table.'];outputs=['lskd_response_contracts.json','lskd_response_profiles.json','lskd_response_replays.json','lskd_response_checks.json','lskd_response_proofs.json','lskd_response_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'source_lift_counts':lifts,'prior_artifacts_checked':1626,'unchanged_prior_artifacts':1620,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_response_source_identity.json'),'aligned_provider_constructor_records':192,'allocator_free_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'native_request_execution_executed':False,'business_request_operation_executed':False,'positive_publication_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_response_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':288,'proofs_unsat':12,'prior_artifacts_checked':1626,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
