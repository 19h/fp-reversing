#!/usr/bin/env python3
"""Pinned source identity, preservation and scoped construction delivery gates.

O(total pinned bytes + report links + source words) time, O(largest JSON/source)
space. No native target, API, heap, synchronization, crypto or IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='2cea6853a7fde5e5293781220a98c0967e11c639635aceada2290e398efd09e6'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'lskd_request_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);assert len(old['files'])==1536
 c=read('lskd_request_contracts.json');p=read('lskd_request_profiles.json');proof=read('lskd_request_proofs.json');checks=read('lskd_request_checks.json');fresh=read('lskd_request_replays.json');preserve=read('lskd_request_preservation.json')
 for obj,name in[(c,'recover_lskd_request.py'),(p,'probe_lskd_request.py'),(proof,'prove_lskd_request.py'),(checks,'validate_lskd_request.py'),(fresh,'validate_lskd_request.py'),(preserve,'validate_lskd_request_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_request_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases']
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 assert len(proof['proofs'])==5
 ce=read('lskd_request_alignment_counterexample.json');assert sha(ROOT/'lskd_request_alignment_counterexample.json')==proof['alignment_counterexample_sha256'];assert ce['record_address64']=='0xa7672f0e'and ce['encoder_key32']=='0xc8310288'and ce['decoder_key32']=='0x800ca44c'and not ce['native_target_executed']
 expected={'compiler_envelopes':15,'new_kernel_helpers':1,'new_source_spans':16,'direct_appender_callers':4,'census_text_words':422089,'exhaustive_rules':42,'bank_byte_inputs':10752,'new_dispatch_slots':10,'source_derived_proofs_unsat':5,'alignment_counterexamples':1,'fresh_cases':222,'source_visits':138546,'source_byte_checks':554184,'source_write_epochs':14778,'read_epochs':26346,'byte_reconstructed_cases':222,'aligned_constructor_records':162,'aligned_initializer_records':114,'typed_heap_return_models':138,'source_zeroed_object_bytes':18240,'source_pointer_publications':96,'inline_constructor_returns':48,'dynamic_allocation_boundaries':18,'null_allocation_returns':24,'null_output_reference_returns':24,'provider_source_compositions':48,'provider_tag72_bytes':576,'next_field_pointer_representations':24,'AVD_source_cleared_bytes':96,'next_scalar32_boundaries':12,'provider_guard_returns':60}
 lifts={'constructor_key_pair':34,'constructor_entry_prekey':6,'constructor_pack':24,'initializer_prekey':45,'initializer_key':17,'initializer_pack':14,'initializer_fields':29};assert checks['verified_counts']==expected and checks['source_lift_counts']==proof['source_lift_counts']==lifts and sum(lifts.values())==169
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE,selected
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 from recover_lskd_request import census
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 stub=next(s for s in c['spans']if s['label']=='fill_stub');assert stub['compiler_start']is None and stub['compiler_end']is None and stub['compiler_bounds_available']is False
 for b in c['bank_rules']:
  assert pointer(k,int(b['slot'],16))==b['original_pointer'];l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];out=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out)
 for b in c['dispatch_slots']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer']
 d=c['typed_view'];assert k.read(int(d['address'],16),64).hex()==d['bytes64_hex'];assert pointer(k,int(d['name_pointer']['slot'],16))==d['name_pointer'];assert k.read(int(d['name_pointer']['target'],16),80).split(b'\0')[0]==b'site.LSKDDispatchStream';assert d['metadata_flags32']==100 and d['metadata_size32']==160 and d['initial_runtime_links16_hex']=='00'*16
 assert pointer(k,int(c['fill_binding']['slot'],16))==c['fill_binding'];syms=k.symbols([int(a,16)for a in c['exact_symbols']]);assert syms==c['exact_symbols'];assert set(r['name']for r in syms['0xfffffe000c648170'])=={'_memset'}
 assert census()==c['append_reference_census'];assert len(c['providers'])==4 and len(c['bank_rules'])==20
 execute=[b for b in c['bank_rules']if b['label'].startswith('execute_')];assert len(execute)==5;assert[b['target']for b in execute]==['0xfffffe000c4b9a08','0xfffffe000c4ba154','0xfffffe000a55f5e4','0xfffffe000c4ba368','0xfffffe000c4b9a24']
 x=c['supplied_calls_excerpt'];assert sha(Path(x['path']))==x['sha256'];assert ''.join(Path(x['path']).read_text().splitlines(keepends=True)[70:74])==x['text']
 rows=fresh['cases'];assert len(rows)==222
 for row in rows:
  assert not row['native_API_executed']and not row['typed_heap_executed']and not row['request_execution_executed']and not row['external_IPC_emission_proved']and not row['native_carrier_validity_proved']and not row['undefined_private_value_reads']
  for m in row['models']:assert m['target']=='0xfffffe000c4ba154'and not m['target_executed']and not m['memory_effects_modeled']
  assert not any(0xfffffe000a50c508<=int(v['pc'],16)<0xfffffe000a50c980 or int(v['pc'],16)in[0xfffffe000c4ba154,0xfffffe000c4ba60c]for v in row['source_visits'])
 identity={'scope':'LSKDDispatchStream construction, inline storage/publication, four actual provider prefixes; execution-wrapper imports static only.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'kernel_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['kernel_functions']],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':syms,'fill_binding':c['fill_binding'],'typed_view':d,'providers':c['providers'],'static_execution_bindings':execute,'contracts_sha256':sha(ROOT/'lskd_request_contracts.json'),'typed_heap_register_return_model_used':True,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'external_IPC_emission_proved':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_request_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1530
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['lskd_request_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_request_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_request_report.md').read_text()
 for term in['LR10','QG7','222','138546','554184','18240','96','128','169','site.LSKDDispatchStream','alignment','unknown','0xa7672f0e','0xfffffe000ccceab8','0xffff5bd9','0xffff5964','four','ten']:assert term in report,term
 evidence=['Factual technical source/interface analysis.','LR1-LR10 define assumptions, dependent results and falsification probes.','Constructor, inline storage/publication, actual provider prefixes and static allocator bindings covered; native heap/execute/IPC and broad objective remain incomplete.','Widths, byte extents/epochs, u32 capacity arithmetic, counts, proof alignment and bounded complexity specified.','Alignment counterexample retained; heap-register model/source memory, inline/dynamic, private/native, pointer representation/external transport and static/executed interfaces separated.','Primary code/metadata/exact symbols/chains, supplied calls, 222 distinct fresh replays and five source-derived original/normalized proof pairs.','Impact-labeled bounded continuation table.']
 outputs=['lskd_request_contracts.json','lskd_request_profiles.json','lskd_request_replays.json','lskd_request_checks.json','lskd_request_proofs.json','lskd_request_alignment_counterexample.json','lskd_request_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'source_lift_counts':lifts,'prior_artifacts_checked':1536,'unchanged_prior_artifacts':1530,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_request_source_identity.json'),'typed_heap_register_return_model_used':True,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'external_IPC_emission_proved':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_request_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':222,'proofs_unsat':5,'prior_artifacts_checked':1536,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
