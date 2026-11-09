#!/usr/bin/env python3
"""Field/source identity, baseline preservation and scoped delivery gates.

O(total pinned bytes + links + source words) time, O(largest source/JSON)
space. No native target, heap, synchronization, crypto, IPC or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='148cf012abf0ac5adbb1f2d4d7d96d501da31094552a8508891bfcf1dce2e717'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'lskd_fields_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);assert len(old['files'])==1564;c=read('lskd_fields_contracts.json');p=read('lskd_fields_profiles.json');proof=read('lskd_fields_proofs.json');checks=read('lskd_fields_checks.json');fresh=read('lskd_fields_replays.json');preserve=read('lskd_fields_preservation.json')
 for obj,name in[(c,'recover_lskd_fields.py'),(p,'probe_lskd_fields.py'),(proof,'prove_lskd_fields.py'),(checks,'validate_lskd_fields.py'),(fresh,'validate_lskd_fields.py'),(preserve,'validate_lskd_fields_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_fields_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases']
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 expected={'compiler_envelopes':3,'new_source_spans':8,'census_text_words':844178,'direct_calls':7,'exhaustive_rules':54,'bank_byte_inputs':13824,'new_bank_pointer_roots':8,'source_derived_proofs_unsat':8,'fresh_cases':336,'source_visits':280500,'source_byte_checks':1122000,'source_write_epochs':21264,'read_epochs':49128,'byte_reconstructed_cases':336,'source_generic_records':408,'standalone_field_returns':288,'rejection_cases':72,'original_copy_calls':336,'original_copy_bytes':1830,'standalone_append_cases':216,'standalone_packet_bytes':1782,'nonnull_zero_length_appends':36,'narrowed_length_appends':36,'scalar32_appends':90,'typed_heap_return_models':48,'source_pointer_publications':48,'provider_source_compositions':48,'provider_packet_bytes':1392,'provider_field_appends':120,'provider_publication_consumptions':120,'provider_pointer_representations':60,'AVD_source_cleared_bytes':96}
 lifts={'span_key':16,'generic_key':20,'span_pack':21,'u32_outer_key':16,'u32_decoder_key':15,'u32_tag_pre':4,'u32_pack':13,'u32_payload':95,'u32_inner_pack':70,'u32_inner_selector':2,'generic_inner_key':20,'variable_header':86,'variable_counter':5};assert checks['verified_counts']==expected and checks['source_lift_counts']==proof['source_lift_counts']==lifts and sum(lifts.values())==383 and len(proof['proofs'])==8
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE,selected
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 from recover_lskd_fields import census
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for b in c['bank_rules']:
  assert pointer(k,int(b['slot'],16))==b['original_pointer'];l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for scan in c['reference_census']:assert census(int(scan['target'],16))==scan
 rows=fresh['cases'];assert len(rows)==336;records=[]
 for row in rows:
  assert not row['native_API_executed']and not row['typed_heap_executed']and not row['request_execution_executed']and not row['external_IPC_emission_proved']and not row['native_carrier_validity_proved']and not row['undefined_private_value_reads']
  for m in row['models']:assert m['target']=='0xfffffe000c4ba154'and not m['target_executed']and not m['memory_effects_modeled']
  for call in row['source_calls']:
   if call['kind']=='constructor_record':records.append(int(call['record']['address'],16));assert records[-1]&15==8
  assert not any(0xfffffe000a50c508<=int(v['pc'],16)<0xfffffe000a50c980 or 0xfffffe000a54df90<=int(v['pc'],16)<0xfffffe000a54e220 or int(v['pc'],16)in[0xfffffe000c4ba154,0xfffffe000c4ba60c]for v in row['source_visits'])
 assert len(records)==48
 extra=function(k,e,0xfffffe000a505638);assert IMAGE.read(int(extra['start'],16),int(extra['end'],16)-int(extra['start'],16)).hex()==extra.get('bytes_hex',extra.get('bytes'));extra_syms=k.symbols([0xfffffe000a505638]);assert[r['name']for r in extra_syms['0xfffffe000a505638']]==['__ZN30com_apple_driver_FairPlayIOKit11R2nPsUOYx6hEPhjS0_j'];call=next(i for i in extra['instructions']if i['ea']=='0xfffffe000a5056ac');assert call['mnemonic']=='bl'and call['operands']=='#0xfffffe000a50bdfc'
 identity={'scope':'Span/u32 source codecs and four complete prepared provider requests; additional R2nPsUOYx6h caller static only.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'providers':c['providers'],'reference_census':c['reference_census'],'additional_direct_span_caller':{'function':extra,'exact_symbols':extra_syms,'direct_call':call,'replayed_in_current_increment':False},'aligned_constructor_records':len(records),'contracts_sha256':sha(ROOT/'lskd_fields_contracts.json'),'typed_heap_register_return_model_used_in_providers':True,'API_effect_models_used_in_standalone_fields':False,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_fields_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1558
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['lskd_fields_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_fields_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_fields_report.md').read_text()
 for term in['LF10','QG7','336','280500','1122000','383','1830','1392','little-endian','big-endian','unknown','R2nPsUOYx6h','0x10000','0xffff5966','ten-byte','48','120','60']:assert term in report,term
 evidence=['Factual source/interface analysis.','LF1-LF10 and inherited constructor LR4 define assumptions, dependencies and falsification probes.','Span/u32 helpers, bounded caller census and four complete prepared requests covered; native validity/execute/IPC and broad objective remain incomplete.','Bit widths, copied byte extents/epochs, endian representation, modulo counters, counts and bounded complexity explicit.','Null/non-null zero length, narrowed lengths, span/scalar encoding, reserved/used capacity, static/replayed caller and private/native claims separated.','Primary code/exact symbols/chains, 336 distinct fresh cases and eight source-derived original/normalized proof pairs.','Impact-labeled continuation table.'];outputs=['lskd_fields_contracts.json','lskd_fields_profiles.json','lskd_fields_replays.json','lskd_fields_checks.json','lskd_fields_proofs.json','lskd_fields_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'source_lift_counts':lifts,'prior_artifacts_checked':1564,'unchanged_prior_artifacts':1558,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_fields_source_identity.json'),'aligned_constructor_records':48,'typed_heap_register_return_model_used_in_providers':True,'API_effect_models_used_in_standalone_fields':False,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_fields_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':336,'proofs_unsat':8,'prior_artifacts_checked':1564,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
