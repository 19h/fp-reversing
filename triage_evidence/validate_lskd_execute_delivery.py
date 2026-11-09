#!/usr/bin/env python3
"""Field/source identity, baseline preservation and scoped delivery gates.

O(total pinned bytes + links + source words) time, O(largest source/JSON)
space. No native target, heap, synchronization, crypto, IPC or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='61c3d4065b27942de809667b3385098f84e27fcfe3675d4d3271f77089520f5c'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'lskd_execute_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);assert len(old['files'])==1597;c=read('lskd_execute_contracts.json');p=read('lskd_execute_profiles.json');proof=read('lskd_execute_proofs.json');checks=read('lskd_execute_checks.json');fresh=read('lskd_execute_replays.json');preserve=read('lskd_execute_preservation.json')
 for obj,name in[(c,'recover_lskd_execute.py'),(p,'probe_lskd_execute.py'),(proof,'prove_lskd_execute.py'),(checks,'validate_lskd_execute.py'),(fresh,'validate_lskd_execute.py'),(preserve,'validate_lskd_execute_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'lskd_execute_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases']
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 expected={'compiler_envelopes':4,'new_source_spans':8,'census_text_words':422089,'direct_execution_calls':8,'exhaustive_rules':64,'bank_byte_inputs':16384,'new_bank_pointer_roots':12,'typed_views':2,'first_dispatch_slots':2,'source_derived_proofs_unsat':6,'fresh_cases':192,'source_visits':172564,'source_byte_checks':690256,'source_write_epochs':17100,'read_epochs':33072,'byte_reconstructed_cases':192,'untouched_auxiliary_cases':192,'register_only_models':432,'workspace_allocation_models':168,'auxiliary_allocation_models':168,'wrapper_range_checks':168,'stopped_before_null_workspace_store':48,'dispatcher_range_checks':120,'source_defined_workspace_bytes':6336,'source_workspace_headers':120,'first_dispatch_boundaries':96,'null_output_state_boundaries':24,'nonnull_output_state_boundaries':72,'source_null_output_returns':24,'source_status_bytes':96,'typed_free_register_models':24,'aligned_free_register_models':24,'provider_request_lineages':48,'provider_request_bytes_preserved':7680,'provider_packet_bytes_preserved':1392,'bounds_checker_returns':16,'stopped_before_bounds_trap':8}
 lifts={'record_encode':23,'decoder_key':15,'record_decode':9,'first_state':10,'status_return':3,'first_range_start':1,'first_range_end':1};assert checks['verified_counts']==expected and checks['source_lift_counts']==proof['source_lift_counts']==lifts and sum(lifts.values())==62 and len(proof['proofs'])==6
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE,selected
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 from recover_lskd_execute import census
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 for b in c['bank_rules']:
  assert pointer(k,int(b['slot'],16))==b['original_pointer'];l=int(b['left'],16);r=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];assert census(0xfffffe000a50c508)==c['execution_wrapper_census']
 for view in c['typed_views']:assert k.read(int(view['address'],16),64).hex()==view['bytes64_hex']and pointer(k,int(view['name_pointer']['slot'],16))==view['name_pointer'];assert view['name']=='site.AllocType'and view['metadata_size32']==4096 and view['metadata_flags32']==0xe4 and view['initial_runtime_links16_hex']=='00'*16
 assert c['typed_views'][0]['bytes64_hex']==c['typed_views'][1]['bytes64_hex']
 for row in c['first_dispatch_slots']:assert pointer(k,int(row['original_pointer']['slot'],16))==row['original_pointer']
 rows=fresh['cases'];assert len(rows)==192;records=[]
 for row in rows:
  assert not row['native_API_executed']and not row['native_heap_executed']and not row['native_request_execution_executed']and not row['protected_operation_executed']and not row['external_IPC_emission_proved']and not row['undefined_private_value_reads']and not row['first_nonnull_output_state_executed']
  for m in row['models']:assert not m['target_executed']and not m['memory_effects_modeled']
  for call in row['source_calls']:
   if call['kind']=='constructor_record':records.append(int(call['record']['address'],16));assert records[-1]&15==8
  assert not any(0xfffffe000a5247ac<=int(v['pc'],16)<0xfffffe000a5248a0 or int(v['pc'],16)in[0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24,0xfffffe000a561068]for v in row['source_visits'])
 assert len(records)==48
 # Static continuation uses the exact entry-frame bank definitions, not neighboring banks.
 static=span(k,0xfffffe000a5247ac,0xfffffe000a52486c);assert IMAGE.read(0xfffffe000a5247ac,0xc0).hex()==static['bytes_hex'];assert static['instructions'][-1]['ea']=='0xfffffe000a524868'and static['instructions'][-1]['mnemonic']=='blraa'
 rules=[]
 for label,l,r,key,add,base,bias in[('next_typed_call',0xfffffe0007920c10,0xfffffe00079170c0,0x20,0x973,0xfffffe000846c420,0),('next_typed_view',0xfffffe00079171c0,0xfffffe0007919bb0,0xea,0x65,0xfffffe00084716e0,-8)]:
  b=selected(l,r,key,add,base=base,bias=bias);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 assert[b['target']for b in rules]==['0xfffffe000c4ba154','0xfffffe000847ae60']
 view_address=0xfffffe000847ae60;raw=k.read(view_address,64);name_pointer=pointer(k,view_address+16);assert k.read(int(name_pointer['target'],16),80).split(b'\0')[0]==b'site.LSKDDispatchStream';assert int.from_bytes(raw[40:44],'little')==0x64 and int.from_bytes(raw[44:48],'little')==160;request_view=read('lskd_request_contracts.json')['typed_view'];assert raw.hex()==request_view['bytes64_hex'];next_view={'address':hex(view_address),'bytes64_hex':raw.hex(),'name':'site.LSKDDispatchStream','name_pointer':name_pointer,'metadata_flags32':0x64,'metadata_size32':160,'matches_request_view_bytes':request_view['address'],'native_allocation_executed':False}
 # Exact compiler ownership and nlist matches for all eight direct callers.
 caller_starts=[0xfffffe000a5053f4,0xfffffe000a505480,0xfffffe000a50550c,0xfffffe000a505638,0xfffffe000a505848,0xfffffe000a505958,0xfffffe000a505ac8,0xfffffe000a505de0];caller_symbols=k.symbols(caller_starts);callers=[]
 for a,call in zip(caller_starts,c['execution_wrapper_census']['direct_calls']):
  f=function(k,e,a);pc=int(call['pc'],16);assert a<=pc<int(f['end'],16)and caller_symbols[hex(a)];assert IMAGE.read(a,int(f['end'],16)-a).hex()==f.get('bytes_hex',f.get('bytes'));callers.append({n:f[n]for n in['start','end','sha256']}|{'direct_call':call,'exact_symbols':caller_symbols[hex(a)],'replayed_in_current_increment':a>=0xfffffe000a505848})
 identity={'scope':'Execution workspace/header, first output-reference state and original null-output cleanup; next nonnull allocation static only.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'typed_views':c['typed_views'],'first_dispatch_slots':c['first_dispatch_slots'],'direct_caller_contexts':callers,'static_nonnull_continuation':{'span':static,'bank_rules':rules,'next_typed_view':next_view,'executed':False},'aligned_provider_constructor_records':48,'contracts_sha256':sha(ROOT/'lskd_execute_contracts.json'),'allocator_free_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'native_request_execution_executed':False,'protected_operation_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_execute_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1591
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['lskd_execute_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'lskd_execute_quality_gates.json',(name,target);links+=1
 report=(BASE/'lskd_execute_report.md').read_text()
 for term in['LE10','QG7','192','172564','690256','62','6336','52','4096','16384','unknown','0xffff5966','0x5e5571af','site.AllocType','site.LSKDDispatchStream','static','48','7680','1392']:assert term in report,term
 evidence=['Factual source/interface analysis.','LE1-LE10 and inherited constructor/field assumptions define dependencies and falsification probes.','Workspace ABI, first state, source null-output return, free arguments and static next allocation covered; native validity/processing/transport and broad objective remain incomplete.','Widths, partial-byte epochs, numeric intervals, u32 status, counts, nonwrapping premise and bounded complexity specified.','Unknown poison/source initialization, register model/source status, bounds/ownership and static/executed paths separated.','Primary code/exact symbols/slots, 192 distinct fresh cases, six original/normalized source-derived proof pairs and separately checked static continuation.','Impact-labeled continuation table.'];outputs=['lskd_execute_contracts.json','lskd_execute_profiles.json','lskd_execute_replays.json','lskd_execute_checks.json','lskd_execute_proofs.json','lskd_execute_preservation.json'];out={'scope':identity['scope'],'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'source_lift_counts':lifts,'prior_artifacts_checked':1597,'unchanged_prior_artifacts':1591,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_execute_source_identity.json'),'aligned_provider_constructor_records':48,'static_continuation_rules':2,'static_continuation_byte_inputs':512,'allocator_free_register_models_used':True,'model_memory_writes':0,'native_heap_executed':False,'native_request_execution_executed':False,'protected_operation_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_execute_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':192,'proofs_unsat':6,'prior_artifacts_checked':1597,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
