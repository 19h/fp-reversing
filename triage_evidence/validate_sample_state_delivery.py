#!/usr/bin/env python3
"""Final state/fill/source, retained-fresh, preservation and report readback.

Writes only new identity/quality records. O(total source/prior bytes + links)
time and bounded JSON/source space. No native target or IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='9eb38f10ea4cc4fa6f6a83b88179dc2d7ff4116c82c8f811cb70068a97932b46'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 oldpath=ROOT/'sample_state_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('sample_state_checks.json');preserve=read('sample_state_preservation.json');c=read('sample_state_contracts.json');p=read('sample_state_profiles.json');f=read('sample_state_fill_profiles.json');proof=read('sample_state_proofs.json');fresh=read('sample_state_replays.json')
 for obj,name in[(checks,'validate_sample_state.py'),(preserve,'validate_sample_state_preservation.py'),(c,'recover_sample_state.py'),(p,'probe_sample_state.py'),(f,'probe_sample_fill.py'),(proof,'prove_sample_state.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_sample_state.py')and fresh['state_cases']==p['cases']and fresh['fill_cases']==f['cases'];assert sha(ROOT/'sample_state_replays.json')==checks['fresh_replays_sha256'];assert proof['contracts_sha256']==sha(ROOT/'sample_state_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and q['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==p['source_sha256']==f['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for row in c['functions']:
  assert function(k,entry,int(row['start'],16))==row;assert IMAGE.read(int(row['start'],16),int(row['end'],16)-int(row['start'],16)).hex()==row['bytes_hex']
 for row in c['kernel_functions']:assert k.function(int(row['start'],16))==row
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']and pointer(k,0xfffffe000847c4c8)==c['copy_import_pointer']
 for row in c['bank_rules']:assert pointer(k,int(row['slot'],16))==row['original_pointer']
 sdk=c['SDK_probe'];assert sdk['compile_exit']==0 and sha(ROOT/sdk['assembly_path'])==sdk['assembly_sha256']and sha(Path(sdk['header_path']))==sdk['header_sha256'];header=Path(sdk['header_path']).read_text();assert re.search(r'void\s+IOFreeData\(void\s*\*\s*address,\s*vm_size_t\s+size\)',header);assert re.search(r'void\s*\*\s*IOMallocData\(vm_size_t\s+size\)',header)
 counts=checks['verified_counts'];expected={'original_kext_functions':3,'original_kernel_functions':3,'copy_thunk_and_stub_bindings':1,'exhaustive_bank_rules':10,'bank_byte_inputs':2560,'source_instruction_facts':36,'SDK_compile_exit':0,'proofs_unsat':6,'fresh_fill_cases':6104,'fresh_fill_source_visits':331922,'fill_source_written_bytes':705008,'canonical_fill_cases':5784,'fill_store_events':124862,'nonuniform_width_stress_cases':132,'fresh_state_cases':1044,'fresh_state_source_visits':825468,'caller_clear_store_events':29232,'caller_clear_source_bytes':175392,'state_object_reconstructions':1044,'modeled_opaque_copy_calls':1556,'modeled_opaque_copy_bytes':33184,'workspace_allocation_models':1044,'source_header_control_cases':1044,'cleanup_return_paths':1034,'source_output_status_bytes':4136,'workspace_null_error_paths':522,'workspace_free_models':512,'empty_loop_success_paths':512,'sample_size_read_boundaries':10};assert counts==expected
 assert len(fresh['state_cases'])==1044 and len(fresh['fill_cases'])==6104 and len(proof['proofs'])==6;assert all(not r['undefined_private_reads']and not r['native_API_executed']for r in fresh['state_cases']);assert all(not r['native_API_executed']for r in fresh['fill_cases'])
 identity={'scope':'Original state/fill/copy/allocation source and ABI readback. Native carrier/task/heap/lifetime identity remains unproved.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'fileset_uuid':entry['uuid'],'functions':[{n:r[n]for n in['start','end','sha256']}for r in c['functions']],'copy_import_pointer':c['copy_import_pointer'],'exact_symbols':c['exact_symbols'],'deeper_allocator_abi':c['deeper_allocator_abi'],'SDK_header_path':sdk['header_path'],'SDK_header_sha256':sdk['header_sha256'],'SDK_void_IOFreeData_declaration_verified':True,'new_live_IDB_ranges':0,'native_target_executed':False,'native_lifetime_proved':False,'native_heap_domain_proved':False,'full_goal_complete':False};(ROOT/'sample_state_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(old['files'])==1338 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1332
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 links=0
 for name in['sample_state_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   pth=Path(target.split('#',1)[0]);pth=pth if pth.is_absolute()else BASE/pth;assert pth.exists()or pth==ROOT/'sample_state_quality_gates.json',(name,target);links+=1
 report=(BASE/'sample_state_report.md').read_text()
 for phrase in['SS8','QG7','7148','360-byte','8192','81920','89','200','unknown','0xfffffe000bcfe5b8','0xfffffe000bcfec48','explicit','implicit']:assert phrase in report,phrase
 evidence=['Factual technical analysis.','SS1-SS8 with dependent results and falsification probes.','Packed carrier/state, pure helper, copy/heap ABI, conditional lifetime and next data boundary; full goal active.','Exact byte intervals, raw widths, fill geometry, source/model event reconstruction and bounded complexity.','Native/model operations, byte/object-size scalars, raw X0/C return type, exact alias/unknown callee names and explicit/implicit completion separated.','Original functions/slots/symbols, ten exhaustive banks, six local proofs, 7148 fresh cases and SDK evidence.','Impact-labeled bounded continuation table.'];outputs=['sample_state_checks.json','sample_state_contracts.json','sample_state_profiles.json','sample_state_fill_profiles.json','sample_state_replays.json','sample_state_proofs.json','sample_state_preservation.json']
 out={'scope':'State/fill/copy/workspace contracts only; native carrier/task identity, heap domain and lifetime remain unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1338,'unchanged_prior_artifacts':1332,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'sample_state_source_identity.json'),'native_target_executed':False,'native_lifetime_proved':False,'native_heap_domain_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'sample_state_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':7148,'proofs_unsat':6,'prior_artifacts_checked':1338,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
