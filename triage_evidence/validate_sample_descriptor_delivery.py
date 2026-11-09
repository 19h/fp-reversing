#!/usr/bin/env python3
"""Final media descriptor source/ABI/replay/preservation and report readback.

Writes only new identity/quality records. O(total source/prior bytes + links)
time and bounded JSON/source space. No native mapping/copy/API/IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='79fe3ff727b44c9e14355fd32f174f22c04d56eb612414eaac3bd788db6edc4e'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 oldpath=ROOT/'sample_descriptor_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('sample_descriptor_checks.json');preserve=read('sample_descriptor_preservation.json');c=read('sample_descriptor_contracts.json');profiles=read('sample_descriptor_profiles.json');proofs=read('sample_descriptor_proofs.json');fresh=read('sample_descriptor_replays.json')
 for obj,name in[(checks,'validate_sample_descriptor.py'),(preserve,'validate_sample_descriptor_preservation.py'),(c,'recover_sample_descriptor.py'),(profiles,'probe_sample_descriptor.py'),(proofs,'prove_sample_descriptor.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_sample_descriptor.py')and fresh['cases']==profiles['cases']and len(fresh['cases'])==276;assert sha(ROOT/'sample_descriptor_replays.json')==checks['fresh_replays_sha256'];assert proofs['contracts_sha256']==sha(ROOT/'sample_descriptor_contracts.json')
 for e in proofs['proofs']:assert sha(ROOT/e['file'])==e['sha256']and e['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_cold_init import pointer
 from recover_kext_aes_handoff import function
 from resolve_kernel_collection_interfaces import macho
 k=Kernel();assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==profiles['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';km=macho(SOURCE.read_bytes(),0,'original normalized kext');fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for r in c['functions']:
  actual=function(k,fp,int(r['start'],16));assert all(r[n]==v for n,v in actual.items());assert IMAGE.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r
 for s in c['nominal_slots']:
  actual=pointer(k,int(s['slot'],16));assert all(s[n]==v for n,v in actual.items())
  if'tail_target'in s:assert k.symbols([int(s['tail_target'],16)])[s['tail_target']]==s['tail_target_exact_symbols']
 sdk=c['SDK_probe'];assert sha(Path(sdk['header_path']))==sdk['header_sha256']and sha(ROOT/sdk['assembly_path'])==sdk['assembly_sha256']and sdk['compile_exit']==0
 release_header=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/libkern/c++/OSObject.h');assert re.search(r'virtual\s+void\s+release\(\)\s+const',release_header.read_text())
 offsets={'create':0x18,'prepare':0x3c,'read':0x44,'write':0x44,'complete':0x3c,'release':0x30}
 for row in fresh['cases']:
  case=row['input']
  if case['mode']=='wrapper'and case['kind']in offsets:assert int(row['modeled_calls'][0]['pc'],16)-int(row['entry'],16)==offsets[case['kind']]
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e');univ=Path('/Users/___/Downloads/fpx/fairplayd');raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(univ)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and fat[3407872:3407872+len(raw)]==raw
 identity={'scope':'Original source/class/factory/range/copy-thunk and daemon file readback;no native descriptor/task/mapping attestation.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kext_uuid':km['uuid'],'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'descriptor_groups':c['groups'],'nominal_slots':c['nominal_slots'],'factory_binding':c['factory_binding'],'SDK_OSObject_header':{'path':str(release_header),'sha256':sha(release_header),'void_release_declaration_verified':True},'daemon_thin_sha256':sha(thin),'daemon_universal_sha256':sha(univ),'daemon_arm64e_slice_offset':3407872,'exact_daemon_slice_equal':True,'new_live_IDB_ranges':0,'whole_IDB_integrity_verified':False,'native_target_executed':False,'native_mapping_proved':False,'complete_lifecycle_proved':False,'full_goal_complete':False};(ROOT/'sample_descriptor_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1285 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1279
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['sample_descriptor_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'sample_descriptor_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];expected={'kext_functions':26,'kernel_functions':7,'exact_direct_method_bindings':5,'nominal_slots':7,'exact_tail_method_bindings':2,'factory_source_facts':13,'concrete_class_source_facts':4,'adapter_bank_rules':2,'adapter_byte_inputs':512,'adapter_source_facts':15,'SDK_compile_exit':0,'proofs_unsat':4,'fresh_runs':276,'fresh_source_visits':6136,'wrapper_runs':216,'creation_calls':96,'creation_prior_nonnull_cases':48,'creation_global_write_bytes':768,'prepare_status_records':16,'read_forwarding_records':36,'write_forwarding_records':36,'completion_tail_records':12,'release_tail_records':12,'pointer_equality_cases':4,'bridge_records':4,'factory_runs':60,'allocation_result_models':60,'factory_range_records':48,'factory_range_source_bytes':768,'factory_null_task_type_records':24,'factory_release_requests':24,'factory_nonnull_task_type_records':24};assert counts==expected
 report=(BASE/'sample_descriptor_report.md').read_text()
 for phrase in['M8','QG7','0xfffffe000c5314ec','0xfffffe000c5312b8','0xfffffe000cb53108','276','release()','void return semantics','5504','16-byte','complete business role']:assert phrase in report or(phrase=='complete business role'and'complete business role remain unresolved'in report),phrase
 evidence=['Factual technical analysis.','M1-M8 with dependent results and falsification probes.','Four global helper groups,concrete factory/range/copy ABI,sample bridge and partial related adapter;native mapping/lifetime/full goal incomplete.','Exact widths/bytes,option/type arithmetic,range epochs,call-site offsets and bounded complexity.','Nominal/native objects,task pointer/port identity,option namespaces,release-register/void semantics,and partial/full lifetime separated.','Original functions/symbols/direct thunk destinations/slots,276 fresh cases,four local proofs,two exhaustive banks and compile-only SDK evidence.','Impact-labeled bounded continuation table.'];outputs=['sample_descriptor_checks.json','sample_descriptor_contracts.json','sample_descriptor_profiles.json','sample_descriptor_replays.json','sample_descriptor_proofs.json','sample_descriptor_preservation.json']
 out={'scope':'Global descriptor/helper/factory and partial adapter contracts;native mapping,ownership and complete lifetime unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1285,'unchanged_prior_artifacts':1279,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'sample_descriptor_source_identity.json'),'native_target_executed':False,'authentication_abstracted':True,'native_mapping_proved':False,'complete_lifecycle_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'sample_descriptor_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_runs':276,'proofs_unsat':4,'range_records':48,'prior_artifacts_checked':1285,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
