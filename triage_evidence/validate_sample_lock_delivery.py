#!/usr/bin/env python3
"""Lock/gate/caller delivery readback; writes only new identity/quality records.

O(total preceding/source bytes + report links) time; bounded JSON/source space.
No native target, lock, synchronization, provider, crypto or IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='238d2727ba010c4156e9f33389ab907449ce1f7e0a3655766048baf40fa57146'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'sample_lock_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);c=read('sample_lock_contracts.json');p=read('sample_lock_profiles.json');rp=read('sample_lock_return_profiles.json');proof=read('sample_lock_proofs.json');checks=read('sample_lock_checks.json');fresh=read('sample_lock_replays.json');preserve=read('sample_lock_preservation.json');sdk=read('sample_lock_sdk_checks.json')
 for obj,name in[(c,'recover_sample_lock.py'),(p,'probe_sample_lock.py'),(rp,'probe_sample_lock_return.py'),(proof,'prove_sample_lock.py'),(checks,'validate_sample_lock.py'),(preserve,'validate_sample_lock_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_sample_lock.py')and fresh['lock_cases']==p['lock_cases']and fresh['gate_cases']==p['gate_cases']and fresh['error_continuations']==rp['cases'];assert sha(ROOT/'sample_lock_replays.json')==checks['fresh_replays_sha256'];assert proof['contracts_sha256']==sha(ROOT/'sample_lock_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and q['result']=='unsat'
 expected={'original_functions':7,'original_spans':9,'exhaustive_banks':10,'bank_byte_inputs':2560,'primitive_bindings':4,'kernel_functions':4,'selected_routes':9,'parent_instructions':72913,'proofs_unsat':9,'SDK_void_signatures':4,'fresh_lock_cases':96,'lock_source_visits':16986,'returns_without_primitive':24,'standalone_adapter_cases':24,'lock_record_bytes_checked':12288,'primitive_boundaries':72,'cached_RW_boundaries':24,'explicit_mutex_boundaries':48,'source_built_lock_records':72,'record_source_written_bytes':864,'preserved_status_snapshots':48,'fresh_gate_cases':20,'gate_source_visits':3260,'unchanged_gate_carrier_bytes':2080,'error_gate_returns':12,'source_header_word_reads':16,'recognized_header_prefixes':8,'fresh_error_continuations':24,'error_continuation_visits':408,'caller_status_routes':4,'all_fresh_cases':140,'all_source_visits':20654};assert checks['verified_counts']==expected
 assert sdk['generator_sha256']==sha(ROOT/'validate_sample_lock.py')and sdk['source_sha256']==sha(ROOT/'sample_lock_sdk_probe.cpp')and sdk['header_sha256']==sha(Path(sdk['header_path']))and sdk['assembly_sha256']==sha(ROOT/'sample_lock_sdk_probe.s')and sdk['compile_exit']==0 and sdk['void_single_pointer_signatures_checked']==4 and not sdk['target_code_executed'];assert sha(ROOT/'sample_lock_sdk_checks.json')==checks['SDK_checks_sha256']
 for r in fresh['lock_cases']+fresh['error_continuations']:assert not r['native_lock_executed']and not r['native_API_executed']and not r['undefined_private_reads']and not r['entry_reachability_proved']
 for r in fresh['gate_cases']:assert not r['native_lock_executed']and not r['native_API_executed']and not r['crypto_operation_executed']and not r['entry_reachability_proved']
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 for b in c['bank_rules']:assert pointer(k,int(b['slot'],16))==b['original_pointer']
 for b in c['primitive_bindings']:
  target=int(b['original_pointer']['target'],16);assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer'];assert k.symbols([target])[hex(target)]==b['exact_symbols']and k.function(target)==b['kernel_function']
 for b in checks['caller_preparer_return_routes']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer']
 identity={'scope':'Original selector-conditioned mutex/RW adapters, caller records and preparer gates. Native lock identity, lifetime, serialization and accepted processing remain unknown.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'primitive_bindings':[{n:b[n]for n in['label','wrapper','original_pointer','exact_symbols']}for b in c['primitive_bindings']],'lock_record':c['lock_record'],'caller_preparer_return_routes':checks['caller_preparer_return_routes'],'contracts_sha256':sha(ROOT/'sample_lock_contracts.json'),'SDK_checks_sha256':sha(ROOT/'sample_lock_sdk_checks.json'),'native_target_executed':False,'native_lock_executed':False,'native_serialization_proved':False,'crypto_operation_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'sample_lock_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(old['files'])==1410 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1404
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['sample_lock_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'sample_lock_quality_gates.json',(name,target);links+=1
 report=(BASE/'sample_lock_report.md').read_text()
 for phrase in['SL9','QG7','140','20654','864','0xce515bbf','0xfffffe000ccceab8','unknown','post-initializer','void','0xc33','0xa07','0x729','2560','2080']:assert phrase in report,phrase
 evidence=['Factual source/ABI analysis.','SL1-SL9 with dependencies and falsification probes.','Lock/gate/record/caller-status contracts covered; full objective remains active.','u32 codec, byte extents, pointer widths, source-write epochs and finite complexity specified.','Acquisition-role refinement, void return/status snapshot, source recognition/acceptance and local sequence/native serialization separated.','Exact original functions/chains/symbol aliases, SDK compile, ten exhaustive banks, nine proofs and 140 fresh cases.','Impact-labeled bounded continuation table.'];outputs=['sample_lock_contracts.json','sample_lock_profiles.json','sample_lock_return_profiles.json','sample_lock_replays.json','sample_lock_checks.json','sample_lock_proofs.json','sample_lock_sdk_checks.json','sample_lock_preservation.json'];out={'scope':'Selector-conditioned lock and preparer/caller source interfaces only; no native synchronization, serialization, accepted operation or Mach event proved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'prior_artifacts_checked':1410,'unchanged_prior_artifacts':1404,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'sample_lock_source_identity.json'),'native_target_executed':False,'native_lock_executed':False,'crypto_operation_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'sample_lock_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':140,'proofs_unsat':9,'prior_artifacts_checked':1410,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
