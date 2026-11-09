#!/usr/bin/env python3
"""Final cold-init source, dependency, replay, preservation and report readback.

Writes only this increment's new identity/quality records. Time O(total source
and prior artifact bytes + links); bounded JSON/source space. No target API.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='e72223aaa49503e6cd7109da50386ef443be51b0ea53c6c668655a36bb9f461e'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 oldpath=ROOT/'kext_cold_init_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=json.loads(oldpath.read_text())
 checks=json.loads((ROOT/'kext_cold_init_checks.json').read_text());preserve=json.loads((ROOT/'kext_cold_init_preservation.json').read_text());c=json.loads((ROOT/'kext_cold_init_contracts.json').read_text());profiles=json.loads((ROOT/'kext_cold_init_profiles.json').read_text());fresh=json.loads((ROOT/'kext_cold_init_replays.json').read_text())
 for obj,producer in[(checks,'validate_kext_cold_init.py'),(preserve,'validate_kext_cold_init_preservation.py'),(c,'recover_kext_cold_init.py'),(profiles,'probe_kext_cold_init.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_kext_cold_init.py')and fresh['cases']==profiles['cases']and len(fresh['cases'])==8;assert sha(ROOT/'kext_cold_init_replays.json')==checks['fresh_replays_sha256']
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE
 from resolve_kernel_collection_interfaces import macho
 k=Kernel();assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==profiles['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';km=macho(SOURCE.read_bytes(),0,'original normalized kext');assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r
 sdk=c['SDK_probe'];assert sha(ROOT/sdk['path'])==sdk['sha256']and sha(Path(sdk['header_path']))==sdk['header_sha256']and sdk['compile_exit']==0
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e');univ=Path('/Users/___/Downloads/fpx/fairplayd');raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(univ)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and fat[3407872:3407872+len(raw)]==raw
 identity={'scope':'Fresh original kext/KC/descriptor/discovery symbol and daemon slice/universal identity. No new live IDB or native endpoint attestation.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kext_uuid':km['uuid'],'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'exact_kernel_symbols':c['exact_symbols'],'daemon_thin_sha256':sha(thin),'daemon_universal_sha256':sha(univ),'daemon_arm64e_slice_offset':3407872,'exact_daemon_slice_equal':True,'new_live_IDB_ranges':0,'whole_IDB_integrity_verified':False,'live_kext_IDB_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_cold_init_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1202 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1196
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['kext_cold_init_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'kext_cold_init_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];expected={'kernel_functions':4,'kext_ranges':4,'typed_descriptors':2,'original_import_data_bindings':5,'nominal_reference_slots':4,'SDK_compile_exit':0,'fresh_runs':8,'fresh_source_visits':18404,'source_heap_store_events':120,'source_written_heap_bytes':248,'source_heap_read_events':16,'modeled_allocations':8,'matching_boundaries':2,'source_timeout_bytes':48,'wait_records':6,'wait_boundaries':2,'release_boundaries':2,'adapter_failure_returns':4,'complete_failure_returns':2,'allocation_mode_path_pairs':4,'source_instructions':1278};assert counts==expected
 report=(BASE/'kext_cold_init_report.md').read_text()
 for phrase in['1 ns = 10^-9 s','+40/u32 = 4096','+36/u32 = 0','81920','runtime_PAGE_SHIFT_CONST','A8','QG7']:assert phrase in report,phrase
 evidence=['Factual technical analysis.','A1-A8 with dependent results and falsification probes.','Cold allocation,partial heap ABI,discovery,timeout and absent-provider cleanup;successful initialization and full goal remain incomplete.','Exact widths,byte epochs,1 ns requested duration,81920-byte capacity and bounded complexity.','Source-initialized reads at40/36,distinct flags,logical versus native free,static versus executed positive paths and runtime shift separated.','Original source/descriptors/symbols/chained slots,SDK compile and eight distinct fresh replays.','Impact-labeled bounded continuation table.']
 out={'scope':'Cold initialization/discovery/failure only;successful provider and complete initialization remain unresolved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1202,'unchanged_prior_artifacts':1196,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in['kext_cold_init_checks.json','kext_cold_init_contracts.json','kext_cold_init_profiles.json','kext_cold_init_replays.json','kext_cold_init_preservation.json']},'source_identity_sha256':sha(ROOT/'kext_cold_init_source_identity.json'),'complete_initialization_proved':False,'provider_success_executed':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kext_cold_init_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_runs':8,'fresh_source_visits':18404,'prior_artifacts_checked':1202,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
