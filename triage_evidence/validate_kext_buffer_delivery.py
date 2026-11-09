#!/usr/bin/env python3
"""Final descriptor-lifecycle source/dependency/replay/preservation readback.

Writes only new identity/quality records. O(total source/prior bytes + links)
verification and bounded JSON/source space. No native API or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='580c044402bd2ac8d36ce673370fca9d8dce90201c13276339ab800784ef4345'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(name):return json.loads((ROOT/name).read_text())
def main():
 oldpath=ROOT/'kext_buffer_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('kext_buffer_checks.json');preserve=read('kext_buffer_preservation.json');c=read('kext_buffer_contracts.json');profiles=read('kext_buffer_profiles.json');cleanup=read('kext_buffer_cleanup_profiles.json');proofs=read('kext_buffer_proofs.json');fresh=read('kext_buffer_replays.json');cfresh=read('kext_buffer_cleanup_replays.json')
 for obj,producer in[(checks,'validate_kext_buffer.py'),(preserve,'validate_kext_buffer_preservation.py'),(c,'recover_kext_buffer.py'),(profiles,'probe_kext_buffer.py'),(cleanup,'probe_kext_buffer_cleanup.py'),(proofs,'prove_kext_buffer.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==cfresh['generator_sha256']==sha(ROOT/'validate_kext_buffer.py');assert fresh['cases']==profiles['cases']and len(fresh['cases'])==4111 and cfresh['cases']==cleanup['cases']and len(cfresh['cases'])==19;assert sha(ROOT/'kext_buffer_replays.json')==checks['fresh_replays_sha256']and sha(ROOT/'kext_buffer_cleanup_replays.json')==checks['fresh_cleanup_replays_sha256']
 assert proofs['contracts_sha256']==sha(ROOT/'kext_buffer_contracts.json')
 for e in proofs['proofs']:assert sha(ROOT/e['file'])==e['sha256']and e['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from resolve_kernel_collection_interfaces import macho
 k=Kernel();assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==cleanup['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']==profiles['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';km=macho(SOURCE.read_bytes(),0,'original normalized kext');assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r
 for r in c['kext_ranges']:assert IMAGE.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex']
 sdk=c['SDK_probe'];assert sha(ROOT/'kext_buffer_sdk_probe.cpp')==sdk['source_sha256']and sdk['compile_exit']==0
 for e in sdk['primary_headers']:assert sha(Path(e['path']))==e['sha256']
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e');univ=Path('/Users/___/Downloads/fpx/fairplayd');raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(univ)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and fat[3407872:3407872+len(raw)]==raw
 cp=BASE/'com.apple.driver.FairPlayIOKit.c';annotations=[{'line':i,'text':line}for i,line in enumerate(cp.read_text().splitlines(),1)if 'cs=0xFFFFFE000A5080D4' in line]
 for arg in[1,2,3]:assert any('E:C(0x0)'in r['text']and r['text'].endswith(','+str(arg)+')')for r in annotations),arg
 identity={'scope':'Fresh original kext/KC/class/factory/getter/cleanup and daemon file identity; no new live IDB/native object attestation.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kext_uuid':km['uuid'],'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'exact_kernel_symbols':c['exact_symbols'],'associated_decompilation_sha256':sha(cp),'contradicted_zero_argument_annotations':annotations,'daemon_thin_sha256':sha(thin),'daemon_universal_sha256':sha(univ),'daemon_arm64e_slice_offset':3407872,'exact_daemon_slice_equal':True,'new_live_IDB_ranges':0,'whole_IDB_integrity_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_buffer_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1217 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1211
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['kext_buffer_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'kext_buffer_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];expected={'kernel_functions':12,'kext_ranges':3,'buffer_slots':5,'metaclass_slots':1,'provider_slots':1,'base_negative_controls':2,'buffer_vptr_installers':5,'factory_source_facts':6,'kext_caller_source_facts':8,'SDK_primary_headers':3,'SDK_compile_exit':0,'proofs_unsat':2,'fresh_runs':4111,'fresh_source_visits':30712,'indirect_returns':1925,'source_data_read_events':10152,'source_data_read_bytes':44207,'decision_grid_cases':4096,'direct_returns':133,'null_returns':2053,'u64_sentinel_cases':15,'original_getter_instructions':14,'cleanup_fresh_runs':19,'cleanup_fresh_source_visits':616,'cleanup_global_write_events':48,'cleanup_release_requests':22,'cleanup_declared_orphan_pointer_states':4,'cleanup_complete_requests':7,'cleanup_nonzero_complete_return_cases':3};assert counts==expected
 report=(BASE/'kext_buffer_report.md').read_text()
 for phrase in['D8','QG7','4111','616','0x9285','0x13','No new daemon port identity','native null cached pointer','C(0)']:assert phrase in report,phrase
 evidence=['Factual technical analysis.','D1-D8 with dependent results and falsification probes.','Descriptor factory,virtual ABI,getter and cleanup;native initialization and full goal remain incomplete.','Explicit widths/bytes,option arithmetic,original read/write epochs and bounded complexity.','Nominal versus actual type/PAC,declared versus native states,logical versus native retirement,and source versus annotation separated.','Original bytes/symbols/chained slots/five installers,4111 fresh getter cases,19 cleanup cases,two local proofs and SDK compilation.','Impact-labeled bounded continuation table.']
 outputs=['kext_buffer_checks.json','kext_buffer_contracts.json','kext_buffer_profiles.json','kext_buffer_cleanup_profiles.json','kext_buffer_replays.json','kext_buffer_cleanup_replays.json','kext_buffer_proofs.json','kext_buffer_preservation.json']
 out={'scope':'Descriptor factory/accessor/cleanup only;native preparation,receiver state and hardware transfer remain unresolved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1217,'unchanged_prior_artifacts':1211,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'kext_buffer_source_identity.json'),'complete_initialization_proved':False,'native_target_executed':False,'native_prepare_executed':False,'native_reference_effects_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kext_buffer_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_getter_runs':4111,'fresh_cleanup_runs':19,'proofs_unsat':2,'prior_artifacts_checked':1217,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
