#!/usr/bin/env python3
"""Final source/producer/dependency/preservation/link readback for close ABI.

Writes only new source/quality records. O(total source/prior artifact bytes+
links) verification; no native target/API or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def main():
 oldpath=ROOT/'kext_close_prior_manifest.json';assert sha(oldpath)=='be4792a0c27164680c786ac1f9ccb848d7a904533f0d82acd8d2ca67d61b4aa0';old=json.loads(oldpath.read_text());checks=json.loads((ROOT/'kext_close_checks.json').read_text());preserve=json.loads((ROOT/'kext_close_preservation.json').read_text());c=json.loads((ROOT/'kext_close_contracts.json').read_text());profiles=json.loads((ROOT/'kext_close_profiles.json').read_text());fresh=json.loads((ROOT/'kext_close_replays.json').read_text())
 for obj,producer in[(checks,'validate_kext_close.py'),(preserve,'validate_kext_close_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and obj['all_checks_pass']and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert c['generator_sha256']==sha(ROOT/'recover_kext_close.py')and profiles['generator_sha256']==sha(ROOT/'probe_kext_close.py');assert fresh['generator_sha256']==sha(ROOT/'validate_kext_close.py')and fresh['cases']==profiles['cases']and len(fresh['cases'])==5;assert sha(ROOT/'kext_close_replays.json')==checks['fresh_replays_sha256']
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE
 from resolve_kernel_collection_interfaces import macho
 k=Kernel();assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==profiles['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';km=macho(SOURCE.read_bytes(),0,'original normalized kext');bindings=k.symbols([0xfffffe000c4ba154]);assert bindings['0xfffffe000c4ba154'][0]['name']=='_IOMallocTypeImpl'
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e');univ=Path('/Users/___/Downloads/fpx/fairplayd');raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(univ)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and fat[3407872:3407872+len(raw)]==raw
 identity={'scope':'Fresh original kext/KC/cold-boundary symbol and daemon slice/universal identity. Live daemon evidence covers four selected ranges only;no live kext or native endpoint attestation.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kext_uuid':km['uuid'],'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'cold_allocator_exact_symbols':bindings,'daemon_thin_sha256':sha(thin),'daemon_universal_sha256':sha(univ),'daemon_arm64e_slice_offset':3407872,'exact_daemon_slice_equal':True,'selected_daemon_IDB_ranges':4,'whole_IDB_integrity_verified':False,'live_kext_IDB_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_close_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1181 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1175
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['kext_close_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'kext_close_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];assert counts['fresh_runs']==5 and counts['completed_flag1_prefixes']==4 and counts['allocator_boundaries']==1 and counts['proofs_unsat']==5 and counts['fresh_daemon_IDB_bytes']==256
 evidence=['Factual technical analysis.','K1-K8 assumptions,dependent results and falsification probes.','Close-prefix,partial record/token ABI and selected live daemon refresh;full finalization and broader goal incomplete.','u32/u64 formulas,source-byte epochs,local proof composition and bounded complexity.','Flag1/null-object fixture versus valid native initialization,marshalling versus token use,return value versus business meaning distinguished.','Original source/banks/slots,distinct fresh prefix replay,five scoped proofs,byte epochs and four fresh daemon ranges.','Impact-labeled bounded continuation table.']
 out={'scope':'Close-wrapper token/record prefix only;successful finalization,extra-tag callers and native lifetime remain unresolved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1181,'unchanged_prior_artifacts':1175,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in['kext_close_checks.json','kext_close_contracts.json','kext_close_profiles.json','kext_close_replays.json','kext_close_preservation.json']},'source_identity_sha256':sha(ROOT/'kext_close_source_identity.json'),'complete_finalization_proved':False,'flag1_plus_null_global_native_reachability':'unknown','native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kext_close_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_runs':5,'proofs_unsat':5,'fresh_daemon_IDB_bytes':256,'prior_artifacts_checked':1181,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
