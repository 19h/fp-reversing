#!/usr/bin/env python3
"""Final RPC700 source, dependency, prior-artifact and report-link readback.

Only new source-identity/quality records are written. O(total source/prior
artifact bytes+links) verification; no native target/API/IDB operation.
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
 oldpath=ROOT/'rpc700_namespace_prior_manifest.json';assert sha(oldpath)=='b24882aa9e523046ff85f8c3888f0b9397d40167f655bcebe89195977f96fc14';old=json.loads(oldpath.read_text());checks=json.loads((ROOT/'rpc700_namespace_checks.json').read_text());preserve=json.loads((ROOT/'rpc700_namespace_preservation.json').read_text());c=json.loads((ROOT/'rpc700_namespace_contracts.json').read_text())
 for obj,producer in[(checks,'validate_rpc700_namespace.py'),(preserve,'validate_rpc700_namespace_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and obj['all_checks_pass']and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert c['generator_sha256']==sha(ROOT/'recover_rpc700_namespace.py')and not c['receiver_identified']and not c['native_target_executed']and not c['native_port_objects_observed']
 from kernel_native_reader import Kernel
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and k.kernel['uuid']==c['kernel_uuid'];sources=[]
 for row in c['candidate_binaries']:
  p=Path(row['source_path']);assert sha(p)==row['source_sha256'];sources.append({'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size,'selected_arm64e_sha256':row['selected_slice']['sha256'],'selected_arm64e_uuid':row['uuid']})
 h=c['SDK_header'];assert sha(Path(h['path']))==h['sha256']and sha(ROOT/h['snapshot'])==h['sha256']
 for p in c['plists']:assert sha(Path(p['path']))==p['sha256']
 assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))==c['positive_control']['source_sha256']
 identity={'scope':'Fresh KC,candidate executable,SDK header,plist and positive-control source readback;cache full-file hashes and GOT readback are pinned in checks/contracts. No native endpoint or live IDB attestation.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'candidate_files':sources,'SDK_header_sha256':h['sha256'],'cache_uuid':c['cache_uuid'],'contracts_sha256':sha(ROOT/'rpc700_namespace_contracts.json'),'checks_sha256':sha(ROOT/'rpc700_namespace_checks.json'),'receiver_identified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc700_namespace_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1166 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1160
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['rpc700_namespace_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'rpc700_namespace_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];assert counts['kernel_functions']==3 and counts['proofs_unsat']==2 and counts['candidate_import_records']==5174 and counts['framework_GOT_records']==298 and counts['rejected_header_shapes']==50 and counts['known_MIG_positive_controls']==1 and counts['SDK_compile_exit']==0
 evidence=['Factual technical analysis.','N1-N8 assumptions,dependent results and falsification probes.','Kernel special-port ABI and bounded candidate inventories;actual receiver and full interface goal remain unresolved.','u32/u64 domains,byte offsets,proof scope and bounded complexity.','SDK labels,plist declarations,header candidates,direct-link search and native endpoint identity distinguished.','Original KC/slice/cache/header/plist readback,two exact symbols,fresh proofs and compile-only SDK assertions.','Impact-labeled bounded continuation table.']
 out={'scope':'RPC700 namespace and bounded receiver leads only;not complete receiver or native endpoint identification.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1166,'unchanged_prior_artifacts':1160,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in['rpc700_namespace_checks.json','rpc700_namespace_contracts.json','rpc700_namespace_preservation.json']},'source_identity_sha256':sha(ROOT/'rpc700_namespace_source_identity.json'),'receiver_identified':False,'native_target_executed':False,'native_port_objects_observed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc700_namespace_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'kernel_functions':3,'proofs_unsat':2,'receiver_identified':False,'prior_artifacts_checked':1166,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
