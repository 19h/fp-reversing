#!/usr/bin/env python3
"""Seal the bounded second-result interface increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_secondary_result_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_secondary_result.py','probe_daemon_secondary_types.py','recover_daemon_secondary_result.py','prove_daemon_secondary_result.py','validate_daemon_secondary_result.py','seal_daemon_secondary_result.py','verify_daemon_secondary_result_publication.py']
EVIDENCE=['daemon_secondary_result_profiles.json','daemon_secondary_result_type_profiles.json','daemon_secondary_result_contracts.json','daemon_secondary_result_proofs.json','daemon_secondary_result_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_secondary_result_prior_manifest.json';assert sha(prior)=='00c0058fb33ac15635ef07fd3318969efd8c1180aeaaa29ba374d716387ea2b5';m=json.loads(prior.read_text());assert len(m['files'])==5137;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5131
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,types,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:5],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert len(source['cases'])==32 and len(types['cases'])==28 and len(proofs['proofs'])==13
 assert symbolic['next_key']['text']=='FairPlay-CoreML-Client'and symbolic['next_key']['NUL_inclusive_bytes']==23 and not symbolic['next_key']['third_query_executed']
 assert symbolic['SDK']['exit_code']==0 and not symbolic['SDK']['target_runtime_version_matched']
 for h in symbolic['SDK']['headers']:assert sha(h['path'])==h['sha256']
 assert sha(ROOT/symbolic['SDK']['LLVM_file'])==symbolic['SDK']['LLVM_sha256']
 assert checks['all_checks_pass']and checks['verified_counts']=={'source_obligations_rebuilt':13,'accepted_SMT_files':26,'profile_cases':60,'prior_source_prefixes_preserved':60,'modeled_numeric_output_effects':16,'numeric_output_source_reads_before_boundaries':0,'marker_31_returns':36,'marker_32_returns':8,'unknown_owner_write_frontiers':18,'allocation_frontiers':18,'number_type_frontiers':8,'number_conversion_frontiers':4,'string_conversion_frontiers':4,'next_CoreML_key_frontiers':8,'modeled_64bit_type_pairs':28,'secondary_release_requests':132,'unique_visited_source_instructions':2257,'SDK_compile_exit':0}
 assert checks['independent_A64_totals']['source_visits']==99380 and checks['independent_A64_totals']['declared_API_models_checked']==1000 and checks['independent_A64_totals']['declared_API_output_effects_checked']==196 and checks['independent_A64_totals']['declared_API_prior_undefined_bytes']==304
 for flag in ['native_framework_calls_executed','native_entitlement_value_observed','native_authorization_outcome_established','hardware_PAC_executed','idb_mutated','new_port_emission_established','full_goal_complete']:assert checks[flag]is False
 assert not source['native_target_executed']and not source['host_API_executed']and not symbolic['native_target_executed']
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==26 and smt=={p.name for p in ROOT.glob('daemon_secondary_result_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| SR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_secondary_result_delivery.json','daemon_secondary_result_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5137,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':26,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_secondary_result_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'fairplay-client Number/String types, signed32/status channels, state bit8, borrowed output owners, next bridge and CoreML-named key frontier. Native sender provenance, entitlement values, owner extents, final policy and framework IPC remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', SR1-SR8, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_secondary_result_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5137,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
