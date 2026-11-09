#!/usr/bin/env python3
"""Seal the bounded Boolean-chain interface increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_boolean_chain_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_boolean_chain.py','probe_daemon_boolean_mixed.py','recover_daemon_boolean_chain.py','prove_daemon_boolean_chain.py','validate_daemon_boolean_chain.py','seal_daemon_boolean_chain.py','verify_daemon_boolean_chain_publication.py']
EVIDENCE=['daemon_boolean_chain_profiles.json','daemon_boolean_chain_mixed_profiles.json','daemon_boolean_chain_contracts.json','daemon_boolean_chain_proofs.json','daemon_boolean_chain_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_boolean_chain_prior_manifest.json';assert sha(prior)=='4adf7e09bea4ae5844c73dcf72a83766173077b2cbace58264f5daf879eff5c0';m=json.loads(prior.read_text());assert len(m['files'])==5213;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5207
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,types,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:5],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert len(source['cases'])==24 and len(types['cases'])==8 and len(proofs['proofs'])==10
 assert symbolic['keys']['FairPlay-CoreML-Client']['NUL_inclusive_bytes']==23 and symbolic['keys']['FairPlay-Classic-Client']['NUL_inclusive_bytes']==24
 assert symbolic['SDK_layout']['exit_code']==0 and not symbolic['SDK_layout']['target_runtime_version_matched']
 assert sha(ROOT/symbolic['SDK_layout']['LLVM_file'])==symbolic['SDK_layout']['LLVM_sha256']
 assert checks['all_checks_pass']and checks['verified_counts']=={'source_obligations_rebuilt':10,'accepted_SMT_files':20,'profile_cases':32,'prior_source_prefixes_preserved':32,'Boolean_adapter_entries':60,'Boolean_adapter_returns':56,'Boolean_query_frontiers':4,'audit_argument_instances':52,'new_adapter_release_requests':120,'encoded_zero_bridge_returns':28,'CoreML_key_instances':32,'Classic_key_instances':28,'marker_5B_returns':24,'marker_5C_returns':32,'bank_byte_inputs':512,'unique_visited_source_instructions':1942,'SDK_compile_exit':0}
 assert checks['independent_A64_totals']['source_visits']==96824 and checks['independent_A64_totals']['declared_API_models_checked']==976 and checks['independent_A64_totals']['declared_API_output_effects_checked']==168 and checks['independent_A64_totals']['declared_API_prior_undefined_bytes']==256
 for flag in ['native_target_executed','native_framework_calls_executed','native_entitlement_values_observed','native_authorization_outcome_established','hardware_PAC_executed','idb_mutated','new_port_emission_established','full_goal_complete']:assert checks[flag]is False
 assert not source['native_target_executed']and not source['host_API_executed']and not symbolic['native_target_executed']
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==20 and smt=={p.name for p in ROOT.glob('daemon_boolean_chain_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| BC'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_boolean_chain_delivery.json','daemon_boolean_chain_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5213,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':20,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_boolean_chain_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Two sequential Boolean key interfaces, 24-byte collector ABI, selector/pointer gate, bit accumulation and encoded status. Native values, sender provenance, final admission, owners and framework IPC remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', BC1-BC8, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_boolean_chain_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5213,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
