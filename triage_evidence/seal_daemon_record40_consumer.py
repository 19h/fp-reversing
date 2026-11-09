#!/usr/bin/env python3
"""Seal the bounded operation-dispatch increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_record40_consumer_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_record40_consumer.py','recover_daemon_record40_consumer.py','prove_daemon_record40_consumer.py','validate_daemon_record40_consumer.py','seal_daemon_record40_consumer.py','verify_daemon_record40_consumer_publication.py']
EVIDENCE=['daemon_record40_consumer_profiles.json','daemon_record40_consumer_contracts.json','daemon_record40_consumer_proofs.json','daemon_record40_consumer_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_record40_consumer_prior_manifest.json';assert sha(prior)=='fa9f39874932dc86d945761b48f62e1ed682daa67676e324eb0282419afeb348';m=json.loads(prior.read_text());assert len(m['files'])==5017;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5011
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:4],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert len(source['cases'])==24 and len(proofs['proofs'])==11
 assert symbolic['literal']['text']=='com.apple.private.fpsd.client'and symbolic['literal']['NUL_inclusive_bytes']==30
 assert symbolic['mode_counts']=={m:4 for m in ['strict','allocator_words','string_null','string_nonnull','task_null','task_nonnull']}
 assert symbolic['SDK']['exit_code']==0 and not symbolic['SDK']['target_runtime_version_matched']
 for h in symbolic['SDK']['headers']:assert sha(h['path'])==h['sha256']
 assert sha(ROOT/symbolic['SDK']['LLVM_file'])==symbolic['SDK']['LLVM_sha256']
 assert checks['all_checks_pass']and checks['verified_counts']=={'source_obligations_rebuilt':11,'accepted_SMT_files':22,'profile_cases':24,'profile_modes':6,'known_key_bytes':30,'audit_token_bits':256,'audit_token_argument_instances':8,'conditional_marker_returns':8,'entitlement_query_frontiers':4,'source_bank_byte_inputs':1024,'unique_visited_source_instructions':395,'SDK_compile_exit':0}
 assert checks['independent_A64_totals']['source_visits']==6260 and checks['independent_A64_totals']['declared_API_models_checked']==28
 for flag in ['native_framework_calls_executed','native_entitlement_value_observed','native_authorization_outcome_established','hardware_PAC_executed','idb_mutated','new_port_emission_established','full_goal_complete']:assert checks[flag]is False
 assert not source['native_target_executed']and not source['host_API_executed']and not symbolic['native_target_executed']
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==22 and smt=={p.name for p in ROOT.glob('daemon_record40_consumer_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RC'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_record40_consumer_delivery.json','daemon_record40_consumer_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5017,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':22,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_record40_consumer_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Record40 selector and key/token flow to a Security entitlement-query frontier, conditional constructor-NULL marker returns and shared header update. Native sender provenance, entitlement values, final policy and framework IPC remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RC1-RC10, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_record40_consumer_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5017,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
