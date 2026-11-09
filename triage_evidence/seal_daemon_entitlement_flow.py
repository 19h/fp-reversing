#!/usr/bin/env python3
"""Seal the bounded two-entitlement interface increment and preserve prior artifacts.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change. No native target use.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_entitlement_flow_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_entitlement_flow.py','probe_daemon_entitlement_audit.py','probe_daemon_secondary_identity.py','recover_daemon_entitlement_flow.py','prove_daemon_entitlement_flow.py','validate_daemon_entitlement_flow.py','seal_daemon_entitlement_flow.py','verify_daemon_entitlement_flow_publication.py']
EVIDENCE=['daemon_entitlement_flow_profiles.json','daemon_entitlement_flow_audit_profiles.json','daemon_entitlement_flow_string_profiles.json','daemon_entitlement_flow_contracts.json','daemon_entitlement_flow_proofs.json','daemon_entitlement_flow_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_entitlement_flow_prior_manifest.json';assert sha(prior)=='a70cf48dd84f45cdfb4a9dcc88cbf244d307d07d3cab52306b58a2e6900a40e8';m=json.loads(prior.read_text());assert len(m['files'])==5081;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5075
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,audit,strings,symbolic,proofs,checks=objects
 for obj,script in zip(objects,SCRIPTS[:6],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert len(source['cases'])==28 and len(audit['cases'])==12 and len(strings['cases'])==12 and len(proofs['proofs'])==18
 assert symbolic['literal']['text']=='fairplay-client'and symbolic['literal']['NUL_inclusive_bytes']==16
 assert symbolic['SDK']['exit_code']==0 and not symbolic['SDK']['target_runtime_version_matched']
 for h in symbolic['SDK']['headers']:assert sha(h['path'])==h['sha256']
 assert sha(ROOT/symbolic['SDK']['assembly_file'])==symbolic['SDK']['assembly_sha256']
 assert checks['all_checks_pass']and checks['verified_counts']=={'source_obligations_rebuilt':18,'accepted_SMT_files':36,'profile_cases':52,'profile_groups':3,'prior_source_prefixes_preserved':52,'conditional_state_bit_writers':20,'declared_PID_output_effects':24,'second_string_frontiers':12,'second_task_frontiers':4,'second_entitlement_query_frontiers':4,'second_NULL_marker_to_malloc_frontiers':4,'token_copy_argument_instances':80,'PID_output_source_reads_before_boundaries':0,'bank_byte_inputs':768,'unique_visited_source_instructions':1264,'SDK_compile_exit':0}
 assert checks['independent_A64_totals']['source_visits']==44860 and checks['independent_A64_totals']['declared_API_models_checked']==428 and checks['independent_A64_totals']['declared_API_output_effects_checked']==76 and checks['independent_A64_totals']['declared_API_prior_undefined_bytes']==96
 for flag in ['native_framework_calls_executed','native_entitlement_value_observed','native_authorization_outcome_established','hardware_PAC_executed','idb_mutated','new_port_emission_established','full_goal_complete']:assert checks[flag]is False
 assert not source['native_target_executed']and not source['host_API_executed']and not symbolic['native_target_executed']
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==36 and smt=={p.name for p in ROOT.glob('daemon_entitlement_flow_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| EF'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_entitlement_flow_delivery.json','daemon_entitlement_flow_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5081,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':36,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_entitlement_flow_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'First-result state-bit/rejoin, PID ABI, token lineage, second record and fairplay-client query, conditional marker-to-allocation frontier. Native sender provenance, entitlement values, final policy and framework IPC remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', EF1-EF8, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_entitlement_flow_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5081,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
