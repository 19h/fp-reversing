#!/usr/bin/env python3
"""Seal daemon/cache/kernel VM-interface evidence and preserve prior artifacts.
O(prior bytes + links) time, O(manifest + largest JSON) space. Only six
owned existing index/publisher paths change; no native target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_vm_cleanup_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'daemon_vm_cleanup_profiles.json':'probe_daemon_vm_cleanup.py','daemon_vm_cleanup_retire_profiles.json':'probe_daemon_vm_retire.py','daemon_vm_cleanup_cache_profiles.json':'probe_vm_cache_transport.py','daemon_vm_cleanup_kernel_components.json':'probe_vm_kernel_ranges.py','daemon_vm_cleanup_contracts.json':'recover_daemon_vm_cleanup.py','daemon_vm_cleanup_proofs.json':'prove_daemon_vm_cleanup.py','daemon_vm_cleanup_checks.json':'validate_daemon_vm_cleanup.py'}
SCRIPTS=list(GENS.values())+['replay_vm_cache_transport.py','seal_daemon_vm_cleanup.py','verify_daemon_vm_cleanup_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_vm_cleanup_prior_manifest.json';assert sha(prior)=='8f38fc8976a4c5e4ce6f0367acd6e895dfb2d16cf4011dab7314ebb43b477376';m=json.loads(prior.read_text());assert len(m['files'])==5303;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert{r['path']for r in changed}==CHANGED and unchanged==5297
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(script,d)
 proof=objects['daemon_vm_cleanup_proofs.json'];checks=objects['daemon_vm_cleanup_checks.json'];contracts=objects['daemon_vm_cleanup_contracts.json'];assert checks['all_checks_pass']and len(proof['proofs'])==11 and len(proof['daemon_proof_domains'])==4
 expected={'source_obligations_rebuilt':11,'accepted_SMT_files':22,'daemon_profiles':96,'prior_source_prefixes_preserved':96,'modeled_VM_returns':96,'modeled_free_requests':48,'post_free_source_accesses':0,'cache_profiles':30,'cache_trap12_boundaries':30,'cache_MIG_request_frontiers':6,'cache_logger_models':15,'daemon_universal_return_contexts':4,'kernel_range_component_cases':2048,'kernel_range_source_visits':20480,'kernel_page_shift_values':256,'unique_daemon_source_instructions':2689,'cache_original_functions':7,'kernel_original_functions':2,'SDK_compile_exit':0};assert checks['verified_counts']==expected and checks['independent_A64_totals']['source_visits']==450384 and checks['independent_cache_A64_totals']['source_visits_checked']==1206
 assert contracts['SDK_layout']['exit_code']==0 and sha(ROOT/contracts['SDK_layout']['LLVM_file'])==contracts['SDK_layout']['LLVM_sha256']and not contracts['SDK_layout']['target_runtime_version_matched']
 for flag in ['native_target_executed','native_VM_or_free_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','daemon_runtime_version_match_established','native_port_right_or_emission_observed','full_goal_complete']:assert checks[flag]is False
 smt={r[k]for r in proof['proofs']for k in ['file','original_file']};assert len(smt)==22 and smt=={p.name for p in ROOT.glob('daemon_vm_cleanup_*.smt2')}
 for r in proof['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| VC'+str(j)+' |'in text for j in range(1,9))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_vm_cleanup_delivery.json','daemon_vm_cleanup_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5303,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':22,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_vm_cleanup_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Daemon VM-return/free ownership, available-cache trap/MIG request ports/framing and original kernel range ABI. Native runtime match/rights, message receiver, owner extents and final admission remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'independent_cache_A64_totals':checks['independent_cache_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_VM_or_free_executed':False,'native_IPC_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'conditional_VM_request_contract_established':True,'native_port_right_or_emission_observed':False,'daemon_runtime_version_match_established':False,'native_owner_extents_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', VC1-VC8, original bytes/binds/chains, rebuilt SMT, independent daemon/cache CPU read/write replay, kernel component checks and prior preservation'}
 (ROOT/'daemon_vm_cleanup_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5303,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
