#!/usr/bin/env python3
"""Seal allocation/span/VM-call contracts while preserving prior evidence.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
Only six existing owned index/publisher files may change. No native calls.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_client_object_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_client_object.py','probe_daemon_client_pair.py','probe_daemon_client_cleanup.py','recover_daemon_client_object.py','prove_daemon_client_object.py','validate_daemon_client_object.py','seal_daemon_client_object.py','verify_daemon_client_object_publication.py']
EVIDENCE=['daemon_client_object_profiles.json','daemon_client_object_pair_profiles.json','daemon_client_object_cleanup_profiles.json','daemon_client_object_contracts.json','daemon_client_object_proofs.json','daemon_client_object_checks.json']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'daemon_client_object_prior_manifest.json';assert sha(prior)=='07bfab2caa4f62d55157dcd418cf3ffab9ff80df664d23f8e1fc4201f7abdaf8';m=json.loads(prior.read_text());assert len(m['files'])==5251;changed=[];unchanged=0
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert{r['path']for r in changed}==CHANGED and unchanged==5245
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objs=[json.loads((ROOT/n).read_text())for n in EVIDENCE];source,pair,cleanup,contracts,proofs,checks=objs
 for obj,script in zip(objs,SCRIPTS[:6],strict=True):
  assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
 assert[len(o['cases'])for o in objs[:3]]==[32,32,16]and len(proofs['proofs'])==16
 assert contracts['SDK_layout']['exit_code']==0 and not contracts['SDK_layout']['target_runtime_version_matched']and sha(ROOT/contracts['SDK_layout']['LLVM_file'])==contracts['SDK_layout']['LLVM_sha256']
 expected={'source_obligations_rebuilt':16,'accepted_SMT_files':32,'profile_cases':80,'prior_source_prefixes_preserved':80,'declared_allocation_requests':128,'object32_initializers':64,'pair16_initializers':16,'borrowed_span_contexts':64,'VM_deallocate_call_frontiers':16,'post_allocation_state_reads':0,'post_allocation_numeric_reads':0,'unique_visited_source_instructions':2703,'original_dispatch_edges':13,'SDK_compile_exit':0}
 assert checks['all_checks_pass']and checks['verified_counts']==expected and checks['independent_A64_totals']['source_visits']==296416 and checks['independent_A64_totals']['uninterpreted_probe_read_bytes']==0
 for flag in ['native_target_executed','native_allocator_executed','native_framework_calls_executed','native_authorization_outcome_established','hardware_PAC_executed','idb_mutated','new_port_emission_established','full_goal_complete']:assert checks[flag]is False
 assert set(checks['boundary_counts'].values())=={16}and len(checks['boundary_counts'])==5
 smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==32 and smt=={p.name for p in ROOT.glob('daemon_client_object_*.smt2')}
 for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CO'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['daemon_client_object_delivery.json','daemon_client_object_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5251,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':32,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_client_object_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'32/16-byte allocation epochs, exact initialization, borrowed pointer/low32 length, guarded byte-reader entry, NULL status and VM cleanup arguments. Native owners, allocation/VM effects, full parser, final state consumers/admission and IPC joins remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'native_allocator_executed':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'native_owner_extents_established':False,'all_native_setup_states_covered':False,'later_emitter_epoch_join_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CO1-CO8, original bytes/fixups, rebuilt SMT, continuous private CPU witnesses and prior artifact preservation'}
 (ROOT/'daemon_client_object_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5251,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
