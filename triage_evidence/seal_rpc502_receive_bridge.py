#!/usr/bin/env python3
"""Seal RPC502 receive-bridge evidence, preserving all but six owned indices.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
No native target operation, IPC, IDB or saved-memory mutation.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['rpc502_receive_bridge_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'rpc502_receive_bridge_source.json':'recover_rpc502_receive_bridge.py','rpc502_receive_bridge_profiles.json':'probe_rpc502_receive_bridge.py','rpc502_receive_bridge_proofs.json':'prove_rpc502_receive_bridge.py','rpc502_receive_bridge_checks.json':'validate_rpc502_receive_bridge.py','rpc502_receive_bridge_daemon_profiles.json':'probe_rpc502_bridge_daemon.py','rpc502_receive_bridge_copyin.json':'recover_rpc502_bridge_copyin.py'}
SCRIPTS=list(GENS.values())+['replay_rpc502_bridge_daemon.py','replay_rpc502_receive_bridge.py','seal_rpc502_receive_bridge.py','verify_rpc502_receive_bridge_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'rpc502_receive_bridge_prior_manifest.json';assert sha(prior)=='f0faba109c08ff1224d432a5ea4a28085af5188b56e92bdac5783cc536c15b37';m=json.loads(prior.read_text());assert len(m['files'])==5592;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5586
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['rpc502_receive_bridge_checks.json'];proof=objects['rpc502_receive_bridge_proofs.json'];profiles=objects['rpc502_receive_bridge_profiles.json'];source=objects['rpc502_receive_bridge_source.json']
 assert checks['all_checks_pass']and len(proof['proofs'])==18 and len(profiles['cases'])==112
 expected={'kernel_cases':112,'daemon_guard_cases':112,'source_obligations_rebuilt':18,'SMT_files_checked':36,'captured_kernel_instructions':1603,'captured_daemon_guard_instructions':77,'MIG_application_boundaries':32,'MIG_type_errors':80,'kernel_success_extent_expansion_rejections':16,'kernel_VM_body_errors':64,'SDK_compile_exit':0};assert checks['verified_counts']==expected and checks['independent_kernel_A64_totals']['source_visits_checked']==108488 and checks['independent_daemon_A64_totals']['source_visits_checked']==2992
 assert len(source['functions'])==6 and len(objects['rpc502_receive_bridge_daemon_profiles.json']['cases'])==112
 copyin=objects['rpc502_receive_bridge_copyin.json'];assert copyin['all_checks_pass']and copyin['verified_counts']=={'original_functions':2,'function_instructions':721,'review_spans':4,'exact_instruction_role_checks':8}and not copyin['actual_copy_type_established']and not copyin['entry_list_expansion_reachable_from_ordinary_kext_request_established']
 assert sha(ROOT/'rpc502_receive_bridge_sdk.ll')==checks['SDK_layout']['LLVM_sha256']
 for key in ['native_target_executed','native_IPC_executed','native_VM_or_namespace_effects_executed','native_framework_forwarding_established','native_application_execution_established','complete_FairPlay_round_trip_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 smt={r[k]for r in proof['proofs']for k in ['file','original_file']};assert len(smt)==36 and smt=={p.name for p in ROOT.glob('rpc502_receive_bridge_*.smt2')}
 for r in proof['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| RB'+str(j)+' |'in text for j in range(1,13))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['rpc502_receive_bridge_delivery.json','rpc502_receive_bridge_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5592,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'SMT_files_checked':36,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'rpc502_receive_bridge_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original RPC502 OOL validation/conversion/packing and daemon MIG guard/ABI. Namespace/VM effects, actual copy type, CF forwarding and native exchange remain unresolved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_kernel_A64_totals':checks['independent_kernel_A64_totals'],'independent_daemon_A64_totals':checks['independent_daemon_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'native_VM_or_namespace_effects_executed':False,'native_framework_forwarding_established':False,'native_application_execution_established':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'private_packet_to_original_MIG_guard_transfer_checked':True,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RB1-RB12, original bytes, rebuilt SMT, SDK compile, independent replay and prior preservation'}
 (ROOT/'rpc502_receive_bridge_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5592,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
