#!/usr/bin/env python3
"""Seal queue-send component evidence, preserving all but six owned indices.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
No native target operation, IPC, IDB or saved-memory mutation.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['kernel_queue_send_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'kernel_queue_send_source.json':'recover_kernel_queue_send.py','kernel_queue_send_profiles.json':'probe_kernel_queue_send.py','kernel_queue_send_proofs.json':'prove_kernel_queue_send.py','kernel_queue_send_checks.json':'validate_kernel_queue_send.py','kernel_queue_send_consumers.json':'kernel_queue_send_consumers.py'}
SCRIPTS=list(GENS.values())+['replay_kernel_queue_send.py','seal_kernel_queue_send.py','verify_kernel_queue_send_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'kernel_queue_send_prior_manifest.json';assert sha(prior)=='30dbe7d1f04f714b84f8cbe225a95dbb4823a96cc7ac61151b07156c5f1860e2';m=json.loads(prior.read_text());assert len(m['files'])==5431;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5425
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['kernel_queue_send_checks.json'];proof=objects['kernel_queue_send_proofs.json'];profiles=objects['kernel_queue_send_profiles.json'];source=objects['kernel_queue_send_source.json']
 assert checks['all_checks_pass']and len(proof['proofs'])==18 and len(profiles['cases'])==146
 expected={'profiles':146,'source_obligations_rebuilt':18,'SMT_files_checked':36,'unique_captured_source_instructions':1187,'source_queue_entries':146,'original_enqueue_cases':94,'direct_receiver_handoffs':32,'too_large_retries':16,'destruction_requests':20,'SDK_compile_exit':0};assert checks['verified_counts']==expected and checks['independent_A64_totals']['source_visits_checked']==34441
 assert checks['continuous_caller_queue_path_executed_in_private_model']is True
 consumers=objects['kernel_queue_send_consumers.json'];assert consumers['all_checks_pass']and consumers['verified_counts']=={'source_spans':5,'captured_instructions':33,'exact_instruction_role_checks':18,'field_joins':3,'prior_contracts_rechecked':2}
 for key in ['same_live_receiver_thread_established','native_authentication_executed','continuous_receiver_execution_established','native_user_delivery_established']:assert consumers[key]is False
 assert len(source['functions'])==11 and source['reference']['exact_native_build_match_established']is False
 assert sha(ROOT/'kernel_queue_send_sdk.ll')==checks['SDK_layout']['LLVM_sha256']
 for key in ['native_target_executed','native_IPC_executed','native_queue_delivery_established','native_MAC_or_PAC_executed','continuous_request_to_send_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 smt={r[k]for r in proof['proofs']for k in ['file','original_file']};assert len(smt)==36 and smt=={p.name for p in ROOT.glob('kernel_queue_send_*.smt2')}
 for r in proof['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| QS'+str(j)+' |'in text for j in range(1,12))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['kernel_queue_send_delivery.json','kernel_queue_send_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5431,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'SMT_files_checked':36,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'kernel_queue_send_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original queue admission/post, circular insertion, receiver handoff and accounting. Scheduler/lock callbacks and native receiver/user delivery remain unresolved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'consumer_joins':consumers['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'native_MAC_or_PAC_executed':False,'native_queue_delivery_established':False,'continuous_request_to_send_established':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'continuous_caller_queue_path_executed_in_private_model':True,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', QS1-QS11, original bytes, rebuilt SMT, SDK compile, independent replay and prior preservation'}
 (ROOT/'kernel_queue_send_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5431,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
