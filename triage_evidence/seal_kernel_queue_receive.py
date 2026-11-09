#!/usr/bin/env python3
"""Seal queue-receive component evidence, preserving all but six owned indices.
O(prior artifact bytes + report links) time, O(manifest + largest JSON) space.
No native target operation, IPC, IDB or saved-memory mutation.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['kernel_queue_receive_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'kernel_queue_receive_source.json':'recover_kernel_queue_receive.py','kernel_queue_receive_profiles.json':'probe_kernel_queue_receive.py','kernel_queue_receive_proofs.json':'prove_kernel_queue_receive.py','kernel_queue_receive_checks.json':'validate_kernel_queue_receive.py'}
SCRIPTS=list(GENS.values())+['replay_kernel_queue_receive.py','seal_kernel_queue_receive.py','verify_kernel_queue_receive_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'kernel_queue_receive_prior_manifest.json';assert sha(prior)=='b5cb1ed92655160d79a5a0b66ce147aa5404a91ce77ee995081fdbbf064cce13';m=json.loads(prior.read_text());assert len(m['files'])==5486;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5480
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['kernel_queue_receive_checks.json'];proof=objects['kernel_queue_receive_proofs.json'];profiles=objects['kernel_queue_receive_profiles.json'];source=objects['kernel_queue_receive_source.json']
 assert checks['all_checks_pass']and len(proof['proofs'])==21 and len(profiles['cases'])==373
 expected={'profiles':373,'source_obligations_rebuilt':21,'SMT_files_checked':42,'unique_captured_source_instructions':787,'state_transfer_prefixes_checked':373,'queued_receive_cases':298,'dequeued_messages':196,'large_message_preservations':102,'source_handoff_consumer_components':64,'empty_receive_cases':11,'SDK_compile_exit':0};assert checks['verified_counts']==expected and checks['independent_A64_totals']['source_visits_checked']==49588
 assert checks['source_produced_state_transfer_established_in_private_model']is True and len(source['functions'])==7 and len(source['caller_excerpts'])==2
 assert sha(ROOT/'kernel_queue_receive_sdk.ll')==checks['SDK_layout']['LLVM_sha256']
 for key in ['native_target_executed','native_IPC_executed','native_receiver_execution_established','native_MAC_or_PAC_executed','continuous_request_to_user_delivery_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 smt={r[k]for r in proof['proofs']for k in ['file','original_file']};assert len(smt)==42 and smt=={p.name for p in ROOT.glob('kernel_queue_receive_*.smt2')}
 for r in proof['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| QR'+str(j)+' |'in text for j in range(1,13))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['kernel_queue_receive_delivery.json','kernel_queue_receive_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5486,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'SMT_files_checked':42,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'kernel_queue_receive_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original common receive/dequeue/preserve, source-state transfer, reader fields and thread-status channels. Native scheduling, rights and user delivery remain unresolved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'native_MAC_or_PAC_executed':False,'native_receiver_execution_established':False,'continuous_request_to_user_delivery_established':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'source_produced_state_transfer_established_in_private_model':True,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', QR1-QR12, original bytes, rebuilt SMT, SDK compile, independent replay and prior preservation'}
 (ROOT/'kernel_queue_receive_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5486,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
