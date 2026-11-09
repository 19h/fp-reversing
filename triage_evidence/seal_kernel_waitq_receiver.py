#!/usr/bin/env python3
"""Seal original waitq membership, selected-list/hold handoff and bounded scheduler return and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_waitq_receiver'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='3237f0effc663e3367efcf32bee52405e76da23583a645600103644eaad2aba2';m=json.loads(prior.read_text());assert len(m['files'])==6226;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6220 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected['cases']==11 and expected['every_dynamic_original_instruction_recaptured']==14101 and expected['no_waitq_selection_release_scheduler_or_port_lock_models_checked']==11 and expected['bounded_scalar_proofs_unsat']==3 and expected['original_notification_caller_success_returns_checked']==9 and expected['explicit_scheduler_or_context_guard_prefixes_checked']==2
 assert totals['source_visits_checked']==14101 and totals['whole_final_RAM_bytes_checked']==11534336 and totals['declared_API_models_checked']==55 and totals['independent_byte_copy_bytes_checked']==484 and totals['original_waitq_membership_scratch_receiver_DAIF_frames_checked']==125
 assert len(prof['cases'])==11 and sum(len(r['source_visits'])for r in prof['cases'])==14101 and sum(len(r['API_models'])for r in prof['cases'])==55
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 oh=src['opaque_keyed_hash'];assert im.k.read(int(oh['start'],16),int(oh['end'],16)-int(oh['start'],16)).hex()==oh['bytes_hex']and len(oh['PACGA_sites'])==5
 for e in src['allocation_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['related_fixed_zone_specs']:assert im.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex']and im.pointer(int(e['name_pointer']['slot'],16))==e['name_pointer']
 for e in src['queue_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['waitq_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['waitq_control_file_bytes']:assert im.k.read(int(e['address'],16),len(bytes.fromhex(e['bytes_hex']))).hex()==e['bytes_hex']
 assert sha(src['SDK_message_definitions']['path'])==src['SDK_message_definitions']['sha256']
 assert len(checks['proofs'])==3 and all(e['result']=='unsat'for e in checks['proofs'])
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| WR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6226,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'waitq_instruction_roles_recaptured':len(src['waitq_instruction_roles']),'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original nested waitq selection, event/identity matching, temporary selected-list and extra preemption hold, receiver spin ownership, DAIF transitions and bounded scheduler fast path with source notification return. Port/owner/inner-waitq/thread/CPU epochs and copy/hash/tag/preflight effects remain declared. Native initialization, blocked scheduling, context switches, copyout, authentication and authentic FairPlay transport remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', WR1-WR8, original bodies/visited words, fresh notification producer and exact CPU/RAM/global entry, independent declared input plans and before images, complete receiver/port/kmsg/inner-queue/scratch/status/accounting/nesting oracles, original hold/ownership/mask frames, nine caller returns and two explicit scheduler/context prefixes, scalar proofs and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
