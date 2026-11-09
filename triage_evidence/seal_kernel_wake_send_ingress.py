#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_kernel_wake_send_ingress import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='33b0d95de7d19cfd933b0db544cd1dc118dec4fe45766ea0866b6f3529da66e0';m=json.loads(prior.read_text());assert len(m['files'])==6551;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6545 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert counts['complete_kernel_functions_recaptured']==183 and counts['captured_kernel_instructions']==24084 and counts['complete_CF_functions_recaptured']==52 and counts['captured_CF_instructions']==4024 and counts['cache_files_hashed']==9 and counts['SDK_arm64e_trailer_layout_assertions_checked']==4
 assert counts['original_Mach47_and_task_readonly_validation_paths_checked']==5 and counts['original_namespace_copy_send_reference_and_internal_header32_enqueue_checked']==4 and counts['complete_wake_header24_trailer68_identity_and_context_oracles_checked']==4 and counts['actual_wake_then_service_ready_head_rotation_and_retained_ready_bits_checked']==4 and counts['scalar_header_reconstructed_from_packed_slots_without_user_copyin_checked']==2 and counts['original_vector48_copyin_and_aux_payload32_header8_reconstruction_checked']==2 and counts['original_vector_copyin_failure_before_send_and_allocation_checked']==1 and counts['actual_kernel_wake_routes_before_one_service_lookup_and_daemon_callback_checked']==4 and counts['unchanged_complete_daemon_suffix_object_and_argument_record_or_return_checked']==4 and counts['scalar_and_vector_delivery_produce_identical_complete_CF_execution_state_checked']==2 and counts['altered_evidence_controls_rejected']==6
 assert totals['source_visits_checked']==45316 and totals['whole_final_RAM_bytes_checked']==5242880 and totals['complete_CF_user_epoch_final_bytes_checked']==10485760 and checks['independent_CF_replay']['original_instruction_visits_checked']==14848 and checks['independent_CF_replay']['whole_final_private_RAM_bytes_checked']==12582912 and checks['fresh_CF_producer_replay']['original_instruction_visits_checked']==3120 and checks['fresh_CF_producer_replay']['whole_final_private_RAM_bytes_checked']==6291456 and checks['fresh_timer_startup_replay']['source_visits_checked']==170 and checks['fresh_receiver_loan_replay']['source_visits_checked']==216 and checks['fresh_zone_replay']['source_visits_checked']==618 and len(prof['cases'])==5 and len(prof['CF_cases'])==4
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| WI'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6551,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Exact original CF scalar/vector packets feed original kernel Mach -47/task-readonly/send/disposition/reference/metadata/policy/queue paths and actual wake-first/service-second set receive. Complete header24/trailer68,identity markers,recipient context,auxiliary header8/payload32 and ready-head rotation verified. Original CF wake route precedes one service lookup and unchanged daemon suffix; scalar/vector full CF state is identical. Task/readonly/identity/counter epochs,raw/copy/hash/runtime/PAC effects and component handoffs remain explicit. Native exception crossing,caller/ownership/authentication,queue-full/coalescing and successful FairPlay output remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'independent_CF_replay':checks['independent_CF_replay'],'fresh_CF_producer_replay':checks['fresh_CF_producer_replay'],'fresh_timer_startup_replay':checks['fresh_timer_startup_replay'],'fresh_receiver_loan_replay':checks['fresh_receiver_loan_replay'],'fresh_zone_replay':checks['fresh_zone_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', WI1-WI8,183 kernel/52 cache bodies,nine cache/two SDK hashes,four arm64e layout assertions,five kernel/four CF/two producer/one timer startup/four loan/three fixed-zone independent replays,full CPU/RAM/header/identity/context/aux/rights/queue/CF oracles and six rejected alterations'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
