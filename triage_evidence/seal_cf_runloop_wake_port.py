#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_cf_runloop_wake_port import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='3c7b5da20da4cb48e8efaf4b7df0d4c0e6a75c389121167d2e268fff22c67257';m=json.loads(prior.read_text());assert len(m['files'])==6525;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6519 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert counts['complete_kernel_functions_recaptured']==172 and counts['captured_kernel_instructions']==22410 and counts['complete_CF_functions_recaptured']==47 and counts['captured_CF_instructions']==3768 and counts['cache_files_hashed']==9 and counts['SDK_headers_hashed']==2
 assert counts['source_wake_receive_send_rights_qlimit_context_and_guard_oracles_checked']==4 and counts['three_inactive_control_members_and_ready_service_ring_checked']==4 and counts['source_runloop_factory_fields_default_mode_and_all_four_members_checked']==4 and counts['CF_kernel_wake_options_context_name_and_membership_pairings_checked']==4 and counts['complete_original_wake_header_stores_send_tuple_and_check_helper_checked']==3 and counts['source_created_suppression_skips_send_checked']==1 and counts['success_or_timeout_original_wake_return_checked']==2 and counts['counterfactual_interrupted_send_diagnostic_boundary_checked']==1 and counts['original_runloop_runtime_null_early_return_checked']==1 and counts['altered_evidence_controls_rejected']==6
 assert totals['source_visits_checked']==27756 and totals['whole_final_RAM_bytes_checked']==4194304 and checks['independent_CF_replay']['original_instruction_visits_checked']==5425 and checks['independent_CF_replay']['whole_final_private_RAM_bytes_checked']==15728640 and checks['fresh_timer_startup_replay']['source_visits_checked']==170 and checks['fresh_timer_startup_replay']['whole_final_RAM_bytes_checked']==1048576 and checks['fresh_receiver_loan_replay']['source_visits_checked']==216 and checks['fresh_zone_replay']['source_visits_checked']==618 and len(prof['kernel_cases'])==4 and len(prof['CF_cases'])==5
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| WP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6525,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original wake construction with complete options24, queue limit1, guard context, receive/send rights and common-set membership; original CF run-loop factory fields and suppression, original gate clear and exact wake-header stores/send tuple verified. Four kernel/five CF cases retain declared lower allocation/runtime/send and external-waker entry contracts. Interrupted send result is counterfactual. Native lower send/retry, wake ingress/delivery, scheduling/concurrency/ownership, caller identity, hardware PAC and successful FairPlay output remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'independent_CF_replay':checks['independent_CF_replay'],'fresh_timer_startup_replay':checks['fresh_timer_startup_replay'],'fresh_receiver_loan_replay':checks['fresh_receiver_loan_replay'],'fresh_zone_replay':checks['fresh_zone_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', WP1-WP8,172 original kernel/47 cache bodies, nine cache/two SDK hashes, four kernel/five CF/one timer startup/four loan/three fixed-zone independent replays, full CPU/RAM/options/rights/queue/context/header/gate oracles and six rejected altered records'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
