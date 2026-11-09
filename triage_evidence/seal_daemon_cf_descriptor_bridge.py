#!/usr/bin/env python3
"""Seal original daemon/CF descriptor construction, callback and invalidation evidence.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_cf_descriptor_bridge import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='55e874355ab0ebecc4169801ffe49d95c2602713681a771800b4c927d91af074';m=json.loads(prior.read_text());assert len(m['files'])==6630;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6624 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_combined_replay']
 expected={'complete_cache_functions_recaptured':133,'captured_cache_instructions':12348,'cache_files_hashed':9,'selected_daemon_CF_slots_checked':9,'original_daemon_static_ranges_checked':13,'new_lower_stub_identities_checked':4,'SDK_arm64e_assertions_checked':16,'SDK_headers_hashed':7,'altered_evidence_controls_rejected':10,'same_epoch_original_callback_invalidate_GetMain_Stop_wake_oracles_checked':6,'original_initializer_record_tail_and_guard_oracles_checked':11,'original_nonsignal_and_event_result_variants_checked':5}
 assert counts==expected
 assert totals['original_instruction_visits_checked']==332479 and totals['original_daemon_in_CF_epoch_visits_checked']==286641 and totals['original_daemon_callback_returns_to_original_CF_checked']==11
 assert totals['whole_final_private_RAM_bytes_checked']==34603008 and totals['whole_final_additional_daemon_mutable_bytes_checked']==26853376 and checks['aggregate_positive_visits']==332479 and checks['complete_final_private_RAM_bytes_checked']==61456384 and len(checks['case_summaries'])==11
 assert totals['complete_CPU_frames_checked']==6881 and totals['ordered_reads_checked']==47701 and totals['ordered_writes_checked']==23324 and totals['explicit_sync_original_block_entries_checked']==62 and totals['intercepted_original_SVC_visits_checked']==6
 for e in checks['SDK_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| BC'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6630,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original daemon initializer/setup explicitly joined with captured CF descriptor/source/public RUN; actual original callback/CF return, invalidation/removal/GetMain/Stop/wake and optional explicit cancel delivery in one private epoch. Runtime/hash/retention/locks/once/POSIX/dispatch/events/main registration/SVC/PAC remain declared. No native startup/lifetime/thread/IPC or successful FairPlay claim.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_combined_replay':totals,'aggregate_positive_visits':checks['aggregate_positive_visits'],'complete_final_private_RAM_bytes_checked':checks['complete_final_private_RAM_bytes_checked'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', BC1-BC8,133 cache routines/12348 instructions,nine CF binds,13 daemon ranges,seven SDK hashes/16 assertions,11 combined epochs/332479 visits/61456384 B,11 original callback returns,six original Stop/wake cases,explicit copied cancel delivery and ten rejected alterations'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
