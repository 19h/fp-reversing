#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_descriptor_source import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='468b624de6b678ea0779a6653ce037c5c77896b81fa4a834b507e89124c725e6';m=json.loads(prior.read_text());assert len(m['files'])==6577;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6571 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_daemon_replay']
 assert counts['original_static_ranges_recaptured']==13 and counts['captured_static_instructions']==973 and counts['exhaustive_256_banks_checked']==9 and counts['selected_original_bindings_checked']==11 and counts['default_mode_nonzero_addend_cancellation_checked']==1 and counts['IDA_original_bytes_checked']==1600 and counts['SDK_arm64e_assertions_checked']==14 and counts['full_domain_local_SMT_proofs']==3
 assert counts['original_initialized_record_tail_bytes_checked']==2000 and counts['record_stride_bytes']==896 and counts['original_record_count']==100 and counts['CF_stop_original_instructions_captured']==53 and counts['CF_stop_active_and_dormant_cases_checked']==3 and counts['altered_evidence_controls_rejected']==8 and counts['cache_files_hashed']==9
 assert totals['original_instruction_visits_checked']==79643 and totals['complete_final_mutable_RAM_bytes_checked']==46383104 and checks['independent_CF_replay']['original_instruction_visits_checked']==4066 and checks['independent_CF_replay']['whole_final_private_RAM_bytes_checked']==9437184 and checks['aggregate_positive_visits']==83709 and checks['complete_final_private_RAM_bytes_checked']==55820288 and len(checks['case_summaries'])==22
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| DS'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6577,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original daemon descriptor creation/signal registration/default-mode source/callback/selected shutdown and separate original CF Stop/current-mode/stop-byte/wake execution. Exact record metadata writes, original data-bind addend cancellation and event-output validity dependencies. Private function/continuation entries, raw backing/once/lock/API/event/CF current-mode/PAC/SVC contracts remain explicit. No native source dispatch, closure, IPC, ownership or whole-startup/successful FairPlay claim.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_daemon_replay':totals,'independent_CF_replay':checks['independent_CF_replay'],'aggregate_positive_visits':checks['aggregate_positive_visits'],'complete_final_private_RAM_bytes_checked':checks['complete_final_private_RAM_bytes_checked'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS+[P+'_ida.json']},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', DS1-DS8,13 daemon ranges/973 instructions,nine exhaustive byte banks,raw binds/addend cancellation,1600 matching IDA bytes,three SDK hashes/14 arm64e assertions,three local full-domain proofs,nineteen daemon/three CF replays,83709 positive visits/55820288 B and eight rejected alterations'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
