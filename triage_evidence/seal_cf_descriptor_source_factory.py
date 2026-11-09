#!/usr/bin/env python3
"""Seal exact CF descriptor/source factory and callback ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_cf_descriptor_source_factory import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='596471f732351a8da6f6dad9ff5d1762fe6dccf56aa9eb09413395154202cc83';m=json.loads(prior.read_text());assert len(m['files'])==6591;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6585 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_daemon_replay']
 assert counts['complete_CF_functions_recaptured']==104 and counts['captured_CF_instructions']==10906 and counts['named_lower_stub_targets_checked']==22 and counts['dispatch_type_fixups_checked']==2 and counts['cache_files_hashed']==9
 assert counts['original_permission_slice_u16_inputs_checked']==65536 and counts['original_permission_slice_instruction_visits_checked']==262144 and counts['SDK_arm64e_assertions_checked']==18 and counts['SDK_headers_hashed']==6 and counts['altered_evidence_controls_rejected']==8
 assert checks['independent_CF_replay']['original_instruction_visits_checked']==38258 and checks['independent_CF_replay']['whole_final_private_RAM_bytes_checked']==50331648 and totals['original_instruction_visits_checked']==27813 and totals['complete_final_mutable_RAM_bytes_checked']==7323648 and checks['aggregate_positive_visits']==66071 and checks['complete_final_private_RAM_bytes_checked']==57655296 and len(checks['case_summaries'])==16
 for e in checks['SDK_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| DF'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6591,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original CF descriptor/source factory, version0 source registration, dispatch handlers, original readiness and callback ABI; separately replayed daemon producer/consumer. Runtime/raw backing/POSIX/dispatch/once/hash/PAC/SVC contracts and explicit handler/Perform entries remain declared. No native source0 scheduler, ownership, closure, IPC or successful FairPlay claim.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_daemon_replay':totals,'independent_CF_replay':checks['independent_CF_replay'],'aggregate_positive_visits':checks['aggregate_positive_visits'],'complete_final_private_RAM_bytes_checked':checks['complete_final_private_RAM_bytes_checked'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', DF1-DF8,104 CF routines/10906 captured instructions,22 lower stubs/two data-type identities,65536-input original scalar slice,six SDK hashes/18 assertions,sixteen CF/three separate daemon replays,66071 positive visits/57655296 B and eight rejected alterations'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
