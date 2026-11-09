#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_request_application import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='5b4c0435efed84205d7c6f4aba678bd64649ababaa9ae7e29cca5836aa8cd20b';m=json.loads(prior.read_text());assert len(m['files'])==6369;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6363 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert counts['daemon_ranges_recaptured']==53 and counts['daemon_instructions_recaptured']==3808 and counts['cache_function_instructions_recaptured']==35 and counts['complete_cache_source_files_hashed']==3 and counts['original_used_fixup_words_checked']==157
 assert counts['exact_original_callback_CPU_and_whole_RAM_prefixes_checked']==2 and counts['complete_private_argument_record120_oracles_checked']==2 and counts['complete_encoded_control_record32_oracles_checked']==2 and counts['complete_original_audit_copy_source_destination_and_stores_checked']==6 and counts['original_libbsm_word5_load_and_PID_store_checked']==2
 assert totals['original_instruction_visits_checked']==5934 and totals['cached_libbsm_instruction_visits_checked']==38 and totals['whole_private_RAM_bytes_checked']==3145728 and totals['final_boundaries_checked']==2 and totals['continuous_application_CPU_and_whole_RAM_handoffs_checked']==2 and totals['complete_application_record_and_ABI_frames_checked']==22 and checks['fresh_callback_producer_replay']['original_instruction_visits_checked']==662
 assert len(prof['cases'])==2
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RA'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6369,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Exact produced requests enter the original callback/MIG/application wrapper continuously. Complete private records, NUL scanning and three original audit-copy calls feed the selected original cached libbsm body and original PID-zero continuation. Stop before pthread identity. Stack-check preservation, library binding, malloc, inherited kernel/framework premises and logical PAC remain explicit. Native credentials, runtime identity/environment, output construction and authentic reply remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'fresh_callback_producer_replay':checks['fresh_callback_producer_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**FLAGS}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RA1-RA8, source recapture,157 fixup/import checks, two continuous application/library replays, two callback-producer replays and complete private-record/string/copy/PID oracles'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
