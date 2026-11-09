#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_kernel_root_port_construct import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','cf_mode_construction_report.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='f94fe50fb70333a6ec089f0a850e844783e6055978b5ddc2bde825b410832cdb';m=json.loads(prior.read_text());assert len(m['files'])==6486;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6479 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert counts['complete_kernel_functions_recaptured']==168 and counts['captured_kernel_instructions']==22141 and counts['complete_CF_functions_recaptured']==43 and counts['captured_CF_instructions']==3498 and counts['cache_files_hashed']==9 and counts['original_construct_trap24_binding_checked']==1 and counts['compiled_arm64_SDK_layout_and_flag_assertions_checked']==1
 assert counts['original_receive_send_right_namespace_context_and_guard_oracles_checked']==5 and counts['same_original_namespace_inactive_root_ready_service_topology_oracles_checked']==5 and counts['original_root_construct_member_service_and_CF_daemon_compositions_checked']==4 and counts['valid_strict_flag_variation_isolated_to_original_port_bit_oracle_checked']==1 and counts['options_copyin_failure_before_port_allocation_oracles_checked']==1 and counts['altered_evidence_controls_rejected']==5
 assert totals['source_visits_checked']==24705 and totals['whole_final_RAM_bytes_checked']==6291456 and checks['independent_CF_replay']['original_instruction_visits_checked']==12356 and checks['independent_CF_replay']['whole_final_private_RAM_bytes_checked']==12582912 and checks['fresh_receiver_loan_replay']['source_visits_checked']==216 and checks['fresh_zone_replay']['source_visits_checked']==394 and len(prof['kernel_cases'])==6 and len(prof['CF_cases'])==4
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6486,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original kernel root port construction, receive/send namespace publication, queue context and guard/strict stores, root membership and queued service receive verified in one private namespace. Four CF consumers use checked root construction/member and service return contracts. Complete options extent24 corrects the earlier16-byte-prefix report. Native allocation/task/namespace epochs, guard enforcement/ownership, timer/wake producers, hardware PAC and successful FairPlay output remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'independent_CF_replay':checks['independent_CF_replay'],'fresh_receiver_loan_replay':checks['fresh_receiver_loan_replay'],'fresh_zone_replay':checks['fresh_zone_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RP1-RP8,168 original kernel/43 cache bodies, nine cache hashes, six kernel/four CF/four loan/two zone independent replays, compiled arm64 SDK assertions, full CPU/RAM/namespace/link/guard/options/wire oracles and five rejected altered records'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
