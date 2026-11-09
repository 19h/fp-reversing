#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_kernel_portset_delivery import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='acccb802d4b9acc217930ad26dcdc37f00bedde148c3e5a800d54be908e36a6d';m=json.loads(prior.read_text());assert len(m['files'])==6447;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6441 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert counts['complete_kernel_functions_recaptured']==163 and counts['captured_kernel_instructions']==21506 and counts['complete_CF_cache_functions_recaptured']==28 and counts['captured_CF_cache_instructions']==2309 and counts['cache_files_hashed']==9 and counts['original_Mach_trap_table_bindings_checked']==2
 assert counts['original_pset_object_name_and_namespace_publication_oracles_checked']==8 and counts['original_membership_and_ready_ring_complete_link_oracles_checked']==8 and counts['complete_portset_receive_wire_OOL_local_name_and_dequeue_oracles_checked']==4 and counts['source_kernel_membership_set_receive_and_CF_daemon_contract_compositions_checked']==4 and counts['short_capacity_preserves_original_queue_before_results_oracles_checked']==2 and counts['duplicate_membership_status11_topology_and_unused_storage_oracles_checked']==1 and counts['drained_set_demotes_ready_link_and_reaches_wait_frontier_oracles_checked']==1 and counts['altered_evidence_controls_rejected']==4
 assert totals['source_visits_checked']==24911 and totals['whole_final_RAM_bytes_checked']==8388608 and checks['independent_CF_replay']['original_instruction_visits_checked']==10108 and checks['independent_CF_replay']['whole_final_private_RAM_bytes_checked']==12582912 and checks['fresh_receiver_loan_replay']['source_visits_checked']==216 and checks['fresh_pset_zone_replay']['source_visits_checked']==157 and len(prof['kernel_cases'])==8 and len(prof['CF_cases'])==4
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| KP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6447,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original kernel allocation/namespace/membership/ready selection/set receive and exact CF return-contract composition are verified in eight kernel/four CF cases. Source set name0x507 and returned local member names are distinct. Short/duplicate/drained controls and full state/byte oracles pass. Native task/image/source/namespace epochs, raw allocation/backing, scheduler execution, CF construction, successful FairPlay output and hardware PAC remain explicit or unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'independent_CF_replay':checks['independent_CF_replay'],'fresh_receiver_loan_replay':checks['fresh_receiver_loan_replay'],'fresh_pset_zone_replay':checks['fresh_pset_zone_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', KP1-KP8,163 original kernel/28 cache bodies, two original trap bindings, nine cache hashes, eight kernel/four CF/four loan/one zone independent replays, full CPU/RAM/model/namespace/link/queue/wire oracles and four rejected altered records'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
