#!/usr/bin/env python3
"""Seal original daemon service/CF source1 registration, stored identity and removal evidence.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_service_cf_lifecycle import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='bf12f60a6d908bd52920c4a65aa35363b6e501db79f2d6e63f3e7f5ca56f205e';m=json.loads(prior.read_text());assert len(m['files'])==6656;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6650 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['repeat_and_independent_service_checks']
 expected={'complete_cache_functions_recaptured':141,'captured_instructions':13030,'cache_files_hashed':9,'selected_daemon_CF_bindings_checked':12,'original_checkin_ranges_checked':11,'inherited_daemon_ranges_checked':13,'new_extract_stub_and_trap_prefix_checked':1,'SDK_headers_hashed':6,'SDK_arm64e_assertions_checked':20,'altered_evidence_controls_rejected':12}
 assert counts==expected
 assert totals['original_instruction_visits_repeated']==264564 and totals['cases_reexecuted']==8 and totals['complete_final_private_RAM_bytes_checked']==44695552
 assert totals['service_lower_state_CPU_and_patch_contracts_recomputed']==157 and totals['original_service_object_source_dictionary_identity_oracles']==5 and totals['complete_public_and_source1_context_oracles']==13
 assert totals['stored_tracked_CPU_frame_records_repeated']==16140 and totals['original_daemon_callback_returns_to_CF_checked']==8 and totals['intercepted_original_wake_SVC_visits_checked']==7
 assert totals['shared_engine_and_lower_models']is True and totals['independent_service_contract_oracles']is True and len(checks['case_summaries'])==8 and len(prof['cases'])==8
 for e in checks['SDK_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| SR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6656,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original typed daemon check-in -> actual CF Mach-port/source1 creation and registration -> header store -> original descriptor callback invalidation/source removal/extract-member wrapper in one private epoch. Repetition shares Engine/lower models; separate service identity/state/patch/CPU/member oracles recompute the new contracts. Bootstrap/runtime/retention/hash/locks/main/TSD/events/Mach/SVC/PAC remain explicit. No native all-service/startup/IPC/namespace/right/lifetime or successful FairPlay proof.','generator_sha256':sha(__file__),'verified_counts':counts,'repeat_and_independent_service_checks':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', SR1-SR8,141 cache routines/13030 instructions,12 CF binds,11 new/13 inherited daemon windows,nine cache hashes,six SDK hashes/20 assertions,eight cases/264564 visits/44695552 B,157 new lower contracts,eight original callback returns,seven wake SVC visits and twelve rejected alterations; explicit shared-engine repetition limitations'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
