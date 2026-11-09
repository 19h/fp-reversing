#!/usr/bin/env python3
"""Seal exact delivered-request/daemon local-ABI evidence and reporting changes.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_cf_source_scheduling import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='0e15310136b3eabf5aaeeecb6d0a319f61c6d9d34b99f5d29c3785605e851377';m=json.loads(prior.read_text());assert len(m['files'])==6434;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6428 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert counts['complete_cache_functions_recaptured']==28 and counts['captured_cache_instructions']==2309 and counts['complete_AddSource_body_instructions']==261 and counts['original_import_stubs_checked']==10 and counts['cache_files_hashed']==9
 assert counts['original_wrappers_consume_registration_produced_mapping_oracles_checked']==4 and counts['nonzero_member_return_with_persistent_CF_bookkeeping_oracles_checked']==4 and counts['repeat_add_skips_second_mapping_membership_and_bag_oracles_checked']==1 and counts['invalid_source_preflight_and_no_publication_oracles_checked']==1 and counts['zero_port_collection_without_mapping_or_member_oracles_checked']==1 and counts['altered_evidence_controls_rejected']==4
 assert totals['original_instruction_visits_checked']==12113 and totals['whole_final_private_RAM_bytes_checked']==34603008 and totals['complete_CPU_frames_checked']==1029 and checks['fresh_kernel_delivery_replay']['source_visits_checked']==10652 and len(prof['cases'])==11 and len(prof['kernel_cases'])==4
 assert sha(Path(checks['SDK_declaration_context']['path']))==checks['SDK_declaration_context']['sha256']and checks['SDK_declaration_context']['AddSource_return_type']=='void'and checks['SDK_declaration_context']['SDK_handled_source_enum_value']==4
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| SS'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6434,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original AddSource/getPort/collection/type-member wrappers create association arguments consumed by original dictionary lookup wrappers and unchanged daemon/application code. Eleven controls separate CF bookkeeping from modeled membership; four kernel packet producers are freshly replayed. Native source/mode/hash construction, task/port-set identity, original-kernel set-based dequeue, full FairPlay processing and hardware PAC remain explicit or unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'fresh_kernel_delivery_replay':checks['fresh_kernel_delivery_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**FLAGS}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', SS1-SS8, original source/nlists/fixups/nine cache hashes, eleven independent scheduling/composition cases, four fresh kernel replays,1029 CPU frames,33MiB memory, complete backend state, four altered-evidence rejections and hashed SDK context'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
