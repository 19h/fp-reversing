#!/usr/bin/env python3
"""Seal CF Mach-port ownership, invalidation, record rendezvous and cleanup evidence.
O(prior bytes+source+links), O(manifest+largest JSON+image). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_cf_mach_port_retirement import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='2fbee72a360a6fef9d1fa8ee8126ce604acd9681a71ff53dbc3be9cf6662c937';m=json.loads(prior.read_text());assert len(m['files'])==6643;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6637 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert src==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['repeat_and_independent_semantic_checks']
 expected={'complete_CF_functions_recaptured':17,'captured_instructions':1155,'retirement_library_functions_captured_static_only':6,'lower_stubs_resolved':18,'cache_files_hashed':5,'daemon_bindings_checked':3,'daemon_windows_checked':3,'retirement_wire_instructions_checked':19,'retirement_wire_constants_checked':5,'SDK_headers_hashed':4,'SDK_assertions_checked':16,'altered_evidence_controls_rejected':10}
 assert counts==expected
 assert totals['original_instruction_visits_repeated']==15793 and totals['cases_reexecuted']==287 and totals['cleanup_flag_inputs_checked']==256 and totals['complete_final_RAM_bytes_repeated']==78761984
 assert totals['semantic_phase_oracles']==350 and totals['record_flags_and_keys_checked']==59 and totals['cleanup_request_arguments_checked']==426 and totals['tracked_CPU_frames_repeated']==3287
 assert totals['shared_engine_and_lower_models']is True and totals['independent_compact_semantic_model']is True and len(checks['case_summaries'])==31 and len(prof['cases'])==287
 for e in checks['SDK_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| MR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6643,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original CF construction/cache/validity/invalidation/destructor/record/cancel and cleanup in private component sequences; six static-only libkernel trap/RPC bodies. Repetition shares Engine/lower models; a separate compact semantic model verifies phases/flags/cleanup. Allocation/retention/collections/locks/dispatch/Mach/callouts/PAC remain explicit. No native lifetime/right/IPC, actual daemon service-object join or successful FairPlay proof.','generator_sha256':sha(__file__),'verified_counts':counts,'repeat_and_independent_semantic_checks':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', MR1-MR8,17 CF routines/1155 instructions,18 stubs,three daemon binds/windows,five cache hashes,six static library bodies/19 wire assertions/five constants,four SDK hashes/16 assertions,287 cases/15793 visits/78761984 B,256 flags,350 semantic phases/426 cleanup arguments and ten rejected alterations; shared-engine repetition limitations explicit'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
