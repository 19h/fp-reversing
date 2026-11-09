#!/usr/bin/env python3
"""Seal static kernel membership-removal contracts and exact reporting changes.
O(prior bytes+capture+links), O(manifest+largest JSON+source). No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_kernel_membership_removal import P,FLAGS,sha,build
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_contracts.json':'analyze_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='689e8a0d2e031a32937aafc299790633bfca3f129e6b362b1a1c79ee549cf5d2';m=json.loads(prior.read_text());assert len(m['files'])==6669;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6663 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)and all(o[k]is False for k in FLAGS)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
 source=objs[P+'_source.json'];contracts=objs[P+'_contracts.json'];checks=objs[P+'_checks.json'];assert source==build()and checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];scope=checks['static_scope']
 expected={'kernel_functions_recaptured':14,'kernel_instructions_captured':703,'cache_functions_recaptured':10,'cache_instructions_captured':498,'cache_files_hashed':5,'trap_bindings_checked':4,'MIG_routine_bindings_checked':1,'exact_instruction_assertions':68,'direct_call_edges_recorded':96,'unresolved_indirect_sites_recorded':2,'algebra_proofs_unsat':2,'SDK_headers_hashed':4,'SDK_assertions_checked':24,'altered_static_controls_rejected':12};assert counts==expected
 assert scope=={'target_instruction_visits':0,'target_instructions_emulated':0,'runtime_states_observed':0,'function_bytes_checked':4804,'analysis_scripts_checked_for_target_emulator_methods':3}
 assert len(contracts['proofs'])==2 and all(p['result']=='unsat'for p in contracts['proofs']);assert sha(contracts['solver']['path'])==contracts['solver']['sha256']
 for e in checks['SDK_headers']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| KR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6669,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':6,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Static original CF/libkernel fast/fallback binding to kernel extraction core; typed argument/message layouts, call/ownership frontiers, source-local status continuations and two algebra proofs. No target execution/emulation or runtime observations. Conversion/diagnostics/transitive effects, native identity/authorization/namespace/right/lifetime and full FairPlay processing remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':scope,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', KR1-KR8,14 kernel/ten cache functions,703+498 instructions/4804 B,four trap bindings/3227 record,68 assertions/96 direct edges/two indirect sites,two UNSAT queries,four SDK hashes/24 assertions,twelve rejected static alterations; target visits/emulation/runtime observations zero'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
