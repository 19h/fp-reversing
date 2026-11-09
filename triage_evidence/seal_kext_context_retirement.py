#!/usr/bin/env python3
"""Seal source/proof/replay increment and six owned existing changes.
O(total prior bytes+links), O(manifest+largest JSON); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kext_context_retirement'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='8caa5e9af796774bcd1a04c496d8863c61bcd36eabf144c2152fef269fb6ffa5';m=json.loads(prior.read_text());assert len(m['files'])==5764;unchanged=0;changed=[]
 for row in m['files']:
  path=BASE/row['path'];assert path.is_file();h=sha(path)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and path.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5758 and {x['path']for x in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for path,h in [('/Users/___/Downloads/zut/fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('/Users/___/Downloads/zut/annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(path)==h
 objs={name:json.loads((ROOT/name).read_text())for name in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
 src=objs[P+'_source.json'];checks=objs[P+'_checks.json'];prof=objs[P+'_profiles.json'];assert checks['all_checks_pass']and checks['source_recapture_match']and len(prof['cases'])==28
 assert checks['verified_counts']=={'cases': 28, 'ranges': 6, 'captured_instructions': 2239, 'views': 2, 'banks256': 2, 'proofs_unsat': 1, 'placement_singleton': 10, 'owner_free_requests': 26, 'successful_closes': 26, 'overwrite_bytes_checked': 28288, 'unlink_before_overwrite_before_free': 26, 'child_free_requests': 22, 'child_free_before_unlink': 22, 'unwire_requests': 14, 'primary_deallocate_requests': 14, 'secondary_deallocate_requests': 13, 'placement_head': 5, 'placement_tail': 5, 'placement_middle': 6, 'placement_miss': 1, 'lookup_miss_returns': 2, 'placement_null': 1, 'page_error_close_compositions': 2, 'VM_status_pairs': 2}
 assert checks['independent_A64_replay']=={'source_visits_checked': 1016058, 'logical_PAC_steps_checked': 29772, 'writes_checked': 59029, 'write_bytes_checked': 271670, 'reads_checked': 38150, 'read_bytes_checked': 281437, 'logical_indirect_edges_checked': 29468, 'declared_API_models_checked': 101, 'final_boundaries_checked': 28, 'declared_call_transitions_checked': 2}
 assert len(src['proofs'])==1 and len(src['views'])==2 and len(src['banks'])==2 and len(src['ranges'])==6
 for obj in [src,prof,checks]:
  for key in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[key]is False
 assert all(checks[key]is False for key in ['native_VM_effects_executed','native_free_executed','native_reference_balance_established','continuous_native_constructor_page_close_established','hardware_PAC_executed'])
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   path=Path(raw.split('#',1)[0]);path=path if path.is_absolute()else BASE/path
   if path.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert path.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5764,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original close entry, typed cleanup, list removal, owner overwrite and two explicit page-error compositions; native effects/reference balance and full lifetime remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_replay':checks['independent_A64_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CR1-CR8, original bytes/fixups, close/list/overwrite contracts and byte proof, independent CPU/argument oracle and prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
