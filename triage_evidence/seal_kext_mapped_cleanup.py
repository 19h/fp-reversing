#!/usr/bin/env python3
"""Seal source/proof/replay increment and six owned existing changes.
O(total prior bytes+links), O(manifest+largest JSON); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kext_mapped_cleanup'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='e926f0b15b31301a6825bbfb79adf896e82e315125ed8761c18cc978189d79bd';m=json.loads(prior.read_text());assert len(m['files'])==5714;unchanged=0;changed=[]
 for row in m['files']:
  path=BASE/row['path'];assert path.is_file();h=sha(path)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and path.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5708 and {x['path']for x in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for path,h in [('/Users/___/Downloads/zut/fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('/Users/___/Downloads/zut/annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(path)==h
 objs={name:json.loads((ROOT/name).read_text())for name in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
 src=objs[P+'_source.json'];checks=objs[P+'_checks.json'];prof=objs[P+'_profiles.json'];assert checks['all_checks_pass']and checks['source_recapture_match']and len(prof['cases'])==60
 assert checks['verified_counts']=={'cases':60,'ranges':16,'captured_instructions':524,'banks256':6,'proofs_unsat':6,'return_status_pairs':30,'typed_free_record':54,'deallocate_aux':24,'unwire':42,'deallocate_primary':42}
 assert checks['independent_A64_replay']=={'source_visits_checked':11862,'reads_checked':2538,'writes_checked':60,'logical_PAC_edges_checked':450,'declared_API_models_checked':162,'final_boundaries_checked':60}
 assert src['instruction_words_scanned']==422089 and len(src['unsigned_STR64_2e8_candidates'])==14
 assert checks['source_seed_components']=={'no_aux_control_seed':'0x1eb','aux_control_seed':'0x1eb','companion_seed':'0x7a3','source_instructions_checked':13}
 for obj in [src,prof,checks]:
  for key in ['native_target_executed','hardware_PAC_executed','idb_mutated','full_goal_complete']:assert obj[key]is False
 assert checks['native_VM_effects_executed']is False and checks['native_record_publication_established']is False
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| MC'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   path=Path(raw.split('#',1)[0]);path=path if path.is_absolute()else BASE/path
   if path.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert path.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5714,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Conditional FairPlay mapped-region close suffix; native entry/publication/VM/release effects and full lifetime remain unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_replay':checks['independent_A64_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', MC1-MC8, original bytes/fixups, source proofs, independent CPU/argument oracle and prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
