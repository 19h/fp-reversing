#!/usr/bin/env python3
"""Seal the reply-ABI increment with six explicitly owned existing changes.
O(prior bytes+links) time; O(manifest+largest JSON) space. No native effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['rpc502_reply_copyin_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'rpc502_reply_copyin_source.json':'recover_rpc502_reply_copyin.py','rpc502_reply_copyin_profiles.json':'probe_rpc502_reply_copyin.py','rpc502_reply_copyin_checks.json':'validate_rpc502_reply_copyin.py'}
SCRIPTS=list(GENS.values())+['replay_rpc502_reply_copyin.py','seal_rpc502_reply_copyin.py','verify_rpc502_reply_copyin_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'rpc502_reply_copyin_prior_manifest.json';assert sha(prior)=='a93af2ae72cbdd913648098b51d0d1dc4ca738b31b54da465a1ec5f92885a30d';m=json.loads(prior.read_text());assert len(m['files'])==5675;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5669
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['rpc502_reply_copyin_checks.json'];src=objects['rpc502_reply_copyin_source.json'];prof=objects['rpc502_reply_copyin_profiles.json']
 assert checks['all_checks_pass']and checks['source_recapture_match']and len(prof['cases'])==46
 assert len(src['functions'])==7 and sum(len(x['instructions'])for x in src['functions'])==2688 and len(src['exact_instruction_roles'])==14
 assert checks['verified_counts']=={'cases': 46, 'functions': 7, 'captured_instructions': 2688, 'exact_instruction_roles': 14, 'normalize': 10, 'body': 36, 'success': 16, 'source_remove_requests': 32, 'backing_release_requests': 16, 'header_release_requests': 8, 'constructed_type3': 32, 'remove_before_publication': 32, 'copied_bytes': 180388, 'allocation_failure': 8, 'prefix_discards': 8, 'copy_failure': 8, 'entry_list_frontier': 4, 'pending_type2': 4}
 assert checks['independent_A64_replay']=={'source_visits_checked': 12430, 'reads_checked': 2276, 'read_bytes_checked': 15832, 'writes_checked': 2446, 'write_bytes_checked': 18124, 'final_boundaries_checked': 46, 'logical_PAC_steps_checked': 216, 'logical_data_auth_steps_checked': 34, 'VM_entry_arguments_checked': 52, 'private_effect_calls_checked': 132, 'declared_API_models_checked': 240, 'private_effect_patches_checked': 40, 'private_effect_bytes_checked': 180772, 'logical_data_sign_steps_checked': 64, 'source_removal_ABIs_checked': 32}
 for key in ['native_target_executed','native_VM_effects_executed','native_source_region_removal_executed','native_IPC_executed','native_namespace_conversion_executed','native_application_success_established','hardware_PAC_executed','complete_FairPlay_round_trip_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| RC'+str(j)+' |'in text for j in range(1,9))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['rpc502_reply_copyin_delivery.json','rpc502_reply_copyin_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5675,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':len(SCRIPTS)+1,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'rpc502_reply_copyin_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original reply descriptor normalization, OOL VM copyin, conditional type3 factory and prefix cleanup; type2 lookup frontier retained. VM/namespace/PAC/allocator effects are modeled.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_replay':checks['independent_A64_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RC1-RC8, original source capture, independent CPU/byte oracle and prior preservation'}
 (ROOT/'rpc502_reply_copyin_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
