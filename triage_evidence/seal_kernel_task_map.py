#!/usr/bin/env python3
"""Seal the reply-ABI increment with six explicitly owned existing changes.
O(prior bytes+links) time; O(manifest+largest JSON) space. No native effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['kernel_task_map_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'kernel_task_map_source.json':'recover_kernel_task_map.py','kernel_task_map_profiles.json':'probe_kernel_task_map.py','kernel_task_map_checks.json':'validate_kernel_task_map.py'}
SCRIPTS=list(GENS.values())+['replay_kernel_task_map.py','seal_kernel_task_map.py','verify_kernel_task_map_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'kernel_task_map_prior_manifest.json';assert sha(prior)=='502187eb7770876afb223646eda5c743c8ca6e9a7bb69eab9243707037e991f3';m=json.loads(prior.read_text());assert len(m['files'])==5701;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5695
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['kernel_task_map_checks.json'];src=objects['kernel_task_map_source.json'];prof=objects['kernel_task_map_profiles.json']
 assert checks['all_checks_pass']and checks['source_recapture_match']and len(prof['cases'])==42
 assert len(src['functions'])==6 and sum(len(x['instructions'])for x in src['functions'])==329 and len(src['exact_instruction_roles'])==11 and len(src['signing_candidates'])==7 and len(src['direct_replacement_calls'])==1 and len(prof['accessor_send_groups'])==8
 assert checks['verified_counts']=={'cases': 42, 'functions': 6, 'captured_instructions': 329, 'instruction_words_scanned': 15490987, 'signing_candidates': 7, 'direct_replacement_calls': 1, 'exact_instruction_roles': 11, 'current_task': 8, 'task_map': 8, 'send_prefix': 8, 'source_map_arguments_checked': 8, 'replace': 18, 'lock_pairs': 18, 'current_switch_requests': 8, 'new_map_cleanup_requests': 8, 'matched_context_groups': 8, 'aliased_context_groups': 2}
 assert checks['independent_A64_replay']=={'source_visits_checked': 3118, 'logical_PAC_steps_checked': 92, 'writes_checked': 420, 'write_bytes_checked': 3112, 'reads_checked': 784, 'read_bytes_checked': 5070, 'final_boundaries_checked': 42, 'logical_data_auth_steps_checked': 47, 'logical_data_sign_steps_checked': 32, 'declared_API_models_checked': 24}
 for key in ['native_target_executed','native_VM_effects_executed','native_hardware_map_switch_executed','native_IPC_executed','native_thread_synchronization_established','hardware_PAC_executed','complete_FairPlay_round_trip_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| TM'+str(j)+' |'in text for j in range(1,9))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['kernel_task_map_delivery.json','kernel_task_map_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5701,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':len(SCRIPTS)+1,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'kernel_task_map_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original named task/map accessors, sender map/space prefix and validated local map replacement. Native VM/switch/synchronization and reference lifetimes remain unestablished.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_replay':checks['independent_A64_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', TM1-TM8, original source capture, independent CPU/byte oracle and prior preservation'}
 (ROOT/'kernel_task_map_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
