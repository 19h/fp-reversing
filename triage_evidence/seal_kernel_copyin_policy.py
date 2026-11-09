#!/usr/bin/env python3
"""Seal the reply-ABI increment with six explicitly owned existing changes.
O(prior bytes+links) time; O(manifest+largest JSON) space. No native effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['kernel_copyin_policy_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'kernel_copyin_policy_source.json':'recover_kernel_copyin_policy.py','kernel_copyin_policy_profiles.json':'probe_kernel_copyin_policy.py','kernel_copyin_policy_checks.json':'validate_kernel_copyin_policy.py'}
SCRIPTS=list(GENS.values())+['replay_kernel_copyin_policy.py','seal_kernel_copyin_policy.py','verify_kernel_copyin_policy_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'kernel_copyin_policy_prior_manifest.json';assert sha(prior)=='ae1539c3943d45b5163d032db27f67eca4298d0d2b50c4a5c8628a13d8f2afcd';m=json.loads(prior.read_text());assert len(m['files'])==5688;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert {r['path']for r in changed}==CHANGED and unchanged==5682
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(n,d)
 checks=objects['kernel_copyin_policy_checks.json'];src=objects['kernel_copyin_policy_source.json'];prof=objects['kernel_copyin_policy_profiles.json']
 assert checks['all_checks_pass']and checks['source_recapture_match']and len(prof['cases'])==111
 assert len(src['functions'])==10 and sum(len(x['instructions'])for x in src['functions'])==1399 and src['policy_cell']['initial_u32']==2 and len(src['direct_references']['references'])==7 and len(prof['predicate_gate_pairs'])==54
 assert checks['verified_counts']=={'cases': 111, 'functions': 10, 'captured_instructions': 1399, 'instruction_words_scanned': 15490987, 'ADRP_page_candidates': 431, 'direct_reference_groups': 7, 'predicate': 54, 'original_owner_lookup_entries': 64, 'gate': 54, 'buffer_factory': 42, 'policy_range_validation': 12, 'file_default_buffer_factory': 12, 'file_default_policy_range_validation': 6, 'startup': 3, 'startup_global_stores': 2, 'matched_pairs': 54}
 assert checks['independent_A64_replay']=={'source_visits_checked': 9988, 'reads_checked': 1755, 'read_bytes_checked': 9981, 'final_boundaries_checked': 111, 'logical_PAC_steps_checked': 280, 'writes_checked': 1311, 'write_bytes_checked': 9802, 'logical_data_auth_steps_checked': 40, 'declared_API_models_checked': 12, 'startup_parser_arguments_checked': 3, 'logical_instruction_auth_steps_checked': 6}
 for key in ['native_target_executed','native_boot_configuration_changed','native_runtime_policy_value_attested','native_VM_effects_executed','native_IPC_executed','hardware_PAC_executed','complete_FairPlay_round_trip_established','idb_mutated','full_goal_complete']:assert checks[key]is False
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| CP'+str(j)+' |'in text for j in range(1,9))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['kernel_copyin_policy_delivery.json','kernel_copyin_policy_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5688,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':len(SCRIPTS)+1,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'kernel_copyin_policy_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original copyin selector initialization, startup/parser writer, validated owner lookup and paired local predicate. Native runtime state and hardware authentication remain unestablished.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_replay':checks['independent_A64_replay'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CP1-CP8, original source capture, independent CPU/byte oracle and prior preservation'}
 (ROOT/'kernel_copyin_policy_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
