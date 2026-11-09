#!/usr/bin/env python3
"""Seal bounded VM-MIG registry/receiver evidence and preserve prior artifacts.
O(prior bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher files change. No native target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['kernel_vm_mig_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={'kernel_vm_mig_source.json':'recover_kernel_vm_mig.py','kernel_vm_mig_profiles.json':'probe_kernel_vm_mig.py','kernel_vm_mig_proofs.json':'prove_kernel_vm_mig.py','kernel_vm_mig_checks.json':'validate_kernel_vm_mig.py'}
SCRIPTS=list(GENS.values())+['kernel_vm_mig_tools.py','replay_kernel_vm_mig.py','seal_kernel_vm_mig.py','verify_kernel_vm_mig_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/'kernel_vm_mig_prior_manifest.json';assert sha(prior)=='799b5259e7a5ea405e5855e33af53d2b3ada1f3162e0bb4df4089bf1223eed99';m=json.loads(prior.read_text());assert len(m['files'])==5348;unchanged=0;changed=[]
 for r in m['files']:
  p=BASE/r['path'];assert p.is_file();h=sha(p)
  if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
  else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
 assert{r['path']for r in changed}==CHANGED and unchanged==5342
 for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  obj=objects[n];assert obj['generator_sha256']==sha(ROOT/script)
  for d,h in obj['dependencies'].items():assert sha(ROOT/d)==h,(script,d)
 source=objects['kernel_vm_mig_source.json'];profiles=objects['kernel_vm_mig_profiles.json'];proof=objects['kernel_vm_mig_proofs.json'];checks=objects['kernel_vm_mig_checks.json'];assert checks['all_checks_pass']and len(proof['proofs'])==10 and len(profiles['cases'])==173
 expected={'source_obligations_rebuilt':10,'SMT_files_checked':20,'profiles':173,'registered_subsystems':20,'registered_routines':358,'hash_slots':1031,'maximum_probe':91,'message4801_slot':677,'initializer_source_visits':29363,'selector_cases':35,'lookup_cases':35,'stub_valid_cases':90,'stub_bad_header_cases':12,'conversion_models':36,'VM_models':90,'release_models':90,'unique_captured_source_instructions':993,'SDK_compile_exit':0};assert checks['verified_counts']==expected and checks['independent_A64_totals']['source_visits_checked']==35844
 assert checks['SDK_layout']['exit_code']==0 and sha(ROOT/'kernel_vm_mig_sdk.ll')==checks['SDK_layout']['LLVM_sha256']and not checks['SDK_layout']['matched_runtime_version_established']
 assert source['subsystems'][0]['routines'][24]['id']==4824 and source['subsystems'][0]['routines'][24]['stub']is None and source['message4801']['initialized_hash_entry']['index']==677
 for flag in ['native_target_executed','native_IPC_executed','native_runtime_table_attested','native_port_or_map_ownership_established','hardware_PAC_executed','idb_mutated','continuous_user_wire_delivery_established','full_goal_complete']:assert checks[flag]is False
 smt={r[k]for r in proof['proofs']for k in ['file','original_file']};assert len(smt)==20 and smt=={p.name for p in ROOT.glob('kernel_vm_mig_*.smt2')}
 for r in proof['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
 for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
 text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| KM'+str(j)+' |'in text for j in range(1,9))and all('QG'+str(j)+':'in text for j in range(1,8));links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   p=Path(raw.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   if p.name not in ['kernel_vm_mig_delivery.json','kernel_vm_mig_quality_gates.json']:assert p.exists(),(n,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5348,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'SMT_files_checked':20,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'kernel_vm_mig_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original kernel VM-MIG registry/init/selector/hash/receiver, five-pointer ABI, conversion/VM/release boundaries and reply result fields. Native admission, continuous wire/namespace conversion and reply send remain unresolved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'source_registration_and_receiver_join_established':True,'native_runtime_table_attested':False,'native_port_or_map_ownership_established':False,'continuous_user_wire_delivery_established':False,'native_reply_emission_observed':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', KM1-KM8, original bytes/chains/registry, initializer-model equality, rebuilt SMT, SDK compile, independent replay and prior preservation'}
 (ROOT/'kernel_vm_mig_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':5348,'unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
