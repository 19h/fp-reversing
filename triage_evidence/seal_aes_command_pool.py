#!/usr/bin/env python3
"""Seal original command-pool/gate/carrier evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='aes_command_pool'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='c1948700d1963096d0f1a3c096e5bf30116f56d57c8fd5b64a1efa00fc892947';m=json.loads(prior.read_text());assert len(m['files'])==5862;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5856 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay'];assert all(expected[k]==v for k,v in {'cases':38,'functions':33,'captured_instructions':2102,'additional_slots':11,'external_object_producer_checked':1,'third_gate_source_attachment_checked':1,'exact_object_transfers_checked':37,'source_seed_carriers_checked':32,'gated_return_frames_checked':33,'gated_get_frames_checked':35,'nonempty_bool_lease_cases_checked':2,'returned_carrier_cycle_checked':1,'additional_unique_drain_leases_checked':31,'empty_status_to_NULL_checked':1,'empty_blocking_sleep_frontier_checked':1,'complete_object_state_pairs_checked':2,'ordered_unique_drain_carriers_checked':32}.items())
 assert len(prof['cases'])==38 and sum(len(r['source_visits'])for r in prof['cases'])==11953 and sum(len(r['API_models'])for r in prof['cases'])==306
 required={'source_visits_checked':11953,'logical_authentication_steps_checked':814,'writes_checked':1750,'write_bytes_checked':13969,'reads_checked':2926,'read_bytes_checked':23242,'logical_indirect_edges_checked':486,'declared_model_memory_effects_checked':2,'declared_model_write_bytes_checked':16,'declared_API_models_checked':306,'logical_return_steps_checked':144,'maintenance_frames_checked':1,'final_boundaries_checked':38,'final_objects_checked':1672,'pool_action_frames_checked':68,'pool_action_statuses_checked':67,'pool_sleep_frontiers_checked':1};assert totals==required
 for key in ['native_IPC_executed','native_allocator_or_constructor_executed','native_reference_effects_executed','native_workloop_or_lock_effects_executed','native_hardware_AES_executed','hardware_PAC_executed']:assert checks[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5862,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':11,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original pool construction/gate attachment, provider 32-carrier seed, circular-list identity-preserving leases/return/drain and empty sleep frontier. Allocator/constructor/reference/lock/thread effects remain modeled; native hardware/daemon lifecycle remains unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CP1-CP8, original source/fixups, source-produced object transfers, independent A64 read/write/branch replay and pool/gate/list/lease/status/sleep oracles, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':11,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
