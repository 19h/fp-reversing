#!/usr/bin/env python3
"""Seal startup/hardware evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kext_startup_hardware_bridge'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='b7c8a9cfbc63b053a566a21663a75791c612a39b3f2f68f11b2fcdfb40bda04b';m=json.loads(prior.read_text());assert len(m['files'])==5823;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5817 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay'];assert all(expected[k]==v for k,v in {'cases':5,'ranges':7,'captured_instructions':2015,'exact_slots':9,'views':2,'exact_source_produced_forks_checked':4,'one_nanosecond_timeout_cases':5,'error_return_and_output_copies_checked':4,'actual_global_buffer_AES_frontiers_checked':2,'hardware_frontier_or_balanced_return_lock_states_checked':5}.items())
 assert len(prof['cases'])==5 and sum(r['fingerprints']['visits']['count']for r in prof['cases'])==6881903 and sum(len(r['API_models'])for r in prof['cases'])==87 and sum(len(r['logical_data_authentication'])for r in prof['cases'])==11
 assert totals['visits_fingerprint_events_checked']==6881903 and totals['API_models_checked']==87 and totals['logical_data_authentication_steps_checked']==11 and totals['source_produced_startup_snapshots_checked']==1 and totals['AES_argument_frame_boundaries_checked']==2 and totals['memory_preserving_call_transitions_checked']==1 and totals['wrapper_returns_checked']==5 and totals['final_boundaries_checked']==5 and totals['bridge_memory_effects_checked']==21 and totals['bridge_memory_reads_checked']==29
 for key in ['native_IPC_executed','native_allocator_executed','native_lock_executed','native_clock_executed','native_provider_start_executed','native_hardware_AES_executed','native_constructor_established','hardware_PAC_executed']:assert checks[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['slots']:p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| HB'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5823,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':9,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original startup/constructor composition, exact source-produced forks, nominal hardware discovery and AES ABI frontier, four error/output continuations. Native hardware/constructor/daemon lifecycle remains unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', HB1-HB8, original source/fixups, source-produced RAM/BSS/FP/resource snapshot, independent event streams and API/flag/output/lock oracles, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':9,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
