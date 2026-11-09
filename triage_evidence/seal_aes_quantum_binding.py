#!/usr/bin/env python3
"""Seal original public-to-quantum job/binding/range and transfer-consumer ABI evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='aes_quantum_binding'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='d4c0c07a947436cf1dd23d0b2c7b04a5847411899d93aba562c24e0d5c70b9de';m=json.loads(prior.read_text());assert len(m['files'])==5940;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5934 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected=checks['verified_counts'];totals=checks['independent_A64_replay'];assert expected=={'source_object_transfers_checked': 13, 'source_global_snapshots_preserved': 13, 'device_configuration_and_emitter_bodies_unexecuted_cases_checked': 13, 'API_descriptor_prepare_model': 14, 'API_descriptor_physical_address_model': 14, 'API_close_gate_no_effect_model': 22, 'API_on_thread_model': 22, 'API_open_gate_no_effect_model': 15, 'API_DMA_bind_no_effect_model': 12, 'API_descriptor_operation_no_effect_model': 12, 'same_job_binding_cache_range_handoffs_checked': 6, 'ignored_bind_and_cache_status_register_cases_checked': 1, 'API_declared_configuration_error_no_effect_model': 1, 'API_DMA_clear_no_effect_model': 2, 'conditional_configuration_error_cleanup_order_checked': 1, 'disabled_state_device_boundary_checked': 1, 'declared_segment_record_effects_checked': 21, 'API_declared_segment_record_model': 9, 'unsigned_segment_minimum_consumer_cases_checked': 3, 'empty_transfer_guard_checked': 1, 'segment_error_assertion_frontiers_checked': 2, 'cases': 13, 'functions': 61, 'captured_instructions': 5892, 'additional_slots': 4}
 assert len(prof['cases'])==13 and sum(len(r['source_visits'])for r in prof['cases'])==6226 and sum(len(r['API_models'])for r in prof['cases'])==123
 assert totals=={'source_visits_checked': 6226, 'logical_authentication_steps_checked': 351, 'writes_checked': 1146, 'write_bytes_checked': 8955, 'reads_checked': 1432, 'read_bytes_checked': 10978, 'logical_indirect_edges_checked': 202, 'declared_API_models_checked': 123, 'outer_pool_frames_checked': 7, 'logical_return_steps_checked': 50, 'outer_pool_action_statuses_checked': 7, 'action_frames_checked': 7, 'quantum_calls_checked': 7, 'inner_pool_frames_checked': 8, 'enable_calls_checked': 8, 'binding_calls_checked': 12, 'cache_operation_calls_checked': 12, 'configuration_calls_checked': 6, 'final_boundaries_checked': 13, 'final_objects_checked': 1950, 'final_source_globals_checked': 26, 'clear_calls_checked': 2, 'effect_frontiers_checked': 7, 'transfer_calls_checked': 6, 'segment_calls_checked': 9, 'declared_model_memory_effects_checked': 21, 'declared_model_write_bytes_checked': 196}
 for obj in [src,prof,checks]:
  for key in ['native_DMA_or_cache_effects_executed','native_device_or_crypto_executed','runtime_candidate_identity_established','hardware_PAC_executed','native_IPC_executed']:assert obj[key]is False
 im=Image();assert src['kernel_sha256']==im.k.sha256
 for s in src['additional_slots']:
  p=s['pointer'];assert im.pointer(int(p['slot'],16))==p and im.k.symbols([int(p['target'],16)])[p['target']]==s['exact_symbols']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| QB'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5940,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'exact_slots_recaptured':4,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original public-to-quantum carrier/job binding, descriptor range operations, conditional configuration-error cleanup and separate segment-record consumers. Enabled state, API/record outcomes and locks/PAC remain explicit premises. Native activation, configuration, mapper/cache/device effects and constructor/daemon continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_IPC_executed':False,'native_hardware_AES_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', QB1-QB8, original source/fixups, same carrier/job identities, descriptor-role/range/cleanup and segment-minimum oracles, independent A64 read/write/branch replay and preserved globals, prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'exact_slots_recaptured':4,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
