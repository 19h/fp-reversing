#!/usr/bin/env python3
"""Seal original free-page gate, adaptive quotas, locks and source-produced refill joins and exactly six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_cache_gate'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='47ab0cf1b723e839887ab506283be534bb02c55fa44a8febacee3e86196edbe1';m=json.loads(prior.read_text());assert len(m['files'])==6200;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6194 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected['cases']==20 and expected['every_dynamic_original_instruction_recaptured']==7898 and expected['source_produced_gate_and_quota_consumed_without_overrides_checked']==3 and expected['bounded_scalar_proofs_unsat']==3 and expected['full_collection_instruction_words_scanned']==15490987 and expected['writer_join_complete_256byte_zero_check_coverage_checked']==2
 assert totals['source_visits_checked']==7898 and totals['whole_final_RAM_bytes_checked']==20971520 and totals['declared_API_models_checked']==9 and totals['gate_policy_and_allocation_frames_checked']==98 and totals['allocation_frames_checked']==12
 assert len(prof['cases'])==20 and sum(len(r['source_visits'])for r in prof['cases'])==7898 and sum(len(r['API_models'])for r in prof['cases'])==9
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 oh=src['opaque_keyed_hash'];assert im.k.read(int(oh['start'],16),int(oh['end'],16)-int(oh['start'],16)).hex()==oh['bytes_hex']and len(oh['PACGA_sites'])==5
 for e in src['allocation_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['zone_startup_entries']:
  assert im.k.read(int(e['entry_address'],16),24).hex()==e['entry_bytes24_hex']and im.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex']and im.pointer(int(e['callback_pointer']['slot'],16))==e['callback_pointer']and im.pointer(int(e['argument_pointer']['slot'],16))==e['argument_pointer']and im.pointer(int(e['name_pointer']['slot'],16))==e['name_pointer']
 for e in src['startup_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['refill_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['original_control_globals']:assert im.k.read(int(e['address'],16),len(e['bytes_hex'])//2).hex()==e['bytes_hex']
 assert len(src['gate_reference_scan']['resolved_syntactic_memory_references'])==12 and src['gate_reference_scan']['instruction_words']==15490987
 for e in src['counter_metadata']:
  assert im.k.read(int(e['record_address'],16),80).hex()==e['bytes80_hex']
  for key in ['argument','name','handler','format','description_pointer']:assert im.pointer(int(e['fields'][key]['slot'],16))==e['fields'][key]
 for e in src['gate_related_fixup_references']:assert im.pointer(int(e['pointer']['slot'],16))==e['pointer']
 assert src['resolved_kmsg_startup_specification']['static_fixed_slot_relationship_established']is True and src['resolved_kmsg_startup_specification']['native_runtime_identity_observed']is False
 assert len(checks['proofs'])==3 and all(e['result']=='unsat'for e in checks['proofs'])
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CG'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6200,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'gate_memory_sites_recaptured':12,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original PID-1-associated publication, unsigned free/reserved-page cache gate, adaptive zone quotas, uncontended lock/cursor ABI and three source-value constructor joins. Process/step/enqueue results and counter/registry/page epochs remain declared. Native invocation/scheduling/backing/retirement, contention, authentication and full FairPlay continuity remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CG1-CG8, original bodies/visited words, counter metadata/fixups/symbols and bounded collection scan, fresh startup replay, complete RAM/global transfer DAG and explicit new call ABIs/input plans, independent gate/quota/filter/ticket/nesting/zero-check oracles, source-produced hysteresis/constructor/fallback joins, scalar proofs and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
