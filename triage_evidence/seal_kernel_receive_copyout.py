#!/usr/bin/env python3
"""Seal original receive frontend/ownership, loan return and user copyout/zeroing and six owned reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_receive_copyout'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='55f5a1758a2ddafcaeca29f5156a26e826b0428ac61d41eb46507b656ffdf85d';m=json.loads(prior.read_text());assert len(m['files'])==6265;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6259 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for n,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/n)==h
 objects={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objects[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  for k in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert obj[k]is False
 src=objects[P+'_source.json'];prof=objects[P+'_profiles.json'];checks=objects[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];expected=checks['verified_counts'];totals=checks['independent_A64_replay']
 assert expected['cases']==20 and expected['consumers']==4 and expected['finishes']==4 and expected['every_producer_original_instruction_recaptured']==4728 and expected['every_sender_original_instruction_recaptured']==5392 and expected['every_results_original_instruction_recaptured']==3594 and expected['bounded_scalar_proofs_unsat']==4 and expected['original_complete_kmsg_zeroing_before_raw_deallocation_checked']==3 and expected['original_file_zero_validation_guard_prefixes_checked']==1
 assert totals['source_visits_checked']==13714 and totals['whole_final_RAM_bytes_checked']==29360128 and totals['declared_API_models_checked']==36 and totals['independent_byte_copy_bytes_checked']==176 and totals['logical_authenticated_continuation_edges_checked']==4 and totals['independent_user_copyout_bytes_copied']==148
 assert len(prof['cases'])==20 and len(prof['consumers'])==4 and len(prof['finishes'])==4 and sum(len(r['source_visits'])for r in prof['cases']+prof['consumers']+prof['finishes'])==13714 and sum(len(r['API_models'])for r in prof['cases']+prof['consumers']+prof['finishes'])==36
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 oh=src['opaque_keyed_hash'];assert im.k.read(int(oh['start'],16),int(oh['end'],16)-int(oh['start'],16)).hex()==oh['bytes_hex']and len(oh['PACGA_sites'])==5
 for e in src['allocation_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['related_fixed_zone_specs']:assert im.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex']and im.pointer(int(e['name_pointer']['slot'],16))==e['name_pointer']
 for e in src['queue_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['waitq_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['enqueue_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['continuation_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['copyout_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 z=src['zone_validation_source'];assert z['bytes8_hex']=='0000000100010000'and z['whole_zone_epoch_transferred']is False
 for e in src['initialization_constants']:assert im.k.read(int(e['address'],16),len(bytes.fromhex(e['bytes_hex']))).hex()==e['bytes_hex']
 z=src['turnstile_zone_spec'];assert im.k.read(int(z['specification_address'],16),48).hex()==z['specification_bytes48_hex']and im.pointer(int(z['name_pointer']['slot'],16))==z['name_pointer']
 for e in src['waitq_control_file_bytes']:assert im.k.read(int(e['address'],16),len(bytes.fromhex(e['bytes_hex']))).hex()==e['bytes_hex']
 assert sha(src['SDK_message_definitions']['path'])==src['SDK_message_definitions']['sha256']
 assert len(checks['proofs'])==4 and all(e['result']=='unsat'for e in checks['proofs'])
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RX'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6265,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'copyout_instruction_roles_recaptured':len(src['copyout_instruction_roles']),'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original make-send-once/frontend lookup/retain, ordinary loan return and receive hold release, header/right conversion, user message/trailer packing, original zeroing and final result status. Namespace/owner/map/SMR epochs, eight transferred startup validation bytes, separate CPU/call contexts, fragment registers/stack/logical PAC, user-copy protection/hash/raw-free outcomes remain explicit. Native scheduling, user protection/retirement, complex descriptors and authentic FairPlay transport remain unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RX1-RX8, original complete bodies/role words, fresh no-senders/startup producers, independent frontend/ownership/loan/packing/zeroing plans and before images, complete records, exact sender/results memory joins, explicit fragment/stack ABI, source-derived user bytes, one file-zero guard, four scalar proofs and independent CPU/effect replay'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
