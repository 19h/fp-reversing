#!/usr/bin/env python3
"""Seal original constructor/RPC request queue evidence and six reporting changes.
O(prior bytes+source bytes+links), O(manifest+image+largest JSON). No target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kernel_request_receive'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py']);GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py'};SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='2fba86f2eed615d72c05ed939562336de7be68d6f24e2c6dfa0e9e3623b5b68c';m=json.loads(prior.read_text());assert len(m['files'])==6317;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6311 and{e['path']for e in changed}==CHANGED
 for e in m['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 for name,h in[('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for n,script in GENS.items():
  o=objs[n];assert o['generator_sha256']==sha(ROOT/script)
  for name,h in o['dependencies'].items():assert sha(ROOT/name)==h
  for key in['native_target_executed','native_VM_effects_executed','native_IPC_executed','native_retirement_executed','native_namespace_conversion_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']:assert o[key]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];assert checks['all_checks_pass']and checks['source_recapture_match'];counts=checks['verified_counts'];totals=checks['independent_A64_replay'];assert counts['functions']==123 and counts['captured_instructions']==15666 and counts['loan_producers']==4 and counts['receiver_cases']==10 and counts['accepted_cases']==8 and counts['capacity_guard_cases']==2 and counts['bounded_scalar_proofs_unsat']==2 and counts['all_original_instruction_visits_recaptured']==17816 and counts['source_original_request_reply_right_namespace_publication_checked']==8
 assert totals['source_visits_checked']==17816 and totals['whole_final_RAM_bytes_checked']==14680064 and totals['declared_API_models_checked']==32 and totals['continuous_receiver_full_CPU_RAM_handoffs_checked']==26 and totals['final_boundaries_checked']==14 and checks['fresh_request_producer_replays']['source_visits_checked']==25786
 assert len(prof['loans'])==4 and len(prof['cases'])==10 and sum(r['boundary']['kind']=='before_original_request_descriptor_copyout'for r in prof['cases'])==8 and sum(r['boundary']['kind']=='before_original_receive_results_with_queue_preserved'for r in prof['cases'])==2
 im=Image();assert im.k.sha256==src['kernel_sha256']
 for f in src['functions']:a=int(f['start'],16);assert im.k.read(a,int(f['end'],16)-a).hex()==f['bytes']
 for e in src['request_receive_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 for e in src['rpc_zone_entries']:assert im.k.read(int(e['entry_address'],16),24).hex()==e['entry_bytes24_hex']and im.k.read(int(e['specification_address'],16),48).hex()==e['specification_bytes48_hex']
 assert len(checks['proofs'])==2 and all(e['result']=='unsat'for e in checks['proofs'])
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RQ'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6317,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':7,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Exact queued constructor state, original receiver loan constructor, original receive frontend/encoded right lookup/fast dequeue/results/header namespace publication and minimum/extended/short capacities. Receiver call/task/map/SMR/namespace epochs, thread-loan publication, inherited producer contracts, keyed hashes, raw retirement and logical PAC remain explicit. Native registration, scheduler, VM descriptor backing, user copyout, daemon delivery and authentic round trip remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'independent_A64_replay':totals,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in list(GENS)+SCRIPTS},'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', RQ1-RQ8, source recapture, independent ordered fixture/import before images, complete object/packet/accounting oracles, twenty-six continuous receiver full CPU/RAM handoffs, fourteen fresh CPU component replays and two scalar proofs'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
