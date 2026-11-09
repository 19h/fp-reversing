#!/usr/bin/env python3
"""Seal startup/table/consumer evidence and exactly six owned existing changes.
O(prior bytes+links+image bytes), O(manifest+largest JSON+image); no target effects.
"""
import ast,hashlib,json,re
from pathlib import Path
from kernel_vm_mig_tools import Image
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kext_provider_initialize'
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
GENS={P+'_source.json':'recover_'+P+'.py',P+'_profiles.json':'probe_'+P+'.py',P+'_checks.json':'validate_'+P+'.py',P+'_registration.json':'capture_'+P+'_registration.py'}
SCRIPTS=list(GENS.values())+['replay_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='b1f9f19b5f6c4b376dbbc2bbdd5f1d855e8098dfbe9d949a320bb77e63e1fcc1';m=json.loads(prior.read_text());assert len(m['files'])==5807;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==5801 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 for name,h in [('fairplayd.arm64e','4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'),('annotated-strace-rax-user.txt','78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e')]:assert sha(Path('/Users/___/Downloads/zut')/name)==h
 objs={n:json.loads((ROOT/n).read_text())for n in GENS}
 for name,script in GENS.items():
  obj=objs[name];assert obj['generator_sha256']==sha(ROOT/script)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(name,n)
  for n in ['native_target_executed','idb_mutated','full_goal_complete']:assert obj[n]is False
 src=objs[P+'_source.json'];prof=objs[P+'_profiles.json'];checks=objs[P+'_checks.json'];reg=objs[P+'_registration.json'];assert checks['all_checks_pass']and checks['source_recapture_match']
 expected={'cases':4,'ranges':9,'captured_instructions':10285,'views':2,'banks256':2,'proofs_unsat':1,'wrapper_returns_checked_by_oracle':5,'API_aligned_allocation_model':5,'API_typed_allocation_model':5,'API_lock_allocation_model':18,'API_data_allocation_model':5,'API_logger_no_effect_model':6,'API_calendar_time_model':2,'API_free_no_effect_model':12,'API_generic_allocation_model':4,'API_lock_model':3,'API_unlock_model':3,'distinct_lock_objects_checked':17,'complete_table_bytes_checked':1024,'table_before_ready_flag_cases':2,'cached_table_reuses_checked':1,'consumer_components':36,'consumer_aligned_offsets_checked':32};assert checks['verified_counts']==expected
 totals={'logical_PAC_steps_checked':100,'API_models_checked':63,'declared_model_memory_effects_checked':4,'declared_model_write_bytes_checked':24,'wrapper_returns_checked':5,'memory_preserving_call_transitions_checked':1,'final_boundaries_checked':4,'visits_fingerprint_events_checked':13741560,'reads_fingerprint_events_checked':2129058,'writes_fingerprint_events_checked':573153,'edges_fingerprint_events_checked':507592,'calls_fingerprint_events_checked':5415,'critical_effects_checked':326};assert checks['independent_A64_replay']==totals
 assert checks['consumer_A64_replay']=={'source_visits_checked':432,'reads_checked':144,'read_bytes_checked':1008,'final_boundaries_checked':36}and len(checks['consumer_profiles'])==36
 assert len(prof['cases'])==4 and sum(r['fingerprints']['visits']['count']for r in prof['cases'])==13741560 and sum(len(r['API_models'])for r in prof['cases'])==63
 for p in src['proofs']:assert p['result']=='unsat'and sha(ROOT/p['path'])==p['sha256']
 for key in ['native_IPC_executed','native_allocator_executed','native_lock_executed','native_clock_executed','native_provider_start_executed','continuous_native_constructor_established','hardware_PAC_executed']:assert checks[key]is False
 im=Image();assert reg['kernel_sha256']==im.k.sha256 and len(reg['nominal_vtable_slots'])==2
 for row in reg['nominal_vtable_slots']:
  p=row['pointer'];assert im.pointer(int(p['slot'],16))==p and p['target']=='0xfffffe000c4d8394'and p['auth']==1 and p['diversity']=='0x7d59'and p['address_diversity']==1 and im.k.symbols([int(p['target'],16)])[p['target']]==row['exact_symbols']
 caller=reg['caller'];assert im.k.read(int(caller['start'],16),int(caller['end'],16)-int(caller['start'],16)).hex()==caller['bytes_hex']
 for key in ['native_registration_executed','runtime_vptr_identity_established','hardware_PAC_executed']:assert reg[key]is False
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| PI'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in [P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':5807,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':8,'local_links_checked':links,'nominal_registration_slots_recaptured':2,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original cmam7f startup/cached/failure paths, source-produced table consumer and nominal provider registration binding. Native provider/constructor/daemon lifecycle remains unknown.','generator_sha256':sha(__file__),'verified_counts':expected,'independent_A64_replay':totals,'consumer_A64_replay':checks['consumer_A64_replay'],'nominal_registration_slots':2,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in GENS},'native_target_executed':False,'native_IPC_executed':False,'idb_mutated':False,'full_goal_complete':False,'goal_status':'active'}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', PI1-PI8, original source/fixups, independent event streams and critical-store/ownership/consumer oracles, u64 bound and prior preservation'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'links_checked':links,'registration_slots_recaptured':2,'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
