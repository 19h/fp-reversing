#!/usr/bin/env python3
"""Final carrier ABI delivery readback; writes only new identity/quality files.

O(total baseline/source bytes + report links) time; bounded JSON/source space.
No native target, crypto, provider or IDB action.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='444f98e76a7fc72292ecd1c7a09b2a87e3e3426c92de4dd3ea7276b926890276'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 prior=ROOT/'carrier_control_prior_manifest.json';assert sha(prior)==BASELINE_SHA;old=read(prior.name);c=read('carrier_control_contracts.json');p=read('carrier_control_profiles.json');proof=read('carrier_control_proofs.json');checks=read('carrier_control_checks.json');fresh=read('carrier_control_replays.json');preserve=read('carrier_control_preservation.json')
 for obj,name in[(c,'recover_carrier_control.py'),(p,'probe_carrier_control.py'),(proof,'prove_carrier_control.py'),(checks,'validate_carrier_control.py'),(preserve,'validate_carrier_control_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_carrier_control.py')and fresh['cases']==p['cases'];assert sha(ROOT/'carrier_control_replays.json')==checks['fresh_replays_sha256'];assert proof['contracts_sha256']==sha(ROOT/'carrier_control_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and q['result']=='unsat'
 expected={'original_functions':4,'original_spans':10,'exhaustive_banks':6,'bank_byte_inputs':1536,'pool_bindings':8,'parent_instructions':72913,'literal_SP_pivots':8,'associated_C_excerpts':2,'proofs_unsat':4,'fresh_cases':192,'source_visits':22422,'cases_reset':24,'reset_written_bytes':4560,'preserved_gap_bytes':432,'carrier_bytes_checked':19968,'cases_heap_controls_11':24,'producer_control_written_bytes':720,'cases_stack_controls_01':24,'cases_preparer_operation_zero':24,'cases_preparer_kind_zero':24,'cases_preparer_kind_three':24,'cases_wrapper_reset_prefix':24,'cases_preparer_entry':24,'decoded_selector_cases':24};assert checks['verified_counts']==expected and len(fresh['cases'])==192
 assert all(not r['undefined_private_reads']and not r['native_API_executed']and not r['crypto_operation_executed']and not r['entry_reachability_proved']for r in fresh['cases']);assert not c['all_reaching_operation_bytes_boolean_proved']
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 for b in c['bank_rules']:assert pointer(k,int(b['slot'],16))==b['original_pointer']
 for b in c['pool_bindings']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer']
 for b in c['associated_C']:assert sha(Path(b['path']))==b['sha256']
 identity={'scope':'Source-pinned reset, common preparer, local producer controls and conditional frames. Native carrier domain, pointer reachability, struct size and enum semantics unknown.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'contracts_sha256':sha(ROOT/'carrier_control_contracts.json'),'native_target_executed':False,'crypto_operation_executed':False,'idb_mutated':False,'all_reaching_operation_bytes_boolean_proved':False,'full_goal_complete':False};(ROOT/'carrier_control_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(old['files'])==1390 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1384
 for row in old['files']:
  path=BASE/row['path'];assert sha(path)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['carrier_control_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'carrier_control_quality_gates.json',(name,target);links+=1
 report=(BASE/'carrier_control_report.md').read_text()
 for phrase in['CC8','QG7','192','22422','95 bytes','104 bytes','unknown','0xe10934e57abbf985','0xff8','0x568','predecessors','72913','1/1','0/1']:assert phrase in report,phrase
 evidence=['Factual technical analysis.','CC1-CC8 with dependencies and falsification probes.','Reset/common preparer/local producers/partial record and conditional frame contracts covered; broad goal remains active.','Byte footprints, fixed-width codec, frame arithmetic, finite cases and complexity specified.','Local controls versus global domain, reset extent versus sizeof, SP pivots versus fixed frames and values versus enum meaning separated.','Original functions/spans/chains/C, six exhaustive banks, four local proofs and 192 fresh cases.','Impact-labeled bounded continuation table.'];outputs=['carrier_control_contracts.json','carrier_control_profiles.json','carrier_control_replays.json','carrier_control_checks.json','carrier_control_proofs.json','carrier_control_preservation.json'];out={'scope':'Carrier source contracts only; no native IPC, accepted operation, key semantics, provider behavior or complete global first-byte domain.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'prior_artifacts_checked':1390,'unchanged_prior_artifacts':1384,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'carrier_control_source_identity.json'),'native_target_executed':False,'crypto_operation_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'carrier_control_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':192,'proofs_unsat':4,'prior_artifacts_checked':1390,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
