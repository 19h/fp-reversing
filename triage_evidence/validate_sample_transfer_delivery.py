#!/usr/bin/env python3
"""Final transfer/provider ABI, source/model records and preservation readback.

Writes only new identity/quality records. O(total prior/source bytes + links)
time and bounded JSON/source space. No native target, provider or IDB action.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='291159eb093c2d2f0120c80c930afbf658ad50c476fe631dd8c7ad07b1e25000'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 oldpath=ROOT/'sample_transfer_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('sample_transfer_checks.json');preserve=read('sample_transfer_preservation.json');c=read('sample_transfer_contracts.json');p=read('sample_transfer_profiles.json');hp=read('sample_transfer_handoff_profiles.json');proof=read('sample_transfer_proofs.json');fresh=read('sample_transfer_replays.json')
 for obj,name in[(checks,'validate_sample_transfer.py'),(preserve,'validate_sample_transfer_preservation.py'),(c,'recover_sample_transfer.py'),(p,'probe_sample_transfer.py'),(hp,'probe_sample_transfer_handoff.py'),(proof,'prove_sample_transfer.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_sample_transfer.py')and fresh['transfer_cases']==p['cases']and fresh['handoff_cases']==hp['cases'];assert sha(ROOT/'sample_transfer_replays.json')==checks['fresh_replays_sha256'];assert proof['contracts_sha256']==sha(ROOT/'sample_transfer_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and q['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==p['source_sha256']==hp['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for f in c['functions']:assert function(k,entry,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];slot=c['nominal_provider_slot'];actual=pointer(k,int(slot['slot'],16));assert all(slot[n]==v for n,v in actual.items());assert slot['exact_symbols']==k.symbols([int(slot['target'],16)])[slot['target']]
 for b in c['bank_rules']:assert pointer(k,int(b['slot'],16))==b['original_pointer']
 counts=checks['verified_counts'];expected={'original_functions':7,'nominal_provider_bindings':1,'exhaustive_bank_rules':6,'bank_byte_inputs':1536,'source_instruction_facts':36,'proofs_unsat':8,'fresh_transfer_cases':201,'fresh_transfer_source_visits':205759,'metadata_read_models':219,'modeled_metadata_bytes':707,'metadata_upper_width_cases':33,'defined_global_bytes':205823,'error_return_cases':71,'multi_sample_prefix_cases':17,'metadata_caller_clobber_cases':6,'empty_return_cases':27,'modeled_sample_reads':178,'modeled_sample_bytes':207246,'tail_read_models':90,'source_xor_masks':88,'source_xor_bytes':1408,'bulk_read_models':88,'buffered_submission_boundaries':78,'operation_domain_difference_cases':16,'descriptor_submission_boundaries':25,'nonzero_direct_offset_cases':2,'fresh_composed_cases':103,'fresh_composed_source_visits':3031,'provider_stack_source_bytes':2472,'composed_IV_key_links':103};assert counts==expected
 assert len(fresh['transfer_cases'])==201 and len(fresh['handoff_cases'])==103 and len(proof['proofs'])==8;assert all(not r['undefined_private_reads']and not r['native_API_executed']for r in fresh['transfer_cases']);assert all(not r['provider_code_executed']and not r['crypto_operation_executed']and not r['provider_observation']['target_executed']for r in fresh['handoff_cases'])
 identity={'scope':'Original metadata/transfer functions, exact provider type and nominal call/stack readback. Native input/task/provider/descriptor validity and post-operation output remain unproved.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'fileset_uuid':entry['uuid'],'functions':[{n:r[n]for n in['start','end','sha256']}for r in c['functions']],'nominal_provider_slot':slot,'carrier_roles':c['carrier_roles'],'contracts_sha256':sha(ROOT/'sample_transfer_contracts.json'),'new_live_IDB_ranges':0,'native_target_executed':False,'provider_code_executed':False,'crypto_operation_executed':False,'native_provider_class_proved':False,'private_key_data_layout_proved':False,'full_goal_complete':False};(ROOT/'sample_transfer_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(old['files'])==1364 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1358
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 links=0
 for name in['sample_transfer_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   pth=Path(target.split('#',1)[0]);pth=pth if pth.is_absolute()else BASE/pth;assert pth.exists()or pth==ROOT/'sample_transfer_quality_gates.json',(name,target);links+=1
 report=(BASE/'sample_transfer_report.md').read_text()
 for phrase in['ST8','QG7','304','2472','8192','81920','IOAESIV','IOAESKeyData','nonwrapping','unknown','255','predecessors']:assert phrase in report,phrase
 evidence=['Factual technical analysis.','ST1-ST8 with dependent results and falsification probes.','Metadata, buffered/direct prefixes, counters, pointer/operation roles and pre-provider composition covered; full goal active.','Exact byte extents, u32/u64 geometry, nonwrapping domains, model/source epochs and bounded complexity.','Argument equality/native behavior, raw/aligned/mask counters, nominal/runtime class and pre/post operation separated.','Original functions, exact provider type/slot, six exhaustive banks, eight local proofs and 304 fresh cases.','Impact-labeled bounded continuation table.'];outputs=['sample_transfer_checks.json','sample_transfer_contracts.json','sample_transfer_profiles.json','sample_transfer_handoff_profiles.json','sample_transfer_replays.json','sample_transfer_proofs.json','sample_transfer_preservation.json']
 out={'scope':'Sample metadata/data prefixes and pre-provider ABI only; no native provider, crypto operation, accepted request or post-operation output proved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1364,'unchanged_prior_artifacts':1358,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'sample_transfer_source_identity.json'),'native_target_executed':False,'provider_code_executed':False,'crypto_operation_executed':False,'native_provider_class_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'sample_transfer_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':304,'proofs_unsat':8,'prior_artifacts_checked':1364,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
