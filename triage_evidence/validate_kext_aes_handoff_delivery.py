#!/usr/bin/env python3
"""Final handoff source/producer/replay/preservation/report readback.

Writes only new identity/quality records. O(total source/prior artifact bytes
and links) time, bounded source/JSON space. No native API or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='b4fd588a6ea50d10cf8a16e0af2745a19e8f1d2b37ec4f88c436fad246a76400'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(name):return json.loads((ROOT/name).read_text())
def main():
 oldpath=ROOT/'kext_aes_handoff_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('kext_aes_handoff_checks.json');preserve=read('kext_aes_handoff_preservation.json');c=read('kext_aes_handoff_contracts.json');profiles=read('kext_aes_handoff_profiles.json');proofs=read('kext_aes_handoff_proofs.json');fresh=read('kext_aes_handoff_replays.json')
 for obj,producer in[(checks,'validate_kext_aes_handoff.py'),(preserve,'validate_kext_aes_handoff_preservation.py'),(c,'recover_kext_aes_handoff.py'),(profiles,'probe_kext_aes_handoff.py'),(proofs,'prove_kext_aes_handoff.py')]:
  assert obj['generator_sha256']==sha(ROOT/producer)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_kext_aes_handoff.py')and fresh['cases']==profiles['cases']and len(fresh['cases'])==85;assert sha(ROOT/'kext_aes_handoff_replays.json')==checks['fresh_replays_sha256'];assert proofs['contracts_sha256']==sha(ROOT/'kext_aes_handoff_contracts.json')
 for e in proofs['proofs']:assert sha(ROOT/e['file'])==e['sha256']and e['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE,CS
 from recover_kext_aes_handoff import function
 from resolve_kernel_collection_interfaces import macho
 k=Kernel();assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==profiles['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';km=macho(SOURCE.read_bytes(),0,'original normalized kext');entries={e['name']:e for e in k.entries}
 for r in c['functions']:assert function(k,entries[r['entry']],int(r['start'],16))==r
 for r in c['kernel_functions']:assert k.function(int(r['start'],16))==r
 for row in c['reference_scan']['ed6d_call_modifier_candidates']:
  ins=list(CS.disasm(IMAGE.read(int(row['pc'],16),8),int(row['pc'],16)));assert[(v.mnemonic,v.op_str)for v in ins]==[('mov','x17, #0xed6d'),('blraa','x8, x17')]
 sdk=c['SDK_probe'];assert sha(ROOT/sdk['assembly_path'])==sdk['assembly_sha256']and sdk['compile_exit']==0
 for e in sdk['primary_headers']:assert sha(Path(e['path']))==e['sha256']
 caller=c['one_resolved_cleanup_caller'];assert caller['resolved_target']=='0xfffffe000a5085e0'and c['one_cleanup_caller_resolved']and not c['all_cleanup_callers_resolved'];cp=Path(caller['associated_C_excerpt']['path']);assert sha(cp)==caller['associated_C_excerpt']['sha256'];assert not caller['native_reachability_proved']
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e');univ=Path('/Users/___/Downloads/fpx/fairplayd');raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(univ)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and fat[3407872:3407872+len(raw)]==raw
 identity={'scope':'Fresh original kext/KC/fileset/compiler-bound/ABI/cleanup-caller and daemon file identity;no native provider/IDB attestation.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kext_uuid':km['uuid'],'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'fileset_function_counts':c['fileset_function_counts'],'exact_definitions':c['exact_definitions'],'nominal_slots':c['nominal_slots'],'associated_decompilation_sha256':sha(cp),'one_resolved_cleanup_caller':caller['cleanup_call'],'cleanup_target':caller['resolved_target'],'all_cleanup_callers_resolved':False,'native_cleanup_reachability_proved':False,'daemon_thin_sha256':sha(thin),'daemon_universal_sha256':sha(univ),'daemon_arm64e_slice_offset':3407872,'exact_daemon_slice_equal':True,'new_live_IDB_ranges':0,'whole_IDB_integrity_verified':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_aes_handoff_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1239 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1233
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['kext_aes_handoff_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'kext_aes_handoff_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];expected={'fileset_functions':13,'matching_kext_functions':6,'kernel_functions':4,'exact_named_slots':14,'nominal_slots':15,'unnamed_buffer_targets':1,'direct_text_refs':1,'direct_text_scan_words':422089,'raw_pointer_candidates':4,'metadata_word_matches':5,'modifier_candidate_sites':6,'unresolved_modifier_sites':5,'same_diversity_table_targets':4,'cleanup_caller_bank_identities':3,'cleanup_caller_byte_inputs':768,'cleanup_caller_source_facts':17,'resolved_cleanup_call_sites':1,'provider_handoff_source_facts':14,'completion_source_facts':9,'queue_source_facts':5,'SDK_compile_exit':0,'SDK_primary_headers':2,'proofs_unsat':3,'fresh_runs':85,'fresh_source_visits':6643,'zero_returns':40,'inplace_descriptor_records':64,'provider_stack_source_bytes':1920,'provider_call_records':80,'local_log_requests':41,'minus22_returns':40,'nonzero_X0_zero_W0_cases':16,'separate_descriptor_records':16,'temporary_descriptor_requests':36,'prepare_requests':28,'copyout_requests':24,'complete_requests':24,'release_requests':32,'minus40_returns':5};assert counts==expected
 report=(BASE/'kext_aes_handoff_report.md').read_text()
 for phrase in['H9','QG7','eight register arguments and three stack arguments','0xfffffe000a6227b4','0xfffffe000c51fe7c','no exact symbol','SDK-correlated','1920','Five candidate sites remain unresolved']:assert phrase in report,phrase
 for e in c['nominal_slots']:
  if e['kind']in['command_pool','command_gate']:assert e['target']in report
 evidence=['Factual technical analysis.','H1-H9 with dependent results and falsification probes.','Complete wrapper ABI,partial command/completion,one cleanup caller and bounded remaining references;native behavior/full goal incomplete.','Explicit register/stack widths,word arithmetic,source epochs,counts and bounded complexity.','Model/native effects,nominal/actual receivers,exact/SDK-correlated methods,one resolved/five unresolved sites and local/native reachability separated.','Original compiler catalogs/bytes/symbols/chains,85 fresh cases,three local proofs,three exhaustive banks and compile-only SDK check.','Impact-labeled bounded continuation table.'];outputs=['kext_aes_handoff_checks.json','kext_aes_handoff_contracts.json','kext_aes_handoff_profiles.json','kext_aes_handoff_replays.json','kext_aes_handoff_proofs.json','kext_aes_handoff_preservation.json']
 out={'scope':'Wrapper/provider ABI,partial command/completion and one cleanup caller;native provider execution/accepted operations unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1239,'unchanged_prior_artifacts':1233,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'kext_aes_handoff_source_identity.json'),'one_cleanup_caller_resolved':True,'all_cleanup_callers_resolved':False,'native_cleanup_reachability_proved':False,'native_target_executed':False,'provider_implementation_executed':False,'key_data_contents_recovered':False,'accepted_operation_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kext_aes_handoff_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_runs':85,'provider_call_records':80,'proofs_unsat':3,'resolved_cleanup_call_sites':1,'prior_artifacts_checked':1239,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
