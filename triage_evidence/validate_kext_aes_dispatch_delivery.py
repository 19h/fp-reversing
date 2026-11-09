#!/usr/bin/env python3
"""Final dispatch/context/record source, dependency and preservation readback.

Writes only new identity/quality records. O(total source/prior artifact bytes
and links) time with bounded JSON/source space; no native API/IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='6be17444f536186da49185d6a95c9f54982c85cec07098d96fc2aedf7819ebe2'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 oldpath=ROOT/'kext_aes_dispatch_prior_manifest.json';assert sha(oldpath)==BASELINE_SHA;old=read(oldpath.name);checks=read('kext_aes_dispatch_checks.json');preserve=read('kext_aes_dispatch_preservation.json');c=read('kext_aes_dispatch_contracts.json');profiles=read('kext_aes_dispatch_profiles.json');leaf=read('kext_record_classifier_profiles.json');proofs=read('kext_aes_dispatch_proofs.json');fresh=read('kext_aes_dispatch_replays.json');lfresh=read('kext_record_classifier_replays.json')
 for obj,name in[(checks,'validate_kext_aes_dispatch.py'),(preserve,'validate_kext_aes_dispatch_preservation.py'),(c,'recover_kext_aes_dispatch.py'),(profiles,'probe_kext_aes_dispatch.py'),(leaf,'probe_kext_record_classifier.py'),(proofs,'prove_kext_aes_dispatch.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==lfresh['generator_sha256']==sha(ROOT/'validate_kext_aes_dispatch.py');assert fresh['cases']==profiles['cases']and len(fresh['cases'])==11264 and lfresh['cases']==leaf['cases']and len(lfresh['cases'])==32;assert sha(ROOT/'kext_aes_dispatch_replays.json')==checks['fresh_dispatch_replays_sha256']and sha(ROOT/'kext_record_classifier_replays.json')==checks['fresh_classifier_replays_sha256'];assert proofs['contracts_sha256']==sha(ROOT/'kext_aes_dispatch_contracts.json')
 for e in proofs['proofs']:assert sha(ROOT/e['file'])==e['sha256']and e['result']=='unsat'
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_cold_init import pointer
 from resolve_kernel_collection_interfaces import macho
 k=Kernel();assert sha(SOURCE)==checks['source_sha256']==c['source_sha256']==profiles['source_sha256']==leaf['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==checks['kernel_collection_sha256']==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';km=macho(SOURCE.read_bytes(),0,'original normalized kext')
 for ctx in c['contexts']:
  a,z=int(ctx['compiler_start'],16),int(ctx['compiler_end'],16);raw=k.read(a,z-a);assert raw==IMAGE.read(a,z-a)and hashlib.sha256(raw).hexdigest()==ctx['compiler_source_sha256']
 for site in c['sites']:assert pointer(k,int(site['choice']['slot'],16))==site['original_slot']and not site['entry_reachability_proved']
 thin=Path('/Users/___/Downloads/zut/fairplayd.arm64e');univ=Path('/Users/___/Downloads/fpx/fairplayd');raw=thin.read_bytes();fat=univ.read_bytes();assert sha(thin)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'and sha(univ)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and fat[3407872:3407872+len(raw)]==raw
 identity={'scope':'Original source/compiler-context/bank/slot and daemon file readback;no native frame/receiver/path attestation.','generator_sha256':sha(Path(__file__)),'kext_sha256':sha(SOURCE),'kext_uuid':km['uuid'],'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'compiler_function_starts_count':c['compiler_function_starts_count'],'conditional_call_mappings':[{'call_pc':s['call_pc'],'target':s['choice']['target'],'original_slot':s['original_slot'],'native_reachability_proved':False}for s in c['sites']],'cleanup_record':c['cleanup_record'],'daemon_thin_sha256':sha(thin),'daemon_universal_sha256':sha(univ),'daemon_arm64e_slice_offset':3407872,'exact_daemon_slice_equal':True,'new_live_IDB_ranges':0,'whole_IDB_integrity_verified':False,'native_target_executed':False,'authentication_executed':False,'all_native_dispatch_contexts_proved':False,'full_goal_complete':False};(ROOT/'kext_aes_dispatch_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={e['path']:e for e in preserve['allowed_existing_changes']};assert len(old['files'])==1260 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1254
 for e in old['files']:assert sha(BASE/e['path'])==(allowed[e['path']]['current_sha256']if e['path']in allowed else e['sha256']),e['path']
 for e in old['inputs_preserved']:assert sha(BASE/e['path'])==e['sha256']and(BASE/e['path']).stat().st_size==e['size_bytes']
 links=0
 for name in['kext_aes_dispatch_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'kext_aes_dispatch_quality_gates.json',(name,target);links+=1
 counts=checks['verified_counts'];expected={'source_spans':14,'source_span_bytes':9716,'compiler_envelopes':8,'compiler_envelope_bytes':168692,'literal_stack_store_overlaps':33,'indexed_SP_store_sites':0,'bank_families':5,'bank_source_bytes':2560,'literal_pointer_lineages':18,'base_bank_rules':8,'base_byte_inputs':2048,'site_bank_rules':11,'site_byte_inputs':2816,'context_mapped_sites':11,'modifier_ed6d_sites':6,'modifier_d939_sites':5,'distinct_target_addresses':8,'record_codec_source_facts':13,'target_role_functions':2,'classifier_source_facts':7,'dispatcher_source_facts':9,'proofs_unsat':6,'fresh_dispatch_runs':11264,'fresh_dispatch_source_visits':158720,'fresh_data_read_events':57344,'fresh_stack_write_events':1024,'source_target_pointer_reads':11264,'fresh_classifier_runs':32,'fresh_classifier_source_visits':992,'classifier_default_markers':24,'classifier_special_markers':8};assert counts==expected
 report=(BASE/'kext_aes_dispatch_report.md').read_text()
 for phrase in['R8','QG7','conditional source-context mappings','0xfffffe000a6080ac','0xfffffe000a62259c','0xfffffe000a5a962c','0xfffffe000a6674d0','11264','0x0253b9f6','preservation across aliases/callees','business meaning']:assert phrase in report,phrase
 for site in c['sites']:assert site['call_pc']in report and site['choice']['slot']in report
 evidence=['Factual technical analysis.','R1-R8 with dependencies and falsification probes.','Conditional target mappings,partial cleanup record and two obfuscated roles;native contexts/full goal incomplete.','Exact word/byte widths,source visits,exhaustive byte domains and bounded complexity.','Frame definitions versus reaching state,constant versus payload-controlled selectors,local versus native execution,and marker versus business meaning separated.','Original compiler envelopes/bytes/slots,lineages/store census,11264 fresh slices,32 classifier cases and six local proofs.','Impact-labeled bounded continuation table.'];outputs=['kext_aes_dispatch_checks.json','kext_aes_dispatch_contracts.json','kext_aes_dispatch_profiles.json','kext_aes_dispatch_replays.json','kext_record_classifier_profiles.json','kext_record_classifier_replays.json','kext_aes_dispatch_proofs.json','kext_aes_dispatch_preservation.json']
 out={'scope':'Conditional source-frame dispatch and local record contracts;actual reaching/native state remains unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':counts,'prior_artifacts_checked':1260,'unchanged_prior_artifacts':1254,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'kext_aes_dispatch_source_identity.json'),'native_target_executed':False,'authentication_executed':False,'all_native_dispatch_contexts_proved':False,'native_cleanup_reachability_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'kext_aes_dispatch_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_dispatch_runs':11264,'fresh_classifier_runs':32,'proofs_unsat':6,'prior_artifacts_checked':1260,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
