#!/usr/bin/env python3
"""Source-only append/serialization identity, preservation and scoped gates.

O(total pinned bytes + links) time, O(largest JSON/source) space. No native
target/API/crypto/heap/lock operation or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='610f889d51abee1fa7d85c80b4b206df22ffa43209b83bd214eab2250bc9770d'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'legacy_tlv_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);assert len(old['files'])==1507;c=read('legacy_tlv_contracts.json');p=read('legacy_tlv_profiles.json');proof=read('legacy_tlv_proofs.json');checks=read('legacy_tlv_checks.json');fresh=read('legacy_tlv_replays.json');preserve=read('legacy_tlv_preservation.json')
 for obj,name in[(c,'recover_legacy_tlv.py'),(p,'probe_legacy_tlv.py'),(proof,'prove_legacy_tlv.py'),(checks,'validate_legacy_tlv.py'),(fresh,'validate_legacy_tlv.py'),(preserve,'validate_legacy_tlv_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'legacy_tlv_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases'];assert proof['dependencies']['legacy_tlv_contracts.json']==sha(ROOT/'legacy_tlv_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 expected={'compiler_envelopes':10,'kernel_functions':1,'source_spans':15,'exhaustive_banks':22,'bank_byte_inputs':5632,'dispatch_slots':8,'additional_bindings':3,'source_derived_proofs_unsat':6,'fresh_cases':312,'source_visits':246972,'source_byte_checks':987888,'source_write_epochs':14904,'read_epochs':36984,'fully_reconstructed_cases':312,'source_staged_payload_bytes':2496,'source_status_pairs':312,'rejection_cases':120,'null_carrier_cases':12,'null_buffer_cases':12,'bad_header_cases':36,'entry_full_cases':24,'byte_full_cases':36,'append_cases':192,'source_written_packet_bytes':2304,'original_copy_bytes':1536};assert checks['verified_counts']==expected;assert checks['source_lift_counts']==proof['source_lift_counts']=={'tag_instructions':42,'payload_instructions':152,'header_instructions':86,'counter_instructions':5}
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 from recover_carrier_control import span
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 stub=next(s for s in c['spans']if s['label']=='copy_stub');assert stub['compiler_start']is None and stub['compiler_end']is None and stub['compiler_bounds_available']is False
 for b in c['bank_rules']:assert pointer(k,int(b['slot'],16))==b['original_pointer']
 for b in c['dispatch_slots']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer']
 assert pointer(k,int(c['copy_binding']['slot'],16))==c['copy_binding'];syms=k.symbols([int(a,16)for a in c['exact_symbols']]);assert syms==c['exact_symbols'];assert set(r['name']for r in syms['0xfffffe000c647f10'])=={'_memcpy','_memmove'};assert '_zzLw2eOVu9pOHqpiNw1K4ki'in[r['name']for r in syms['0xfffffe000a50c2b0']]
 rows=fresh['cases'];assert len(rows)==312 and all(not r['native_API_executed']and not r['API_effect_models_used']and not r['models']and r['inner_record_operations_executed']and r['inner_record_operation_executed_in_private_guest']and not r['native_reachability_proved']and not r['undefined_private_value_reads']for r in rows)
 identity={'scope':'Named wrapper/context-specific selector-0x224 12-byte append, admission, source memory statuses, shared fragments and original kernel copy binding.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'compiler_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'kernel_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['kernel_functions']],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':syms,'copy_binding':c['copy_binding'],'carrier_partial_layout':c['carrier_partial_layout'],'contracts_sha256':sha(ROOT/'legacy_tlv_contracts.json'),'API_effect_models_used':False,'native_target_executed':False,'native_carrier_validity_proved':False,'external_TLV_emission_proved':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'legacy_tlv_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1501
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['legacy_tlv_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'legacy_tlv_quality_gates.json',(name,target);links+=1
 report=(BASE/'legacy_tlv_report.md').read_text()
 for term in['LT9','QG7','312','246972','987888','2304','1536','2496','285','0xfffffe000ccceab8','unknown','160','four-byte','ten-byte','0xffff5966','0x5e561849','0x5e5571af','285','5632']:assert term in report,term
 evidence=['Factual technical source/interface analysis.','LT1-LT9 define assumptions, dependencies and falsification probes.','Current source-only append/admission/format/copy/status context covered; native validity/IPC/cached publication and broad objective remain incomplete.','Fixed widths, byte epochs, offsets, source/copy counts, timeouts and bounded complexity specified.','Fixed wrapper/generic entry, private/native, safe fixture/wrapping arithmetic and four-/ten-byte formats separated.','Primary source/symbols/chains, 312 fresh source compositions, 22 exhaustive banks and six source-derived original/normalized proof pairs.','Impact-labeled bounded continuation table.'];outputs=['legacy_tlv_contracts.json','legacy_tlv_profiles.json','legacy_tlv_replays.json','legacy_tlv_checks.json','legacy_tlv_proofs.json','legacy_tlv_preservation.json'];out={'scope':'Context-specific source-only private TLV-shaped append; native carrier validity, external emission/consumer linkage and cached-lock publication remain unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'source_lift_counts':checks['source_lift_counts'],'prior_artifacts_checked':1507,'unchanged_prior_artifacts':1501,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'legacy_tlv_source_identity.json'),'API_effect_models_used':False,'native_target_executed':False,'native_carrier_validity_proved':False,'external_TLV_emission_proved':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'legacy_tlv_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'source_only_cases':312,'proofs_unsat':6,'prior_artifacts_checked':1507,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
