#!/usr/bin/env python3
"""Legacy stack/record source identity, preservation and scoped quality gates.

O(total pinned bytes + links) time, O(largest source/JSON) space. No native
target/API/crypto/heap/synchronization operation; no IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='9e67568ee4535cca357cc0dad45c530ec5e5e220c74e88865115e8907f7856cf'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 baseline=ROOT/'legacy_stack_prior_manifest.json';assert sha(baseline)==BASELINE_SHA;old=read(baseline.name);assert len(old['files'])==1481;c=read('legacy_stack_contracts.json');p=read('legacy_stack_profiles.json');proof=read('legacy_stack_proofs.json');checks=read('legacy_stack_checks.json');fresh=read('legacy_stack_replays.json');preserve=read('legacy_stack_preservation.json')
 for obj,name in[(c,'recover_legacy_stack.py'),(p,'probe_legacy_stack.py'),(proof,'prove_legacy_stack.py'),(checks,'validate_legacy_stack.py'),(fresh,'validate_legacy_stack.py'),(preserve,'validate_legacy_stack_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert sha(ROOT/'legacy_stack_replays.json')==checks['fresh_replays_sha256'];assert fresh['cases']==p['cases'];assert proof['contracts_sha256']==sha(ROOT/'legacy_stack_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and sha(ROOT/q['original_file'])==q['original_sha256']and q['result']=='unsat'
 expected={'original_functions':8,'exhaustive_banks':18,'bank_byte_inputs':4608,'original_bindings':10,'original_mutable_globals':6,'proofs_unsat':5,'fresh_cases':192,'source_visits':67968,'outer_record_source_bytes':8544,'source_byte_checks':271872,'source_write_epochs':5760,'read_epochs':14016,'modeled_written_bytes':1344,'record32_cases':48,'inner_record_source_bytes':1152,'affine_operand_observations':48,'forwarded_status_bytes':192,'W1_period_trace_pairs':12,'record64_cases':144,'original_probe_reads':144,'source_stack_displacements':144,'zero_displacement_returns':72,'relocated_read_stops':72};assert checks['verified_counts']==expected
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 for b in c['original_bindings']:assert pointer(k,int(b['slot'],16))==b
 for b in c['bank_rules']:assert pointer(k,int(b['slot'],16))==b['original_pointer']
 syms=k.symbols([int(a,16)for a in c['exact_symbols']]);assert syms==c['exact_symbols']
 for a,name in[(0xfffffe000a50c2b0,'_zzLw2eOVu9pOHqpiNw1K4ki'),(0xfffffe000a50e618,'_Vt05NUgPD3Xy28y1R3R'),(0xfffffe000a5a1cc4,'___chkstk_darwin'),(0xfffffe000a5a1ccc,'___chkstk_darwin_probe')]:assert name in[r['name']for r in syms[hex(a)]]
 for a in[0xfffffe000a52fd18,0xfffffe000a570cf4,0xfffffe000a55e8b0,0xfffffe000a561344]:assert not syms[hex(a)]
 assert[(r['call_PC'],r['resolved_target'])for r in c['reclassified_modifier_sites']]==[('0xfffffe000a50c4cc','0xfffffe000a52fd18'),('0xfffffe000a50e860','0xfffffe000a570cf4')];assert c['remaining_unresolved_modifier_candidates']==6
 rows=fresh['cases'];assert len(rows)==192 and all(not r['native_API_executed']and not r['inner_record_operations_executed']and not r['native_reachability_proved']and not r['undefined_private_value_reads']for r in rows);assert sum(r['boundary']['kind']=='before_relocated_output_read'for r in rows)==72
 identity={'scope':'Two named legacy outer wrappers, two unnamed record bridges, exact original stack-probe helpers and two unexecuted inner record targets.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'exact_symbols':syms,'reclassified_modifier_sites':c['reclassified_modifier_sites'],'remaining_unresolved_modifier_candidates':6,'contracts_sha256':sha(ROOT/'legacy_stack_contracts.json'),'native_target_executed':False,'relocated_frame_validity_proved':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'legacy_stack_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['unchanged_prior_artifacts']==1475
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['legacy_stack_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'legacy_stack_quality_gates.json',(name,target);links+=1
 report=(BASE/'legacy_stack_report.md').read_text()
 for term in['LS9','QG7','192','67968','271872','8544','1152','144','1048560','0xfffffe000ccceab8','unknown','52','22','six','0xfffffe000a50e874','0x442b0f63903f796e','___chkstk_darwin_probe']:assert term in report,term
 evidence=['Factual technical analysis.','LS1-LS9 state assumptions, dependent results and falsification probes.','Two candidate exclusions, local record/stack/status contracts and original probe covered; cached publication and broad objective remain unproved.','Fixed widths, byte provenance/epochs, displacement bounds, finite counts and complexity specified.','Modifier/target, affine intermediate/final operand, model/source outputs and zero/nonzero/private/native effects separated.','Primary bytes/exact symbols/chains, eighteen exhaustive banks, 192 fresh cases and five original/normalized local proof pairs.','Impact-labeled bounded continuation table.'];outputs=['legacy_stack_contracts.json','legacy_stack_profiles.json','legacy_stack_replays.json','legacy_stack_checks.json','legacy_stack_proofs.json','legacy_stack_preservation.json'];out={'scope':'Conditional original wrapper/bridge/probe contracts; inner operation semantics, relocated native frames and cached-lock publication remain unproved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'prior_artifacts_checked':1481,'unchanged_prior_artifacts':1475,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'legacy_stack_source_identity.json'),'native_target_executed':False,'inner_operations_executed':False,'relocated_frame_validity_proved':False,'cached_FairPlay_lock_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'legacy_stack_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':192,'proofs_unsat':5,'prior_artifacts_checked':1481,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
