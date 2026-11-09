#!/usr/bin/env python3
"""RW source/model/candidate delivery readback; new identity/quality files only.

O(total prior/source bytes + links) time, bounded JSON/source space. No native
heap, lock, group accounting, provider, crypto or IDB operation.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
BASELINE_SHA='d6f07c6114f101265aa5ba0a5c2a6641b6291020c5520a9f2751d3f6c24ef440'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 path=ROOT/'rw_lifecycle_prior_manifest.json';assert sha(path)==BASELINE_SHA;old=read(path.name);c=read('rw_lifecycle_contracts.json');p=read('rw_lifecycle_profiles.json');proof=read('rw_lifecycle_proofs.json');checks=read('rw_lifecycle_checks.json');fresh=read('rw_lifecycle_replays.json');preserve=read('rw_lifecycle_preservation.json');sdk=read('rw_lifecycle_sdk_checks.json')
 for obj,name in[(c,'recover_rw_lifecycle.py'),(p,'probe_rw_lifecycle.py'),(proof,'prove_rw_lifecycle.py'),(checks,'validate_rw_lifecycle.py'),(preserve,'validate_rw_lifecycle_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,n
 assert checks['all_checks_pass']and preserve['all_checks_pass'];assert fresh['generator_sha256']==sha(ROOT/'validate_rw_lifecycle.py');assert sha(ROOT/'rw_lifecycle_replays.json')==checks['fresh_replays_sha256'];assert proof['contracts_sha256']==sha(ROOT/'rw_lifecycle_contracts.json')
 for q in proof['proofs']:assert sha(ROOT/q['file'])==q['sha256']and q['result']=='unsat'
 groups=['initialize_cases','free_validation_cases','API_prefixes','legacy_candidates'];assert all(fresh[n]==p[n]for n in groups);rows=[r for n in groups for r in fresh[n]];assert len(rows)==284 and all(not r['private_undefined_reads']and not r['native_API_executed']and not r['group_accounting_executed']and not r['heap_backend_executed']and not r['entry_reachability_proved']for r in rows)
 expected={'kext_functions':4,'kernel_functions':7,'original_spans':4,'exhaustive_banks':4,'bank_byte_inputs':1024,'native_API_bindings':2,'typed_sites':1,'original_constant_spans':3,'literal_modifier_candidates':11,'unresolved_modifier_candidates':8,'candidate_state_values':64,'proofs_unsat':4,'SDK_signatures':2,'source_byte_checks':31352,'fresh_initializer_cases':68,'initializer_visits':1224,'initializer_source_written_bytes':1088,'default_attribute_cases':4,'fresh_free_validation_cases':68,'free_validation_visits':1768,'free_header_source_written_bytes':544,'fresh_API_prefixes':12,'API_prefix_visits':54,'modeled_wrapper_returns':136,'fresh_allocation_candidates':128,'allocation_candidate_visits':4608,'fresh_cleanup_candidates':8,'cleanup_candidate_visits':184,'source_cleared_cell_bytes':64,'all_fresh_cases':284,'all_source_visits':7838};assert checks['verified_counts']==expected
 assert sdk['generator_sha256']==sha(ROOT/'validate_rw_lifecycle.py')and sdk['probe_sha256']==sha(ROOT/'rw_lifecycle_sdk_probe.cpp')and sdk['header_sha256']==sha(Path(sdk['header_path']))and sdk['assembly_sha256']==sha(ROOT/'rw_lifecycle_sdk_probe.s')and sdk['compile_exit']==0 and sdk['signatures_checked']==2 and not sdk['target_code_executed'];assert sha(ROOT/'rw_lifecycle_sdk_checks.json')==checks['SDK_checks_sha256']
 from kernel_native_reader import Kernel
 from kext_port_tools import SOURCE,IMAGE
 from recover_kext_aes_handoff import function
 from recover_kext_cold_init import pointer
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert sha(SOURCE)==c['source_sha256']==p['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f
 for b in c['bank_rules']:assert pointer(k,int(b['slot'],16))==b['original_pointer']
 syms=k.symbols([0xfffffe000c4bb6e4,0xfffffe000c4bb780,0xfffffe000bd06180,0xfffffe000bd062b8,0xfffffe000bcfefc8,0xfffffe000bd7a4b8,0xfffffe000bd03ad0,0xfffffe000cb52628])
 for a,name in[(0xfffffe000c4bb6e4,'_IORWLockAlloc'),(0xfffffe000c4bb780,'_IORWLockFree'),(0xfffffe000bd06180,'_lck_rw_alloc_init'),(0xfffffe000bd062b8,'_lck_rw_free')]:assert name in[r['name']for r in syms[hex(a)]]
 for a in[0xfffffe000bcfefc8,0xfffffe000bd7a4b8,0xfffffe000bd03ad0,0xfffffe000cb52628]:assert not syms[hex(a)]
 d=c['typed_site'];assert k.read(int(d['address'],16),64).hex()==d['bytes64_hex'];assert pointer(k,int(d['site_name_pointer']['slot'],16))==d['site_name_pointer'];assert d['site_name']=='site.lck_rw_old_t'and d['size_word_at44']==16
 identity={'scope':'Build-specific IO RW allocation/free source, old_t typed site, private initialization/free validation and unresolved producer candidates. Cached-cell publication/native lifetime remain unproved.','generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'fileset_uuid':e['uuid'],'kext_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['functions']],'kernel_functions':[{n:f[n]for n in['start','end','sha256']}for f in c['kernel_functions']],'exact_symbols':syms,'typed_site':d,'contracts_sha256':sha(ROOT/'rw_lifecycle_contracts.json'),'SDK_checks_sha256':sha(ROOT/'rw_lifecycle_sdk_checks.json'),'native_target_executed':False,'heap_backend_executed':False,'group_accounting_executed':False,'cached_cell_publication_proved':False,'native_lock_lifetime_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rw_lifecycle_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(old['files'])==1440 and len(allowed)==6 and preserve['unchanged_prior_artifacts']==1434
 for row in old['files']:assert sha(BASE/row['path'])==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
 for row in old['inputs_preserved']:
  path=BASE/row['path'];assert sha(path)==row['sha256']and path.stat().st_size==row['size_bytes']
 links=0
 for name in['rw_lifecycle_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'rw_lifecycle_quality_gates.json',(name,target);links+=1
 report=(BASE/'rw_lifecycle_report.md').read_text()
 for text in['RL9','QG7','284','7838','31352','site.lck_rw_old_t','unknown','1088','544','2648','0xfffffe000ccceab8','0xdddddead','old_t']:assert text in report,text
 evidence=['Factual technical analysis.','RL1-RL9 with dependent results and falsification probes.','RW allocation/free/layout/API/candidate interfaces covered; cached-cell publication and full objective remain unproved.','Fixed widths, byte epochs, typed-site/runtime capacity separation and finite complexity specified.','Modifier/callee identity, old_t/current SDK, file/runtime initialization and generic/cached publication separated.','Original code/metadata/chains/census, 284 fresh cases, four proofs and two SDK signatures.','Impact-labeled bounded continuation table.'];outputs=['rw_lifecycle_contracts.json','rw_lifecycle_profiles.json','rw_lifecycle_replays.json','rw_lifecycle_checks.json','rw_lifecycle_proofs.json','rw_lifecycle_sdk_checks.json','rw_lifecycle_preservation.json'];out={'scope':'RW source interfaces/private prefixes and bounded producer candidates; no native lifecycle, cached-cell publication, synchronization or IPC event proved.','generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':v}for i,v in enumerate(evidence,1)},'verified_counts':expected,'prior_artifacts_checked':1440,'unchanged_prior_artifacts':1434,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'rw_lifecycle_source_identity.json'),'native_target_executed':False,'heap_backend_executed':False,'group_accounting_executed':False,'cached_cell_publication_proved':False,'native_lock_lifetime_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rw_lifecycle_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_scoped_quality_gates_pass':True,'fresh_cases':284,'proofs_unsat':4,'prior_artifacts_checked':1440,'report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
