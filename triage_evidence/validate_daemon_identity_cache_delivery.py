#!/usr/bin/env python3
"""Seal identity UTF-8/SHA-1-prefix evidence, preserving explicit native gaps.
O(owned artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_identity_cache_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and not r['full_goal_complete']
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_identity_cache_contracts.json','recover_daemon_identity_cache.py'),('daemon_identity_cache_context.json','capture_daemon_identity_cache.py'),('daemon_identity_cache_proofs.json','prove_daemon_identity_cache.py'),('daemon_identity_cache_profiles.json','probe_daemon_identity_cache.py'),('daemon_identity_cache_checks.json','validate_daemon_identity_cache.py'),('daemon_identity_cache_preservation.json','validate_daemon_identity_cache_preservation.py')];c,ctx,p,r,k,keep=[checked(n,g)for n,g in pairs];assert k['all_checks_pass']and keep['all_checks_pass'];v=k['verified_counts']
 expected={'restored_parent_contexts':96,'parent_visits_reconstructed':33120,'parent_effects_reconstructed':8832,'original_source_spans':14,'distinct_original_opcodes':1250,'original_fixups':63,'live_IDB_ranges':10,'live_IDB_bytes':1404,'exhaustive_bank_inputs':256,'rebuilt_source_obligations_unsat':12,'SMT_files_unsat_and_formula_matched':24,'source_lift_visits':86,'identity_format_models_checked':768,'UTF16_length_models_checked':672,'maximum_size_models_checked':672,'allocation_models_checked':672,'complete_source_zero_fills_checked':576,'source_zero_fill_bytes_checked':111744,'CString_models_checked':576,'byte_length_models_checked':480,'free_requests_checked':96,'CFRelease_requests_checked':1920,'API_models_checked':5856,'ordered_source_reads_checked':336672,'ordered_source_writes_checked':157824,'SHA1_context_initializations_checked':480,'shared_helper_calls_checked':288,'SHA1_short_padding_blocks_checked':288,'SHA1_first_input_blocks_checked':192,'SP3050_frontiers_checked':288,'undefined_frame_frontiers_checked':768,'persisted_A64_cases':768,'freshly_recomputed_A64_cases':768,'source_visits_checked':4034496,'cache_owner_bytes_defined':0};assert v==expected,(v,expected)
 assert len(p['proofs'])==12 and len(list(ROOT.glob('daemon_identity_cache_*.smt2')))==24 and not c['new_port_emission_established']and not c['cache_content_or_completed_digest_established']and c['SDK_compile']['exit_code']==0
 for name,h in c['SDK_compile']['header_hashes'].items():assert sha(Path(name))==h
 assert len(ctx['contexts'])==96 and len(r['cases'])==768 and len(k['SHA1_prefix_certificates'])==480
 assert sha(ROOT/'daemon_identity_cache_prior_manifest.json')==BASELINE_SHA;old=read('daemon_identity_cache_prior_manifest.json');changed={x['path']:x for x in keep['allowed_existing_changes']};assert len(old['files'])==3880 and keep['unchanged_prior_artifacts']==3874 and set(changed)==ALLOWED
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 reports=['daemon_identity_cache_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_identity_cache_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text();assert report.isascii()
 for term in ['IC14','QG7','4,034,496','33,120','SP+3050','SP+2E50','SP+2C8C','F4F92DF7','UTF-16','UTF-8','36-byte','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 scripts=list(ROOT.glob('*daemon_identity_cache*.py'));assert len(scripts)==7
 for f in scripts:ast.parse(f.read_text(),filename=str(f))
 evidence=['Factual original-source and ABI analysis.','IC1-IC14 record source,frame,opaque-object,conversion,owner,ABI,state,PAC and scope premises with probes.','UTF-8/count/context/input/padding/failure cleanup and unresolved frame producers covered; full interface objective remains active.','UTF-16 code units,UTF-8 bytes,capacity bytes,digest bits,u32/u64 expressions and SDK declarations explicit.','Short helper and long direct-compression paths separated; no completed digest,cache content,native caller or transport claim.','Original source/fixups,12 rebuilt proof pairs,96 reconstructed parents,768 fresh cases,byte ledgers,480 context/block checks,1404 IDB bytes and SDK types checked.','Impact-bounded compression-root,cache-consumer,caller,library,lifetime,state and transport questions retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'source_sha256':sha(source),'source_lift_counts':p['source_lift_counts'],'prior_artifacts_checked':3880,'unchanged_prior_artifacts':3874,'checked_report_links':links,'new_python_files_syntax_checked':len(scripts),'inputs_preserved':old['inputs_preserved'],'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_identity_cache_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'proof_pairs':12,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
