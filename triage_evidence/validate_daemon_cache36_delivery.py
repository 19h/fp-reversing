#!/usr/bin/env python3
"""Seal the hardware-property/formatting increment with explicit native limits.
O(owned artifact bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_cache36_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and not r['full_goal_complete']
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_cache36_contracts.json','recover_daemon_cache36.py'),('daemon_cache36_context.json','capture_daemon_cache36.py'),('daemon_cache36_proofs.json','prove_daemon_cache36.py'),('daemon_cache36_profiles.json','probe_daemon_cache36.py'),('daemon_cache36_checks.json','validate_daemon_cache36.py'),('daemon_cache36_preservation.json','validate_daemon_cache36_preservation.py')];c,ctx,p,r,k,keep=[checked(n,g)for n,g in pairs];assert k['all_checks_pass']and keep['all_checks_pass'];v=k['verified_counts']
 expected={'restored_parent_contexts':24,'parent_source_visits_reconstructed':1804820,'parent_effects_reconstructed':427656,'original_source_spans':12,'distinct_original_opcodes':707,'original_fixups':52,'live_IDB_ranges':12,'live_IDB_bytes':1279,'MobileGestalt_key_hashes_recomputed':4,'rebuilt_source_obligations_unsat':11,'SMT_files_unsat_and_formula_matched':22,'source_lift_visits':78,'declared_nonnull_allocations':432,'API_models_checked':3744,'ordered_source_reads_checked':43152,'ordered_source_writes_checked':7536,'MobileGestalt_models_checked':1440,'release_requests_checked':1440,'cache_publication_order_certificates':432,'undefined_frame_frontiers_checked':336,'persisted_A64_cases':432,'source_visits_checked':205008,'cache_owner_bytes_defined':0,'freshly_recomputed_A64_cases':432,'CFNumber_models_checked':240,'chip_format_models_checked':192,'identity_five_vararg_frontiers_checked':96};assert v==expected,(v,expected)
 assert len(p['proofs'])==11 and len(list(ROOT.glob('daemon_cache36_*.smt2')))==22 and not c['new_port_emission_established']and not c['cache_content_or_identity_digest_established']and c['SDK_compile']['exit_code']==0
 assert sha(ROOT/'daemon_cache36_sdk.s')==c['SDK_compile']['assembly_sha256'];assert len(ctx['contexts'])==24 and len(r['cases'])==432
 assert sha(ROOT/'daemon_cache36_prior_manifest.json')==BASELINE_SHA;old=read('daemon_cache36_prior_manifest.json');changed={x['path']:x for x in keep['allowed_existing_changes']};assert len(old['files'])==3835 and keep['unchanged_prior_artifacts']==3829 and set(changed)==ALLOWED
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 reports=['daemon_cache36_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_cache36_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text();assert report.isascii()
 for term in ['C36-13','QG7','205,008','1,804,820','SP+3050','SerialNumber','UniqueChipID','%@%@%@%@%@','36-byte','unknown','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 scripts=list(ROOT.glob('*daemon_cache36*.py'));assert len(scripts)==7
 for f in scripts:ast.parse(f.read_text(),filename=str(f))
 evidence=['Factual original-source and ABI analysis.','C36-1 through C36-13 record source,frame,library,property-name,owner,ABI,PAC and scope premises with falsification probes.','Hardware-property,conversion,formatting,allocation/publication and current frontiers covered; full interface objective remains active.','u32/u64 modular equations,36-byte owner,8-byte signed output,Boolean width and Apple ARM64 variadic stack contract verified.','Cache contents,SP3050 continuity,native object types,concurrency and IPC remain explicitly unknown.','Original bytes/fixups,11 rebuilt proof pairs,24 reconstructed contexts,432 fresh cases,byte ledgers,1279 IDB bytes and SDK assembly checked.','Impact-bounded cache-consumer,caller,library-version,synchronization and transport continuation questions retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'source_sha256':sha(source),'source_lift_counts':p['source_lift_counts'],'prior_artifacts_checked':3835,'unchanged_prior_artifacts':3829,'checked_report_links':links,'new_python_files_syntax_checked':len(scripts),'inputs_preserved':old['inputs_preserved'],'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_cache36_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'proof_pairs':11,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
