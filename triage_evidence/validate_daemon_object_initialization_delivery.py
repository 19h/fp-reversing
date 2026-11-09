#!/usr/bin/env python3
"""Seal initialization source, finite byte/PRNG evidence and bounded reporting.
O(owned artifact bytes+report links) time; O(largest artifact+manifest) space.
"""
import ast,json,re
from pathlib import Path
from validate_daemon_object_initialization_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
def read(n):return json.loads((ROOT/n).read_text())
def checked(n,g):
 r=read(n);assert r['generator_sha256']==sha(ROOT/g)and r['full_goal_complete']is False
 for dep,h in r.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return r
def main():
 pairs=[('daemon_object_initialization_contracts.json','recover_daemon_object_initialization.py'),('daemon_object_initialization_context.json','capture_daemon_object_initialization.py'),('daemon_object_initialization_proofs.json','prove_daemon_object_initialization.py'),('daemon_object_initialization_profiles.json','probe_daemon_object_initialization.py'),('daemon_object_initialization_checks.json','validate_daemon_object_initialization.py'),('daemon_object_initialization_preservation.json','validate_daemon_object_initialization_preservation.py')];c,ctx,p,r,k,keep=[checked(n,g)for n,g in pairs];assert k['all_checks_pass']and keep['all_checks_pass'];v=k['verified_counts']
 assert len(ctx['source_frame_fields'])==24 and len(ctx['coherent_provider_snapshots'])==4
 assert len(p['proofs'])==22 and len(list(ROOT.glob('daemon_object_initialization_*.smt2')))==44
 assert v['SMT_files_unsat_and_formula_matched']==44 and v['rebuilt_source_obligations_unsat']==22 and v['source_lift_visits']==278 and v['persisted_private_A64_cases']==4 and v['fresh_complete_private_A64_cases']==1 and v['compact_scratch_bytes_matched']==192 and v['nonzero_sampler_bytes']==2412 and v['object_field_effects_checked']==846 and v['imported_data_reads_checked']==24 and v['live_IDB_raw_bytes']==1152
 assert c['new_port_emission_established']is False and c['native_AEE_caller']==c['native_registry_publication']=='unknown';assert len(r['cases'])==4 and [x['boundary']['pc']for x in r['cases']]==['0x100bad4c8']*3+['0x100daba8c']
 assert sha(ROOT/'daemon_object_initialization_prior_manifest.json')==BASELINE_SHA;old=read('daemon_object_initialization_prior_manifest.json');changed={x['path']:x for x in keep['allowed_existing_changes']};assert len(old['files'])==3704 and keep['unchanged_prior_artifacts']==3698 and set(changed)==ALLOWED and len(ALLOWED)==6
 for row in old['files']:assert sha(BASE/row['path'])==(changed[row['path']]['current_sha256']if row['path']in changed else row['sha256']),row['path']
 for row in old['inputs_preserved']:f=BASE/row['path'];assert f.stat().st_size==row['size_bytes']and sha(f)==row['sha256']
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 reports=['daemon_object_initialization_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md'];links=0
 for name in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   f=Path(raw.split('#',1)[0]);f=f if f.is_absolute()else BASE/f;assert f.exists()or f==ROOT/'daemon_object_initialization_quality_gates.json',(name,raw);links+=1
 report=(BASE/reports[0]).read_text()
 for term in ['OI12','QG7','587','0x100BD7204','0x100BAD4C8','0xFF590BE3C05A7786','unknown','1,152','full daemon/kext/deeper-interface investigation remains active']:assert term in report,term
 assert f"{v['source_visits_checked']:,}"in report
 syntax=0
 for f in ROOT.glob('*daemon_object_initialization*.py'):ast.parse(f.read_text(),filename=str(f));syntax+=1
 assert syntax==8
 evidence=['Factual code,data-flow,port-data and ABI analysis.','OI1-OI12 register source,frame,cursor,provider snapshots,relocation,API/PAC,finite sampling,field identity and coverage premises with falsification probes.','Allocation initialization,cache-derived48 bytes,field stores,import data,587-byte sample,PRNG clone and external frontier covered; full interface goal remains active.','u32/u64 widths,byte order,48/512/587/872/2496-byte extents,source counts,modular arithmetic and complexity explicit.','Classifier+CC is reached in three cases;the NULL buffer case stops before a source byte store;imported port data does not imply emission; native publication and type unknown.','Original bytes/fixups,22 rebuilt proof pairs,independent compact mixer and full finite twist/readback checks,one freshly recomputed full case and1152 IDB bytes verified.','Impact-bounded actual caller,time continuation,object publication,buffer ownership and PRNG synchronization leads retained.']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':v,'independent_A64_totals':k['independent_A64_totals'],'source_lift_counts':p['source_lift_counts'],'new_validation_outputs':{n:sha(ROOT/n)for n,g in pairs},'report_sha256':{n:sha(BASE/n)for n in reports},'source_sha256':sha(source),'prior_artifacts_checked':3704,'unchanged_prior_artifacts':3698,'checked_report_links':links,'new_python_files_syntax_checked':syntax,'live_IDB_outputs':{'daemon_object_initialization_ida_bytes.json':sha(ROOT/'daemon_object_initialization_ida_bytes.json')},'inputs_preserved':old['inputs_preserved'],'new_port_emission_established':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_initialization_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'proof_pairs':22,'checked_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
