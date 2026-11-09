#!/usr/bin/env python3
"""Seal selected error/normalizer/return/source/byte/proof/preservation evidence.
O(pinned artifact bytes+reports) time,O(largest JSON) space. No native target.
"""
import hashlib,json,re
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,TABLE,FIXUPS,IMAGE,verify_original_fixups
from validate_daemon_iokit_errors_preservation import BASELINE_SHA,ALLOWED
BASE=ROOT.parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 old=read('daemon_iokit_errors_prior_manifest.json');assert sha(ROOT/'daemon_iokit_errors_prior_manifest.json')==BASELINE_SHA and len(old['files'])==2543
 c,check,proof,pre=map(read,['daemon_iokit_errors_contracts.json','daemon_iokit_errors_checks.json','daemon_iokit_errors_proofs.json','daemon_iokit_errors_preservation.json'])
 for obj,name in [(c,'recover_daemon_iokit_errors.py'),(check,'validate_daemon_iokit_errors.py'),(proof,'prove_daemon_iokit_errors.py'),(pre,'validate_daemon_iokit_errors_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 counts=check['verified_counts'];assert check['all_checks_pass']and pre['all_checks_pass']
 expected={'original_source_spans':13,'exhaustive_bank_rules':4,'bank_inputs_checked':1024,'original_fixups_verified':85,'retained_prior_sources_verified':6,'live_IDB_source_rows_matched':579,'source_proof_pairs_unsat':29,'independent_byte_reconstructed_cases':972,'composed_cases_audited':224,'composed_source_visits':312977,'composed_fresh_replays':16,'outer_result_publications_and_ABI_returns':224,'prior_source_and_epoch_prefixes_retained':92,'prior_return_controls_retained':24,'former_error_frontiers_closed':68,'source_status_adapter_returns':200,'error_path_release_sequences_checked':200,'isolated_cases_audited':748,'isolated_source_visits':173368,'isolated_fresh_replays':16,'isolated_zero_status_not_native_reachable_claims':2}
 for name,v in expected.items():assert counts[name]==v,(name,counts[name],v)
 assert check['case_matrix']=={'service_open_error_returns':56,'matching_services_error_returns':76,'main_port_error_returns':68,'isolated_default':542,'isolated_positive':198,'isolated_passthrough':8}
 assert sum(check['source_lift_counts'].values())==440 and check['source_lift_counts']==proof['source_lift_counts'];assert len(proof['proofs'])==29
 assert {p['name']for p in proof['proofs']} >= {'composed_all_u32_status_formula','decoded_output_negative_interval','decoded_normalizer_idempotence'}
 for row in proof['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 routes=[];originals={r['address']:r for r in c['original_fixup_records']['records']}
 for index,target,div in [(0xb4f0,0x10011959c,0x6607),(0x952a,0x1001ddc64,0x6607),(0x94e0,0x1002cb160,0x6607),(0x6c14,0x100202e14,0x36bd),(0x6c4c,0x1000d44ac,0x36bd),(0x8201,0x10013b168,0x36bd),(0x1e29,0x10004e43c,0xf547),(0x3d3a,0x10003b414,0xf547),(0x1e25,0x10013b168,0xf547)]:
  a=TABLE+8*index;r=originals[hex(a)];assert r['decoded_target']==hex(target)and r['key']=='IA'and r['diversity']==hex(div)and r['address_diversity']==0 and r['authenticated']and FIXUPS[a]['target']==target;routes.append({'index':hex(index),'original_word_hex':IMAGE.read(a,8).hex(),**r})
 assert verify_original_fixups([int(r['address'],16)for r in routes])['records']==[{k:v for k,v in r.items()if k not in ['index','original_word_hex']}for r in sorted(routes,key=lambda x:int(x['address'],16))]
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert set(allowed)==ALLOWED and pre['prior_artifacts_checked']==2543 and pre['unchanged_prior_artifacts']==2537
 for row in old['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in old['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents']
 links=0
 for name in ['daemon_iokit_errors_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   p=Path(t.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'daemon_iokit_errors_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_iokit_errors_report.md').read_text()
 for term in ['DE12','QG7','unknown','224','748','68','972','29','440','579','7998','4294959199','0x100422A60','0x1010A1490','0x952A','idempotence','Mach']:assert term in report,term
 assert -42001-(-49998)+1==7998 and (1<<32)-99-7998==4294959199
 evidence=['Factual technical analysis.','DE1-DE12 include dependent results and falsification probes.','Three selected error continuations,all-u32 normalizer and returning cleanup covered;full objective remains active.','u32/u64,16-byte record,alignment,signed predicates,exact cardinalities and complexity explicit.','Nonzero caller versus isolated zero,source/native ownership,saved Open versus release status,and algebraic/semantic decoding distinguished.','972 independent epoch audits,32 fresh replays,29 proof pairs,85 fixups,579 IDB rows and six preserved leads.','Impact-labeled bounded continuation table.'];outputs=['daemon_iokit_errors_contracts.json','daemon_iokit_errors_profiles.json','daemon_iokit_errors_checks.json','daemon_iokit_errors_proofs.json','daemon_iokit_errors_live_ida.json','daemon_iokit_errors_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':check['source_lift_counts'],'case_matrix':check['case_matrix'],'status_dispatch_routes':routes,'normalizer_domain_cardinalities':{'positive':99,'passthrough':7998,'default':4294959199,'total_u32':4294967296},'prior_artifacts_checked':2543,'unchanged_prior_artifacts':2537,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'native_target_executed':False,'native_ownership_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_errors_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
