#!/usr/bin/env python3
"""Seal bounded caller census, conditional edges, result consumers and evidence.
O(pinned artifact bytes+reports) time,O(largest JSON) space. No native target.
"""
import hashlib,json,re
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,TABLE,FIXUPS,verify_original_fixups
from validate_daemon_iokit_callers_preservation import BASELINE_SHA,ALLOWED
BASE=ROOT.parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 old=read('daemon_iokit_callers_prior_manifest.json');assert sha(ROOT/'daemon_iokit_callers_prior_manifest.json')==BASELINE_SHA and len(old['files'])==2617
 c,check,proof,pre=map(read,['daemon_iokit_callers_contracts.json','daemon_iokit_callers_checks.json','daemon_iokit_callers_proofs.json','daemon_iokit_callers_preservation.json'])
 for obj,name in [(c,'recover_daemon_iokit_callers.py'),(check,'validate_daemon_iokit_callers.py'),(proof,'prove_daemon_iokit_callers.py'),(pre,'validate_daemon_iokit_callers_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert not c['upstream_context_producers_proved']and not check['upstream_context_producers_proved']and check['all_checks_pass']and pre['all_checks_pass'];counts=check['verified_counts']
 expected={'exact_literal_candidates':23,'original_bounded_spans':25,'exhaustive_bank_rules':2,'bank_inputs_checked':512,'original_fixups_verified':86,'same_discriminator_distinct_target_slots':4,'caller_continuation_routes_verified':4,'live_IDB_source_rows_matched':92,'live_IDB_instruction_bytes_matched':416,'live_xref_inputs_preserved':4,'source_proof_pairs_unsat':12,'independent_byte_reconstructed_cases':40,'caller_record_capture_epochs_checked':120,'composed_cases_audited':40,'source_visits':59356,'unknown_caller_result_cells_preserved_before_init':40,'callee_integer_ABI_returns':40,'embedded_original_callee_sequences':40,'fresh_replayed_cases':12,'metadata_error_cases_retaining_zero_result_gate':6}
 for name,v in expected.items():assert counts[name]==v,(name,counts[name],v)
 assert check['case_matrix']=={'313_zero_result':6,'313_nonzero_result':14,'AF_zero_result':6,'AF_nonzero_result':14}and sum(check['source_lift_counts'].values())==71 and check['source_lift_counts']==proof['source_lift_counts']and len(proof['proofs'])==12
 done=set()
 for row in proof['proofs']:
  assert row['result']=='unsat'and set(row['depends_on'])<=done;done.add(row['name']);assert sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 assert {r['name']:r['depends_on']for r in proof['proofs']if r['depends_on']}=={'caller313_unique_init_phase':['caller313_selector_decode'],'callerAF_unique_init_phase':['callerAF_selector_decode']}
 decoded=verify_original_fixups([int(r['address'],16)for r in c['original_fixup_records']['records']]);assert decoded==c['original_fixup_records'];by={r['address']:r for r in decoded['records']}
 for r in c['caller_continuation_routes']:
  a=TABLE+int(r['index'],16)*8;row=by[hex(a)];assert row['decoded_target']==r['target']and row['diversity']==r['modifier16']and row['key']=='IA'and row['address_diversity']==0 and FIXUPS[a]==r['fixup']
 row=by['0x1010a0520'];assert row['decoded_target']=='0x1004601d0'and row['diversity']=='0xa74'and row['key']=='IA'and row['address_diversity']==0
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert set(allowed)==ALLOWED and pre['prior_artifacts_checked']==2617 and pre['unchanged_prior_artifacts']==2611
 for row in old['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in old['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in ['daemon_iokit_callers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   p=Path(t.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p==ROOT/'daemon_iokit_callers_quality_gates.json',(name,t);links+=1
 report=(BASE/'daemon_iokit_callers_report.md').read_text()
 for term in ['CB12','QG7','unknown','40','71','92','416','23','21','12','0x1003134D4','0x100AFEDD4','0x1010A0520','0x8B3DC651','Mach']:assert term in report,term
 evidence=['Factual technical analysis.','CB1-CB12 include dependent results and falsification probes.','Bounded census,two conditional caller/consumer interfaces and metadata-result separation covered;full goal remains active.','8-byte record,u32/u64 arithmetic,alignment,source normal forms,unique preimages and complexity explicit.','Root premises/producers,literal/target,record/W0,zero result/query status,local fragment/semantic owner and native limits distinguished.','40 epoch audits,12 fresh replays,12 proof pairs,86 fixups,two exhaustive banks,92 IDB rows and preserved xrefs.','Impact-labeled bounded continuation table.'];outputs=['daemon_iokit_callers_contracts.json','daemon_iokit_callers_profiles.json','daemon_iokit_callers_checks.json','daemon_iokit_callers_proofs.json','daemon_iokit_callers_live_ida.json','daemon_iokit_callers_live_xrefs.json','daemon_iokit_callers_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':counts,'source_lift_counts':check['source_lift_counts'],'case_matrix':check['case_matrix'],'conditional_caller_banks':c['bank_rules'],'caller_continuation_routes':c['caller_continuation_routes'],'context_root_premises':c['context_root_premises'],'upstream_context_producers_proved':False,'prior_artifacts_checked':2617,'unchanged_prior_artifacts':2611,'inputs_preserved':old['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_callers_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'verified_counts':counts,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
