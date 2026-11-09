#!/usr/bin/env python3
"""Seal the scoped self-text window increment with explicit unavailable-IDB status.
O(artifact bytes+report links) time, O(largest JSON+manifest) space; no target runs.
"""
import json,re
from pathlib import Path
from validate_daemon_global_state_preservation import ROOT,BASE,BASELINE_SHA,ALLOWED,sha
EXPECTED={'unavailable_IDA_probes':2,'original_source_spans':14,'original_fixups_verified':2,'bank_inputs_checked':512,'nonempty_premise_witnesses':3,'source_proof_pairs_unsat':16,'SMT_queries_unsat':32,'sealed_full_continuations_checked':8,'source_window_block_visits_checked':3288,'sealed_publication_values_checked':32,'distinct_observed_offsets':8,'full_source_observation_checkpoints':22,'cases':1434,'source_visits':589374,'source_read_events':27246,'source_write_events':5736,'distinct_size_inputs':207,'current_image_offsets':32,'upper_word_variants_per_offset':2,'containment_applicable_cases':1329,'outside_containment_domain_cases':105,'fresh_isolated_A64_cases':1}
def read(n):return json.loads((ROOT/n).read_text())
def check(n,g):
 q=read(n);assert q['generator_sha256']==sha(ROOT/g)and not q['full_goal_complete']
 for dep,h in q.get('dependencies',{}).items():assert sha(ROOT/dep)==h,(n,dep)
 return q
def main():
 pairs=[('daemon_global_state_contracts.json','recover_daemon_global_state.py'),('daemon_global_state_observations.json','probe_daemon_global_state.py'),('daemon_global_state_proofs.json','prove_daemon_global_state.py'),('daemon_global_state_replays.json','replay_daemon_global_state.py'),('daemon_global_state_checks.json','validate_daemon_global_state.py'),('daemon_global_state_preservation.json','validate_daemon_global_state_preservation.py')]
 c,observed,proofs,replays,k,p=[check(n,g)for n,g in pairs];assert k['verified_counts']==EXPECTED and k['all_checks_pass']and p['all_checks_pass']and replays['all_checks_pass']
 assert not c['live_IDB_available']and not k['live_IDB_verification_available']and c['live_IDB_rows_matched']==0
 for n in ['daemon_global_state_live_ida.json','daemon_global_state_ida_retry.json']:assert read(n)['isError']
 for proof in proofs['proofs']:assert proof['result']=='unsat'and sha(ROOT/proof['original_file'])==proof['original_sha256']and sha(ROOT/proof['file'])==proof['sha256']
 assert len(proofs['proofs'])==16 and len(proofs['nonempty_premise_witnesses'])==3 and sum(proofs['source_lift_counts'].values())==385
 assert c['text_section']['address']=='0x100001058'and c['text_section']['size_bytes']==14849960 and c['current_image_window']['offset_mask']=='0xe21000'and c['current_image_window']['possible_offset_count']==32
 source=Path('/Users/___/Downloads/zut/fairplayd.arm64e');assert sha(source)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha(ROOT/'daemon_global_state_prior_manifest.json')==BASELINE_SHA;old=read('daemon_global_state_prior_manifest.json');changes={r['path']:r for r in p['allowed_existing_changes']};assert set(changes)==ALLOWED and len(old['files'])==3134 and p['unchanged_prior_artifacts']==3128
 for row in old['files']:assert sha(BASE/row['path'])==(changes[row['path']]['current_sha256']if row['path']in changes else row['sha256']),row['path']
 for row in old['inputs_preserved']:path=BASE/row['path'];assert path.stat().st_size==row['size_bytes']and sha(path)==row['sha256']
 links=0
 for name in ['daemon_global_state_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   path=Path(target.split('#',1)[0]);path=path if path.is_absolute()else BASE/path;assert path.exists()or path==ROOT/'daemon_global_state_quality_gates.json',(name,target);links+=1
 report=(BASE/'daemon_global_state_report.md').read_text()
 for term in ['GS14','QG7','__TEXT,__text','14,849,960','0x100001058','0xE297A8','0x1003F19DC','0x1003F19F8','0x1003F1850','0x1003F18F8','0xE21000','0x7F8000','0x100E2A058','1,960','32,768','1,434','1,329','105','1,960','385','411','unknown','Fresh IDB verification is unavailable','full investigation remains active']:assert term in report,term
 evidence=['Factual technical analysis.','GS1-GS14 retain assumptions, dependencies and falsification probes.','Self-section provenance, complete window formula, four codecs, finite offsets and publication reconciliation covered; full objective active.','u64 wrapping/masked shifts, bytes,32768-byte window,4096-byte relative grid,16-byte theorem margin and current1960-byte margin explicit.','Temporal roles, small-size arithmetic, containment applicability, unrestricted-Q/native distribution and unavailable-IDB/source scope distinguished.','Original image/header,14 source spans,2 fixups,512 bank inputs,16 proof pairs,8 sealed continuations and1434 isolated cases; fresh IDB verification unavailable.','Impact-labeled bounded continuation table.']
 outputs=[n for n,g in pairs]+['daemon_global_state_live_ida.json','daemon_global_state_ida_retry.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{i}':{'status':'pass_for_increment'if i==3 else'pass','evidence':e}for i,e in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':proofs['source_lift_counts'],'source_sha256':sha(source),'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'prior_artifacts_checked':3134,'unchanged_prior_artifacts':3128,'checked_report_links':links,'inputs_preserved':old['inputs_preserved'],'live_IDB_verification_available':False,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_global_state_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'source_proof_pairs':16,'isolated_A64_cases':1434,'checked_links':links,'live_IDB_verification_available':False,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
