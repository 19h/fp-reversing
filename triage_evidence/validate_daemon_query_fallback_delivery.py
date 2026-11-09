#!/usr/bin/env python3
"""Seal fallback ABI/threshold/source/byte/proof/preservation evidence.

O(pinned bytes+I+256R+reports) time,O(largest JSON) space plus30 s/query.
No native target/API/Mach execution or IDB/memory mutation.
"""
import hashlib,json,re
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from recover_daemon_iokit_census import native
from daemon_query_fallback_symbolic import queries
BASE=ROOT.parent;BASELINE='65c5456ea700733b569573d54901f214b6e806e98a2caa99ddcaa8eb7f986f2b'
EXPECTED={'original_source_spans':9,'exhaustive_bank_rules':2,'bank_inputs_checked':512,'original_fixups_verified':33,'direct_dispatch_slots_verified':10,'retained_prior_sources_verified':4,'live_IDB_source_rows_matched':162,'source_proof_pairs_unsat':16,'source_instruction_byte_checks':1297984,'source_write_epochs':16172,'source_read_epochs':56600,'source_capacity_resets':1128,'API_write_epochs':1808,'independent_byte_reconstructed_cases':564,'source_controller_update_checks':1128,'record_preservation_checks':564,'exact_preceding_prefixes':264,'fresh_cases':564,'original_instruction_visits':324496,'normal_returns_before_unknown_iterator':564,'final_encoded_cache_checks':564,'API_models_retained':1128,'nonzero_capabilities_skip_fallback':32,'completed_zero_capability_fallbacks':532,'record_result_publications':532,'caller_result_alias_checks':532,'fallback_controller_store_checks':1064,'version_qualified_capability_bit_stores':156,'low_version_byte_independence_pairs':150}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'daemon_query_fallback_prior_manifest.json')==BASELINE;baseline=read('daemon_query_fallback_prior_manifest.json');assert len(baseline['files'])==2340
 c,check,proof,pre=map(read,['daemon_query_fallback_contracts.json','daemon_query_fallback_checks.json','daemon_query_fallback_proofs.json','daemon_query_fallback_preservation.json'])
 for obj,name in[(c,'recover_daemon_query_fallback.py'),(check,'validate_daemon_query_fallback.py'),(proof,'prove_daemon_query_fallback.py'),(pre,'validate_daemon_query_fallback_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert check['all_checks_pass']and check['verified_counts']==EXPECTED and pre['all_checks_pass']and sha(ROOT/'daemon_query_fallback_replays.json')==check['fresh_replays_sha256']
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex']
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records']
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup']
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents']
 live=read('daemon_query_fallback_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']and not live['native_target_executed'];nr=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;nr+=1
 assert nr==len(c['live_IDB_source_rows_matched'])==162
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==16 and lifts==proof['source_lift_counts']==check['source_lift_counts']and sum(lifts.values())==138
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=read('daemon_query_fallback_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_daemon_query_fallback.py')and fresh['dependencies']==check['dependencies']and len(fresh['cases'])==564;frontiers=[]
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['full_goal_complete']and r['helper_returned']and r['boundary']['pc']=='0x100483ca8'
  frontiers.append({'input':r['input'],'frame_SP':r['frame_SP'],'boundary':r['boundary'],'state_cache':r['state_cache'],'fallback_access_record':r['fallback_access_record'],'fallback_returned':r['fallback_returned']})
 del fresh
 assert check['fallback_marker_counts']=={'0x3a9c01d9':376,'0x3a9c01da':4,'0x3a9c01db':152}and len(check['decision_edge_counts'])==9
 # Frozen predecessor proof establishes the encoded input record used by the
 # callee-control theorem. Pin it explicitly as well as through preservation.
 prior=read('daemon_query_state_proofs.json');assert len(prior['proofs'])==11 and prior['dependencies']['daemon_query_state_symbolic.py']==sha(ROOT/'daemon_query_state_symbolic.py')
 for row in prior['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert len(allowed)==6 and pre['prior_artifacts_checked']==2340 and pre['unchanged_prior_artifacts']==2334
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in['daemon_query_fallback_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'daemon_query_fallback_source_identity.json',ROOT/'daemon_query_fallback_quality_gates.json'],(name,target);links+=1
 assert links>940;report=(BASE/'daemon_query_fallback_report.md').read_text()
 for term in['QF12','QG7','unknown','564','324496','2340','2334','16','138','532','162','0x2E1E','0x10043BD18','0x100483CA8','0x3A9C01DA','0xC49697F8','Mach']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'current_IDB_node':'6b117c693e3b','live_source_rows_matched':162,'source_spans':c['spans'],'bank_rules':c['bank_rules'],'original_fixup_records':c['original_fixup_records'],'premises':c['premises'],'retained_prior_source_hashes':{r['path']:r['sha256']for r in c['retained_prior_sources']},'preceding_input_pack_proof_sha256':sha(ROOT/'daemon_query_state_proofs.json'),'frontier_cases':frontiers,'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','QF1-QF12 list dependent results and falsification probes.','Selected fallback/result ABI,threshold,cache effects and return covered; full objective remains active.','Exact B/u32/u64 widths,unsigned predicates,modular formulas,counts and reproduction.','16B input/20B accessed record,marker/status and native/private/prior evidence distinguished.','564 fresh byte/algebra audits,16 source proof pairs,33 original fixups,two exhaustive banks and162 live IDB rows.','Impact-labeled bounded continuation table.'];outputs=['daemon_query_fallback_contracts.json','daemon_query_fallback_profiles.json','daemon_query_fallback_replays.json','daemon_query_fallback_checks.json','daemon_query_fallback_proofs.json','daemon_query_fallback_live_ida.json','daemon_query_fallback_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':2340,'unchanged_prior_artifacts':2334,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'daemon_query_fallback_source_identity.json'),'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_query_fallback_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':564,'source_proof_pairs':16,'prior_artifacts_checked':2340,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
