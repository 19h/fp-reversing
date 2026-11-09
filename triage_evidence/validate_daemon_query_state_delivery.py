#!/usr/bin/env python3
"""Seal query-state source/proof/byte-audit/report/preservation evidence.

O(pinned bytes+I+256R+report bytes) time,O(largest JSON) space plus30 s/query.
No native target/API/Mach execution, IDB mutation or memory writes.
"""
import hashlib,json,re
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from daemon_query_state_symbolic import queries
BASE=ROOT.parent;BASELINE='f27cf8fa5506cf362077b11f7b9f9f184c9a071db2e1d51f9845c9999731ce1f'
EXPECTED={'original_source_spans':7,'exhaustive_bank_rules':7,'bank_inputs_checked':1792,'original_fixups_verified':25,'independent_bind_checks':2,'direct_dispatch_slots_verified':3,'live_IDB_source_rows_matched':78,'source_proof_pairs_unsat':11,'source_instruction_byte_checks':446464,'source_write_epochs':6688,'source_read_epochs':18504,'source_capacity_resets':528,'API_write_epochs':608,'independent_byte_reconstructed_cases':264,'source_controller_update_checks':528,'record_preservation_checks':264,'preceding_query_prefixes_with_declared_alias_adjustments':256,'fresh_cases':264,'original_instruction_visits':111616,'packed_record_checks':264,'encoded_cache_checks':264,'API_models_retained':528,'normal_returns_before_unknown_iterator':32,'zero_capability_fallback_frontiers':232,'low_version_byte_independence_pairs':2}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'daemon_query_state_prior_manifest.json')==BASELINE;baseline=read('daemon_query_state_prior_manifest.json');assert len(baseline['files'])==2300
 c,check,proof,pre=map(read,['daemon_query_state_contracts.json','daemon_query_state_checks.json','daemon_query_state_proofs.json','daemon_query_state_preservation.json'])
 for obj,name in[(c,'recover_daemon_query_state.py'),(check,'validate_daemon_query_state.py'),(proof,'prove_daemon_query_state.py'),(pre,'validate_daemon_query_state_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert check['all_checks_pass']and check['verified_counts']==EXPECTED and pre['all_checks_pass']and sha(ROOT/'daemon_query_state_replays.json')==check['fresh_replays_sha256']
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex']
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records']
 assert binding(0x1010a0240)==c['release_binding']and binding(0x1010b1e18)==c['stack_guard_binding']
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup']
 live=read('daemon_query_state_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']and not live['native_target_executed'];nr=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;nr+=1
 assert nr==len(c['live_IDB_source_rows_matched'])==78
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==11 and lifts==proof['source_lift_counts']==check['source_lift_counts']and sum(lifts.values())==142
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=read('daemon_query_state_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_daemon_query_state.py')and fresh['dependencies']==check['dependencies']and len(fresh['cases'])==264;frontiers=[]
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['full_goal_complete']and r['internal_record_helper_executed']
  assert r['boundary']['pc']==('0x100483ca8'if r['helper_returned']else'0x100011674');frontiers.append({'input':r['input'],'frame_SP':r['frame_SP'],'boundary':r['boundary'],'state_cache':r['state_cache'],'query_state_record':r['query_state_record'],'fallback_record':r['fallback_record'],'helper_returned':r['helper_returned']})
 del fresh
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert len(allowed)==6 and pre['prior_artifacts_checked']==2300 and pre['unchanged_prior_artifacts']==2294
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in['daemon_query_state_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'daemon_query_state_source_identity.json',ROOT/'daemon_query_state_quality_gates.json'],(name,target);links+=1
 assert links>870;report=(BASE/'daemon_query_state_report.md').read_text()
 for term in['QS12','QG7','unknown','264','111616','2300','2294','11','142','232','78','0x10043BD18','0x100483CA8','0x8515CFBD','0x0DA54C41','Mach']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'current_IDB_node':'6b117c693e3b','live_source_rows_matched':78,'source_spans':c['spans'],'bank_rules':c['bank_rules'],'original_fixup_records':c['original_fixup_records'],'release_binding':c['release_binding'],'stack_guard_binding':c['stack_guard_binding'],'premises':c['premises'],'frontier_cases':frontiers,'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_query_state_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','QS1-QS12 list dependent results and falsification probes.','Bounded record/cache/controller/continuation increment covered; full interface objective remains active.','Exact B/u32/u64 widths,modular formulas,counts and reproduction.','Fixture/native,initial/final state,normal/fallback and declared prefix differences separated; unknowns explicit.','264 fresh byte/algebra audits,11 source proof pairs,25 original fixups,seven exhaustive banks and78 live IDB rows.','Impact-labeled bounded continuation table.'];outputs=['daemon_query_state_contracts.json','daemon_query_state_profiles.json','daemon_query_state_replays.json','daemon_query_state_checks.json','daemon_query_state_proofs.json','daemon_query_state_live_ida.json','daemon_query_state_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':2300,'unchanged_prior_artifacts':2294,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'daemon_query_state_source_identity.json'),'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_query_state_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':264,'source_proof_pairs':11,'prior_artifacts_checked':2300,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
