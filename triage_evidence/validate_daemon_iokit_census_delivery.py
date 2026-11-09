#!/usr/bin/env python3
"""Seal daemon query/census evidence with original/IDB/proof/preservation readback.

O(pinned bytes+I+256R+F) time,O(largest JSON) space plus solver cost30 s/query.
Native open,actual getter values,port identity and selector18 use remain unknown.
"""
import hashlib,json,re,struct
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,verify_original_fixups,selected,TABLE
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from daemon_iokit_census_symbolic import queries
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from kext_port_tools import SOURCE as KSOURCE
BASE=ROOT.parent;BASELINE_SHA='39595f742c125c321d57d4c958ffbbae9a76c4deca24ee5fbeee68629cd4d339'
EXPECTED={'original_daemon_source_spans': 5, 'independent_whole_text_four_byte_units': 3712490, 'exact_syntactic_candidates': 24, 'bounded_candidate_source_windows': 24, 'windows_preparing_21_22_23_or_26': 12, 'exhaustive_bank_rules': 2, 'bank_byte_inputs_checked': 512, 'original_dispatch_and_root_fixups': 8, 'same_modifier_original_pointer_slots': 4, 'original_kext_source_spans': 4, 'kext_query_routes_verified': 2, 'source_proof_pairs_unsat': 13, 'source_instruction_byte_checks': 137856, 'source_write_epochs': 960, 'source_read_epochs': 6144, 'source_capacity_reset_before_API': 512, 'API_write_epochs': 576, 'independent_byte_reconstructed_cases': 256, 'fresh_cases': 256, 'original_instruction_visits': 34464, 'unknown_gap_preserved_cases': 256, 'joint_query_consumer_frontiers': 256, 'API_response_models_checked': 512, 'successful_status_size_query_responses': 64, 'source_failure_output_clears': 448, 'high_word_size_mismatch_responses': 128, 'second_queries_after_first_query_rejection': 224}

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'daemon_iokit_census_prior_manifest.json')==BASELINE_SHA;baseline=read('daemon_iokit_census_prior_manifest.json');assert len(baseline['files'])==2254
 c=read('daemon_iokit_census_contracts.json');checks=read('daemon_iokit_census_checks.json');proof=read('daemon_iokit_census_proofs.json');preserve=read('daemon_iokit_census_preservation.json');live=read('daemon_iokit_census_live_ida.json')
 for obj,name in[(c,'recover_daemon_iokit_census.py'),(checks,'validate_daemon_iokit_census.py'),(proof,'prove_daemon_iokit_census.py'),(preserve,'validate_daemon_iokit_census_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']and sha(ROOT/'daemon_iokit_census_replays.json')==checks['fresh_replays_sha256']
 for flag in['native_target_executed','native_port_identity_proved','actual_selector18_caller_established']:assert not checks[flag]
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 for s in c['spans']:
  now=native(s['label'],int(s['start'],16),int(s['end'],16));assert now==s
 for row in c['census']['candidates']:
  now=native('candidate',int(row['start'],16),int(row['end'],16));assert all(now[n]==row[n]for n in now)and int(row['end'],16)-int(row['start'],16)<=148 and not row['target_proved_by_modifier']
 assert len(c['census']['candidates'])==24 and c['API_binding']==binding(0x1010a0640)and c['API_binding']['import_ordinal']==104 and c['API_binding']['authenticated']and c['API_binding']['total_addend']==0
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),TABLE,0);assert all(now[n]==b[n]for n in now)
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records']
 for row in c['modifier_collision_pointers']:
  a=int(row['address'],16);assert {n:row[n]for n in FIXUPS[a]}==FIXUPS[a]
 collisions=verify_original_fixups([int(row['address'],16)for row in c['modifier_collision_pointers']]);assert len(collisions['records'])==4
 assert live['idb_node']=='6b117c693e3b'and live['input_universal_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'and not live['idb_mutated']and not live['native_target_executed'];live_count=0
 for row in live['open_code']['results']:
  for ins in row['instructions']:
   raw=bytes.fromhex(ins['bytes']);assert IMAGE.read(int(ins['address'],16),len(raw))==raw;live_count+=1
 assert live_count==len(c['live_IDB_source_rows_matched'])==105
 for row in live['bank_bytes']:
  if row['address']=='0x1010a0640':assert int.from_bytes(bytes.fromhex(row['hex']),'little')==0x1010ca388 and IMAGE.read(0x1010a0640,8).hex()!=row['hex']
  else:assert IMAGE.read(int(row['address'],16),len(bytes.fromhex(row['hex']))).hex()==row['hex']
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'and sha(KSOURCE)==c['kext_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c';entry=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for s in c['kext_spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)
 for q in c['kext_query_contracts']:
  for name in['descriptor_pointer','method_pointer','provider_slot']:assert pointer(k,int(q[name]['slot'],16))==q[name]
  assert function(k,entry,int(q['provider_slot']['target'],16))==q['provider_stub']and not q['core_return_value_known']
 assert k.symbols([int(a,16)for a in c['exact_kext_symbols']])==c['exact_kext_symbols']
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==13 and lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==83
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 fresh=read('daemon_iokit_census_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_daemon_iokit_census.py')and fresh['dependencies']==checks['dependencies']and len(fresh['cases'])==256 and not fresh['full_goal_complete'];joint=[]
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete']and r['boundary']['pc']=='0x1003c39b0'and len(r['API_models'])==2
  joint.append({'input':r['input'],'frame_SP':r['frame_SP'],'source_edges':r['source_edges'],'query_words':r['query_words'],'returned_size':r['returned_size'],'boundary':r['boundary']})
 del fresh
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==2254 and preserve['unchanged_prior_artifacts']==2248
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['daemon_iokit_census_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'daemon_iokit_census_source_identity.json',ROOT/'daemon_iokit_census_quality_gates.json'],(name,target);links+=1
 assert links>850;report=(BASE/'daemon_iokit_census_report.md').read_text()
 for term in['DC12','QG7','unknown','256','34464','2254','2248','24','13','83','448','105','0x1010CA388','0x100000004','0xfffffe000a505110','selector18','Mach']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'daemon_thin_sha256':sha(SOURCE),'live_IDB_input_universal_sha256':live['input_universal_sha256'],'kernel_collection_sha256':k.sha256,'kext_sha256':sha(KSOURCE),'source_spans':c['spans'],'census_source':c['census'],'original_modifier_collision_pointer_records':collisions,'API_binding':c['API_binding'],'kext_query_contracts':c['kext_query_contracts'],'source_entry_premises':c['source_entry_premises'],'live_source_rows_matched':105,'loader_pointer_representation_note':live['scope'],'joint_consumer_cases':joint,'actual_selector18_caller_established':False,'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','DC1-DC12 list dependencies and falsification probes.','Bounded caller census and query ABI/data/status covered; selector18 and full objective incomplete.','Exact widths,fixture cardinality,counts and reproduction.','Discriminator/target,IDB/file pointers,conditional/native routing and output/return layers separated.','256 fresh byte audits,13 source proof pairs,independent text census,original fixups and105 live source-row comparisons.','Impact-labeled continuation table.'];outputs=['daemon_iokit_census_contracts.json','daemon_iokit_census_profiles.json','daemon_iokit_census_replays.json','daemon_iokit_census_checks.json','daemon_iokit_census_proofs.json','daemon_iokit_census_live_ida.json','daemon_iokit_census_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'live_source_rows_matched':105,'prior_artifacts_checked':2254,'unchanged_prior_artifacts':2248,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'daemon_iokit_census_source_identity.json'),'actual_selector18_caller_established':False,'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':256,'source_proof_pairs':13,'prior_artifacts_checked':2254,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
