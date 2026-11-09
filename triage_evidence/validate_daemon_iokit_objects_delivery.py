#!/usr/bin/env python3
"""Seal object-flow/source/ABI/SDK/proof/provenance/preservation evidence.

O(pinned bytes+I+256R+reports+SDK bytes) time,O(largest JSON) space plus
30 s/query. No native target/API/Mach execution or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups,TABLE,POOL
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_iokit_objects import sdk_check
from daemon_iokit_objects_symbolic import queries
from probe_daemon_iokit_objects import Objects,cases,DICT,STATE
BASE=ROOT.parent;BASELINE='90bacf71cf0446db39eb732856a12ffdde6b94b6855bb137b4cb5568b1f0eb35'
EXPECTED={'original_source_spans':8,'exhaustive_bank_rules':7,'bank_inputs_checked':1792,'original_fixups_verified':44,'direct_dispatch_slots_verified':8,'original_binding_decodes':5,'ordinary_data_bind_addend_cancellations':1,'SDK_syntax_checks':1,'SDK_width_assertions':8,'SDK_function_signature_checks':4,'retained_prior_sources_verified':4,'live_IDB_source_rows_matched':179,'source_proof_pairs_unsat':19,'source_instruction_byte_checks':1773568,'source_write_epochs':19352,'source_read_epochs':81540,'API_write_epochs':2992,'query_capacity_resets':1136,'common_cleanup_unknown_pointer_frontiers':588,'independent_byte_reconstructed_cases':632,'embedded_query_prefixes_with_declared_unused_register_adjustment':564,'fresh_cases':632,'original_instruction_visits':443392,'API_produced_iterator_cells_preserved':600,'connection_outputs_consumed_by_queries':568,'metadata_API_models_retained':1136,'fallback_input_unknown_result_checks':532,'high_bit_handle_controls':64,'open_error_frontiers_after_service_release':12,'matching_error_frontiers':32,'successful_null_iterator_controls':4}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'daemon_iokit_objects_prior_manifest.json')==BASELINE;baseline=read('daemon_iokit_objects_prior_manifest.json');assert len(baseline['files'])==2390
 c,check,proof,pre=map(read,['daemon_iokit_objects_contracts.json','daemon_iokit_objects_checks.json','daemon_iokit_objects_proofs.json','daemon_iokit_objects_preservation.json'])
 for obj,name in[(c,'recover_daemon_iokit_objects.py'),(check,'validate_daemon_iokit_objects.py'),(proof,'prove_daemon_iokit_objects.py'),(pre,'validate_daemon_iokit_objects_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert check['all_checks_pass']and check['verified_counts']==EXPECTED and pre['all_checks_pass']and sha(ROOT/'daemon_iokit_objects_replays.json')==check['fresh_replays_sha256']
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),0);assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex']
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records']
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup']
 for b in c['bindings']:assert binding(int(b['slot'],16))==b
 task=next(b for b in c['bindings']if b['symbol']=='_mach_task_self_');assert task['word']=='0x4008000000000012'and task['import_ordinal']==18 and task['library_ordinal']==12 and task['total_addend']==0x7bf13863 and not task['authenticated']and(task['total_addend']+int(c['task_bind_source_bias64'],16))&((1<<64)-1)==0
 assert sdk_check()==c['SDK']and c['SDK']['exit_code']==0
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents']
 live=read('daemon_iokit_objects_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated']and not live['native_target_executed'];nr=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;nr+=1
 assert nr==len(c['live_IDB_source_rows_matched'])==179 and len(c['candidate_state_pointer_publications'])==2
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==19 and lifts==proof['source_lift_counts']==check['source_lift_counts']and sum(lifts.values())==94
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(f);assert str(s.check())=='unsat',name
 # Private initialization snapshot only: no source instruction/API runs here.
 init=Objects(next(cases()));F=init.F;regs={str(j):hex(init.reg(j))for j in range(31)}
 for j,v in[(0,DICT),(19,0x101031ea0),(20,0x100fc4230),(21,0x101031fa0),(22,0x1010b7d48),(23,0x1010c4670),(24,TABLE),(25,0x100fc4130),(27,POOL),(28,0xb606),(29,F+0x120)]:assert init.reg(j)==v
 assert init.image_initial_fixtures==[{'address':hex(STATE),'bytes_hex':'09','provenance':3}];entry={'frame_SP':hex(F),'registers31':regs,'private_fixtures':init.initial,'image_fixtures':init.image_initial_fixtures,'scope':'Explicit private entry initialization;connection field is original-file provenance0 until Open summary writes it.','source_instructions_executed':False};del init
 fresh=read('daemon_iokit_objects_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_daemon_iokit_objects.py')and fresh['dependencies']==check['dependencies']and len(fresh['cases'])==632;frontiers=[]
 for r in fresh['cases']:
  assert not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete']and r['boundary']['pc']in['0x100318cc0','0x1004bdb24','0x100383b00']
  frontiers.append({'input':r['input'],'frame_SP':r['frame_SP'],'boundary':r['boundary'],'iterator_cell':r['iterator_cell'],'state_cache':r['state_cache'],'IOKit_models':r['IOKit_models']})
 del fresh
 assert check['IOKit_model_role_counts']=={'matching_services':632,'iterator_next':600,'service_open':580,'service_release':580,'iterator_release':588}
 prior=read('daemon_query_fallback_proofs.json');assert len(prior['proofs'])==16
 for row in prior['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert len(allowed)==6 and pre['prior_artifacts_checked']==2390 and pre['unchanged_prior_artifacts']==2384
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in['daemon_iokit_objects_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'daemon_iokit_objects_source_identity.json',ROOT/'daemon_iokit_objects_quality_gates.json'],(name,target);links+=1
 assert links==960;report=(BASE/'daemon_iokit_objects_report.md').read_text()
 for term in['OI14','QG7','unknown','632','443392','2390','2384','19','94','568','179','0x7BF13863','0xFFFFFFFF840EC79D','0x100383B00','0x100478C2C','0x100483CC0','Mach']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'current_IDB_node':'6b117c693e3b','live_source_rows_matched':179,'source_spans':c['spans'],'bank_rules':c['bank_rules'],'original_fixup_records':c['original_fixup_records'],'bindings':c['bindings'],'entry_initialization_snapshot':entry,'SDK':c['SDK'],'candidate_pointer_publications':c['candidate_state_pointer_publications'],'prior_query_fallback_proof_sha256':sha(ROOT/'daemon_query_fallback_proofs.json'),'frontier_cases':frontiers,'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_objects_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','OI1-OI14 include dependent results and falsification probes.','Discovery/open/query/release linkage,data-symbol ABI and bounded reader leads covered;full objective remains active.','Exact B/u32/u64 widths,modular/unsigned formulas,cardinalities and reproduction.','Typed object roles,32/64-bit cells and frame epochs,SDK/native/private boundaries and partial xref candidates distinguished.','632 fresh byte/lineage audits,19 source proof pairs,44 fixups,179 IDB rows and typed SDK compile.','Impact-labeled bounded continuation table.'];outputs=['daemon_iokit_objects_contracts.json','daemon_iokit_objects_profiles.json','daemon_iokit_objects_replays.json','daemon_iokit_objects_checks.json','daemon_iokit_objects_proofs.json','daemon_iokit_objects_live_ida.json','daemon_iokit_objects_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':2390,'unchanged_prior_artifacts':2384,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'daemon_iokit_objects_source_identity.json'),'native_target_executed':False,'native_port_identity_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_objects_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'fresh_cases':632,'source_proof_pairs':19,'prior_artifacts_checked':2390,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
