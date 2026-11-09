#!/usr/bin/env python3
"""Seal class-family/source/constructor/SDK/proof/byte/preservation evidence.
O(pinned bytes+I+256R+reports+KC+SDK bytes) time,O(largest JSON+KC) space
plus30 s/query. No native daemon/kernel/API or IDB mutation.
"""
import hashlib,json,re
from pathlib import Path
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,selected,verify_original_fixups
from daemon_import_bindings import binding
from recover_daemon_iokit_census import native
from recover_daemon_iokit_class import sdk_check
from daemon_iokit_class_symbolic import queries
from kernel_native_reader import Kernel
from recover_carrier_control import span
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from kext_port_tools import SOURCE as KSOURCE,IMAGE as KIMAGE
from probe_daemon_iokit_class import Matching,cases,NAME,P
BASE=ROOT.parent;BASELINE='def984ec6b8e2a77e0f026d6a26db7155c0b024f16f383eea0b763e5bb7e9139'
EXPECTED={'original_daemon_spans':3,'exhaustive_bank_rules':3,'bank_inputs_checked':768,'original_fixups_verified':52,'direct_dispatch_slots_verified':5,'original_binding_decodes':2,'SDK_syntax_checks':1,'SDK_width_assertions':3,'SDK_function_signature_checks':2,'retained_prior_sources_verified':4,'original_class_pointer_rebases':1,'live_IDB_source_rows_matched':208,'kext_metaclass_constructors_verified':2,'kext_import_stub_spans_verified':1,'kext_pointer_bindings_verified':2,'daemon_kext_class_name_equalities':1,'source_proof_pairs_unsat':15,'source_instruction_byte_checks':2550560,'source_write_epochs':58980,'source_read_epochs':136240,'API_write_epochs':3656,'query_capacity_resets':1144,'common_cleanup_unknown_pointer_frontiers':596,'independent_byte_reconstructed_cases':1176,'composed_fresh_cases':664,'composed_instruction_visits':573640,'embedded_object_prefixes_with_declared_unused_register_adjustments':632,'main_port_API_models':664,'API_produced_main_ports_preserved':640,'exact_class_matching_calls':640,'class_data_pointer_epoch_checks':1280,'matching_dictionary_forwardings':636,'metadata_API_models_retained':1144,'IOKit_object_models_retained':3000,'fallback_input_unknown_result_checks':532,'null_dictionary_cleanup_paths':4,'main_port_error_frontiers':24,'decoder_fresh_cases':512,'decoder_instruction_visits':64000,'exact_decoder_class_controls':2}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'daemon_iokit_class_prior_manifest.json')==BASELINE;baseline=read('daemon_iokit_class_prior_manifest.json');assert len(baseline['files'])==2447
 c,check,proof,pre=map(read,['daemon_iokit_class_contracts.json','daemon_iokit_class_checks.json','daemon_iokit_class_proofs.json','daemon_iokit_class_preservation.json'])
 for obj,name in[(c,'recover_daemon_iokit_class.py'),(check,'validate_daemon_iokit_class.py'),(proof,'prove_daemon_iokit_class.py'),(pre,'validate_daemon_iokit_class_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert check['all_checks_pass']and check['verified_counts']==EXPECTED and pre['all_checks_pass']and sha(ROOT/'daemon_iokit_class_replays.json')==check['fresh_replays_sha256']
 assert sha(SOURCE)==c['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e';universal=Path('/Users/___/Downloads/fpx/fairplayd');assert sha(universal)=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
 for s in c['spans']:assert native(s['label'],int(s['start'],16),int(s['end'],16))==s
 for b in c['bank_rules']:
  now=selected(int(b['left'],16),int(b['right'],16),int(b['key'],16),int(b['additive'],16),int(b['base'],16),int(b['bias'],16));assert all(now[n]==b[n]for n in now)and IMAGE.read(int(b['left'],16),256).hex()==b['left256_hex']and IMAGE.read(int(b['right'],16),256).hex()==b['right256_hex']
 assert verify_original_fixups([int(x['address'],16)for x in c['original_fixup_records']['records']])==c['original_fixup_records']
 for row in c['dispatch_slots']:
  a=int(row['slot'],16);assert IMAGE.read(a,8).hex()==row['original_word_hex']and FIXUPS[a]==row['fixup']
 for b in c['bindings']:assert binding(int(b['slot'],16))==b
 assert sdk_check()==c['SDK']
 for row in c['retained_prior_sources']:assert sha(Path(row['path']))==row['sha256']and Path(row['path']).read_text()==row['contents']
 assert FIXUPS[0x1010b8cc0]['target']==0x100fd40c0 and IMAGE.read(0x1010b8cc0,8).hex()==c['class_data']['raw_word_hex']and IMAGE.read(0x100fd40c0,31).hex()==c['class_data']['encoded31_hex']and c['class_data']['expected_class31_hex']==NAME.hex()
 live=read('daemon_iokit_class_live_ida.json');assert live['idb_node']=='6b117c693e3b'and not live['idb_mutated'];nr=0
 for row in live['disassembly']['results']:
  for i in row['instructions']:
   raw=bytes.fromhex(i['bytes']);assert IMAGE.read(int(i['address'],16),len(raw))==raw;nr+=1
 assert nr==len(c['live_IDB_source_rows_matched'])==208
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']and sha(KSOURCE)==c['kext_sha256'];e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for f in c['kext_constructors']:assert function(k,e,int(f['start'],16))==f
 for s in c['kext_spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[key]==s[key]for key in now)
 for p in c['kext_pointers']:assert pointer(k,int(p['slot'],16))==p
 assert k.symbols([int(a,16)for a in c['exact_kext_symbols']])==c['exact_kext_symbols']and k.read(0xfffffe000790cc00,31)==KIMAGE.read(0xfffffe000790cc00,31)==NAME
 qs,lifts=queries(c);assert len(qs)==len(proof['proofs'])==15 and lifts==proof['source_lift_counts']==check['source_lift_counts']and sum(lifts.values())==141
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for form in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(form);assert str(s.check())=='unsat',name
 # Private entry setup only;no source instruction executes in this snapshot.
 init=Matching(next(cases()));F=init.F
 for j,v in[(19,P+0x2000),(12,0x100f4e290),(13,0x100e99800),(23,0x1010c4000),(25,0x1010c4670),(28,0x597a),(29,F+0x120)]:assert init.reg(j)==v
 assert init.snapshot(F+0x7c,4)['known_mask_hex']=='00000000'and init.snapshot(F+0x38,24)['known_mask_hex']=='00'*24;entry={'frame_SP':hex(F),'registers31':[hex(init.reg(j))for j in range(31)],'private_fixtures':init.initial,'image_fixtures':init.image_initial_fixtures,'scope':'Entry after unexecuted lock/state prefix;main-port/context/table cells start unknown and are produced by selected source/API epochs.','source_instructions_executed':False};del init
 fresh=read('daemon_iokit_class_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_daemon_iokit_class.py')and fresh['dependencies']==check['dependencies']and len(fresh['composed_cases'])==664 and len(fresh['decoder_cases'])==512;frontiers=[]
 for r in fresh['composed_cases']:
  assert not r['native_target_executed']and not r['native_port_identity_proved']and not r['full_goal_complete'];frontiers.append({'input':r['input'],'frame_SP':r['frame_SP'],'boundary':r['boundary'],'class_buffer':r['class_buffer'],'main_port_cell':r['main_port_cell'],'prefix_models':r['prefix_models']})
 del fresh
 prior=read('daemon_iokit_objects_proofs.json');assert len(prior['proofs'])==19
 for row in prior['proofs']:assert row['result']=='unsat'and sha(ROOT/row['file'])==row['sha256']and sha(ROOT/row['original_file'])==row['original_sha256']
 allowed={r['path']:r for r in pre['allowed_existing_changes']};assert len(allowed)==6 and pre['prior_artifacts_checked']==2447 and pre['unchanged_prior_artifacts']==2441
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert sha(p)==row['sha256']and p.stat().st_size==row['size_bytes']
 links=0
 for name in['daemon_iokit_class_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for t in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   t=t.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',t)or t.startswith('#'):continue
   p=Path(t.split('#',1)[0]);p=p if p.is_absolute()else BASE/p;assert p.exists()or p in[ROOT/'daemon_iokit_class_source_identity.json',ROOT/'daemon_iokit_class_quality_gates.json'],(name,t);links+=1
 assert links==971;report=(BASE/'daemon_iokit_class_report.md').read_text()
 for term in['IC14','QG7','unknown','664','512','573640','64000','2447','2441','15','141','208','0x1010B8CC0','0x100FD40C0','0xFFFFFE000790CC00','136 B','subclass','Mach']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'daemon_thin_sha256':sha(SOURCE),'daemon_universal_sha256':sha(universal),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(KSOURCE),'current_IDB_node':'6b117c693e3b','live_source_rows_matched':208,'source_spans':c['spans'],'original_fixup_records':c['original_fixup_records'],'bindings':c['bindings'],'class_data':c['class_data'],'kext_constructors':c['kext_constructors'],'kext_pointers':c['kext_pointers'],'exact_kext_symbols':c['exact_kext_symbols'],'entry_initialization_snapshot':entry,'SDK':c['SDK'],'prior_objects_proof_sha256':sha(ROOT/'daemon_iokit_objects_proofs.json'),'frontier_cases':frontiers,'native_target_executed':False,'native_service_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_class_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','IC1-IC14 include dependencies and falsification probes.','MainPort/class/object-flow composition and static metaclass association covered;full objective remains active.','Exact B/u32/u64 widths,modular formulas,cardinalities and reproduction.','Class-or-subclass criterion,native publication limits,file-initial pointer and unused-register changes distinguished.','1176 fresh byte/lineage audits,15 source proof pairs,52 daemon fixups,208 IDB rows,kext source/pointers/symbols and SDK compile.','Impact-labeled bounded continuation table.'];outputs=['daemon_iokit_class_contracts.json','daemon_iokit_class_profiles.json','daemon_iokit_class_replays.json','daemon_iokit_class_checks.json','daemon_iokit_class_proofs.json','daemon_iokit_class_live_ida.json','daemon_iokit_class_preservation.json']
 obj={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':2447,'unchanged_prior_artifacts':2441,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'daemon_iokit_class_source_identity.json'),'native_target_executed':False,'native_service_publication_proved':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_iokit_class_quality_gates.json').write_text(json.dumps(obj,indent=2)+'\n');print(json.dumps({'scoped_gates_pass':True,'composed_cases':664,'decoder_cases':512,'source_proof_pairs':15,'prior_artifacts_checked':2447,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
