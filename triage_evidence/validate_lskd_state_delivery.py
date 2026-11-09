#!/usr/bin/env python3
"""Seal scoped state delivery: source identity, proof re-lift, epochs and preservation.

O(pinned bytes+visits+certificate rows+256R) time and O(largest JSON) space,
plus solver-dependent cost with a 30 s/query bound. No native target executes.
"""
import hashlib,json,re
from pathlib import Path
from collections import Counter
import z3,capstone
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from lskd_state_symbolic import queries
BASE=ROOT.parent
BASELINE_SHA='80e6b29f9be7dc89b4437e7972a679341e3f80d33361cfcac213f874432d2f8b'
EXPECTED={'bounded_source_spans':16,'exhaustive_context_root_banks':2,'bank_byte_input_checks':512,'independent_kill_instruction_cases':6,'source_proof_pairs_unsat':7,'fresh_cases':379,'source_visits':1258134,'source_byte_checks':5032536,'source_write_epochs':127997,'read_epochs':253019,'discarded_probe_read_epochs':379,'byte_reconstructed_cases':379,'preceding_complete_prefixes_equal':355,'FP64_contexts_preserved':379,'register_only_models':2104,'discarded_unknown_load_epochs':24,'original_state_authenticated_edges':420,'source_dead_window_instructions':2004,'source_dead_load_windows':24,'source_zero_context_cache_reads':49,'source_resolved_context_error_returns':24,'source_stop_stream_free_preparations':24,'original_stop_method_returns':12,'stop_cleanup_GP_SP_returns':48,'additional_context_fixture_prefixes_equal':24,'nonnull_context_guard_retained_cases':24}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 assert sha(ROOT/'lskd_state_prior_manifest.json')==BASELINE_SHA
 baseline=read('lskd_state_prior_manifest.json');assert len(baseline['files'])==1949
 c=read('lskd_state_contracts.json');checks=read('lskd_state_checks.json');proof=read('lskd_state_proofs.json');preserve=read('lskd_state_preservation.json')
 for obj,name in[(c,'recover_lskd_state.py'),(checks,'validate_lskd_state.py'),(proof,'prove_lskd_state.py'),(preserve,'validate_lskd_state_preservation.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert checks['all_checks_pass']and checks['verified_counts']==EXPECTED and preserve['all_checks_pass']
 assert sha(ROOT/'lskd_state_replays.json')==checks['fresh_replays_sha256']
 k=Kernel();assert k.sha256==c['kernel_collection_sha256']==checks['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sha(SOURCE)==c['source_sha256']==checks['source_sha256']=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)
  assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex']
 e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 assert function(k,e,0xfffffe000a505480)==c['stop_caller']and k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex']
  now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer']
 assert len(c['bank_rules'])==2 and {b['slot']for b in c['bank_rules']}=={'0xfffffe0008471c80'}
 assert k.read(0xfffffe000ccc78d0,8).hex()==c['context_cache']['original8_hex']=='0000000000000000'
 for ptr in c['callback_and_cache_slots']+checks['original_state_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 kill=c['kill'];a=int(kill['pc'],16);word=int.from_bytes(k.read(a,4),'little');assert(word&0x9f000000)==0x90000000 and word&31==13
 imm=((word>>5)&0x7ffff)<<2|((word>>29)&3);imm=imm-(1<<21)if imm&(1<<20)else imm
 page=((a&~4095)+(imm<<12))&((1<<64)-1);assert page==0xfffffe000ccc2000==int(checks['kill_instruction_decoded_value64'],16)
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']==checks['source_lift_counts']and sum(lifts.values())==56 and len(qs)==7
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat'
  op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   solver=z3.Solver();solver.set(timeout=30000);solver.add(f);assert str(solver.check())=='unsat',name
 fresh=read('lskd_state_replays.json');assert fresh['generator_sha256']==sha(ROOT/'validate_lskd_state.py')and fresh['dependencies']==checks['dependencies']and len(fresh['cases'])==379
 cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);cs.detail=True;counts=Counter();boundaries=Counter()
 for r in fresh['cases']:
  counts['cases']+=1;counts['visits']+=len(r['source_visits']);boundaries[r['boundary']['kind']]+=1
  assert not r['uninitialized_values_consumed']and not r['dead_register_value_live_at_boundary']and r['initial_fp_callee_saved64']==r['final_fp_callee_saved64']
  for flag in['native_API_executed','native_heap_executed','native_synchronization_executed','native_object_free_executed','external_IPC_emission_proved','full_goal_complete']:assert not r[flag],flag
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled'];counts['models']+=1
  assert r['uninitialized_private_loads']==[x for x in r['source_reads']if x.get('discarded_dead_load')]
  for w in r['state_dead_load_windows']:
   assert w['cache_predicate']=={'address':'0xfffffe000ccc78d0','value64':'0x0'}and w['register13_after']==hex(page)
   assert w['origin']['snapshot']['known_mask_hex'][:16]=='00'*8 and w['origin']['snapshot']['provenance_hex'][:16]=='00'*8
   rows=w['intervening'];assert len(rows)==(82 if w['origin']['pc']=='0xfffffe000a57eef8'else 85)
   for j,row in enumerate(rows):
    addr=int(row['pc'],16);raw=k.read(addr,4);assert raw.hex()==row['bytes_hex'];ins=next(cs.disasm(raw,addr));rd,wr=ins.regs_access();assert[ins.reg_name(x)for x in rd]==row['reads']and[ins.reg_name(x)for x in wr]==row['writes']
    assert not any(x in['x13','w13']for x in row['reads'])
    if j<len(rows)-1:assert not re.search(r'\b[wx]13\b',ins.op_str)and not any(x in['x13','w13']for x in row['writes'])
    else:assert row==w['kill']and row['pc']==kill['pc']and ins.mnemonic=='adrp'and row['reads']==[]and row['writes']==['x13']
    counts['dead_rows']+=1
   counts['windows']+=1;assert r['boundary']['registers31'][0]=='0xffffffff'and r['source_execution_wrapper_returned']
  if r['input'].get('context_cache_fixture'):
   assert r['boundary']['kind']=='before_uninitialized_private_read'and not r['state_dead_load_windows'];counts['nonnull_guards']+=1
  if r['original_stop_method_return_executed']:
   assert r['boundary']['registers31'][0]=='0x0'and r['boundary']['SP']==r['entry_SP']and len(r['state_stop_returns'])==4;counts['stop_returns']+=1
 assert dict(counts)=={'cases':379,'visits':1258134,'models':2104,'dead_rows':2004,'windows':24,'stop_returns':12,'nonnull_guards':24},dict(counts)
 assert dict(boundaries)==checks['boundary_coverage'];del fresh
 allowed={r['path']:r for r in preserve['allowed_existing_changes']};assert len(allowed)==6 and preserve['prior_artifacts_checked']==1949 and preserve['unchanged_prior_artifacts']==1943
 for row in baseline['files']:
  p=BASE/row['path'];assert sha(p)==(allowed[row['path']]['current_sha256']if row['path']in allowed else row['sha256']),row['path']
  if row['path']not in allowed:assert p.stat().st_size==row['size_bytes']
 for row in baseline['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 links=0
 for name in['lskd_state_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   target=target.strip('<>')
   if re.match(r'^[a-zA-Z][\w+.-]*://',target)or target.startswith('#'):continue
   p=Path(target.split('#',1)[0]);p=p if p.is_absolute()else BASE/p
   assert p.exists()or p in[ROOT/'lskd_state_quality_gates.json',ROOT/'lskd_state_source_identity.json'],(name,target);links+=1
 report=(BASE/'lskd_state_report.md').read_text()
 for term in['ST12','QG7','379','1258134','5032536','2004','1949','1943','unknown','Mach','0xfffffe000ccc78d0','0xfffffe000ccc78a8']:assert term in report,term
 identity={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'kernel_collection_sha256':k.sha256,'kext_sha256':sha(SOURCE),'kernel_uuid':k.kernel['uuid'],'source_spans':[{n:s[n]for n in['label','start','end','sha256','compiler_start','compiler_end']}for s in c['spans']],'exact_symbols':c['exact_symbols'],'context_cache':c['context_cache'],'context_root_banks':c['bank_rules'],'kill':kill,'independently_decoded_kill_value64':hex(page),'stop_caller':c['stop_caller'],'delivery_case_counts':dict(counts),'boundary_coverage':dict(boundaries),'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'lskd_state_source_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
 evidence=['Factual source/interface analysis.','ST1-ST12 include explicit dependencies and falsification probes.','Cold frontiers conditionally resolved, hot guards retained and original stop return checked; broader goal remains active.','Fixed-width arithmetic, byte extents and exact source audit counts.','Unknown loads versus uses, cache-state premises, static/executed schemas and model/native effects separated.','Original source rechecked,379 fresh epoch-audited cases,2004 independently decoded def/use rows and seven re-lifted proof pairs.','Impact-labeled continuation table.']
 outputs=['lskd_state_contracts.json','lskd_state_profiles.json','lskd_state_replays.json','lskd_state_checks.json','lskd_state_proofs.json','lskd_state_preservation.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),**{f'QG{j}':{'status':'pass_for_increment'if j==3 else'pass','evidence':v}for j,v in enumerate(evidence,1)},'verified_counts':EXPECTED,'source_lift_counts':lifts,'prior_artifacts_checked':1949,'unchanged_prior_artifacts':1943,'inputs_preserved':baseline['inputs_preserved'],'checked_report_links':links,'new_validation_outputs':{n:sha(ROOT/n)for n in outputs},'source_identity_sha256':sha(ROOT/'lskd_state_source_identity.json'),'model_memory_writes':0,'uninitialized_values_consumed':0,'native_target_executed':False,'external_IPC_emission_proved':False,'idb_mutated':False,'full_goal_complete':False}
 (ROOT/'lskd_state_quality_gates.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'scoped_quality_gates_pass':True,'verified_counts':dict(counts),'prior_artifacts_checked':1949,'checked_report_links':links,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
