#!/usr/bin/env python3
"""Fresh state replay, independent byte epochs, def/use and original stop return.

O(B+C*(V+E)+I+256R) time/space plus solver-dependent cost (30 s/query).
Discarded unknown loads require a zero-cache path and a checked source kill;
no source initialization or model memory write is introduced. No native API.
"""
import gc,hashlib,json,re,struct
from collections import Counter
from pathlib import Path
import z3,unicorn,capstone
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected,CS
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from probe_lskd_state import State,cases
from lskd_state_audit import audit
from lskd_state_symbolic import queries
from probe_lskd_response import P,OBJECT,RESPONSE
T=0xfffffe000846c420

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_state_contracts.json');p=read('lskd_state_profiles.json');proof=read('lskd_state_proofs.json');old=read('lskd_continuations_profiles.json');continued=read('lskd_continuations_contracts.json');prior_readback=read('lskd_readback_contracts.json');prior=read('legacy_stack_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');response=read('lskd_response_contracts.json');handlers=read('lskd_handlers_contracts.json');handlers={**handlers,'additional_mutable_globals':handlers['additional_mutable_globals']+prior_readback['additional_mutable_globals']+continued['additional_mutable_globals']};k=Kernel();counts=Counter();boundaries=Counter();slots={};cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);cs.detail=True
 for obj,name in[(c,'recover_lskd_state.py'),(p,'probe_lskd_state.py'),(proof,'prove_lskd_state.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256'];e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_source_spans']+=1
 assert function(k,e,0xfffffe000a505480)==c['stop_caller']and k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_context_root_banks']+=1;counts['bank_byte_input_checks']+=256
 assert len({b['slot']for b in c['bank_rules']})==1 and c['bank_rules'][0]['slot']=='0xfffffe0008471c80';assert k.read(0xfffffe000ccc78d0,8).hex()==c['context_cache']['original8_hex']=='0000000000000000'
 for ptr in c['callback_and_cache_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 kill=c['kill'];a=int(kill['pc'],16);raw=k.read(a,4);word=int.from_bytes(raw,'little');assert(word&0x9f000000)==0x90000000 and word&31==13;imm=((word>>5)&0x7ffff)<<2|((word>>29)&3);imm=imm-(1<<21)if imm&(1<<20)else imm;page=((a&~4095)+(imm<<12))&((1<<64)-1);assert page==0xfffffe000ccc2000==int(kill['decoded_page_value64'],16)
 kill_tests=[]
 for initial in[0,1,0x8000000000000000,(1<<64)-1,0xa5a5a5a5a5a5a5a5,0x1234567887654321]:
  u=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM);u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);u.mem_map(a&~4095,4096);u.mem_write(a,raw);u.reg_write(ar.UC_ARM64_REG_X13,initial);u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);u.emu_start(a,a+4,count=1);assert u.reg_read(ar.UC_ARM64_REG_X13)==page and u.reg_read(ar.UC_ARM64_REG_NZCV)==0xa0000000;kill_tests.append({'register13_before':hex(initial),'register13_after':hex(page),'NZCV_after':'0xa0000000'});counts['independent_kill_instruction_cases']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts']and[n for n,q in qs]==[q['name']for q in proof['proofs']]
 for(name,q),row in zip(qs,proof['proofs']):
  op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   solver=z3.Solver();solver.set(timeout=30000);solver.add(f);assert str(solver.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected and len(expected)==379;fresh=[];native_entries={x for api in continued['lock_apis']for x in[api['wrapper']['start'],api['stub']['start'],api['binding']['target']]}
 def edge(r,ix,target,mod):
  candidates=[z for z in r['source_reads']if z['source_visit_index']<ix and z['size_bytes']==8 and T<=int(z['address'],16)<0xfffffe0008471c00 and z['bytes_hex']==struct.pack('<Q',int(target,16)).hex()];assert candidates,(ix,target);ptr=pointer(k,int(candidates[-1]['address'],16));assert ptr['target']==target and ptr['authenticated']and int(ptr['diversity'],16)==mod;slots[ptr['slot']]=ptr;counts['original_state_authenticated_edges']+=1
 for j,(case,retained)in enumerate(zip(expected,p['cases'])):
  f=State(case);r=f.run();del f;assert r==retained,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);boundaries[r['boundary']['kind']]+=1
  assert not any(r[n]for n in['native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','native_object_free_executed','native_complete_business_handler_executed','native_synchronization_executed','external_IPC_emission_proved','full_goal_complete','dead_register_value_live_at_boundary','uninitialized_values_consumed']);assert not any(x['pc']in native_entries for x in r['source_visits']);assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])))
  snaps=[{'source_visit_index':x['source_visit_index'],'out_reference':s}for x in r['readback_returns']for s in x['snapshots'].values()]+[{'source_visit_index':x['source_visit_index'],'out_reference':x['record']}for x in r['readback_calls']+r['continuation_calls']+r['continuation_returns']+r['state_stop_calls']+r['state_stop_returns']if x['record']is not None]
  if r['continuation_entry']is not None:snaps.append({'source_visit_index':r['continuation_entry']['source_visit_index'],'out_reference':r['continuation_entry']['record']})
  for w in r['state_dead_load_windows']:snaps.append({'source_visit_index':w['origin']['source_visit_index'],'out_reference':w['origin']['snapshot']})
  if r['unexecuted_unknown_private_read']is not None:snaps.append({'source_visit_index':len(r['source_visits']),'out_reference':r['unexecuted_unknown_private_read']['snapshot']})
  audit({**r,'observations':r['observations']+snaps},response,prior,ctor,fields,execute,k,counts,handlers)
  previous=old['cases'][j]if j<355 else next(x for x in old['cases']if x['input']=={a:b for a,b in case.items()if a!='context_cache_fixture'});cut=len(previous['source_visits']);assert r['source_visits'][:cut]==previous['source_visits'];assert(r['state_prior_boundary']if r['state_prior_boundary']is not None else r['boundary'])==previous['boundary']
  for name in['source_reads','source_writes','source_calls','source_dispatches','models']:assert[x for x in r[name]if x['source_visit_index']<cut]==previous[name],(j,name)
  counts['preceding_complete_prefixes_equal'if j<355 else'additional_context_fixture_prefixes_equal']+=1
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64'];counts['FP64_contexts_preserved']+=1
  for model in r['models']:
   assert not model['target_executed']and not model['memory_effects_modeled'];counts['register_only_models']+=1
   if model['kind']=='stop_stream_free_register_clobbers':assert model['pc']=='0xfffffe000a517dd0'and model['target']=='0xfffffe000c4ba368'and model['registers8'][0]=='0xfffffe000847af60'and int(model['registers8'][1],16)in[OBJECT,RESPONSE];edge(r,model['source_visit_index'],model['target'],0x560f);counts['source_stop_stream_free_preparations']+=1
  for x in r['source_dispatches']:
   if x['source_visit_index']>=cut:edge(r,x['source_visit_index'],x['target'],int(x['registers31'][17],16))
  for x in r['source_calls']:
   if x['source_visit_index']>=cut:
    assert x['target_executed_in_private_guest']and r['source_visits'][x['source_visit_index']+1]['pc']==x['target'];ins=next(CS.disasm(k.read(int(x['pc'],16),4),int(x['pc'],16)))
    if ins.mnemonic=='blraa':edge(r,x['source_visit_index'],x['target'],0x9f59 if x['pc']=='0xfffffe000a50d254'else 0x84cc)
    else:assert ins.mnemonic=='bl'and int(ins.op_str[1:],16)==int(x['target'],16)
  for w in r['state_dead_load_windows']:
   origin=w['origin'];idx=origin['source_visit_index'];pc=origin['pc'];i=next(cs.disasm(k.read(int(pc,16),4),int(pc,16)));reads,writes=i.regs_access();assert[i.reg_name(x)for x in reads]==['sp']and 'x13'in[i.reg_name(x)for x in writes];assert w['cache_predicate']=={'address':'0xfffffe000ccc78d0','value64':'0x0'};assert r['source_visits'][idx]['pc']==pc;assert origin['snapshot']['known_mask_hex'][:16]=='00'*8 and origin['snapshot']['provenance_hex'][:16]=='00'*8
   epochs=[x for x in r['source_reads']if x['source_visit_index']==idx and x.get('discarded_dead_load')];assert len(epochs)==1 and epochs[0]['address']==w['unknown_address']and epochs[0]['size_bytes']==8
   rows=w['intervening'];assert len(rows)==(82 if pc=='0xfffffe000a57eef8'else 85);assert[x['source_visit_index']for x in rows]==list(range(idx+1,idx+1+len(rows)))
   for n,row in enumerate(rows):
    a=int(row['pc'],16);assert k.read(a,4).hex()==row['bytes_hex']and r['source_visits'][row['source_visit_index']]['pc']==row['pc'];i=next(cs.disasm(k.read(a,4),a));rd,wr=i.regs_access();assert[i.reg_name(x)for x in rd]==row['reads']and[i.reg_name(x)for x in wr]==row['writes'];assert not any(x in['x13','w13']for x in row['reads'])
    if n<len(rows)-1:assert not re.search(r'\b[wx]13\b',i.op_str)and not any(x in['x13','w13']for x in row['writes'])
    else:assert row==w['kill']and row['pc']==c['kill']['pc']and row['bytes_hex']==c['kill']['bytes_hex']and i.mnemonic=='adrp'and row['reads']==[]and row['writes']==['x13']
    counts['source_dead_window_instructions']+=1
   assert w['register13_after']=='0xfffffe000ccc2000';counts['source_dead_load_windows']+=1
  assert r['uninitialized_private_loads']==[x for x in r['source_reads']if x.get('discarded_dead_load')]
  for x in r['source_reads']:
   if x['address']=='0xfffffe000ccc78d0':assert x['bytes_hex']==bytes(8).hex()and not case.get('context_cache_fixture');counts['source_zero_context_cache_reads']+=1
  assert not any(x['address']=='0xfffffe000ccc78d0'for x in r['source_writes'])
  if case.get('context_cache_fixture'):
   assert len(r['state_load_predicates'])==1 and r['state_load_predicates'][0]['value64']==hex(P+0xe800)and not r['state_dead_load_windows']and r['unexecuted_unknown_private_read']is not None and r['boundary']['kind']=='before_uninitialized_private_read';counts['nonnull_context_guard_retained_cases']+=1
  elif r['state_dead_load_windows']:
   assert r['source_execution_wrapper_returned']and r['boundary']['kind']=='continued_wrapper_returned_to_provider'and r['boundary']['registers31'][0]=='0xffffffff'and r['unexecuted_unknown_private_read']is None;assert bytes.fromhex(r['workspace']['bytes_hex'])[48:52]==struct.pack('<I',0x5e561848);counts['source_resolved_context_error_returns']+=1
  if r['original_stop_method_return_executed']:
   assert r['state_stop_wrapper_return']['registers31'][0]=='0x0'and r['source_execution_wrapper_returned']and r['source_stop_local_success_executed'];assert r['boundary']['pc']==hex(P+0x1f000)and r['boundary']['registers31'][0]=='0x0'and r['boundary']['SP']==r['entry_SP'];assert[int(x,16)for x in r['boundary']['registers31'][19:30]]==[0x111100000000+i*0x1111 for i in range(19,30)];assert len(r['state_stop_calls'])==len(r['state_stop_returns'])==4;assert len([x for x in r['models']if x['kind']=='stop_stream_free_register_clobbers'])==2;counts['original_stop_method_returns']+=1
  for x in r['state_stop_returns']:
   call=max((z for z in r['state_stop_calls']if z['pc']==x['call_pc']and z['source_visit_index']<x['source_visit_index']),key=lambda z:z['source_visit_index']);assert call['SP']==x['SP']and call['registers31'][19:30]==x['registers31'][19:30];counts['stop_cleanup_GP_SP_returns']+=1
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==379 and counts['source_visits']==1258134 and counts['register_only_models']==2104 and counts['source_dead_load_windows']==24 and counts['source_dead_window_instructions']==2004 and counts['discarded_unknown_load_epochs']==24 and counts['original_stop_method_returns']==12 and counts['nonnull_context_guard_retained_cases']==24 and counts['source_stop_stream_free_preparations']==24
 deps={n:sha(ROOT/n)for n in['probe_lskd_state.py','lskd_state_spec.py','lskd_state_contracts.json','lskd_state_audit.py','lskd_state_symbolic.py','lskd_state_proofs.json','lskd_continuations_profiles.json','lskd_values_symbolic.py','lskd_state_profiles.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_state_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundary_coverage':dict(boundaries),'original_state_slots':list(slots.values()),'kill_instruction_cases':kill_tests,'kill_instruction_decoded_value64':hex(page),'unicorn_version':unicorn.__version__,'capstone_version':capstone.__version__,'fresh_replays_sha256':sha(ROOT/'lskd_state_replays.json'),'all_checks_pass':True,'model_memory_writes':0,'uninitialized_values_consumed':0,'native_target_executed':False,'native_synchronization_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_state_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundaries':dict(boundaries)}),flush=True)
if __name__=='__main__':main()
