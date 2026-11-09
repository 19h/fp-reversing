#!/usr/bin/env python3
"""Fresh full-prefix execution, byte audit and table/pointer/def-use provenance.

O(B+C*(V+E)+I+256R) time and O(B+C*(V+E)+I) retained space plus solver cost,
30 s/query. No native API/heap/synchronization/IPC or IDB mutation executes.
"""
import gc,hashlib,json,re,struct
from pathlib import Path
from collections import Counter
import z3,capstone
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_lskd_lookup import inventory,TABLE,POOL
from probe_lskd_lookup import Lookup,cases
from lskd_lookup_symbolic import queries
from lskd_lookup_audit import audit
from probe_legacy_stack import P
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_lookup_contracts.json');p=read('lskd_lookup_profiles.json');proof=read('lskd_lookup_proofs.json');state=read('lskd_state_contracts.json');old=read('lskd_state_profiles.json');old={json.dumps(r['input'],sort_keys=True):r for r in old['cases']if r['input'].get('context_cache_fixture')};continued=read('lskd_continuations_contracts.json');readback=read('lskd_readback_contracts.json');prior=read('legacy_stack_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');response=read('lskd_response_contracts.json');handlers=read('lskd_handlers_contracts.json');handlers={**handlers,'additional_mutable_globals':handlers['additional_mutable_globals']+readback['additional_mutable_globals']+continued['additional_mutable_globals']};k=Kernel();counts=Counter()
 for obj,name in[(c,'recover_lskd_lookup.py'),(p,'probe_lskd_lookup.py'),(proof,'prove_lskd_lookup.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_source_spans']+=1
 e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');assert inventory(k,e)==c['indexed_store_inventory'];counts['aligned_text_words_examined']=c['indexed_store_inventory']['aligned_words_examined'];counts['decoded_text_instructions']=c['indexed_store_inventory']['decoded_instruction_count'];counts['undecoded_text_words']=len(c['indexed_store_inventory']['undecoded_aligned_words']);counts['indexed_store_candidates']=len(c['indexed_store_inventory']['candidates'])
 assert k.read(TABLE,4096).hex()==c['table']['original4096_hex']==bytes(4096).hex()and IMAGE.read(TABLE,4096)==bytes(4096);assert c['table']['sha256']==hashlib.sha256(bytes(4096)).hexdigest();counts['original_table_bytes_checked']=4096
 for b in c['bank_rules']:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_table_root_banks']+=1;counts['bank_input_checks']+=256
 aliases=[]
 for delta in c['bounded_pointer_alias_deltas']:
  for va,off,n in IMAGE.segments:
   raw=IMAGE.data[off:off+n];needle=struct.pack('<Q',TABLE+delta);at=raw.find(needle)
   while at>=0:aliases.append({'bias_from_table_bytes':delta,'pointer':pointer(k,va+at)});at=raw.find(needle,at+1)
 assert aliases==c['bounded_pointer_aliases']and len(aliases)==2
 for ptr in c['secondary_dispatch_slots']+c['bank_input_slots']:assert pointer(k,int(ptr['slot'],16))==ptr
 qs,lifts=queries(c,state);assert lifts==proof['source_lift_counts']and len(qs)==15
 for(name,q),row in zip(qs,proof['proofs']):
  assert name==row['name']and row['result']=='unsat';op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   solver=z3.Solver();solver.set(timeout=30000);solver.add(f);assert str(solver.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 cs=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN);cs.detail=True;fresh=[];inputs=list(cases());assert len(inputs)==40 and[r['input']for r in p['cases']]==inputs
 for j,(case,retained)in enumerate(zip(inputs,p['cases'])):
  f=Lookup(case);r=f.run();del f;assert r==retained,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits'])
  assert r['boundary']['kind']=='continued_wrapper_returned_to_provider'and r['boundary']['registers31'][0]=='0xffff5953'and bytes.fromhex(r['workspace']['bytes_hex'])[48:52]==struct.pack('<I',0x5e55719c);assert r['source_execution_wrapper_returned']and not r['lookup_unexecuted_branch'];counts['source_lookup_error_wrapper_returns']+=1
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64'];counts['FP64_contexts_preserved']+=1
  for flag in['native_API_executed','native_heap_executed','native_synchronization_executed','native_object_free_executed','external_IPC_emission_proved','full_goal_complete','dead_register_value_live_at_boundary','uninitialized_values_consumed']:assert not r[flag],flag
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled'];counts['register_only_models']+=1
  snaps=[{'source_visit_index':x['source_visit_index'],'out_reference':s}for x in r['readback_returns']for s in x['snapshots'].values()]+[{'source_visit_index':x['source_visit_index'],'out_reference':x['record']}for x in r['readback_calls']+r['continuation_calls']+r['continuation_returns']if x['record']is not None]
  if r['continuation_entry']is not None:snaps.append({'source_visit_index':r['continuation_entry']['source_visit_index'],'out_reference':r['continuation_entry']['record']})
  for w in r['state_dead_load_windows']:snaps.append({'source_visit_index':w['origin']['source_visit_index'],'out_reference':w['origin']['snapshot']})
  for entry in r['lookup_entries']:snaps.append({'source_visit_index':entry['source_visit_index'],'out_reference':entry['saved_table_pointer']})
  audit({**r,'observations':r['observations']+snaps},response,prior,ctor,fields,execute,k,counts,handlers)
  if j<24:
   previous=old[json.dumps(case,sort_keys=True)];cut=len(previous['source_visits']);assert r['source_visits'][:cut]==previous['source_visits']and r['lookup_prior_boundary']==previous['boundary']
   for n in['source_reads','source_writes','source_calls','source_dispatches','models']:assert[x for x in r[n]if x['source_visit_index']<cut]==previous[n],(j,n)
   counts['preceding_complete_prefixes_equal']+=1
  provider=case['provider'];store='0xfffffe000a52fcb0'if provider=='vault'else'0xfffffe000a55d158';load='0xfffffe000a52fca8'if provider=='vault'else'0xfffffe000a55d150'
  ws=[x for x in r['source_writes']if x['pc']==store];rd=[x for x in r['source_reads']if x['pc']==load];assert len(ws)==len(rd)==1 and ws[0]['after_hex']==struct.pack('<Q',TABLE).hex()and rd[0]['address']=='0xfffffe0008471af8'and rd[0]['bytes_hex']==struct.pack('<Q',TABLE+8).hex();counts['source_table_pointer_stores']+=1
  assert not any(TABLE<=int(x['address'],16)<TABLE+4096 for x in r['fixture_additions'])and not any(int(x['address'],16)<TABLE+4096 and int(x['address'],16)+x['size_bytes']>TABLE for x in r['source_writes'])
  for entry in r['lookup_entries']:
   s=entry['saved_table_pointer'];assert s['address']==ws[0]['address']and s['bytes_hex']==struct.pack('<Q',TABLE).hex()and s['known_mask_hex']=='01'*8 and s['provenance_hex']=='01'*8;counts['source_pointer_store_to_lookup_pairs']+=1
  key=case['context64']&0xffffffff;at=TABLE+4*(key&0x3ff);table_reads=[x for x in r['source_reads']if TABLE<=int(x['address'],16)<TABLE+4096]
  assert len(table_reads)==(0 if case['context64']==0 else 2 if key==0 else 1)
  for x in table_reads:assert int(x['address'],16)==at and x['size_bytes']==4 and x['bytes_hex']=='00000000';counts['original_table_u32_read_epochs']+=1
  if case['context64']==0:assert not r['lookup_entries']and not r['state_dead_load_windows'];counts['source_zero_context_rejections']+=1
  elif key==0:
   expected='0xfffffe000a56dfb8'if provider=='vault'else'0xfffffe000a52dc00';assert table_reads[1]['pc']==expected;counts['zero_key_second_stage_rejections']+=1
  for w in r['state_dead_load_windows']:
   assert w['cache_predicate']=={'address':'0xfffffe000ccc78d0','value64':hex(P+0xe800)};origin=w['origin'];idx=origin['source_visit_index'];rows=w['intervening'];assert len(rows)==(102 if provider=='vault'else 34)and[x['source_visit_index']for x in rows]==list(range(idx+1,idx+1+len(rows)));assert origin['snapshot']['known_mask_hex'][:16]=='00'*8 and origin['snapshot']['provenance_hex'][:16]=='00'*8
   for n,row in enumerate(rows):
    addr=int(row['pc'],16);raw=k.read(addr,4);assert raw.hex()==row['bytes_hex']and r['source_visits'][row['source_visit_index']]['pc']==row['pc'];ins=next(cs.disasm(raw,addr));rd,wr=ins.regs_access();assert[ins.reg_name(x)for x in rd]==row['reads']and[ins.reg_name(x)for x in wr]==row['writes'];assert not any(x in['x13','w13']for x in row['reads'])
    if n<len(rows)-1:assert not re.search(r'\b[wx]13\b',ins.op_str)and not any(x in['x13','w13']for x in row['writes'])
    else:
     assert row==w['kill']
     if provider=='vault':assert row['pc']=='0xfffffe000a551f64'and ins.mnemonic=='adrp'and row['reads']==[]and row['writes']==['x13']and w['register13_after']=='0xfffffe000ccc2000'
     else:assert row['pc']=='0xfffffe000a531164'and ins.mnemonic=='and'and row['reads']==['w11']and row['writes']==['w13']and int(w['register13_after'],16)==key&0x3ff
    counts['source_dead_window_instructions']+=1
   counts['source_dead_load_windows']+=1
  assert r['uninitialized_private_loads']==[x for x in r['source_reads']if x.get('discarded_dead_load')]
  if j%8==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==40 and counts['source_visits']==228037 and counts['register_only_models']==280 and counts['source_dead_load_windows']==38 and counts['source_dead_window_instructions']==2584 and counts['original_table_u32_read_epochs']==42 and counts['zero_key_second_stage_rejections']==4 and counts['preceding_complete_prefixes_equal']==24
 deps={n:sha(ROOT/n)for n in['probe_lskd_lookup.py','recover_lskd_lookup.py','lskd_lookup_contracts.json','lskd_lookup_audit.py','lskd_lookup_symbolic.py','lskd_lookup_proofs.json','lskd_state_profiles.json','lskd_lookup_profiles.json']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_lookup_replays.json').write_text(json.dumps(out,indent=2)+'\n')
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replays_sha256':sha(ROOT/'lskd_lookup_replays.json'),'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'all_checks_pass':True,'model_memory_writes':0,'uninitialized_values_consumed':0,'native_target_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_lookup_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
