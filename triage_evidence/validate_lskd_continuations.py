#!/usr/bin/env python3
"""Fresh continuation replay, byte epochs, context codecs and lock boundaries.

O(B+C*(V+E)+I+256R) time/space plus solver-dependent checking (30 s/query).
No native heap, synchronization, cryptographic, target-file or IPC operation.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from probe_lskd_continuations import Continuations,cases
from validate_lskd_values import audit
from lskd_continuations_symbolic import queries
from probe_lskd_response import P,OBJECT,RESPONSE
T=0xfffffe000846c420

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def main():
 c=read('lskd_continuations_contracts.json');prior_readback=read('lskd_readback_contracts.json');p=read('lskd_continuations_profiles.json');proof=read('lskd_continuations_proofs.json');old=read('lskd_readback_profiles.json');prior=read('legacy_stack_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');response=read('lskd_response_contracts.json');handlers=read('lskd_handlers_contracts.json');handlers={**handlers,'additional_mutable_globals':handlers['additional_mutable_globals']+prior_readback['additional_mutable_globals']+c['additional_mutable_globals']};k=Kernel();counts=Counter();slots={};boundaries=Counter();extra_rules=[]
 for obj,name in[(c,'recover_lskd_continuations.py'),(p,'probe_lskd_continuations.py'),(proof,'prove_lskd_continuations.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256']and sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)and IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['bounded_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for d in c['additional_mutable_globals']:assert k.read(int(d['address'],16),8).hex()==d['original8_hex'];counts['additional_controller_cells']+=1
 assert k.read(0xfffffe000ccc78a8,8).hex()==c['cached_RW_cell']['original8_hex']=='0000000000000000'
 for label,l,r,key,add in[('cached_global_acquire',0x79172c0,0x7919cb0,0x8d,-0x25),('cached_global_free',0x79174c0,0x7919db0,0x18,-0xb8)]:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=0xfffffe00084716e0);assert b['target']=='0xfffffe000ccc78a8';b.update(label=label,base='0xfffffe00084716e0',left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));extra_rules.append(b)
 for b in c['bank_rules']+extra_rules:
  l,r=int(b['left'],16),int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(r,256).hex()==b['right256_hex'];now=selected(l,r,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(now[n]==b[n]for n in now)and pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_bank_rules']+=1;counts['bank_byte_input_checks']+=256
 for a in c['lock_apis']:
  for s in[a['wrapper'],a['stub']]:
   now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now)
  b=a['binding'];assert pointer(k,int(b['slot'],16))==b and k.symbols([int(b['target'],16)])[b['target']]==a['exact_target_symbols'];counts['original_lock_API_bindings']+=1
 for o in c['bounded_pointer_aliases']+ [{'pointer':x}for x in c['lock_control_slots']]:assert pointer(k,int(o['pointer']['slot'],16))==o['pointer']
 qs,lifts=queries(c,prior_readback);assert lifts==proof['source_lift_counts']and[n for n,q in qs]==[q['name']for q in proof['proofs']]
 for(name,q),row in zip(qs,proof['proofs']):
  op,np=ROOT/row['original_file'],ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for f in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   solver=z3.Solver();solver.set(timeout=30000);solver.add(f);assert str(solver.check())=='unsat',name
  counts['source_proof_pairs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected and len(expected)==355;fresh=[];native_entries={x for a in c['lock_apis']for x in[a['wrapper']['start'],a['stub']['start'],a['binding']['target']]}
 def edge(r,ix,target,mod):
  candidates=[z for z in r['source_reads']if z['source_visit_index']<ix and z['size_bytes']==8 and T<=int(z['address'],16)<0xfffffe0008471c00 and z['bytes_hex']==struct.pack('<Q',int(target,16)).hex()];assert candidates,(ix,target);ptr=pointer(k,int(candidates[-1]['address'],16));assert ptr['target']==target and ptr['authenticated']and int(ptr['diversity'],16)==mod;slots[ptr['slot']]=ptr;counts['original_authenticated_edges']+=1
 for j,(case,retained)in enumerate(zip(expected,p['cases'])):
  g=Continuations(case);r=g.run();del g;assert r==retained,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);boundaries[r['boundary']['kind']]+=1
  assert not any(r[f]for f in['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','external_IPC_emission_proved','full_goal_complete','native_object_free_executed','native_complete_business_handler_executed','native_synchronization_executed'])
  assert not any(v['pc']in native_entries or v['pc']=='0xfffffe000a5793bc'for v in r['source_visits']);assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])))
  snaps=[{'source_visit_index':x['source_visit_index'],'out_reference':s}for x in r['readback_returns']for s in x['snapshots'].values()]+[{'source_visit_index':x['source_visit_index'],'out_reference':x['record']}for x in r['readback_calls']+r['continuation_calls']+r['continuation_returns']if x['record']is not None]
  if r['continuation_entry']is not None:snaps.append({'source_visit_index':r['continuation_entry']['source_visit_index'],'out_reference':r['continuation_entry']['record']})
  if r['unexecuted_unknown_private_read']is not None:snaps.append({'source_visit_index':len(r['source_visits']),'out_reference':r['unexecuted_unknown_private_read']['snapshot']})
  audit({**r,'observations':r['observations']+snaps},response,prior,ctor,fields,execute,k,counts,handlers)
  previous=old['cases'][j]if j<343 else next(x for x in old['cases']if x['input']=={a:b for a,b in case.items()if a!='entity_fixture'});cut=len(previous['source_visits']);assert r['source_visits'][:cut]==previous['source_visits'];assert(r['preceding_readback_boundary']if r['preceding_readback_boundary']is not None else r['boundary'])==previous['boundary']
  for name in['source_reads','source_writes','source_calls','source_dispatches','models']:assert[x for x in r[name]if x['source_visit_index']<cut]==previous[name],(j,name)
  counts['preceding_complete_prefixes_equal'if j<343 else'additional_presence_fixture_prefixes_equal']+=1
  assert not any(any(int(d['address'],16)<=int(x['address'],16)<int(d['address'],16)+8 for d in c['additional_mutable_globals'])or x['address']=='0xfffffe000ccc78a8'for x in previous['source_reads'])
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64'];counts['FP64_contexts_preserved']+=1
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled'];counts['register_only_models']+=1
  for x in r['continuation_branches']:edge(r,x['source_visit_index'],x['target'],int(x['registers31'][17],16))
  for x in r['continuation_calls']:
   i=next(CS.disasm(k.read(int(x['pc'],16),4),int(x['pc'],16)))
   if i.mnemonic=='blraa':edge(r,x['source_visit_index'],x['target'],int(x['registers31'][17],16))
   else:assert i.mnemonic=='bl'and int(i.op_str[1:],16)==int(x['target'],16)
   if x['source_visit_index']==len(r['source_visits']):assert x['target']=='0xfffffe000a508d94'and x['registers31'][0]==hex(P+0xe000);counts['unexecuted_RW_write_calls']+=1
   else:assert r['source_visits'][x['source_visit_index']+1]['pc']==x['target'];counts['original_continuation_calls']+=1
   if x['target']=='0xfffffe000a54e220':
    b=bytes.fromhex(x['record']['bytes_hex']);R=int(x['record']['address'],16);D=(struct.unpack_from('<I',b,8)[0]-((R^0x1d65dad0)*0xe9655f4d))&0xffffffff;assert D==0x2d2 and struct.unpack_from('<Q',b)[0]==0;counts['source_acquisition_records']+=1
   elif x['target']=='0xfffffe000a551f38':
    b=bytes.fromhex(x['record']['bytes_hex']);R=int(x['record']['address'],16);D=(struct.unpack_from('<I',b)[0]-((R^0xdfb9786f)*0x1e2776fd))&0xffffffff;assert D==0x1d3 and struct.unpack_from('<Q',b,8)[0]==0;counts['source_release_records']+=1
   elif x['target']=='0xfffffe000a5529a8':
    b=bytes.fromhex(x['record']['bytes_hex']);R=int(x['record']['address'],16);assert(struct.unpack_from('<I',b)[0]-((R^0xb0a65f3a)*0x4ca11177))&0xffffffff==0x52f;counts['source_cached_free_records']+=1
   elif x['target']in['0xfffffe000a52f9f4','0xfffffe000a55ce30']:
    b=bytes.fromhex(x['record']['bytes_hex']);R=int(x['record']['address'],16);vault=x['target']=='0xfffffe000a52f9f4';K=((R^(0x0cf045eec410a4c0 if vault else 0x0448a65ef71c80fa))*(0xaed3b63b if vault else 0xdd76ff8f))&((1<<64)-1);assert(struct.unpack_from('<I',b,16 if vault else 48)[0]+K)&0xffffffff==(0x72d if vault else 0x8ac);value=struct.unpack_from('<Q',b,64 if vault else 40)[0]^K;assert value==(case['context64']^(0xe5fc6c5572d2c184 if vault else 0xfc6c08b9c3804423));counts['context_record_roundtrips']+=1
    if not vault:assert(struct.unpack_from('<I',b,32)[0]+K-0x04ccbe9b)&0xffffffff==0x13579bdf;counts['allowed_scalar_record_roundtrips']+=1
   elif x['target']=='0xfffffe000a561058':
    assert int(x['registers31'][0],16)<=int(x['registers31'][1],16);root=next(z for z in r['continuation_calls']if z['target']in['0xfffffe000a52f9f4','0xfffffe000a55ce30']);b=bytes.fromhex(root['record']['bytes_hex']);vault=root['target']=='0xfffffe000a52f9f4';assert int(x['registers31'][0],16)==struct.unpack_from('<Q',b,32 if vault else 56)[0]+(64 if vault else 128)and int(x['registers31'][1],16)==struct.unpack_from('<Q',b,48 if vault else 24)[0];counts['source_bounds_argument_pairs']+=1
  for x in r['continuation_returns']:
   call=max((a for a in r['continuation_calls']if a['pc']==x['call_pc']and a['source_visit_index']<x['source_visit_index']),key=lambda a:a['source_visit_index']);assert x['SP']==call['SP']and x['registers31'][19:30]==call['registers31'][19:30];counts['GP_and_SP_helper_returns']+=1
   if x['target']in['0xfffffe000a54e220','0xfffffe000a551f38','0xfffffe000a5529a8']:assert x['record']==call['record'];counts['lock_records_preserved']+=1
   if x['target']in['0xfffffe000a52f9f4','0xfffffe000a55ce30']:
    b=bytes.fromhex(x['record']['bytes_hex']);assert struct.unpack_from('<I',b,56 if x['target']=='0xfffffe000a52f9f4'else 0)[0]==0x5e55719c;counts['source_context_zero_helper_errors']+=1
  for z in r['source_reads']:
   if z['address']=='0xfffffe000ccc78a8':assert z['bytes_hex']==(struct.pack('<Q',P+0xe000).hex()if case.get('entity_fixture')else bytes(8).hex());counts['cached_RW_read_epochs']+=1
  assert not any(z['address']=='0xfffffe000ccc78a8'for z in r['source_writes'])
  if r['unexecuted_unknown_private_read']is not None:
   q=r['unexecuted_unknown_private_read'];pc=q['instruction']['pc'];s=q['snapshot'];sp=int(r['boundary']['SP'],16);assert pc==r['boundary']['pc']and not any(v['pc']==pc for v in r['source_visits']);assert pc in['0xfffffe000a57eef8','0xfffffe000a57282c'];assert int(s['address'],16)==sp+(24 if pc.endswith('7eef8')else 88);assert s['known_mask_hex']==('00'*8+'01'*8 if pc.endswith('7eef8')else'00'*8);assert s['bytes_hex'][:16]=='a5'*8
   if pc.endswith('7eef8'):assert s['bytes_hex'][16:]==struct.pack('<Q',0xfffffe000a56a150).hex();assert any(z['pc']=='0xfffffe000a57ee04'and int(z['address'],16)==sp+32 and z['after_hex']==s['bytes_hex'][16:]for z in r['source_writes'])
   counts['unexecuted_unknown_private_read_boundaries']+=1
  if r['continuation_entry']is not None:
   counts['continued_cases']+=1
   if case.get('entity_fixture'):assert r['boundary']['kind']=='continuation_unexecuted_call'
   elif case['operation32']==0x1b5a:
    assert r['source_stop_local_success_executed']and r['source_execution_wrapper_returned']and r['boundary']['registers31'][0]=='0x0';pub=r['response_publication'];assert pub is not None and pub['candidate']['bytes_hex']==bytes(160).hex()and r['response']['bytes_hex']==bytes(160).hex();assert r['execution_response_reference_final']['bytes_hex']==struct.pack('<Q',RESPONSE).hex();writes=[x for x in r['source_writes']if x['pc']=='0xfffffe000a522e44'];assert len(writes)==1 and writes[0]['after_hex']==struct.pack('<Q',RESPONSE).hex();counts['source_stop_zeroed_candidate_publications']+=1
   elif case.get('provider')in['vault','allowed']and case['context64']:assert r['boundary']['kind']=='before_uninitialized_private_read'
   else:assert r['source_execution_wrapper_returned']and r['boundary']['kind']=='continued_wrapper_returned_to_provider'and r['boundary']['registers31'][0]==('0xffffffff'if case.get('provider')=='avd'else'0xffff5953');counts['continued_context_error_wrapper_returns']+=1
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==355 and counts['source_visits']==1113798 and counts['register_only_models']==1912 and counts['continued_cases']==85 and counts['source_stop_zeroed_candidate_publications']==13 and counts['unexecuted_unknown_private_read_boundaries']==24 and counts['unexecuted_RW_write_calls']==12 and counts['context_record_roundtrips']==48 and counts['GP_and_SP_helper_returns']==159
 deps={n:sha(ROOT/n)for n in['probe_lskd_continuations.py','lskd_continuations_spec.py','lskd_continuations_contracts.json','lskd_continuations_symbolic.py','lskd_continuations_proofs.json','lskd_readback_contracts.json','lskd_readback_profiles.json','lskd_values_symbolic.py','validate_lskd_values.py','lskd_continuations_profiles.json']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_continuations_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundary_coverage':dict(boundaries),'additional_bank_rules':extra_rules,'original_authenticated_slots':list(slots.values()),'fresh_replays_sha256':sha(ROOT/'lskd_continuations_replays.json'),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'all_checks_pass':True,'model_memory_writes':0,'native_target_executed':False,'native_synchronization_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_continuations_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'boundaries':dict(boundaries)}),flush=True)
if __name__=='__main__':main()
