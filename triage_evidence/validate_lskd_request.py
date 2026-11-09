#!/usr/bin/env python3
"""Fresh constructor/provider-prefix replay, source publication and byte audit.

O(B+C*(V+E)+W+256R+I) time/space plus solver cost. Typed heap return is a
declared register model; no native allocation/execute/IPC/lifetime proof.
"""
import gc,hashlib,json,struct
from collections import Counter
from pathlib import Path
import z3
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from recover_lskd_request import census
from probe_lskd_request import Request,cases,P,M64,OBJECT,PARAM,OUT,OTHER_OUT
from lskd_request_symbolic import queries,key_forms
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def ctor_key(r):return((((2*(r&0x3785b370)-r+0xc87a4c8c)&0xffffffff)^0x0499ffe6)*0x9a00b30b)&0xffffffff
def expected_object(op,n,b,appended=None):
 raw=bytearray(160);struct.pack_into('<4I',raw,0,1,op,n,(b+4*n)&0xffffffff);struct.pack_into('<Q',raw,144,OBJECT+16)
 if appended is not None:raw[16:28]=struct.pack('>HHQ',0x72,8,appended);struct.pack_into('<II',raw,152,1,12)
 return raw
def audit(r,c,prior,k,counts):
 state={};known=set();prov={};initial={};events={};snapshots={};case=r['input'];globals=prior['mutable_globals']+c['additional_mutable_globals']
 for j,d in enumerate(globals):
  a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if case['global_fixture']=='original'else 0 if case['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
 for a,raw in[(OUT,struct.pack('<Q',case['out_initial64'])),(OTHER_OUT,bytes(8)),(PARAM,bytes.fromhex(r['initial_params256_hex']))]:
  for x,v in enumerate(raw,a):initial[x]=v;known.add(x);prov[x]=3
 guard=int(prior['guard']['address'],16);initial.update({guard+n:b for n,b in enumerate(bytes.fromhex(prior['guard']['original8_hex']))})
 def base(a):
  if a in initial:return initial[a]
  if P<=a<P+0x20000:return 0xa5
  try:return IMAGE.read(a,1)[0]
  except ValueError:return k.read(a,1)[0]
 def bytes_at(a,n):return bytes(state.get(x,base(x))for x in range(a,a+n))
 def snap(s):
  a=int(s['address'],16);n=s['size_bytes'];assert bytes_at(a,n).hex()==s['bytes_hex'];assert bytes(int(x in known)for x in range(a,a+n)).hex()==s['known_mask_hex'];assert bytes(prov.get(x,0)for x in range(a,a+n)).hex()==s['provenance_hex']
 for e in r['source_reads']:events.setdefault(e['source_visit_index'],[]).append(('read',e))
 for e in r['source_writes']:events.setdefault(e['source_visit_index'],[]).append(('write',e))
 for call in r['source_calls']:snapshots.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload']if n in call)
 for o in r['observations']:snapshots.setdefault(o['source_visit_index'],[]).extend([o['out_reference'],o['object']])
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snapshots.get(ix,[]):snap(s)
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert not e['probe_only']and bytes_at(a,n).hex()==e['bytes_hex'],(e['pc'],hex(a))
    if P<=a<a+n<=P+0x20000:assert all(x in known for x in range(a,a+n)),(e['pc'],hex(a))
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in globals)
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);prov[x]=1
    counts['source_write_epochs']+=1
 for s in[r['object'],r['params'],r['out_reference'],r['boundary_memory']]:
  if s is not None:snap(s)
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1
def main():
 c=read('lskd_request_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');p=read('lskd_request_profiles.json');proof=read('lskd_request_proofs.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_lskd_request.py'),(p,'probe_lskd_request.py'),(proof,'prove_lskd_request.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for f in c['kernel_functions']:assert k.function(int(f['start'],16))==f;counts['new_kernel_helpers']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];assert census()==c['append_reference_census'];counts['direct_appender_callers']=len(c['providers']);counts['census_text_words']=c['append_reference_census']['text_words_scanned']
 for b in prior['bank_rules']+tlv['bank_rules']+c['bank_rules']:
  l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 for b in c['dispatch_slots']:assert pointer(k,int(b['original_pointer']['slot'],16))==b['original_pointer'];counts['new_dispatch_slots']+=1
 d=c['typed_view'];assert k.read(int(d['address'],16),64).hex()==d['bytes64_hex'];assert pointer(k,int(d['name_pointer']['slot'],16))==d['name_pointer'];assert d['name']=='site.LSKDDispatchStream'and d['metadata_size32']==160;assert pointer(k,int(c['fill_binding']['slot'],16))==c['fill_binding'];x=c['supplied_calls_excerpt'];path=Path(x['path']);assert sha(path)==x['sha256']and ''.join(path.read_text().splitlines(keepends=True)[70:74])==x['text']
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 ce=read('lskd_request_alignment_counterexample.json');assert sha(ROOT/'lskd_request_alignment_counterexample.json')==proof['alignment_counterexample_sha256'];R,ko,kd,_=key_forms(c);address=int(ce['record_address64'],16);assert address&7;ko_v=z3.simplify(z3.substitute(ko,(R,z3.BitVecVal(address,64)))).as_long();kd_v=z3.simplify(z3.substitute(kd,(R,z3.BitVecVal(address,64)))).as_long();assert ko_v==int(ce['encoder_key32'],16)!=kd_v==int(ce['decoder_key32'],16);counts['alignment_counterexamples']=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[]
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Request(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['undefined_private_value_reads']and not r['native_API_executed']and not r['typed_heap_executed']and not r['request_execution_executed']and not r['native_carrier_validity_proved'];assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,c,prior,k,counts)
  assert not any(0xfffffe000a50c508<=int(v['pc'],16)<0xfffffe000a50c980 or int(v['pc'],16)in[0xfffffe000c4ba154,0xfffffe000c4ba60c]for v in r['source_visits'])
  if r['boundary']['kind']=='returned':assert r['boundary']['SP']==r['entry_SP']
  calls=r['source_calls'];models=r['models'];ow=[w for w in r['source_writes']if OBJECT<=int(w['address'],16)<OBJECT+160];pub=[w for w in r['source_writes']if w['pc']=='0xfffffe000a53191c'];ctorcalls=[v for v in calls if v['kind']=='constructor_record'];initcalls=[v for v in calls if v['kind']=='initializer_record']
  for call in calls:assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
  for call in ctorcalls:
   a=int(call['record']['address'],16);raw=bytes.fromhex(call['record']['bytes_hex']);assert a&15==8 and((int.from_bytes(raw[24:28],'little')-ctor_key(a))&0xffffffff)==0x6a5;counts['aligned_constructor_records']+=1
  for call in initcalls:assert int(call['record']['address'],16)&15==8;counts['aligned_initializer_records']+=1
  for m in models:assert m['target']=='0xfffffe000c4ba154'and m['registers8'][0]=='0xfffffe000847b160'and not m['target_executed']and not m['memory_effects_modeled'];counts['typed_heap_return_models']+=1
  if case['kind']=='provider'and case['guard']!='valid':
   assert not models and not calls and not ow and not pub;want=0xffff5bd9 if case['provider']=='avd'else 0xffff5966;assert r['boundary']['kind']=='returned'and int(r['boundary']['registers31'][0],16)==want and int(r['boundary']['SP'],16)==int(r['entry_SP'],16);assert r['params']['bytes_hex']==r['initial_params256_hex'];counts['provider_guard_returns']+=1;continue
  if case['kind']=='constructor':op,n,b,out=case['inputs8'][:4]
  else:provider=next(v for v in c['providers']if v['label']==case['provider']);op=provider['operation32'];n=provider['entry_limit32'];b=provider['payload_budget32'];out=int(r['out_address'],16)
  if not out:
   assert not models and not ow and not pub and r['out_reference']is None;assert r['boundary']['kind']=='returned'and int(r['boundary']['registers31'][0],16)==0xffff5966;counts['null_output_reference_returns']+=1;continue
  if not case['heap_nonnull']:
   assert len(models)==1 and models[0]['result_X0_fixture']=='0x0'and not ow and not pub;assert r['out_reference']['bytes_hex']==struct.pack('<Q',case['out_initial64']).hex()and r['boundary']['kind']=='returned'and int(r['boundary']['registers31'][0],16)==0xffff5964;counts['null_allocation_returns']+=1;continue
  assert len(models)==1 and models[0]['result_X0_fixture']==hex(OBJECT);fills=[w for w in ow if 0xfffffe000c648170<=int(w['pc'],16)<0xfffffe000c648218];assert{a for w in fills for a in range(int(w['address'],16),int(w['address'],16)+w['size_bytes'])}==set(range(OBJECT,OBJECT+160));assert all(int(w['after_hex'],16)==0 for w in fills);counts['source_zeroed_object_bytes']+=160;assert r['object']['known_mask_hex']=='01'*160 and r['object']['provenance_hex']=='01'*160
  capacity=(b+4*n)&0xffffffff
  if capacity>128:
   assert case['kind']=='constructor'and r['boundary']['kind']=='before_dynamic_allocation'and int(r['boundary']['registers31'][0],16)==capacity and not pub;assert r['out_reference']['bytes_hex']==struct.pack('<Q',case['out_initial64']).hex()and r['object']['bytes_hex']==expected_object(op,n,b).hex();counts['dynamic_allocation_boundaries']+=1;continue
  assert len(pub)==1 and pub[0]['address']==hex(out)and pub[0]['after_hex']==struct.pack('<Q',OBJECT).hex()and pub[0]['source_visit_index']>models[0]['source_visit_index'];assert r['out_reference']['bytes_hex']==pub[0]['after_hex']and r['out_reference']['provenance_hex']=='01'*8;counts['source_pointer_publications']+=1
  if case['kind']=='constructor':assert r['boundary']['kind']=='returned'and int(r['boundary']['registers31'][0],16)==0 and r['object']['bytes_hex']==expected_object(op,n,b).hex();counts['inline_constructor_returns']+=1
  else:
   assert r['boundary']['kind']=='before_next_provider_call'and r['boundary']['pc']==provider['boundary_call'];created=[v for v in calls if v['kind']=='provider_create'];assert len(created)==1 and[int(x,16)for x in created[0]['registers8'][:4]]==[op,n,b,out]and created[0]['out_reference']['bytes_hex']=='00'*8 and created[0]['out_reference']['provenance_hex']=='01'*8;obs=r['observations'];assert len(obs)==1 and obs[0]['object']['bytes_hex']==expected_object(op,n,b).hex()and obs[0]['source_visit_index']>pub[0]['source_visit_index']
   ac=[v for v in calls if v['kind']=='provider_append64'];assert len(ac)==1 and ac[0]['pc']==provider['append_call']and ac[0]['registers8'][:3]==[hex(OBJECT),'0x72',hex(case['context64'])];rs=[v for v in r['source_reads']if v['pc']==hex(int(provider['append_call'],16)-12)and v['address']==hex(out)];assert len(rs)==1 and rs[0]['bytes_hex']==pub[0]['after_hex']and rs[0]['source_visit_index']>pub[0]['source_visit_index'];assert r['object']['bytes_hex']==expected_object(op,n,b,case['context64']).hex();counts['provider_source_compositions']+=1;counts['provider_tag72_bytes']+=12
   params=bytearray.fromhex(r['initial_params256_hex'])
   if case['provider']=='avd':params[240:248]=bytes(8);counts['AVD_source_cleared_bytes']+=8
   assert r['params']['bytes_hex']==params.hex();regs=[int(x,16)for x in r['boundary']['registers31']]
   if case['provider']=='scalar64':assert regs[0]==OBJECT and r['boundary_memory']['bytes_hex']=='00'*8
   elif case['provider']in['vault','avd']:assert regs[0]==OBJECT and regs[1]==(0x8b if case['provider']=='vault'else 0x6b)and regs[3]==8;assert r['boundary_memory']['bytes_hex']==struct.pack('<Q',case['inputs8'][2]).hex();counts['next_field_pointer_representations']+=1
   else:assert regs[:3]==[OBJECT,0x7e,0x13579bdf];counts['next_scalar32_boundaries']+=1
  if j%12==0:gc.collect()
 assert counts['fresh_cases']==222 and counts['source_visits']==138546 and counts['source_pointer_publications']==96 and counts['provider_source_compositions']==48 and counts['source_zeroed_object_bytes']==18240
 deps={n:sha(ROOT/n)for n in['recover_lskd_request.py','probe_lskd_request.py','lskd_request_symbolic.py','prove_lskd_request.py','lskd_request_contracts.json','lskd_request_profiles.json','lskd_request_proofs.json','lskd_request_alignment_counterexample.json','legacy_tlv_symbolic.py','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']};out={'scope':'Distinct fresh private constructor/provider prefixes; complete retained/fresh equality.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'typed_heap_executed':False,'request_execution_executed':False,'full_goal_complete':False};(ROOT/'lskd_request_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replays_sha256':sha(ROOT/'lskd_request_replays.json'),'all_checks_pass':True,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_request_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
