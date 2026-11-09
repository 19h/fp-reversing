#!/usr/bin/env python3
"""Fresh value-decoder, caller-handoff, shape and query-publication verification.

O(B+C*(V+E)+256R+I) time/space plus solver-dependent cost (30 s/query).
Only declared allocator/free register models; no native target/heap/API/IPC.
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
from probe_lskd_values import Values,cases
from probe_lskd_response import P,M64,OBJECT,PARAM,OUT,WORK,AUX,RESPONSE,SEPARATED_AUX
from probe_lskd_request import OTHER_OUT
from lskd_values_symbolic import queries
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def rec(tag,b):return struct.pack('>HH',tag,len(b))+b
def provider_request(case,p):
 packet=rec(0x72,struct.pack('>Q',case['context64']));extra=[]
 if case['provider']=='vault':extra=[(0x8b,struct.pack('<Q',OTHER_OUT))]
 elif case['provider']=='avd':extra=[(t,struct.pack('<Q',PARAM+off))for t,off in[(0x6b,0),(0x6c,0xa0),(0x89,0x60),(0x8a,0xbc)]]
 elif case['provider']=='allowed':extra=[(0x7e,struct.pack('>I',0x13579bdf))]
 for tag,b in extra:packet+=rec(tag,b)
 obj=bytearray(160);struct.pack_into('<4I',obj,0,1,p['operation32'],p['entry_limit32'],p['capacity32']);obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,1+len(extra),len(packet));return obj
def workspace(request,out,aux,status=None):
 raw=bytearray(b'\xa5'*0x4000);known=bytearray(0x4000);key=((WORK^0xae0701e7)*0x952f3cb7)&0xffffffff
 for off,fmt,v in[(0,'Q',request),(8,'Q',WORK+64),(16,'I',key^0x563),(24,'Q',aux),(32,'Q',WORK+0x4000),(40,'Q',aux+0x1000),(56,'Q',out)]+([]if status is None else[(48,'I',status)]):
  b=struct.pack('<'+fmt,v);raw[off:off+len(b)]=b;known[off:off+len(b)]=b'\1'*len(b)
 return raw,known
def audit(r,c,prior,ctor,fields,execute,k,counts,handlers_contract):
 state={};known=set();prov={};initial={};events={};snaps={};case=r['input'];globals=prior['mutable_globals']+ctor['additional_mutable_globals']+fields['additional_mutable_globals']+execute['additional_mutable_globals']+c['additional_mutable_globals']+handlers_contract['additional_mutable_globals']
 for j,d in enumerate(globals):
  a=int(d['address'],16);v=int.from_bytes(bytes.fromhex(d['original8_hex']),'little')if case['global_fixture']=='original'else 0 if case['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;initial.update({a+n:b for n,b in enumerate(struct.pack('<Q',v))})
 fixtures=[(OUT,struct.pack('<Q',case['out_initial64'])),(OTHER_OUT,bytes(8)),(PARAM,bytes.fromhex(r['initial_params256_hex']))]+[(int(s['address'],16),bytes.fromhex(s['bytes_hex']))for s in r['fixture_additions']]
 for a,raw in fixtures:
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
 for call in r['source_calls']:snaps.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload','destination_before','argument_bytes','workspace_header','response_before','candidate_before','delta_cell']if n in call)
 for o in r['observations']:snaps.setdefault(o['source_visit_index'],[]).extend(o[n]for n in['out_reference','object']if n in o)
 if r['execution_input']is not None:
  x=r['execution_input'];snaps.setdefault(x['source_visit_index'],[]).extend([x['response_reference'],x['request']])
 if r['shared_prepare_entry'] is not None:
  x=r['shared_prepare_entry'];snaps.setdefault(x['source_visit_index'],[]).extend([x['operation_scratch'],x['auxiliary_frame_cell']])
 for name,fields_to_check in [('handler_entry',['request','response_before']),('field_search_return',['record','length_output','pointer_output']),('response_initializer_return',['record','response']),('prepared_handler_call',['record'])]:
  if r[name] is not None:
   x=r[name];snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in fields_to_check if n in x)
 for x in r['value_bridge_returns']:
  snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in ['record','value_output','pointer_output','length_output']if n in x)
 if r['next_record_handoff']is not None:
  x=r['next_record_handoff'];snaps.setdefault(x['source_visit_index'],[]).extend([x['record']]if 'record'in x else [])
 if r['response_publication']is not None:
  x=r['response_publication'];snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in ['out_reference_before','candidate','frame_out_reference','frame_candidate'])
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snaps.get(ix,[]):snap(s)
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert bytes_at(a,n).hex()==e['bytes_hex']
    if e['probe_only']:assert e['pc']in['0xfffffe000a5a1cdc','0xfffffe000a5a1cf0']and n==1;counts['discarded_probe_read_epochs']+=1
    if P<=a<a+n<=P+0x20000 and not e['probe_only']:assert all(x in known for x in range(a,a+n))
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in globals)
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);prov[x]=1
    counts['source_write_epochs']+=1
 for s in snaps.get(len(r['source_visits']),[]):snap(s)
 for n in['workspace','auxiliary','actual_auxiliary','response','object','params','out_reference','execution_response_reference_final']:snap(r[n])
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1



def main():
 c=read('lskd_values_contracts.json');handlers=read('lskd_handlers_contracts.json');response=read('lskd_response_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');p=read('lskd_values_profiles.json');proof=read('lskd_values_proofs.json');baseline=read('lskd_handlers_profiles.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in [(c,'recover_lskd_values.py'),(p,'probe_lskd_values.py'),(proof,'prove_lskd_values.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 assert function(k,e,int(c['query_caller_static']['start'],16))==c['query_caller_static'];counts['static_query_caller']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 rng=selected(0xfffffe00079171c0,0xfffffe0007919bb0,0x58,0x986,base=0xfffffe000846c420);rng.update(label='span_random',base='0xfffffe000846c420',left256_hex=IMAGE.read(0xfffffe00079171c0,256).hex(),right256_hex=IMAGE.read(0xfffffe0007919bb0,256).hex(),original_pointer=pointer(k,int(rng['slot'],16)));assert rng['target']=='0xfffffe000a508d6c'
 rootbank=selected(0xfffffe00079172c0,0xfffffe0007919cb0,0xff,-0x35,base=0xfffffe00084716e0,bias=-0xc);rootbank.update(label='global_random_destination',base='0xfffffe00084716e0',left256_hex=IMAGE.read(0xfffffe00079172c0,256).hex(),right256_hex=IMAGE.read(0xfffffe0007919cb0,256).hex(),original_pointer=pointer(k,int(rootbank['slot'],16)));assert rootbank['target']=='0xfffffe000ccc2ce0'
 for obj in [prior,tlv,ctor,fields,execute,response,handlers,c,{'bank_rules':[rng,rootbank]}]:
  for b in obj['bank_rules']:
   l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 qs,lifts=queries(c,handlers,fields,response);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[];outcomes=Counter();nextcalls=Counter();tables={};imports={};rng_roots={};TABLE=0xfffffe000846c420
 def original_edge(r,ix,target,modifier):
  candidates=[z for z in r['source_reads']if z['source_visit_index']<ix and z['size_bytes']==8 and (TABLE<=int(z['address'],16)<0xfffffe0008471c00 or 0xfffffe000847c000<=int(z['address'],16)<0xfffffe000847d000)and z['bytes_hex']==struct.pack('<Q',int(target,16)).hex()];assert candidates,(ix,target);ptr=pointer(k,int(candidates[-1]['address'],16));assert ptr['target']==target and ptr['authenticated'];slot=int(ptr['slot'],16);mod=int(modifier,16)
  if TABLE<=slot<0xfffffe0008471c00:assert int(ptr['diversity'],16)==mod;tables[ptr['slot']]=ptr;counts['original_continuation_table_edges']+=1
  else:assert ptr['diversity']=='0x0'and(int(ptr['word'],16)>>48)&1 and mod==slot;imports[ptr['slot']]=ptr;counts['original_continuation_import_edges']+=1
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Values(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);outcomes[r['boundary']['kind']]+=1
  for flag in ['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','complete_native_business_operation_executed','random_backend_executed','stop_helper_executed','external_IPC_emission_proved','full_goal_complete']:assert not r[flag],flag
  assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,response,prior,ctor,fields,execute,k,counts,handlers)
  assert not any(v['pc']in ['0xfffffe000a508d6c','0xfffffe000a69f394','0xfffffe000be57d68','0xfffffe000a54e220',*[h['target']for h in c['handoffs']]]for v in r['source_visits'])
  if j<271:
   oldbase=baseline['cases'][j];assert oldbase['input']==case;cut=len(oldbase['source_visits']);assert r['source_visits'][:cut]==oldbase['source_visits'];assert(r['prior_boundary']if r['prior_boundary']is not None else r['boundary'])==oldbase['boundary']
   for n in ['source_reads','source_writes','source_calls','source_dispatches']:assert[z for z in r[n]if z['source_visit_index']<cut]==oldbase[n],(j,n)
   for n in ['field_search_return','response_initializer_return','prepared_handler_call']:assert r[n]==oldbase[n],(j,n)
   counts['preceding_complete_prefix_equal_cases']+=1
  else:cut=r['field_search_return']['source_visit_index']if r['field_search_return']is not None else len(r['source_visits'])
  for branch in r['source_dispatches']:
   if branch['source_visit_index']>=cut:original_edge(r,branch['source_visit_index'],branch['target'],branch['registers31'][17])
  for call in r['source_calls']:
   assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
   if call['source_visit_index']>=cut and call['pc']in ['0xfffffe000a525d74','0xfffffe000a54df54','0xfffffe000a51a600']:original_edge(r,call['source_visit_index'],call['target'],hex(0x1322 if call['pc']=='0xfffffe000a525d74'else 0x1103 if call['pc']=='0xfffffe000a54df54'else 0x1103))
  for model in r['models']:assert not model['target_executed']and not model['memory_effects_modeled'];counts['register_only_models']+=1
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64'];counts['FP64_contexts_preserved']+=1
  assert len(r['probe_only_reads'])==1 and all(z['loaded_register']=='wzr'and z['mapped_private_page_only']for z in r['probe_only_reads']);counts['discarded_original_stack_probes']+=1
  op=case['operation32'];ap=AUX if case['auxiliary_location']=='adjacent'else SEPARATED_AUX;out=OUT
  if case['kind']!='execute':
   x=r['execution_input'];out=int(x['response_reference']['address'],16)
   if case['kind']=='provider':obj=provider_request(case,next(z for z in fields['providers']if z['label']==case['provider']))
   else:
    length=case['inputs8'][2]if case['caller']=='span'else 0;packet=rec(0x66,bytes((11+37*n)&255 for n in range(length)))if case['caller']=='span'else b'';obj=bytearray(160);struct.pack_into('<4I',obj,0,1,op,int(bool(packet)),len(packet));obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,int(bool(packet)),len(packet))
   assert x['request']['bytes_hex']==r['object']['bytes_hex']==obj.hex()and r['object']['provenance_hex']=='01'*160;counts['source_caller_lineages']+=1;counts['source_constructed_packet_bytes']+=int.from_bytes(obj[156:160],'little')
   cr=[z for z in r['source_calls']if z['kind']=='constructor_record'];assert len(cr)==1 and int(cr[0]['record']['address'],16)&15==8;counts['aligned_source_constructor_records']+=1
  else:
   packet=b''.join(rec(tag,bytes.fromhex(data))for tag,data in case['stream_fields']);obj=bytearray(160);struct.pack_into('<4I',obj,0,1,op,len(case['stream_fields']),len(packet));obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,len(case['stream_fields']),len(packet));assert r['object']['bytes_hex']==obj.hex()and r['object']['provenance_hex']=='03'*160;counts['explicit_stream_fixture_cases']+=1
  ret=r['value_bridge_returns'];assert len(ret)==int(r['field_search_return']is not None)
  if ret:
   ret=ret[0];call=next(z for z in r['source_calls']if z['kind']in ['scalar_record','span_record']);assert ret['SP']==call['SP']and ret['registers31'][19:30]==call['registers31'][19:30];counts['GP_and_SP_bridge_contexts_preserved']+=1
   rawlookup=int.from_bytes(bytes.fromhex(r['field_search_return']['record']['bytes_hex'])[:4],'little');status=int.from_bytes(bytes.fromhex(ret['record']['bytes_hex'])[8:12]if call['kind']=='scalar_record'else bytes.fromhex(ret['record']['bytes_hex'])[12:16],'little')
   if call['kind']=='scalar_record':
    length=int.from_bytes(bytes.fromhex(r['field_search_return']['length_output']['bytes_hex']),'little');dp=int.from_bytes(bytes.fromhex(r['field_search_return']['pointer_output']['bytes_hex']),'little');ok=rawlookup==0x5e561849 and dp!=0 and length==8;assert status==(0x5e561849 if ok else 0x5e5571af)
    value=int.from_bytes(obj[dp-OBJECT:dp-OBJECT+8],'big')if ok else 0;assert ret['value_output']['bytes_hex']==struct.pack('<Q',value).hex();a=int(ret['value_output']['address'],16);effects=[z for z in r['source_writes']if call['source_visit_index']<z['source_visit_index']<ret['source_visit_index']and int(z['address'],16)<a+8 and a<int(z['address'],16)+z['size_bytes']]
    if ok:assert len(effects)==1 and effects[0]['pc']=='0xfffffe000a54f4f4'and effects[0]['size_bytes']==8;counts['source_BE64_output_stores']+=1;counts['source_BE64_payload_byte_reads']+=8
    else:assert not effects;counts['common_failure_output_words_unchanged']+=1
    counts['common_value_bridge_returns']+=1
   else:
    assert status==(rawlookup-0x5e561849)&0xffffffff and ret['pointer_output']==r['field_search_return']['pointer_output']and ret['length_output']==r['field_search_return']['length_output'];counts['span_value_bridge_returns']+=1
  hand=r['next_record_handoff']
  if hand is not None:
   original_edge(r,hand['source_visit_index'],hand['target'],hand['registers31'][17]);nextcalls[hand['pc']]+=1
   if hand['kind']=='random_41_call':
    assert case.get('span_shape_fixture')=='length37'and hand['pc']=='0xfffffe000a5296e4'and hand['target']=='0xfffffe000a508d6c'and hand['registers31'][:2]==['0xfffffe000ccc2ce0','0x29'];assert hand['external_destination']['bytes_hex']==k.read(0xfffffe000ccc2ce0,41).hex();sp=int(hand['SP'],16);rd=next(z for z in r['source_reads']if z['pc']=='0xfffffe000a5296d8');assert rd['address']==hex(sp+0x118)and rd['bytes_hex']==struct.pack('<Q',0xfffffe000ccc2ce0).hex()
    root=next(z for z in r['source_reads']if z['pc']=='0xfffffe000a52dde0');assert root['address']==rootbank['slot']and root['bytes_hex']==struct.pack('<Q',0xfffffe000ccc2cec).hex();ptr=pointer(k,int(root['address'],16));assert ptr['target']=='0xfffffe000ccc2cec';rng_roots[ptr['slot']]=ptr;counts['prepared_41byte_random_calls']+=1
   else:assert hand['kind']=='record'and r['boundary']['kind']=='before_next_record_helper';counts['prepared_next_record_calls']+=1
  pub=r['response_publication'];published=pub is not None;assert r['positive_publication_executed']==published
  if published:
   assert op==0x1b5b and r['source_query_success_executed']and r['source_execution_wrapper_returned'];response_obj=bytearray(160);struct.pack_into('<4I',response_obj,0,1,op,1,8);response_obj[16:24]=bytes.fromhex('0065000413180000');struct.pack_into('<QII',response_obj,144,RESPONSE+16,1,8);assert r['response']['bytes_hex']==pub['candidate']['bytes_hex']==response_obj.hex()and r['response']['provenance_hex']=='01'*160
   assert pub['registers31'][8:10]==[hex(out),hex(RESPONSE)]and pub['frame_out_reference']['bytes_hex']==struct.pack('<Q',out).hex()and pub['frame_candidate']['bytes_hex']==struct.pack('<Q',RESPONSE).hex();stores=[z for z in r['source_writes']if z['pc']=='0xfffffe000a522e44'];assert len(stores)==1 and stores[0]['source_visit_index']==pub['source_visit_index']and stores[0]['address']==hex(out)and stores[0]['after_hex']==struct.pack('<Q',RESPONSE).hex();assert r['execution_response_reference_final']['bytes_hex']==struct.pack('<Q',RESPONSE).hex()and r['execution_response_reference_final']['provenance_hex']=='01'*8;counts['source_query_candidate_publications']+=1
   call=next(z for z in r['source_calls']if z['kind']=='query_u32_append_record');assert call['pc']=='0xfffffe000a525d74'and call['target']=='0xfffffe000a54daf8';copies=[z for z in r['source_calls']if z['kind']=='original_payload_copy'and z['source_visit_index']>call['source_visit_index']];assert len(copies)==1 and copies[0]['payload']['bytes_hex']=='13180000';counts['query_source_u32_append_bytes']+=4
  else:
   assert not r['source_query_success_executed']and r['response']['bytes_hex']=='00'*160
   expected_ref=bytes(8)if case['kind']!='execute'else struct.pack('<Q',case['out_initial64']);assert r['execution_response_reference_final']['bytes_hex']==expected_ref.hex()
  frees=[m for m in r['models']if 'free_register_clobbers'in m['kind']]
  if r['source_execution_wrapper_returned']:
   raw=0x5e561849 if published else 0x5e5571af;assert int(r['boundary']['registers31'][0],16)==(raw-0x5e561849)&0xffffffff;assert r['workspace']['bytes_hex'][0x78*2:0x7c*2]==struct.pack('<I',raw).hex();d=[z for z in r['source_writes']if z['pc']=='0xfffffe000a58a3c8'];assert len(d)==1 and d[0]['after_hex']=='00'*8;counts['source_zero_displacement_returns']+=1
   entry=[z for z in r['source_writes']if z['pc']=='0xfffffe000a50c52c'];frame=min(int(z['address'],16)for z in entry)-0x28;assert int(r['boundary']['SP'],16)==frame+0xa0;counts['source_execution_wrapper_returns']+=1
   expected_free=[]if published else[('response_free_register_clobbers','0xfffffe000a5356d8',['0xfffffe000847b020',hex(RESPONSE)])];expected_free+=[('typed_free_register_clobbers','0xfffffe000a50c8f8',['0xfffffe000847aee0',hex(ap)]),('aligned_free_register_clobbers','0xfffffe000a50c950',[hex(WORK),'0x4000'])];assert[(m['kind'],m['pc'],m['registers8'][:2])for m in frees]==expected_free;counts['source_prepared_free_calls']+=len(frees)
   if not published:counts['source_error_wrapper_returns']+=1
  else:assert not frees
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==343 and counts['source_visits']==922309 and counts['register_only_models']==1670 and counts['source_query_candidate_publications']==13 and counts['source_BE64_output_stores']==120 and counts['source_execution_wrapper_returns']==166 and counts['prepared_41byte_random_calls']==12 and counts['preceding_complete_prefix_equal_cases']==271
 deps={n:sha(ROOT/n)for n in ['recover_lskd_values.py','probe_lskd_values.py','lskd_values_spec.py','lskd_values_symbolic.py','prove_lskd_values.py','lskd_values_contracts.json','lskd_values_profiles.json','lskd_values_proofs.json','probe_lskd_handlers.py','lskd_handlers_contracts.json','lskd_handlers_profiles.json','probe_lskd_consumer.py','lskd_consumer_contracts.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'full_goal_complete':False};(ROOT/'lskd_values_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundary_coverage':dict(outcomes),'next_handoff_coverage':dict(nextcalls),'additional_bank_rules':[rng,rootbank],'original_continuation_slots':list(tables.values()),'original_import_slots':list(imports.values()),'global_rng_pointer_roots':list(rng_roots.values()),'global_rng_exact_symbols':k.symbols([0xfffffe000ccc2ce0]),'fresh_replays_sha256':sha(ROOT/'lskd_values_replays.json'),'all_checks_pass':True,'native_target_executed':False,'native_request_execution_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_values_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundaries':dict(outcomes),'handoffs':dict(nextcalls)}),flush=True)
if __name__=='__main__':main()
