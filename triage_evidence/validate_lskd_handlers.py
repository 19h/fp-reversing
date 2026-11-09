#!/usr/bin/env python3
"""Fresh handler/lookup/initializer verification and independent source byte epochs.

O(B+C*(V+E)+256R+I) time/space, plus solver-dependent cost (30 s/query).
No native target/API/heap/crypto/IPC or complete business-handler execution.
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
from probe_lskd_handlers import Handlers,cases,CALLS
from probe_lskd_response import P,M64,OBJECT,PARAM,OUT,WORK,AUX,RESPONSE,SEPARATED_AUX
from probe_lskd_request import OTHER_OUT
from lskd_handlers_symbolic import queries
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
 for call in r['source_calls']:snaps.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload','destination_before','argument_bytes','workspace_header','response_before','delta_cell']if n in call)
 for o in r['observations']:snaps.setdefault(o['source_visit_index'],[]).extend(o[n]for n in['out_reference','object']if n in o)
 if r['execution_input']is not None:
  x=r['execution_input'];snaps.setdefault(x['source_visit_index'],[]).extend([x['response_reference'],x['request']])
 if r['shared_prepare_entry'] is not None:
  x=r['shared_prepare_entry'];snaps.setdefault(x['source_visit_index'],[]).extend([x['operation_scratch'],x['auxiliary_frame_cell']])
 for name,fields_to_check in [('handler_entry',['request','response_before']),('field_search_return',['record','length_output','pointer_output']),('response_initializer_return',['record','response']),('prepared_handler_call',['record'])]:
  if r[name] is not None:
   x=r[name];snaps.setdefault(x['source_visit_index'],[]).extend(x[n]for n in fields_to_check if n in x)
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
 c=read('lskd_handlers_contracts.json');response=read('lskd_response_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');p=read('lskd_handlers_profiles.json');proof=read('lskd_handlers_proofs.json');consumer=read('lskd_consumer_contracts.json');baseline=read('lskd_consumer_profiles.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in [(c,'recover_lskd_handlers.py'),(p,'probe_lskd_handlers.py'),(proof,'prove_lskd_handlers.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']and k.symbols([int(a,16)for a in c['random_exact_symbols']])==c['random_exact_symbols'];assert pointer(k,int(c['random_import_binding']['slot'],16))==c['random_import_binding'];counts['random_import_binding']+=1
 for obj in [prior,tlv,ctor,fields,execute,response,c]:
  for b in obj['bank_rules']:
   l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b;counts['new_bank_pointer_roots']+=1
 qs,lifts=queries(c,p,ctor);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in [z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:
   s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=json.loads(json.dumps(list(cases())));assert[r['input']for r in p['cases']]==expected;fresh=[];outcomes=Counter();operations=Counter();newslots={};readsites=Counter();lookup_outcomes=Counter()
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Handlers(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);outcomes[r['boundary']['kind']]+=1
  for flag in ['undefined_private_value_reads','native_API_executed','native_heap_executed','native_request_execution_executed','native_business_operation_executed','positive_publication_executed','external_IPC_emission_proved','complete_business_handler_executed','random_backend_executed','stop_helper_executed','full_goal_complete']:assert not r[flag],flag
  assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,response,prior,ctor,fields,execute,k,counts,c)
  assert not any(v['pc']in [c['random_import_binding']['target'],'0xfffffe000a508d6c','0xfffffe000a69f394','0xfffffe000a54e220','0xfffffe000a522e44']for v in r['source_visits'])
  for call in r['source_calls']:assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
  for model in r['models']:assert not model['target_executed']and not model['memory_effects_modeled'];counts['register_only_models']+=1
  assert len(r['models'])==3+int(case['kind']!='execute')
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64'];counts['FP64_contexts_preserved']+=1
  probes=[v for v in r['source_reads']if v['probe_only']];assert len(probes)==len(r['probe_only_reads'])==1 and all(v['loaded_register']=='wzr'and v['mapped_private_page_only']for v in r['probe_only_reads']);counts['discarded_original_stack_probes']+=1
  op=case['operation32'];ap=AUX if case['auxiliary_location']=='adjacent'else SEPARATED_AUX;entry=r['handler_entry'];en=len(r['source_visits'])if entry is None else entry['source_visit_index'];out=OUT
  if case['kind']!='execute':
   oldbase=next(z for z in baseline['cases']if z['input']==case);assert r['source_visits'][:en]==oldbase['source_visits']
   for name in ['source_reads','source_writes','source_calls','source_dispatches']:assert[z for z in r[name]if z['source_visit_index']<en]==oldbase[name],(j,name)
   assert r['execution_input']==oldbase['execution_input'];counts['preceding_source_prefix_equal_cases']+=1;x=r['execution_input'];out=int(x['response_reference']['address'],16)
   if case['kind']=='provider':obj=provider_request(case,next(v for v in fields['providers']if v['label']==case['provider']))
   else:
    packet=rec(0x66,bytes((11+37*x)&255 for x in range(8)))if case['caller']=='span'else b'';obj=bytearray(160);struct.pack_into('<4I',obj,0,1,op,int(bool(packet)),len(packet));obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,int(bool(packet)),len(packet))
   assert x['request']['bytes_hex']==r['object']['bytes_hex']==obj.hex()and r['object']['provenance_hex']=='01'*160;assert r['execution_response_reference_final']['bytes_hex']=='00'*8 and r['execution_response_reference_final']['provenance_hex']=='01'*8;counts['source_constructed_packet_bytes']+=int.from_bytes(obj[156:160],'little');counts['source_caller_lineages']+=1
   cr=[v for v in r['source_calls']if v['kind']=='constructor_record'];assert len(cr)==1 and int(cr[0]['record']['address'],16)&15==8;counts['aligned_source_constructor_records']+=1
  else:
   packet=b''.join(rec(tag,bytes.fromhex(data))for tag,data in case['stream_fields']);obj=bytearray(160);struct.pack_into('<4I',obj,0,1,op,len(case['stream_fields']),len(packet));obj[16:16+len(packet)]=packet;struct.pack_into('<QII',obj,144,OBJECT+16,len(case['stream_fields']),len(packet));assert r['object']['bytes_hex']==obj.hex()and r['object']['provenance_hex']=='03'*160;assert r['execution_response_reference_final']['bytes_hex']==struct.pack('<Q',case['out_initial64']).hex()and r['execution_response_reference_final']['provenance_hex']=='03'*8;counts['explicit_stream_fixture_cases']+=1
  top,known=workspace(OBJECT,out,ap);assert r['workspace']['bytes_hex'][:128]==top[:64].hex()and r['workspace']['known_mask_hex'][:128]==r['workspace']['provenance_hex'][:128]==known[:64].hex();counts['source_top_header_bytes']+=sum(known[:64])
  if entry is None:
   assert op not in [int(h['operation'],16)for h in c['handlers']]and r['boundary']['pc']==consumer['default_leaf']and r['boundary']['kind']=='selected_operation_leaf';assert not r['source_handler_preparation_executed'];counts['unchanged_default_boundaries']+=1
  else:
   assert r['source_handler_preparation_executed']and entry['pc']==consumer['leaf_map'][hex(op)];operations[hex(op)]+=1;assert entry['request']['bytes_hex']==obj.hex()and entry['response_before']['bytes_hex']=='00'*160
   for branch in r['source_dispatches']:
    if branch['source_visit_index']<en:continue
    reads=[z for z in r['source_reads']if z['source_visit_index']<branch['source_visit_index']and z['size_bytes']==8 and 0xfffffe000846c420<=int(z['address'],16)<0xfffffe0008471c00 and z['bytes_hex']==struct.pack('<Q',int(branch['target'],16)).hex()];assert reads
    ptr=pointer(k,int(reads[-1]['address'],16));assert ptr['target']==branch['target']and ptr['authenticated']and int(ptr['diversity'],16)==int(branch['registers31'][17],16);newslots[ptr['slot']]=ptr;counts['original_handler_branch_edges']+=1
   for call in r['source_calls']:
    if int(call['pc'],16)not in CALLS:continue
    reads=[z for z in r['source_reads']if z['source_visit_index']<call['source_visit_index']and z['size_bytes']==8 and 0xfffffe000846c420<=int(z['address'],16)<0xfffffe0008471c00 and z['bytes_hex']==struct.pack('<Q',int(call['target'],16)).hex()];assert reads;ptr=pointer(k,int(reads[-1]['address'],16));assert ptr['target']==call['target']and ptr['authenticated']and int(ptr['diversity'],16)==int(call['registers31'][17],16);newslots[ptr['slot']]=ptr;counts['original_handler_call_edges']+=1
   if r['field_search_return']is not None:
    assert r['original_field_lookup_executed'];ret=r['field_search_return'];calls0=[v for v in r['source_calls']if v['kind']=='generic_field_search'];assert len(calls0)==1;call=calls0[0];raw=bytes.fromhex(call['record']['bytes_hex']);G=int(call['record']['address'],16);key=((G^0xae0701e7)*0x952f3cb7)&0xffffffff;tag=0x66 if op==0x1b5c else 0x72
    assert struct.unpack_from('<I',raw,24)[0]==key^0x526 and struct.unpack_from('<H',raw,4)[0]==(key+tag+0x12bd)&0xffff and struct.unpack_from('<Q',raw,32)[0]==OBJECT
    lp,dp=struct.unpack_from('<QQ',raw,8);assert ret['length_output']['address']==hex(lp)and ret['pointer_output']['address']==hex(dp)
    cursor=0;found=None;headers=[]
    for ordinal in range(int.from_bytes(obj[8:12],'little')):
     if cursor>=int.from_bytes(obj[12:16],'little'):break
     t,n=struct.unpack_from('>HH',obj,16+cursor);headers.extend(OBJECT+16+cursor+x for x in range(4))
     if t==tag:found=(OBJECT+20+cursor,n);break
     cursor+=4+n
    expected_status=0x5e561849 if found is not None else 0x5e5571af;endraw=bytes.fromhex(ret['record']['bytes_hex']);assert struct.unpack_from('<I',endraw,0)[0]==expected_status
    assert ret['length_output']['bytes_hex']==struct.pack('<H',found[1]if found else 0).hex()and ret['pointer_output']['bytes_hex']==struct.pack('<Q',found[0]if found else 0).hex();assert ret['length_output']['provenance_hex']=='01'*2 and ret['pointer_output']['provenance_hex']=='01'*8
    actual=[z for z in r['source_reads']if z['source_visit_index']>=call['source_visit_index']and OBJECT+16<=int(z['address'],16)<OBJECT+144];assert[int(z['address'],16)for z in actual]==headers and all(z['size_bytes']==1 for z in actual);counts['source_wire_header_byte_reads']+=len(actual);counts['field_search_returns']+=1;lookup_outcomes['found'if found else'not_found']+=1
    for z in r['source_reads']:
     if z['source_visit_index']>=call['source_visit_index']:assert int(z['address'],16)not in [OBJECT+152,OBJECT+156];readsites[z['pc']]+=1
    caller=next(v for v in r['source_calls']if v['kind']in ['scalar_record','span_record']);R=int(caller['record']['address'],16);kr=((R^0xc410a4c0)*0xaed3b63b)&0xffffffff;rr=bytes.fromhex(caller['record']['bytes_hex'])
    if op==0x1b5c:assert struct.unpack_from('<I',rr,8)[0]==(0x526-kr-0xb7647540)&0xffffffff and struct.unpack_from('<H',rr,16)[0]==(kr^0x66)&0xffff and struct.unpack_from('<Q',rr,32)[0]==OBJECT;counts['span_record_lineages']+=1
    else:assert struct.unpack_from('<Q',rr,0)[0]==OBJECT and struct.unpack_from('<I',rr,12)[0]==(kr+0x148)&0xffffffff and struct.unpack_from('<H',rr,16)[0]==(kr^0x4411)&0xffff;counts['scalar_record_lineages']+=1
   elif op==0x1b5b:
    assert r['original_response_initializer_executed']and r['boundary']['kind']=='response_initializer_return';objr=bytearray(160);struct.pack_into('<4I',objr,0,1,op,1,8);struct.pack_into('<Q',objr,144,RESPONSE+16);assert r['response']['bytes_hex']==objr.hex()and r['response']['known_mask_hex']==r['response']['provenance_hex']=='01'*160
    call=next(v for v in r['source_calls']if v['kind']=='response_initializer');rr=bytes.fromhex(call['record']['bytes_hex']);R=int(call['record']['address'],16);key=((R^0x2bf25469f26d6f2a)*0xeac8f755)&0xffffffff;assert struct.unpack_from('<Q',rr,0)[0]==RESPONSE and struct.unpack_from('<I',rr,24)[0]^key==0x542;assert int(r['boundary']['registers31'][0],16)==8 and int.from_bytes(bytes.fromhex(r['response_initializer_return']['record']['bytes_hex'])[12:16],'little')==0x5e561849;counts['query_response_initializations']+=1
   elif op==0x1b59:
    call=r['prepared_handler_call'];assert r['boundary']['kind']=='before_random_call'and call['pc']=='0xfffffe000a50fd10'and call['target']=='0xfffffe000a508d6c'and call['registers31'][:2]==[hex(WORK+0x9c),'0x4'];counts['prepared_random_calls']+=1
   else:assert op==0x1b5a and r['boundary']['kind']=='before_stop_helper'and r['prepared_handler_call']['target']=='0xfffffe000a54e220';counts['prepared_stop_helper_calls']+=1
  if op!=0x1b5b:assert r['response']['bytes_hex']=='00'*160 and r['response']['provenance_hex']=='01'*160
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==271 and counts['source_visits']==720474 and counts['register_only_models']==957 and counts['preceding_source_prefix_equal_cases']==144 and len(operations)==12 and counts['field_search_returns']==213 and lookup_outcomes=={'found':180,'not_found':33}
 deps={n:sha(ROOT/n)for n in ['recover_lskd_handlers.py','probe_lskd_handlers.py','lskd_handlers_spec.py','lskd_handlers_symbolic.py','prove_lskd_handlers.py','lskd_handlers_contracts.json','lskd_handlers_profiles.json','lskd_handlers_proofs.json','probe_lskd_consumer.py','lskd_consumer_contracts.json','lskd_consumer_profiles.json','probe_lskd_response.py','lskd_response_contracts.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_target_executed':False,'complete_business_handler_executed':False,'full_goal_complete':False};(ROOT/'lskd_handlers_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundary_coverage':dict(outcomes),'operation_coverage':dict(operations),'lookup_outcomes':dict(lookup_outcomes),'post_lookup_read_sites':dict(readsites),'original_dynamic_handler_slots':list(newslots.values()),'fresh_replays_sha256':sha(ROOT/'lskd_handlers_replays.json'),'all_checks_pass':True,'native_target_executed':False,'complete_business_handler_executed':False,'positive_publication_executed':False,'random_backend_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_handlers_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts,'boundaries':dict(outcomes),'lookup_outcomes':dict(lookup_outcomes)}),flush=True)
if __name__=='__main__':main()
