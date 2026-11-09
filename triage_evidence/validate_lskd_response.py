#!/usr/bin/env python3
"""Distinct response/metadata replays, probe-read epochs and local source proofs.

O(B+C*(V+E)+W+256R+I) time/space plus solver-dependent cost. Only declared
allocator/free register effects; native request/heap/crypto/IPC unproved.
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
from recover_lskd_fields import census
from probe_lskd_response import Response,cases,P,M64,OBJECT,PARAM,OUT,WORK,AUX,RESPONSE,SEPARATED_AUX
from probe_lskd_request import OTHER_OUT
from lskd_response_symbolic import queries
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
def audit(r,c,prior,ctor,fields,execute,k,counts):
 state={};known=set();prov={};initial={};events={};snaps={};case=r['input'];globals=prior['mutable_globals']+ctor['additional_mutable_globals']+fields['additional_mutable_globals']+execute['additional_mutable_globals']+c['additional_mutable_globals']
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
 for n in['workspace','auxiliary','actual_auxiliary','response','object','params','out_reference','execution_response_reference_final']:snap(r[n])
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1
def main():
 c=read('lskd_response_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');execute=read('lskd_execute_contracts.json');p=read('lskd_response_profiles.json');proof=read('lskd_response_proofs.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_lskd_response.py'),(p,'probe_lskd_response.py'),(proof,'prove_lskd_response.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for f in c['stack_helpers']:assert function(k,e,int(f['start'],16))==f;counts['original_stack_helpers']+=1
 assert pointer(k,int(c['stack_binding']['slot'],16))==c['stack_binding']
 for b in prior['bank_rules']+tlv['bank_rules']+ctor['bank_rules']+fields['bank_rules']+execute['bank_rules']+c['bank_rules']:
  l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b;counts['new_bank_pointer_roots']+=1
 for v in c['typed_views']:assert k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and pointer(k,int(v['name_pointer']['slot'],16))==v['name_pointer'];assert v['name']=='site.LSKDDispatchStream'and v['metadata_size32']==160 and v['metadata_flags32']==100;counts['typed_views']+=1
 for slot in c['dispatch_slots']:assert pointer(k,int(slot['original_pointer']['slot'],16))==slot['original_pointer'];counts['dispatch_slots']+=1
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[]
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Response(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['undefined_private_value_reads']and not r['native_API_executed']and not r['native_heap_executed']and not r['native_request_execution_executed']and not r['business_request_operation_executed']and not r['positive_publication_executed']and not r['external_IPC_emission_proved'];assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,c,prior,ctor,fields,execute,k,counts)
  assert not any(0xfffffe000a59bf78<=int(v['pc'],16)<0xfffffe000a59bf84 or 0xfffffe000a522e38<=int(v['pc'],16)<0xfffffe000a522e5c or int(v['pc'],16)in[0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]for v in r['source_visits'])
  for call in r['source_calls']:assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
  assert r['initial_fp_callee_saved64']==r['final_fp_callee_saved64']=={f'd{v}':hex(0x1122334455660000+v)for v in range(8,12)};counts['FP64_contexts_preserved']+=1
  probes=[v for v in r['source_reads']if v['probe_only']];assert len(probes)==len(r['probe_only_reads'])and all(v['loaded_register']=='wzr'and v['mapped_private_page_only']for v in r['probe_only_reads']);counts['original_stack_probe_calls']+=len(probes)
  assert r['actual_auxiliary']['bytes_hex']=='a5'*4096 and r['actual_auxiliary']['known_mask_hex']=='00'*4096 and r['actual_auxiliary']['provenance_hex']=='00'*4096;counts['auxiliary_storage_untouched_cases']+=1
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled'];counts['register_only_models']+=1
  ap=AUX if case['auxiliary_location']=='adjacent'else SEPARATED_AUX;models=r['models'];am=[m for m in models if m['kind']=='auxiliary_typed_register_return'];rm=[m for m in models if m['kind']=='response_typed_register_return'];assert len(am)==len(rm)==1 and am[0]['result_X0_fixture']==hex(ap)and rm[0]['pc']=='0xfffffe000a524868'and rm[0]['target']=='0xfffffe000c4ba154'and rm[0]['registers8'][0]=='0xfffffe000847ae60';assert rm[0]['result_X0_fixture']==r['response_pointer']==hex(RESPONSE if case['response_nonnull']else 0);counts['response_allocation_models']+=1
  if case['kind']=='provider':
   provider=next(v for v in fields['providers']if v['label']==case['provider']);x=r['execution_input'];obj=provider_request(case,provider);assert x['request_pointer']==hex(OBJECT)and x['request']['bytes_hex']==r['object']['bytes_hex']==obj.hex()and r['object']['provenance_hex']=='01'*160;out=int(x['response_reference']['address'],16);request=OBJECT;header=1;operation=provider['operation32'];assert r['execution_response_reference_final']['bytes_hex']=='00'*8 and r['execution_response_reference_final']['provenance_hex']=='01'*8;counts['provider_source_request_lineages']+=1;counts['provider_packet_bytes_preserved']+=int.from_bytes(obj[156:160],'little')
  else:request=case['inputs8'][0];out=OUT;header=case['request_header32'];operation=case['operation32'];assert r['execution_response_reference_final']['bytes_hex']==struct.pack('<Q',case['out_initial64']).hex()and r['execution_response_reference_final']['provenance_hex']=='03'*8
  entry=[w for w in r['source_writes']if w['pc']=='0xfffffe000a50c52c'];frame=min(int(w['address'],16)for w in entry)-0x28;cells={int(w['address'],16)+n:b for w in entry for n,b in enumerate(bytes.fromhex(w['after_hex']))};assert bytes(cells[frame+0x28+n]for n in range(16))==struct.pack('<QQ',out,request)
  assert not any(int(w['address'],16)<out+8 and out<int(w['address'],16)+w['size_bytes']and w['source_visit_index']>min(v['source_visit_index']for v in entry)for w in r['source_writes'])
  complete=not case['response_nonnull']or not request or header!=1;rawstatus=0x5e5571ad if not case['response_nonnull']else 0x5e5571af if complete else None;top,top_known=workspace(request,out,ap,rawstatus);assert r['workspace']['bytes_hex'][:128]==top[:64].hex()and r['workspace']['known_mask_hex'][:128]==r['workspace']['provenance_hex'][:128]==top_known[:64].hex();counts['source_top_header_bytes']+=sum(top_known[:64])
  data_reads=[v for v in r['source_reads']if v['pc']in['0xfffffe000a56b454','0xfffffe000a53533c']];copies=[w for w in r['source_writes']if w['pc']=='0xfffffe000a535340'];clears=[w for w in r['source_writes']if RESPONSE<=int(w['address'],16)<RESPONSE+160]
  if not case['response_nonnull']:
   assert not data_reads and not clears and not probes and not r['request_metadata_getter_executed_in_private_guest'];assert r['response']['bytes_hex']=='a5'*160 and r['response']['known_mask_hex']==r['response']['provenance_hex']=='00'*160;counts['null_response_allocation_returns']+=1
  else:
   assert r['response']['bytes_hex']=='00'*160 and r['response']['known_mask_hex']==r['response']['provenance_hex']=='01'*160;assert{a for w in clears for a in range(int(w['address'],16),int(w['address'],16)+w['size_bytes'])}==set(range(RESPONSE,RESPONSE+160));assert all(0xfffffe000c648170<=int(w['pc'],16)<0xfffffe000c648218 and int(w['after_hex'],16)==0 for w in clears);counts['original_response_clear_bytes']+=160
   bridge=[v for v in r['source_calls']if v['kind']=='workspace_record_bridge'];inner=[v for v in r['source_calls']if v['kind']=='inner_workspace_record'];pcalls=[v for v in r['source_calls']if v['kind']=='original_stack_probe'];assert len(bridge)==len(inner)==len(pcalls)==len(probes)==1;R=WORK+0x40;assert bridge[0]['registers8'][0]==inner[0]['registers8'][0]==hex(R);before=bytearray(b'\xa5'*64);basis=((((2*(R&0x3bf7fab9)-R+0xc4080546)&0xffffffff)^0x18a186)*0xaed3b63b)&0xffffffff
   for off,fmt,v in[(0,'Q',WORK+0x80),(8,'Q',ap),(16,'Q',WORK+0x4000),(24,'I',(0x3be-basis)&0xffffffff),(32,'Q',request),(40,'Q',RESPONSE),(48,'Q',ap+0x1000)]:struct.pack_into('<'+fmt,before,off,v)
   assert bridge[0]['record']['bytes_hex']==inner[0]['record']['bytes_hex']==before.hex();seed=int.from_bytes(bytes.fromhex(bridge[0]['delta_cell']['bytes_hex']),'little');inner_cell=int(inner[0]['delta_cell']['address'],16);assert int.from_bytes(bytes.fromhex(inner[0]['delta_cell']['bytes_hex']),'little')==(seed-0xd0)&M64;adjust=[w for w in r['source_writes']if w['pc']=='0xfffffe000a571020'];assert len(adjust)==1 and adjust[0]['address']==hex(inner_cell)and adjust[0]['after_hex']==struct.pack('<Q',seed).hex();size=((((seed*0x2ec5+1)&M64)>>56)&0xf0)+16;assert pcalls[0]['probe_size_X8']==hex(size)and 16<=size<=256 and size%16==0;counts['source_record_compositions']+=1;counts['source_local_seed_adjustments']+=1
   # Getter status is a record field, not a C return-register status.
   getters=[v for v in r['source_calls']if v['kind']=='request_metadata_getter'];assert len(getters)==int(bool(request));scratch=WORK+0x118;word=operation if request and header==1 else 0;assert r['workspace']['bytes_hex'][0x118*2:0x11c*2]==struct.pack('<I',word).hex()and r['workspace']['provenance_hex'][0x118*2:0x11c*2]=='01'*4
   if request:
    assert data_reads[0]['pc']=='0xfffffe000a56b454'and data_reads[0]['address']==hex(OBJECT)and data_reads[0]['bytes_hex']==struct.pack('<I',header).hex();counts['request_header_reads']+=1;G=WORK+0xa8;gkey=((((G+0xce6c2b02-2*(G&0xce6c2b02))&0xffffffff)^0xa78f753d)*0x7a59c441)&0xffffffff;graw=struct.pack('<IIQQ',gkey^0x6ef,0x5e561849 if header==1 else 0x5e5571af,OBJECT,scratch);assert r['workspace']['bytes_hex'][0xa8*2:0xc0*2]==graw.hex()and r['workspace']['provenance_hex'][0xa8*2:0xc0*2]=='01'*24;counts['metadata_getter_records']+=1
    if header==1:assert len(data_reads)==2 and data_reads[1]['pc']=='0xfffffe000a53533c'and data_reads[1]['address']==hex(OBJECT+4)and data_reads[1]['bytes_hex']==struct.pack('<I',operation).hex();assert len(copies)==1 and copies[0]['address']==hex(scratch)and copies[0]['after_hex']==struct.pack('<I',operation).hex();counts['request_operation_copies']+=1
    else:assert len(data_reads)==1 and not copies;counts['bad_header_returns']+=1
   else:assert not data_reads and not copies;counts['null_request_returns']+=1
   if complete:
    pivot=[w for w in r['source_writes']if w['pc']=='0xfffffe000a58a3c8'];assert len(pivot)==1 and pivot[0]['address']==bridge[0]['delta_cell']['address']and pivot[0]['after_hex']=='00'*8;counts['source_zero_displacement_returns']+=1
   else:assert not any(w['pc']=='0xfffffe000a58a3c8'for w in r['source_writes'])
  frees=[m for m in models if 'free_register_clobbers'in m['kind']]
  if complete:
   assert r['boundary']['kind']==('wrapper_returned_to_provider'if case['kind']=='provider'else'returned')and int(r['boundary']['SP'],16)==frame+0xa0;assert int(r['boundary']['registers31'][0],16)==((rawstatus-0x5e561849)&0xffffffff);status=[w for w in r['source_writes']if w['pc']=='0xfffffe000a51062c'];assert len(status)==1 and status[0]['address']==hex(WORK+0x30)and status[0]['after_hex']==struct.pack('<I',rawstatus).hex();counts['source_outer_error_returns']+=1
   expected_free=[]if not case['response_nonnull']else[('response_free_register_clobbers','0xfffffe000a5356d8',['0xfffffe000847b020',hex(RESPONSE)])];expected_free += [('typed_free_register_clobbers','0xfffffe000a50c8f8',['0xfffffe000847aee0',hex(ap)]),('aligned_free_register_clobbers','0xfffffe000a50c950',[hex(WORK),'0x4000'])];assert[(m['kind'],m['pc'],m['registers8'][:2])for m in frees]==expected_free;assert[m['source_visit_index']for m in frees]==sorted(m['source_visit_index']for m in frees);counts['source_prepared_free_calls']+=len(frees)
  else:
   assert not frees and r['boundary']['kind']=='before_business_request_state'and r['boundary']['pc']=='0xfffffe000a51bee0'and r['boundary']['registers31'][9]=='0xfffffe000a59bf78';counts['metadata_success_boundaries']+=1
  assert len(models)==3+int(case['kind']=='provider')+len(frees)
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==288 and counts['source_visits']==725748 and counts['register_only_models']==1392 and counts['metadata_success_boundaries']==144 and counts['source_outer_error_returns']==144
 deps={n:sha(ROOT/n)for n in['recover_lskd_response.py','probe_lskd_response.py','lskd_response_symbolic.py','prove_lskd_response.py','lskd_response_contracts.json','lskd_response_profiles.json','lskd_response_proofs.json','probe_lskd_execute.py','lskd_execute_contracts.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']};out={'scope':'Distinct fresh response staging/metadata/error replays, full retained equality and independent source bytes/epochs.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_heap_executed':False,'business_request_operation_executed':False,'positive_publication_executed':False,'full_goal_complete':False};(ROOT/'lskd_response_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replays_sha256':sha(ROOT/'lskd_response_replays.json'),'all_checks_pass':True,'native_heap_executed':False,'business_request_operation_executed':False,'positive_publication_executed':False,'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_response_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
