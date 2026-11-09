#!/usr/bin/env python3
"""Distinct workspace/provider replays, unknown-byte epochs and source proofs.

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
from probe_lskd_execute import Execute,cases,P,M64,OBJECT,PARAM,OUT,OTHER_OUT,WORK,AUX
from lskd_execute_symbolic import queries
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
def audit(r,c,prior,ctor,fields,k,counts):
 state={};known=set();prov={};initial={};events={};snaps={};case=r['input'];globals=prior['mutable_globals']+ctor['additional_mutable_globals']+fields['additional_mutable_globals']+c['additional_mutable_globals']
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
 for call in r['source_calls']:snaps.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload','destination_before','argument_bytes','workspace_header']if n in call)
 for o in r['observations']:snaps.setdefault(o['source_visit_index'],[]).extend(o[n]for n in['out_reference','object']if n in o)
 if r['execution_input']is not None:
  x=r['execution_input'];snaps.setdefault(x['source_visit_index'],[]).extend([x['response_reference'],x['request']])
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snaps.get(ix,[]):snap(s)
  for kind,e in events.get(ix,[]):
   assert e['pc']==v['pc'];a=int(e['address'],16);n=e['size_bytes']
   if kind=='read':
    assert not e['probe_only']and bytes_at(a,n).hex()==e['bytes_hex']
    if P<=a<a+n<=P+0x20000:assert all(x in known for x in range(a,a+n))
    counts['read_epochs']+=1
   else:
    b=bytes.fromhex(e['after_hex']);assert len(b)==n
    if not P<=a<a+n<=P+0x20000:assert any(int(d['address'],16)<=a<a+n<=int(d['address'],16)+8 for d in globals)
    for x,byte in enumerate(b,a):state[x]=byte;known.add(x);prov[x]=1
    counts['source_write_epochs']+=1
 for n in['workspace','auxiliary','object','params','out_reference']:snap(r[n])
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1
def main():
 c=read('lskd_execute_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');ctor=read('lskd_request_contracts.json');fields=read('lskd_fields_contracts.json');p=read('lskd_execute_profiles.json');proof=read('lskd_execute_proofs.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_lskd_execute.py'),(p,'probe_lskd_execute.py'),(proof,'prove_lskd_execute.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols'];assert census(0xfffffe000a50c508)==c['execution_wrapper_census'];counts['census_text_words']=c['execution_wrapper_census']['text_words_scanned'];counts['direct_execution_calls']=len(c['execution_wrapper_census']['direct_calls'])
 for b in prior['bank_rules']+tlv['bank_rules']+ctor['bank_rules']+fields['bank_rules']+c['bank_rules']:
  l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b;counts['new_bank_pointer_roots']+=1
 for v in c['typed_views']:assert k.read(int(v['address'],16),64).hex()==v['bytes64_hex']and pointer(k,int(v['name_pointer']['slot'],16))==v['name_pointer'];assert v['metadata_size32']==4096 and v['metadata_flags32']==0xe4;counts['typed_views']+=1
 for slot in c['first_dispatch_slots']:assert pointer(k,int(slot['original_pointer']['slot'],16))==slot['original_pointer'];counts['first_dispatch_slots']+=1
 bound=next(s for s in c['spans']if s['label']=='bounds_checker');assert[(i['mnemonic'],i['operands'])for i in bound['instructions']]==[('bti','c'),('cmp','x0, x1'),('b.hi','#0xfffffe000a561068'),('ret',''),('brk','#1')]
 qs,lifts=queries(c);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[]
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Execute(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['undefined_private_value_reads']and not r['native_API_executed']and not r['native_heap_executed']and not r['native_request_execution_executed']and not r['protected_operation_executed']and not r['external_IPC_emission_proved']and not r['first_nonnull_output_state_executed'];assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,c,prior,ctor,fields,k,counts)
  assert not any(0xfffffe000a5247ac<=int(v['pc'],16)<0xfffffe000a5248a0 or int(v['pc'],16)in[0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24,0xfffffe000a561068]for v in r['source_visits'])
  for call in r['source_calls']:assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
  assert r['auxiliary']['bytes_hex']=='a5'*4096 and r['auxiliary']['known_mask_hex']=='00'*4096 and r['auxiliary']['provenance_hex']=='00'*4096;assert not any(AUX<=int(w['address'],16)<AUX+4096 for w in r['source_writes']);counts['untouched_auxiliary_cases']+=1
  assert r['out_reference']['bytes_hex']==struct.pack('<Q',case['out_initial64']).hex()and r['out_reference']['provenance_hex']=='03'*8
  for m in r['models']:assert not m['target_executed']and not m['memory_effects_modeled'];counts['register_only_models']+=1
  if case['kind']=='bounds':
   a,b=case['inputs8'][:2];assert not r['models']and not r['request_wrapper_executed_in_private_guest']and not r['protected_dispatcher_prefix_executed_in_private_guest'];assert r['boundary']['kind']==('returned'if a<=b else'before_bounds_trap');assert r['workspace']['bytes_hex']=='a5'*0x4000 and r['workspace']['known_mask_hex']=='00'*0x4000
   if a<=b:assert r['boundary']['SP']==r['entry_SP'];counts['bounds_checker_returns']+=1
   else:counts['stopped_before_bounds_trap']+=1
   continue
  models=r['models'];req_models=[m for m in models if m['kind']=='typed_heap_register_return'];aligned=[m for m in models if m['kind']=='aligned_workspace_register_return'];typed=[m for m in models if m['kind']=='auxiliary_typed_register_return'];assert len(aligned)==len(typed)==1
  wm=aligned[0];am=typed[0];assert wm['pc']=='0xfffffe000a50c6ac'and wm['target']=='0xfffffe000c4b9a08'and wm['registers8'][:2]==['0x4000','0x40'];assert am['pc']=='0xfffffe000a50c74c'and am['target']=='0xfffffe000c4ba154'and am['registers8'][0]=='0xfffffe000847ae20';assert wm['source_visit_index']<am['source_visit_index'];wp=WORK if case['workspace_nonnull']else 0;ap=AUX if case['auxiliary_nonnull']else 0;assert wm['result_X0_fixture']==r['workspace_pointer']==hex(wp)and am['result_X0_fixture']==r['auxiliary_pointer']==hex(ap);counts['workspace_allocation_models']+=1;counts['auxiliary_allocation_models']+=1
  if case['kind']=='provider':
   provider=next(v for v in fields['providers']if v['label']==case['provider']);x=r['execution_input'];assert x is not None and x['pc']==provider['execution_call']and x['request_pointer']==hex(OBJECT)and x['response_reference']['bytes_hex']=='00'*8 and x['response_reference']['provenance_hex']=='01'*8;obj=provider_request(case,provider);assert x['request']['bytes_hex']==r['object']['bytes_hex']==obj.hex()and x['request']['provenance_hex']==r['object']['provenance_hex']=='01'*160;request=OBJECT;out=int(x['response_reference']['address'],16);assert len(req_models)==1 and req_models[0]['result_X0_fixture']==hex(OBJECT)and len(models)==3
   assert not any(OBJECT<=int(v['address'],16)<OBJECT+160 and v['source_visit_index']>x['source_visit_index']for v in r['source_reads']+r['source_writes']);assert not any(out<=int(v['address'],16)<out+8 and v['source_visit_index']>x['source_visit_index']for v in r['source_writes']);counts['provider_request_lineages']+=1;counts['provider_request_bytes_preserved']+=160;counts['provider_packet_bytes_preserved']+=int.from_bytes(obj[156:160],'little')
  else:request,out=case['inputs8'][:2];assert not req_models and r['execution_input']is None
  checkcalls=[v for v in r['source_calls']if v['kind']=='unsigned_bounds_checker'];assert checkcalls[0]['pc']=='0xfffffe000a50c7a8'and checkcalls[0]['registers8'][:2]==[hex(wp+0x40),hex(wp+0x4000)];counts['wrapper_range_checks']+=1
  if not case['workspace_nonnull']:
   assert r['boundary']['kind']=='before_null_workspace_store'and r['boundary']['pc']=='0xfffffe000a50c7e4'and not r['protected_dispatcher_prefix_executed_in_private_guest']and len(checkcalls)==1;assert r['workspace']['bytes_hex']=='a5'*0x4000 and r['workspace']['known_mask_hex']=='00'*0x4000;assert len(models)==2;counts['stopped_before_null_workspace_store']+=1;continue
  assert len(checkcalls)==2 and checkcalls[1]['pc']=='0xfffffe000a55f7dc'and checkcalls[1]['registers8'][:2]==[hex(WORK+0x80),hex(WORK+0x4000)];counts['dispatcher_range_checks']+=1
  completed=case['mode']=='null_output_return';want,known=workspace(request,out,ap,0x5e5571af if completed else None);assert r['workspace']['bytes_hex']==want.hex()and r['workspace']['known_mask_hex']==known.hex()and r['workspace']['provenance_hex']==known.hex();ws=[w for w in r['source_writes']if WORK<=int(w['address'],16)<WORK+0x4000];assert{a for w in ws for a in range(int(w['address'],16),int(w['address'],16)+w['size_bytes'])}=={WORK+j for j,b in enumerate(known)if b};counts['source_defined_workspace_bytes']+=sum(known);counts['source_workspace_headers']+=1
  dc=[v for v in r['source_calls']if v['kind']=='dispatcher_prefix'];assert len(dc)==1 and dc[0]['registers8'][0]==hex(WORK);pre,pk=workspace(request,out,ap);assert dc[0]['workspace_header']['bytes_hex']==pre[:64].hex()and dc[0]['workspace_header']['known_mask_hex']==pk[:64].hex();assert r['protected_dispatcher_prefix_executed_in_private_guest']
  if completed:
   assert not out and r['boundary']['kind']=='returned'and r['boundary']['SP']==r['entry_SP']and int(r['boundary']['registers31'][0],16)==0xffff5966;store=[w for w in ws if w['pc']=='0xfffffe000a51062c'];assert len(store)==1 and store[0]['address']==hex(WORK+48)and store[0]['after_hex']=='af71555e';free=[m for m in models if m['kind'].endswith('free_register_clobbers')];assert len(models)==4 and len(free)==2
   assert free[0]['pc']=='0xfffffe000a50c8f8'and free[0]['target']=='0xfffffe000c4ba368'and free[0]['registers8'][:2]==['0xfffffe000847aee0',hex(ap)];assert free[1]['pc']=='0xfffffe000a50c950'and free[1]['target']=='0xfffffe000c4b9a24'and free[1]['registers8'][:2]==[hex(WORK),'0x4000'];assert free[0]['source_visit_index']<free[1]['source_visit_index'];assert any(v['pc']=='0xfffffe000a55f814'and v['target']=='0xfffffe000a510628'for v in r['source_dispatches']);counts['source_null_output_returns']+=1;counts['source_status_bytes']+=4;counts['typed_free_register_models']+=1;counts['aligned_free_register_models']+=1
  else:
   target='0xfffffe000a510628'if not out else'0xfffffe000a5247ac';assert r['boundary']['kind']=='before_first_protected_state'and r['boundary']['pc']=='0xfffffe000a55f814'and r['boundary']['registers31'][9]==target and r['boundary']['registers31'][17]=='0xe140';counts['first_dispatch_boundaries']+=1;counts['nonnull_output_state_boundaries'if out else'null_output_state_boundaries']+=1
  if j%16==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==192 and counts['source_visits']==172564 and counts['source_null_output_returns']==24 and counts['provider_request_lineages']==48 and counts['register_only_models']==432
 deps={n:sha(ROOT/n)for n in['recover_lskd_execute.py','probe_lskd_execute.py','lskd_execute_symbolic.py','prove_lskd_execute.py','lskd_execute_contracts.json','lskd_execute_profiles.json','lskd_execute_proofs.json','probe_lskd_fields.py','lskd_fields_contracts.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']};out={'scope':'Distinct fresh workspace/provider/null-output replays, complete retained equality and independent partial initialization/epochs.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'native_heap_executed':False,'protected_operation_executed':False,'full_goal_complete':False};(ROOT/'lskd_execute_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replays_sha256':sha(ROOT/'lskd_execute_replays.json'),'all_checks_pass':True,'native_heap_executed':False,'protected_operation_executed':False,'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_execute_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
