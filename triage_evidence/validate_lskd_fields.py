#!/usr/bin/env python3
"""Distinct field/provider replays, independent bytes, epochs and source proofs.

O(B+C*(V+E)+W+256R+I) time/space plus solver-dependent cost. Declared typed
heap register returns are not native allocation, request or IPC evidence.
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
from probe_lskd_fields import Fields,cases,P,M64,OBJECT,PARAM,OUT,OTHER_OUT,BUFFER,DATA
from lskd_fields_symbolic import queries
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()
def read(n):return json.loads((ROOT/n).read_text())
def generic_key(r):return((((2*(r&0xbf13e450)-r+0x40ec1baf)&0xffffffff)^0x0e64f3c9)*0xcfc386d7)&0xffffffff
def record(tag,payload):return struct.pack('>HH',tag&0xffff,len(payload))+payload
def audit(r,c,prior,ctor,k,counts):
 state={};known=set();prov={};initial={};events={};snaps={};case=r['input'];globals=prior['mutable_globals']+ctor['additional_mutable_globals']+c['additional_mutable_globals']
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
 for call in r['source_calls']:snaps.setdefault(call['source_visit_index'],[]).extend(call[n]for n in['record','out_reference','object_before','payload','destination_before','argument_bytes']if n in call)
 for o in r['observations']:snaps.setdefault(o['source_visit_index'],[]).extend(o[n]for n in['out_reference','object']if n in o)
 for v in r['source_visits']:
  ix=v['source_visit_index'];assert k.read(int(v['pc'],16),4).hex()==v['bytes_hex'];counts['source_byte_checks']+=4
  for s in snaps.get(ix,[]):snap(s)
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
 for n in['object','params','out_reference','buffer','response_reference']:
  if r[n]is not None:snap(r[n])
 assert not any(v==2 for v in prov.values());counts['byte_reconstructed_cases']+=1
def main():
 c=read('lskd_fields_contracts.json');prior=read('legacy_stack_contracts.json');tlv=read('legacy_tlv_contracts.json');ctor=read('lskd_request_contracts.json');p=read('lskd_fields_profiles.json');proof=read('lskd_fields_proofs.json');counts=Counter();k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit')
 for obj,name in[(c,'recover_lskd_fields.py'),(p,'probe_lskd_fields.py'),(proof,'prove_lskd_fields.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)and not obj['full_goal_complete']
  for dep,h in obj.get('dependencies',{}).items():assert sha(ROOT/dep)==h,dep
 assert k.sha256==c['kernel_collection_sha256']==p['kernel_collection_sha256'];assert sha(SOURCE)==c['source_sha256']==p['source_sha256']
 for f in c['functions']:assert function(k,e,int(f['start'],16))==f;counts['compiler_envelopes']+=1
 for s in c['spans']:
  now=span(k,int(s['start'],16),int(s['end'],16));assert all(now[n]==s[n]for n in now);assert IMAGE.read(int(s['start'],16),int(s['end'],16)-int(s['start'],16)).hex()==s['bytes_hex'];counts['new_source_spans']+=1
 assert k.symbols([int(a,16)for a in c['exact_symbols']])==c['exact_symbols']
 for scan in c['reference_census']:assert census(int(scan['target'],16))==scan;counts['census_text_words']+=scan['text_words_scanned'];counts['direct_calls']+=len(scan['direct_calls'])
 for b in prior['bank_rules']+tlv['bank_rules']+ctor['bank_rules']+c['bank_rules']:
  l=int(b['left'],16);rr=int(b['right'],16);assert IMAGE.read(l,256).hex()==b['left256_hex']and IMAGE.read(rr,256).hex()==b['right256_hex'];out=selected(l,rr,int(b['key'],16),int(b['additive'],16),base=int(b['base'],16),bias=int(b['bias'],16));assert all(out[n]==b[n]for n in out);assert pointer(k,int(b['slot'],16))==b['original_pointer'];counts['exhaustive_rules']+=1;counts['bank_byte_inputs']+=256
 for b in c['original_bank_pointer_roots']:assert pointer(k,int(b['slot'],16))==b;counts['new_bank_pointer_roots']+=1
 qs,lifts=queries(c,tlv);assert lifts==proof['source_lift_counts'];assert[n for n,q in qs]==[v['name']for v in proof['proofs']]
 for (name,q),row in zip(qs,proof['proofs']):
  op=ROOT/row['original_file'];np=ROOT/row['file'];assert sha(op)==row['original_sha256']and sha(np)==row['sha256'];orig=z3.parse_smt2_string(op.read_text());assert len(orig)==1
  for formula in[z3.simplify(q),z3.simplify(orig[0]),z3.Xor(z3.simplify(q),z3.simplify(orig[0])),*z3.parse_smt2_string(np.read_text())]:s=z3.Solver();s.set(timeout=30000);s.add(formula);assert str(s.check())=='unsat',name
  counts['source_derived_proofs_unsat']+=1
 expected=list(cases());assert[r['input']for r in p['cases']]==expected;fresh=[]
 for j,(case,old)in enumerate(zip(expected,p['cases'])):
  g=Fields(case);r=g.run();del g;assert r==old,(j,case);fresh.append(r);counts['fresh_cases']+=1;counts['source_visits']+=len(r['source_visits']);assert not r['undefined_private_value_reads']and not r['native_API_executed']and not r['typed_heap_executed']and not r['request_execution_executed']and not r['external_IPC_emission_proved']and not r['native_carrier_validity_proved'];assert[v['source_visit_index']for v in r['source_visits']]==list(range(len(r['source_visits'])));audit(r,c,prior,ctor,k,counts)
  assert not any(0xfffffe000a50c508<=int(v['pc'],16)<0xfffffe000a50c980 or int(v['pc'],16)in[0xfffffe000c4ba154,0xfffffe000c4ba60c]or 0xfffffe000a54df90<=int(v['pc'],16)<0xfffffe000a54e220 for v in r['source_visits'])
  calls=r['source_calls'];copies=[v for v in calls if v['kind']=='original_payload_copy'];generic=[v for v in calls if v['kind']=='generic_append_record']
  for call in calls:assert call['target_executed_in_private_guest']and r['source_visits'][call['source_visit_index']+1]['pc']==call['target']
  for call in generic:
   a=int(call['record']['address'],16);raw=bytes.fromhex(call['record']['bytes_hex']);key=generic_key(a);assert(int.from_bytes(raw[12:16],'little')^key)==0x224;length=(int.from_bytes(raw[8:10],'little')+key-0x6601)&0xffff;tag=((int.from_bytes(raw[10:12],'little')-key)^0x8151)&0xffff;assert length<=17 and tag in[0,0xffff,0x5678,0x72,0x8b,0x6b,0x6c,0x89,0x8a,0x7e];counts['source_generic_records']+=1
  for call in copies:
   n=int(call['registers8'][2],16);assert n==call['payload']['size_bytes'];counts['original_copy_calls']+=1;counts['original_copy_bytes']+=n
  if case['kind']=='field':
   assert not r['models']and r['boundary']['kind']=='returned'and r['boundary']['SP']==r['entry_SP'];counts['standalone_field_returns']+=1;initial=bytearray.fromhex(r['initial_object160_hex']);buf=bytearray(b'\xa5'*512)
   if case['route']!='append':assert int(r['boundary']['registers31'][0],16)==0xffff5966 and not copies;counts['rejection_cases']+=1
   else:
    assert int(r['boundary']['registers31'][0],16)==0 and len(copies)==1;tag=case['inputs8'][1]&0xffff;payload=bytes((n*37+11)&255 for n in range(case['inputs8'][3]&0xffff))if case['family']=='span'else struct.pack('>I',case['inputs8'][2]&0xffffffff);packet=record(tag,payload);assert copies[0]['payload']['bytes_hex']==payload.hex();assert copies[0]['registers8'][0]==hex(BUFFER+8)and int(copies[0]['registers8'][2],16)==len(payload);buf[4:4+len(packet)]=packet;struct.pack_into('<II',initial,152,3,4+len(packet));counts['standalone_append_cases']+=1;counts['standalone_packet_bytes']+=len(packet)
    if not payload:counts['nonnull_zero_length_appends']+=1
    if case['family']=='span'and case['inputs8'][3]>0xffff:counts['narrowed_length_appends']+=1
    if case['family']=='u32':counts['scalar32_appends']+=1
   assert r['object']['bytes_hex']==initial.hex()and r['buffer']['bytes_hex']==buf.hex()
  else:
   provider=next(v for v in c['providers']if v['label']==case['provider']);assert r['boundary']['kind']=='before_request_execution'and r['boundary']['pc']==provider['execution_call'];assert r['boundary']['registers31'][0]==hex(OBJECT)and r['response_reference']['bytes_hex']=='00'*8 and r['response_reference']['provenance_hex']=='01'*8;assert len(r['models'])==1
   m=r['models'][0];assert m['target']=='0xfffffe000c4ba154'and m['result_X0_fixture']==hex(OBJECT)and not m['target_executed']and not m['memory_effects_modeled'];counts['typed_heap_return_models']+=1
   pub=[w for w in r['source_writes']if w['pc']=='0xfffffe000a53191c'];assert len(pub)==1 and pub[0]['address']==r['out_address']and pub[0]['after_hex']==struct.pack('<Q',OBJECT).hex();counts['source_pointer_publications']+=1
   packet=record(0x72,struct.pack('>Q',case['context64']));extra=[]
   if case['provider']=='vault':extra=[(0x8b,struct.pack('<Q',OTHER_OUT))]
   elif case['provider']=='avd':extra=[(tag,struct.pack('<Q',PARAM+off))for tag,off in[(0x6b,0),(0x6c,0xa0),(0x89,0x60),(0x8a,0xbc)]]
   elif case['provider']=='allowed':extra=[(0x7e,struct.pack('>I',0x13579bdf))]
   for tag,b in extra:packet+=record(tag,b)
   want=bytearray(160);struct.pack_into('<4I',want,0,1,provider['operation32'],provider['entry_limit32'],provider['capacity32']);want[16:16+len(packet)]=packet;struct.pack_into('<QII',want,144,OBJECT+16,1+len(extra),len(packet));assert r['object']['bytes_hex']==want.hex()and r['object']['provenance_hex']=='01'*160;assert len(copies)==1+len(extra)and len(generic)==len(copies);counts['provider_source_compositions']+=1;counts['provider_packet_bytes']+=len(packet);counts['provider_field_appends']+=len(copies)
   appends=[v for v in calls if v['kind']in['provider_append64','provider_span','provider_u32']];assert len(appends)==1+len(extra)
   for call in appends:
    assert call['registers8'][0]==hex(OBJECT);reads=[v for v in r['source_reads']if v['address']==r['out_address']and v['bytes_hex']==pub[0]['after_hex']and pub[0]['source_visit_index']<v['source_visit_index']<call['source_visit_index']and call['source_visit_index']-v['source_visit_index']<=8];assert reads;counts['provider_publication_consumptions']+=1
   spans=[v for v in appends if v['kind']=='provider_span'];assert[(int(v['registers8'][1],16),bytes.fromhex(v['argument_bytes']['bytes_hex']))for v in spans]==[(t,b)for t,b in extra if t!=0x7e];counts['provider_pointer_representations']+=len(spans)
   obs=[v for v in r['observations']if v['kind']=='field_return_to_provider'];assert len(obs)==len(appends)and all(int(v['registers31'][0],16)==0 for v in obs)
   params=bytearray.fromhex(r['initial_params256_hex'])
   if case['provider']=='avd':params[240:248]=bytes(8);counts['AVD_source_cleared_bytes']+=8;assert len(packet)==60 and provider['capacity32']-len(packet)==4
   assert r['params']['bytes_hex']==params.hex()
  if j%24==0:gc.collect();print(json.dumps({'fresh_cases_completed':j+1}),flush=True)
 assert counts['fresh_cases']==336 and counts['source_visits']==280500 and counts['provider_source_compositions']==48 and counts['source_pointer_publications']==48
 deps={n:sha(ROOT/n)for n in['recover_lskd_fields.py','probe_lskd_fields.py','lskd_fields_symbolic.py','prove_lskd_fields.py','lskd_fields_contracts.json','lskd_fields_profiles.json','lskd_fields_proofs.json','probe_lskd_request.py','lskd_request_contracts.json','legacy_tlv_contracts.json','legacy_stack_contracts.json','probe_legacy_stack.py','kernel_native_reader.py','kext_port_tools.py']};out={'scope':'Distinct fresh field/provider replay with complete retained equality and independent compact bytes/epochs.','generator_sha256':sha(Path(__file__)),'dependencies':deps,'cases':fresh,'typed_heap_executed':False,'request_execution_executed':False,'full_goal_complete':False};(ROOT/'lskd_fields_replays.json').write_text(json.dumps(out,indent=2)+'\n');checks={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':deps,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'verified_counts':dict(counts),'source_lift_counts':lifts,'fresh_replays_sha256':sha(ROOT/'lskd_fields_replays.json'),'all_checks_pass':True,'typed_heap_executed':False,'request_execution_executed':False,'native_carrier_validity_proved':False,'full_goal_complete':False};(ROOT/'lskd_fields_checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps({'all_checks_pass':True,'verified_counts':dict(counts),'source_lift_counts':lifts}),flush=True)
if __name__=='__main__':main()
