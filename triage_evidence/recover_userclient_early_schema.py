#!/usr/bin/env python3
"""Freeze exhausted-input handoff, first schema lookup and ADID field custody.
O(B+I+C*W+packet bytes) construction/space; no native execution or IDB change.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_early_publication as Parent
P='userclient_early_schema'
SCOPE='Conditional exhausted early parse through container publication, source-fixed action selection and caller-specific lookup of raw key fa834112. Independent byte parsing finds that key as a nested u32 field in twelve frozen source-built ADID Avp follow-up packets. Kernel field decoding/meaning, Avp100-to-primary-selector26 transport, native admission/PAC/ownership and matched transactions remain unknown. Continuous private execution remains stopped.'
SPANS={'mode_literal':(0xfffffe000a635960,0xfffffe000a63596c),'result_root':(0xfffffe000a636054,0xfffffe000a63605c),'lookup_root':(0xfffffe000a635eac,0xfffffe000a635eb4),'container_alias':(0xfffffe000a636344,0xfffffe000a63634c),'container_zero':(0xfffffe000a63593c,0xfffffe000a635940),'result_zero':(0xfffffe000a635944,0xfffffe000a635948),'container_root_save':(0xfffffe000a63594c,0xfffffe000a635950),'exhaustion':(0xfffffe000a660b2c,0xfffffe000a660b64),'container_publish':(0xfffffe000a660b64,0xfffffe000a660b88),'action_first':(0xfffffe000a660b88,0xfffffe000a660bb8),'action_second':(0xfffffe000a660bb8,0xfffffe000a660bc8),'action_third':(0xfffffe000a660bc8,0xfffffe000a660bd8),'action_status':(0xfffffe000a660bd8,0xfffffe000a660c28),'schema_request':(0xfffffe000a6366e0,0xfffffe000a636728),'schema_entry':(0xfffffe000a654278,0xfffffe000a6542d4),'schema_lookup':(0xfffffe000a6542d4,0xfffffe000a654330)}
BRANCHES=Parent.BRANCHES|{0xfffffe000a660b50:[0x6c7],0xfffffe000a660b74:[0x693],0xfffffe000a660c0c:[0x656,0xc35],0xfffffe000a636704:[0x20a],0xfffffe000a654290:[0xf6],0xfffffe000a6542bc:[0x3d8,0x3f2],0xfffffe000a654310:[0x49a],0xfffffe000a662ac0:[0x6c,0x7f]}
DIRECT=Parent.DIRECT|{0xfffffe000a660bb4:('b.eq',0xfffffe000a66128c),0xfffffe000a660bc4:('b.eq',0xfffffe000a661144),0xfffffe000a660bd4:('b.ne',0xfffffe000a636310)}
FALSE=Parent.FALSE+['kernel_schema_field_decoding_established','schema_field_meaning_established','Avp100_primary_selector26_transport_established','native_ADID_kext_transaction_correlated']
def records(data,start,end):
 rows=[];at=start
 while at<end:
  assert at+10<=end;key=int.from_bytes(data[at:at+4],'big');kind=int.from_bytes(data[at+4:at+6],'big');n=int.from_bytes(data[at+6:at+10],'big');assert at+10+n<=end;rows.append({'offset':at,'key32':key,'type16':kind,'length32':n,'body_offset':at+10,'end_exclusive':at+10+n});at+=10+n
 assert at==end;return rows
def adid_fields():
 checks=json.loads(read(ROOT/'adid_avp_packet_checks.json'));contracts=json.loads(read(ROOT/'adid_avp_packet_contracts.json'));profiles=json.loads(read(ROOT/'adid_avp_packet_profiles.json'));assert contracts['thin_sha256']==profiles['thin_sha256']=='ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf';rows=[]
 for packet in checks['source_built_followup_packets']:
  data=bytes.fromhex(packet['bytes320']);assert len(data)==320 and sha256(data).hexdigest()=='fb8563f814c1534bf411f71cba2ee7ce87e5fb8aeb4b5e1016e258b9fca7eda8';start,end=0,len(data);path=[]
  for j,key in enumerate([0xfd2821c7,0x351bdea7,0xfd2821c7,0xfa834112]):
   matches=[q for q in records(data,start,end)if q['key32']==key];assert len(matches)==1;q=matches[0];path.append(q)
   if j<3:assert q['type16']==0x50db;start,end=q['body_offset'],q['end_exclusive']
   else:assert q['type16']==0x9777 and q['length32']==4 and q['offset']==118 and data[q['body_offset']:q['end_exclusive']]==bytes(4)
  rows.append({'label':packet['label'],'packet_sha256':sha256(data).hexdigest(),'packet_size_bytes':320,'containment_path':path,'field_record_hex':data[118:132].hex(),'raw_scalar32':0})
 assert len(rows)==12;return {'thin_sha256':contracts['thin_sha256'],'uuid':contracts['uuid'],'source_profiles_sha256':sha(ROOT/'adid_avp_packet_profiles.json'),'source_checks_sha256':sha(ROOT/'adid_avp_packet_checks.json'),'source_contracts_sha256':sha(ROOT/'adid_avp_packet_contracts.json'),'packets':rows,'new_native_callback_executed':False}
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_early_publication_checks.json'));parents=json.loads(read(ROOT/'userclient_early_data_checks.json'));raw=k.read(0xfffffe000a635208,0x31728);assert sha256(raw).hexdigest()==prior['source']['container']['sha256']and IMAGE.read(0xfffffe000a635208,len(raw))==raw;spans=[]
 for label,(a,z)in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,len(b))==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 rows=[]
 for p in prior['predecessor_states']:
  r=parents['cases'][p['predecessor_case_index']];g=[int(x,16)for x in p['handoff_state']['registers31']];F=int(p['frame_base_SP'],16);C,S=g[11],g[3];H=int(p['original_container'],16);cells=[]
  for root,base,off,n,want in [('C',C,0xb0,8,H),('C',C,0x170,8,C+0x418),('C',C,0x718,8,C+0x418),('C',C,0x418,8,0),('F',F,0x908,8,C+0x418),('F',F,0x648,8,S+0xbc4),('F',F,0x708,8,C+0x710),('S',S,0x1e0,4,0x1830b7ce),('S',S,0xbc4,4,0)]:
   state=[None]*n;touches=[]
   for w in r['source_writes']:
    a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(a,base+off);hi=min(a+len(b),base+off+n)
    if lo<hi:
     touches.append(w)
     for addr in range(lo,hi):state[addr-base-off]=b[addr-a]
   assert None not in state and int.from_bytes(bytes(state),'little')==want;cells.append({'root':root,'offset':hex(off),'size_bytes':n,'reconstructed_bytes_hex':bytes(state).hex(),'overlapping_source_stores':touches})
  visit=next(j for j,v in enumerate(r['source_visits'])if v['pc']=='0xfffffe000a63594c');assert int(r['source_frames'][visit]['registers31'][17],16)==C+0x418
  rows.append({**p,'additional_source_defined_cells':cells})
 names=set(prior['dependencies'])|{'recover_userclient_early_publication.py','audit_userclient_early_publication.py','userclient_early_publication_checks.json','userclient_early_publication_audit.json','adid_avp_packet_checks.json','adid_avp_packet_profiles.json','adid_avp_packet_contracts.json','validate_adid_avp_packet_delivery.py','recover_adid_avp_packets.py','probe_adid_avp_packets.py'}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(names)},'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'bank_rule':prior['source']['bank_rule'],'banks':prior['source']['banks']},'publication_source':prior['source'],'payload_source':prior['payload_source'],'header_source':prior['header_source'],'predecessor_states':rows,'adid_evidence':adid_fields(),'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(q['instructions'])for q in spans),'original_table_pointers':len(pointers),'predecessor_states':len(rows),'additional_source_cells_per_state':9,'ADID_packets':12,'ADID_containment_levels':4,'requested_raw_key32':0xfa834112},'conditional_exhaustion_to_schema_lookup_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
