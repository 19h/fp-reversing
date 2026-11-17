#!/usr/bin/env python3
"""Freeze actual schema lookup helper and caller result consumers.
O(B+I+C*W+256) construction/space; no native execution or IDB mutation.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_schema_registry as Parent
P='userclient_schema_lookup_result'
SCOPE='Conditional source execution of the actual schema token541 record through the shared lookup helper, its saved-register frame and caller status/found/payload consumers. Positive arbitrary capacity, first occupied-key hit, first empty candidate and NULL-array profiles; explicit opaque authenticated-return premise. Native authentication, allocation epoch, holder/table coherence, payload pointee validity, complete operation and daemon/kext transport remain unknown.'
def pc(x):return 0xfffffe0000000000+x
SPANS={n:(pc(a),pc(z))for n,a,z in [
 ('result_frame_roots',0xa6362f8,0xa636300),
 ('result_helper_entry',0xa5ae354,0xa5ae418),('result_helper_gate',0xa5ae418,0xa5ae4a0),
 ('result_helper_decode',0xa5ae4a0,0xa5ae518),('result_flag_clear',0xa5ae518,0xa5ae534),
 ('result_probe_setup',0xa5ae534,0xa5ae658),('result_probe_resume',0xa5ae658,0xa5ae66c),
 ('result_probe_wrap',0xa5ae66c,0xa5ae6b4),('result_probe_budget',0xa5ae6b4,0xa5ae700),
 ('result_probe_state',0xa5ae700,0xa5ae724),('result_empty_test',0xa5ae724,0xa5ae72c),
 ('result_key_address',0xa5ae758,0xa5ae774),('result_key_retag',0xa5ae774,0xa5ae778),
 ('result_key_compare',0xa5ae778,0xa5ae7a0),('result_choose_empty',0xa5ae7cc,0xa5ae7f0),
 ('result_found',0xa5ae7f0,0xa5ae830),('result_found_store',0xa5ae830,0xa5ae844),
 ('result_index',0xa5ae844,0xa5ae864),('result_status_return',0xa5ae864,0xa5ae88c),
 ('result_caller_return',0xa65b530,0xa65b564),('result_payload_address',0xa65b564,0xa65b594),
 ('result_payload_retag',0xa65b594,0xa65b598),('result_payload_copy',0xa65b598,0xa65b5ac),
 ('result_restore',0xa65b5ac,0xa65b5ec),('result_inner_trampoline',0xa65b5ec,0xa65b5f8),
 ('result_outer_trampoline',0xa65b5f8,0xa65b608),('result_outer_status',0xa636854,0xa6368b0),
 ('result_outer_found',0xa6368b0,0xa636904),('result_outer_payload',0xa636904,0xa636958)]}
BRANCHES=Parent.BRANCHES|{pc(k):v for k,v in {
 0xa5ae48c:[0x541,0x55a],0xa5ae50c:[0x30d,0x323],0xa5ae528:[0x323],
 0xa5ae5f4:[0xeba],0xa5ae65c:[0x5ca],0xa5ae6a4:[0x5ca,0xe3e],0xa5ae6f0:[0x79c,0x7b0],
 0xa5ae794:[0x234,0x29a],0xa5ae7e4:[0x6d0],0xa5ae824:[0x7db,0x7ff],0xa5ae838:[0x7db],0xa5ae850:[0x7b0],
 0xa65b558:[0x2ed,0x2f5],0xa65b5a0:[0x2ed],0xa65b5b8:[0x272],
 0xa636898:[0x656,0x884],0xa6368ec:[0xaca,0xe68],0xa636940:[0xac2,0xaca]}.items()}
RETAGS=Parent.RETAGS|{pc(0xa5ae770):pc(0xa5ae774),pc(0xa65b590):pc(0xa65b594)}
DIRECT=Parent.DIRECT|{pc(0xa5ae720):('b.eq',pc(0xa5ae758)),pc(0xa5ae728):('b.eq',pc(0xa5ae7cc))}
FALSE=[n for n in Parent.FALSE if n!='schema_registry_lookup_result_established']+['native_lookup_result_established','native_PAC_verified','payload_pointee_validity_established','whole_operation_completed']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_schema_registry_checks.json'));assert prior==Parent.build();helper=json.loads(read(ROOT/'userclient_hash_table_lookup_checks.json'));parents=json.loads(read(ROOT/'userclient_early_data_checks.json'));spans=[]
 for label,(a,z)in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ii]})
 envelope=helper['lookup_function'];a=int(envelope['start'],16);raw=bytes.fromhex(envelope['bytes_hex']);assert k.read(a,len(raw))==IMAGE.read(a,len(raw))==raw
 rule=next(r for r in helper['bank_rules']if r['name']=='helper_table');banks={}
 for n,a in [('BL',int(rule['left'],16)),('BR',int(rule['right'],16))]:
  raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[n]={'address':hex(a),'bytes_hex':raw.hex()}
 left,right=(bytes.fromhex(banks[n]['bytes_hex'])for n in ['BL','BR']);assert all(j^right[left[j]^int(rule['key'],16)]==int(rule['constant'],16)for j in range(256));assert pointer(k,int(rule['slot'],16))==rule['original_pointer']
 pointers=[pointer(k,TABLE+8*j)|{'index':j}for j in sorted({j for js in BRANCHES.values()for j in js})]
 for q in pointers:assert int(q['target'],16)==qword(TABLE+8*q['index'])
 rows=[]
 for p in prior['predecessor_states']:
  r=parents['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);cells=[]
  for off,want,producer in [(0xa30,pc(0xccc30d0),pc(0xa6362f8)),(0xa60,TABLE,pc(0xa6362fc))]:
   state=[None]*8;touches=[]
   for w in r['source_writes']:
    a=int(w['address'],16);b=bytes.fromhex(w['after_hex']);lo=max(a,F+off);hi=min(a+len(b),F+off+8)
    if lo<hi:
     touches.append(w)
     for addr in range(lo,hi):state[addr-F-off]=b[addr-a]
   assert None not in state and int.from_bytes(bytes(state),'little')==want and int(touches[-1]['pc'],16)==producer;cells.append({'root':'F','offset':hex(off),'size_bytes':8,'reconstructed_bytes_hex':bytes(state).hex(),'overlapping_source_stores':touches})
  rows.append({**p,'result_additional_source_cells':cells})
 names=set(prior['dependencies'])|{'recover_userclient_schema_registry.py','audit_userclient_schema_registry.py','userclient_schema_registry_checks.json','userclient_schema_registry_audit.json','recover_userclient_hash_table_initializer.py','audit_userclient_hash_table_initializer.py','userclient_hash_table_initializer_checks.json','userclient_hash_table_initializer_audit.json'}
 return {**prior,'generator_sha256':sha(__file__),'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in sorted(names)},'registry_source':prior['source'],'source':{'container':prior['source']['container'],'spans':spans,'branch_pointers':pointers,'bank_rule':prior['source']['bank_rule'],'banks':prior['source']['banks']},'result_helper_envelope':envelope,'result_bank_rule':rule,'result_banks':banks,'predecessor_states':rows,'verified_counts':{'new_source_spans':len(spans),'new_captured_words':sum(len(q['instructions'])for q in spans),'original_table_pointers':len(pointers),'predecessor_states':len(rows),'additional_source_cells_per_state':2,'additional_source_cell_bytes_per_state':16,'new_bank_rules':1,'new_bank_input_cases':256,'helper_frame_bytes':112,'entry_stride_bytes':24},'conditional_source_lookup_result_established':True,'schema_registry_lookup_result_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
